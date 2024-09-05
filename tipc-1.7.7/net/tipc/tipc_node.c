/*
 * net/tipc/tipc_node.c: TIPC node management routines
 *
 * Copyright (c) 2000-2006, Ericsson AB
 * Copyright (c) 2005-2008, 2010, Wind River Systems
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2024
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "tipc_core.h"
#include "tipc_cfgsrv.h"
#include "tipc_node.h"
#include "tipc_net.h"
#include "tipc_addr.h"
#include "tipc_link.h"
#include "tipc_port.h"
#include "tipc_bearer.h"
#include "tipc_name_distr.h"
#include "linux/tipc_config.h"
#include "net/genetlink.h"

static void node_lost_contact(struct tipc_node *n_ptr);
static void node_established_contact(struct tipc_node *n_ptr);

static LIST_HEAD(nodes_list);   /* sorted list of neighboring nodes */
static int node_count = 0;      /* number of neighboring nodes that exist */
static int link_count = 0;      /* number of unicast links node currently has */

static DEFINE_SPINLOCK(node_create_lock);

/**
 * tipc_node_create - create neighboring node
 *
 * Currently, this routine is called by neighbor discovery code, which holds
 * net_lock for reading only.  We must take node_create_lock to ensure a node
 * isn't created twice if two different bearers discover the node at the same
 * time.  (It would be preferable to switch to holding net_lock in write mode,
 * but this is a non-trivial change.)
 */

struct tipc_node *tipc_node_create(u32 addr)
{
    struct tipc_node *n_ptr;
    struct tipc_node *curr_n_ptr;
    struct mclink *mcl = NULL; /* */
    char addr_str[16]; /* */

    spin_lock_bh(&node_create_lock);

    n_ptr = tipc_net_find_node(addr);
    if (n_ptr != NULL) {
        spin_unlock_bh(&node_create_lock);
        return n_ptr;
    }

    n_ptr = kzalloc(sizeof(*n_ptr), GFP_ATOMIC);
    if (n_ptr != NULL) {
        n_ptr->elm.addr = addr;
        spin_lock_init(&n_ptr->elm.lock);
        INIT_LIST_HEAD(&n_ptr->elm.nsub);
#ifdef CONFIG_TIPC_MCASTGID_MAX   /* */

        INIT_LIST_HEAD(&n_ptr->mclinks);

        /* mclink0 */
        mcl = &n_ptr->bclink;
        mcl->mcgl = tipc_bclink_find_mcglink(0);
        dbg_assert(mcl->mcgl);
        mcl->mcgid = 0;
        list_add_tail(&mcl->mclist, &n_ptr->mclinks);
        n_ptr->mc_count = 1;
#endif      
        tipc_net_attach_node(n_ptr);

        list_for_each_entry(curr_n_ptr, &nodes_list, node_list) {
            if (addr < curr_n_ptr->elm.addr)
                break;
        }
        list_add_tail(&n_ptr->node_list, &curr_n_ptr->node_list);
        n_ptr->cleanup_required = WAIT_PEER_DOWN;

        node_count++;
        tipc_addr_string_fill(addr_str, n_ptr->elm.addr);
        info("Create node %s\n", addr_str);
    } else {
        warn("Node creation failed, no memory\n");
    }

    spin_unlock_bh(&node_create_lock);
    return n_ptr;
}

void tipc_node_delete(struct tipc_node *n_ptr)
{
    struct mclink *mcl, *mcl_tmp; /* */

    spin_lock_bh(&node_create_lock);

    if (n_ptr->cleanup_required) {
        warn("Node delete in cleanuping...\n");
    }
    node_count--;
    list_del(&n_ptr->node_list);
    spin_lock_term(&n_ptr->elm.lock);

#ifdef CONFIG_TIPC_MCASTGID_MAX   /* */
    list_del(&n_ptr->bclink.mclist);

    list_for_each_entry_safe(mcl, mcl_tmp, &n_ptr->mclinks, mclist) {
        list_del(&mcl->mclist);
        kfree(mcl);
    }
#endif  
    tipc_net_detach_node(n_ptr);/* */

    kfree(n_ptr);
    spin_unlock_bh(&node_create_lock);
}

/* */
void tipc_node_unlock_delete(struct tipc_node *n_ptr)
{
    char addr_str[16];
    
    if (n_ptr->link_cnt > 0 || n_ptr->cleanup_required) {
        tipc_node_unlock(n_ptr);
        return;
    }
    tipc_node_unlock(n_ptr);

    tipc_addr_string_fill(addr_str, n_ptr->elm.addr);
    info("Delete node %s\n", addr_str);
    tipc_node_delete(n_ptr);
}

/**
 * tipc_node_link_up - handle addition of link
 *
 * Link becomes active (alone or shared) or standby, depending on its priority.
 */

void tipc_node_link_up(struct tipc_node *n_ptr, struct link *l_ptr)
{
    n_ptr->working_links++;

    /* link_net_plane*/
    info("Established link <%s> on network plane %c-%c\n",
         l_ptr->name, BID2P(l_ptr->b_ptr->identity), BID2P(l_ptr->peer_bearer_id));

    tipc_node_link_active(n_ptr, l_ptr);
}

void tipc_node_link_active(struct tipc_node *n_ptr, struct link *l_ptr)
{
    struct link **active = &n_ptr->active_links[0];

    l_ptr->fast_standby = 0;
#ifdef CONFIG_TIPC_MULTIPLE_LINKS
    if (active[0] == NULL) {
        active[0] = active[1] = l_ptr;
        node_established_contact(n_ptr);
        return;
    }
    if (l_ptr->priority < active[0]->priority) {
        dbg("New link <%s> becomes standby\n", l_ptr->name);
        return;
    }
#ifdef CONFIG_TIPC_NODE_LINK_MAX   /* */ 
    /* 这一段需要修改如下，以防止a[0]!=a[1]且pri相等时振荡 */
    if (l_ptr->priority == active[0]->priority) {
        /* 避免选中频繁reset的链路 */
        if (active[0] == active[1] &&
            LINK_PRIO2(l_ptr) >= LINK_PRIO2(active[0])) {
            info("New link <%s> becomes load sharing\n", l_ptr->name);
            tipc_link_send_duplicate(active[1], l_ptr);
            active[1] = l_ptr;
        }

        return;
    }
    
    tipc_link_send_duplicate(active[0], l_ptr);
     
    info("Old link <%s> becomes standby\n", active[0]->name);
    if (active[1] != active[0]) {
        tipc_link_send_duplicate(active[1], l_ptr);
        dbg("Old link <%s> becomes standby\n", active[1]->name);
    }
    active[0] = active[1] = l_ptr;

    return;
#else
    tipc_link_send_duplicate(active[0], l_ptr);
    if (l_ptr->priority == active[0]->priority) {
        active[0] = l_ptr;
        return;
    }
    info("Old link <%s> becomes standby\n", active[0]->name);
    if (active[1] != active[0])
        info("Old link <%s> becomes standby\n", active[1]->name);
    active[0] = active[1] = l_ptr;
#endif /* */       
#else
    active[0] = active[1] = l_ptr;
    node_established_contact(n_ptr);
#endif

}

static struct link* node_find_alt(struct tipc_node *n_ptr, struct link *l_ptr)
{
    struct link *alt = NULL;
    u32 i, n;

    /* 排除自身、刚变为fast_standby的，只允许最高优先级的WW链路，错包较少
     * 第一轮优先选择非active链路，第二轮允许active链路
     */
    for (n=0; n<2; n++) {
        for (i=0; i<TIPC_MAX_LINKS; i++) {
            alt = n_ptr->links[i];
            if (alt && (alt != l_ptr) &&
                (alt->fast_standby == 0) &&
                link_working_working(alt) &&
                (alt->priority == l_ptr->priority) &&
                (LINK_PRIO2(alt) >= LINK_PRIO2(l_ptr)) &&
                (!tipc_link_is_active(alt) || n>0))
                return alt;
        }
    }

    return NULL;
}

void tipc_node_link_standby(struct tipc_node *n_ptr, struct link *l_ptr)
{
    struct link **active = &n_ptr->active_links[0];
    struct link *alt = NULL;

    alt = node_find_alt(n_ptr, l_ptr);
    if (!alt)
        return;

    /* 如alt报文太多(可比OUT_QUE_EXCESS略大)，不如不切换 */
    if (alt->out_queue_size + l_ptr->out_queue_size > 600)
        return;

    l_ptr->fast_standby = 1;
    info("Link <%s> becomes standby, send %u tunnel msgs,in=%u,out=%u,sndcnt=%u,rcvcnt=%u,fcnt=%u\n",
         l_ptr->name, l_ptr->out_queue_size, l_ptr->next_in_no, l_ptr->next_out_no, l_ptr->stats.sent_states,
         l_ptr->stats.recv_states, l_ptr->fsm_msg_cnt);
    tipc_link_send_duplicate(l_ptr, alt);
    if (active[0] == l_ptr)
        active[0] = alt;
    if (active[1] == l_ptr)
        active[1] = alt;
    
    if (!list_empty(&l_ptr->waiting_ports))
        tipc_link_wakeup_ports(l_ptr, 1);
}

#ifdef CONFIG_TIPC_MULTIPLE_LINKS
/**
 * node_select_active_links - select active link
 */

static void node_select_active_links(struct tipc_node *n_ptr)
{
    struct link **active = &n_ptr->active_links[0];
    u32 i;
    u32 highest_prio = 0;

    active[0] = active[1] = NULL;

    for (i = 0; i < TIPC_MAX_LINKS; i++) {
        struct link *l_ptr = n_ptr->links[i];

        if (!l_ptr || !tipc_link_is_up(l_ptr) ||
            (l_ptr->priority < highest_prio))
            continue;

        if (l_ptr->priority > highest_prio) {
            highest_prio = l_ptr->priority;
            active[0] = active[1] = l_ptr;
        } else {
            /* 2012: 两条全断后只选出一条，避免多次切换后不能完全保序 */
            if (0 && LINK_PRIO2(l_ptr) >= LINK_PRIO2(active[0]))
                active[1] = l_ptr;
        }
    }
}
#endif

/**
 * tipc_node_link_down - handle loss of link
 */

void tipc_node_link_down(struct tipc_node *n_ptr, struct link *l_ptr)
{
    struct link **active = &n_ptr->active_links[0];

    n_ptr->working_links--;

#ifdef CONFIG_TIPC_MULTIPLE_LINKS
    /* link_net_plane*/
    if (!tipc_link_is_active(l_ptr)) {
        dbg("Lost standby link <%s> on network plane %c-%c\n",
             l_ptr->name, BID2P(l_ptr->b_ptr->identity), BID2P(l_ptr->peer_bearer_id));
        tipc_link_changeover(l_ptr); /* 多于两条不一致, send too. */
        return;
    }

    dbg("Lost link <%s> on network plane %c-%c\n",
         l_ptr->name, BID2P(l_ptr->b_ptr->identity), BID2P(l_ptr->peer_bearer_id));


    if (active[0] == l_ptr)
        active[0] = active[1];
    if (active[1] == l_ptr)
        active[1] = active[0];
#ifdef CONFIG_TIPC_NODE_LINK_MAX   /* */
    /* 多于一条时重新选择?需要处理报文序. 等UP再选 */
    if (active[0] == l_ptr) {
        node_select_active_links(n_ptr);
    }
#else   
    if (active[0] == l_ptr)
        node_select_active_links(n_ptr);
#endif  /* */
    if (tipc_node_is_up(n_ptr))
        tipc_link_changeover(l_ptr);
    else
        node_lost_contact(n_ptr);
#else
    info("Lost link <%s> on network plane %c\n",
         l_ptr->name, link_net_plane(l_ptr));

    active[0] = active[1] = NULL;
    node_lost_contact(n_ptr);
#endif
}

int tipc_node_is_up(struct tipc_node *n_ptr)
{
    return (n_ptr->active_links[0] != NULL);
}

u32 tipc_node_has_redundant_links(struct link *l_ptr)
{
#ifdef CONFIG_TIPC_MULTIPLE_LINKS
    return (l_ptr->owner->working_links > tipc_link_is_up(l_ptr));
#else
    return 0;
#endif
}

struct tipc_node *tipc_node_attach_link(struct link *l_ptr)
{
    struct tipc_node *n_ptr = tipc_net_find_node(l_ptr->addr);

    if (!n_ptr)
        n_ptr = tipc_node_create(l_ptr->addr);
    if (n_ptr) {
        u32 bearer_id = l_ptr->b_ptr->identity;
        char addr_string[16];
        u32 bid; /* */

        /* CONFIG_TIPC_NODE_LINK_MAX */
        if (n_ptr->link_cnt >= TIPC_MAX_LINKS) {
            tipc_addr_string_fill(addr_string, n_ptr->elm.addr);
            err("Attempt to more than %d links to %s\n",
                n_ptr->link_cnt, addr_string);
            return NULL;
        }

#ifdef CONFIG_TIPC_LINK_TAG  /* */
        /* a bearer has max 2 links to dest */
        if (n_ptr->bearer_link_cnt[bearer_id] >= TIPC_MAX_LINKS/2) {
            tipc_addr_string_fill(addr_string, n_ptr->elm.addr);
            err("Attempt to create %d link to %s on bearer %d\n",
                n_ptr->bearer_link_cnt[bearer_id], addr_string, bearer_id);
            return NULL;
        }
        
        /* support multi-link in a bearer */
        bid = bearer_id;
        do {
            if (!n_ptr->links[bid]) {
                l_ptr->net_plane = bid + 'A';
                n_ptr->links[bid] = l_ptr;
                n_ptr->link_cnt++;
                n_ptr->bearer_link_cnt[bearer_id]++;
                link_count++;

                return n_ptr;
            }
            
            bid = (bid + 1) % TIPC_MAX_LINKS;
        } while (bid != bearer_id);
        tipc_addr_string_fill(addr_string, l_ptr->addr);
        err("Failed to establish link on <%s> to %s \n",
            l_ptr->b_ptr->publ.name, addr_string);      
#else
        if (!n_ptr->links[bearer_id]) {
            n_ptr->links[bearer_id] = l_ptr;
            n_ptr->link_cnt++;
            link_count++;
            return n_ptr;
        }
        tipc_addr_string_fill(addr_string, l_ptr->addr);
        err("Attempt to establish second link on <%s> to %s \n",
            l_ptr->b_ptr->publ.name, addr_string);
#endif
    }
    return NULL;
}

#ifdef CONFIG_TIPC_LINK_TAG   /* */
/* support multi-link in a bearer */
struct link *tipc_node_find_link_byaddr(struct tipc_node *n_ptr, struct bearer *b_ptr, struct tipc_media_addr *media_addr)
{
    struct link *l_ptr = NULL;
    u32 bearer_id = b_ptr->identity;
    u32 bid = b_ptr->identity;
    do {
        l_ptr = n_ptr->links[bid];
        if (l_ptr && l_ptr->b_ptr == b_ptr) {
            /* 需要根据报文源地址判断,可能需要建立一条新链路 */
            if (tipc_bearer_eq_addr(media_addr, &l_ptr->media_addr))
                return l_ptr;
        }
        
        bid = (bid + 1) % TIPC_MAX_LINKS;
    } while (bid != bearer_id);

    return NULL;
}

/* support multi-link in a bearer */
struct link *tipc_node_find_link_bybuf(struct tipc_node *n_ptr, struct bearer *b_ptr, struct sk_buff *buf)
{
    struct link *l_ptr = NULL;
    u32 bearer_id = b_ptr->identity;
    u32 bid = b_ptr->identity;
    do {
        l_ptr = n_ptr->links[bid];
        if (l_ptr && l_ptr->b_ptr == b_ptr) {
#if 0   /* 如果是l_ptr被删除后再收到l_ptr的报文，有问题，需要检查报文源地址 */     
            /* 如果只有一条,可见不需要检查 */
            if (n_ptr->bearer_link_cnt[bearer_id] == 1) {
                return l_ptr;
            }
#endif
            /* 需要根据报文源地址判断了, ugly!! */
            if (tipc_bearer_eq_skb_addr(buf, &b_ptr->publ, &l_ptr->media_addr))
                return l_ptr;
        }
        
        bid = (bid + 1) % TIPC_MAX_LINKS;
    } while (bid != bearer_id);

    return NULL;
}

/* support multi-link in a bearer */
struct link *tipc_node_find_link_byplane(struct tipc_node *n_ptr, u32 bearer_id, u32 net_plane)
{
    struct link *l_ptr = NULL;
    u32 bid = bearer_id;
    /* 由于netplane少于8个，而ICU链路多于8个，用bearerid代替 */

    do {
        l_ptr = n_ptr->links[bid];
        if (l_ptr && l_ptr->b_ptr->identity == bearer_id &&
            l_ptr->peer_bearer_id == net_plane) {
            return l_ptr;
        }
        
        bid = (bid + 1) % TIPC_MAX_LINKS;
    } while (bid != bearer_id);

    return NULL;
}
#endif /* */
void tipc_node_detach_link(struct tipc_node *n_ptr, struct link *l_ptr)
{
#ifdef CONFIG_TIPC_LINK_TAG   /* */
    u32 bearer_id = l_ptr->b_ptr->identity;
    u32 bid = bearer_id;
    do {
        if (l_ptr == n_ptr->links[bid]) {
            n_ptr->links[bid] = NULL;
            n_ptr->link_cnt--;
            n_ptr->bearer_link_cnt[bearer_id]--;
            link_count--;
            return ;
        }
        
        bid = (bid + 1) % TIPC_MAX_LINKS;
    } while (bid != bearer_id); 
#else
    n_ptr->links[l_ptr->b_ptr->identity] = NULL;
    n_ptr->link_cnt--;
    link_count--;
#endif /* */
}


#ifdef CONFIG_TIPC_MCASTGID_MAX   /* */
struct mclink *tipc_node_create_mclink(struct tipc_node *n_ptr, u32 mcgid)
{
    struct mclink *mcl = NULL;


    mcl = kzalloc(sizeof(*mcl), GFP_ATOMIC);
    if (mcl != NULL) {
        mcl->mcgl = tipc_bclink_find_mcglink(mcgid);
        if (!mcl->mcgl) {
            dbg_assert(0);
            warn("Node %x mcl %d creation failed, not find mcglink\n", n_ptr->elm.addr, mcgid);
            kfree(mcl);
            return NULL;
        }

        mcl->mcgid = mcgid;
        
        list_add_tail(&mcl->mclist, &n_ptr->mclinks);

        n_ptr->mc_count++;
    } else {
        warn("Node %x mcl %d creation failed, no memory\n", n_ptr->elm.addr, mcgid);
    }
    
    return mcl;     
}

void tipc_node_reset_mclink(struct mclink *mcl)
{
    while (mcl->deferred_head) {
        struct sk_buff* buf = mcl->deferred_head;
        mcl->deferred_head = buf->next;
        buf_discard(buf);
    }
    mcl->deferred_head = NULL;
    mcl->deferred_size = 0;
    while (mcl->defragm) {
        struct sk_buff* buf = mcl->defragm;
        mcl->defragm = buf->next;
        buf_discard(buf);  
    }
    mcl->defragm = NULL;

    mcl->oos_state = 0;
    /* 其它信息不需要清除 */    
}

/* maybe return null */
static inline struct mclink *tipc_node_find_mclink(struct tipc_node *n_ptr, u32 mcgid)
{
    struct mclink *mcl = NULL;

    list_for_each_entry(mcl, &n_ptr->mclinks, mclist) {
        if (mcl->mcgid == mcgid)
            return mcl;
    }

    /* becareful! here mcl->mclist == list_entry(n_ptr->mclinks) */
    return NULL;
}

struct mclink *tipc_node_find_active_mclink(struct tipc_node *n_ptr, u32 mcgid)
{
    struct mclink *mcl = tipc_node_find_mclink(n_ptr, mcgid);

    if (mcl && mcl->supported)
        return mcl;
    else
        return NULL;
}

void tipc_node_enable_mclink(struct tipc_node *n_ptr, u32 mcgid)
{
    struct mclink *mcl = NULL;

    mcl = tipc_node_find_mclink(n_ptr, mcgid);
    if (NULL == mcl) {
        mcl = tipc_node_create_mclink(n_ptr, mcgid);
    }

    if (mcl && !mcl->supported) {
        mcl->supported = 1;

        if (tipc_node_is_up(n_ptr)) {
            tipc_bclink_add_node(n_ptr, mcl);
        }
    }
}

void tipc_node_disable_mclink(struct tipc_node *n_ptr, u32 mcgid)
{
    struct mclink *mcl = NULL;

    mcl = tipc_node_find_mclink(n_ptr, mcgid);
    if (mcl && mcl->supported) {
        tipc_node_reset_mclink(mcl);
        mcl->supported = 0;

        if (tipc_node_is_up(n_ptr)) {
            tipc_bclink_remove_node(n_ptr, mcl);
        }
        /* 清除保存的接收FLAG信息 */
        clr_bytes_bit(n_ptr->mc_nord_recv, mcl->mcgid);
        clr_bytes_bit(n_ptr->mc_ccack_recv, mcl->mcgid);
    }
}

void tipc_nodes_enable_mclink(u32 mcgid)
{
    struct tipc_node *n_ptr;
    
    read_lock_bh(&tipc_net_lock);
    
    list_for_each_entry(n_ptr, &nodes_list, node_list) {
        tipc_node_lock(n_ptr);
        if (test_bytes_bit(n_ptr->mc_peer, mcgid))
            tipc_node_enable_mclink(n_ptr, mcgid);
        tipc_node_unlock(n_ptr);
    }

    read_unlock_bh(&tipc_net_lock);
}

void tipc_nodes_disable_mclink(u32 mcgid)
{
    struct tipc_node *n_ptr;
    
    read_lock_bh(&tipc_net_lock);
    
    list_for_each_entry(n_ptr, &nodes_list, node_list) {
        tipc_node_lock(n_ptr);
        if (test_bytes_bit(n_ptr->mc_peer, mcgid))
            tipc_node_disable_mclink(n_ptr, mcgid);
        tipc_node_unlock(n_ptr);
    }

    read_unlock_bh(&tipc_net_lock);
}

/* mcl的个数可能大于mci的个数，所以:
 * 第一遍优先选择有变化的mci,
 * 第二遍接着上次的点继续其它未变化的
 */

int tipc_node_get_mcinfo(struct tipc_node *n_ptr, 
    struct mcast_ackinfo mcinfo[], u32 mci_cnt)
{
    struct mclink *mcl = NULL;
    u32 last_sent = 0;

    u32 time = 0;
    u32 find_mci_chk = 0;
    u32 k = 0;
    
    u32 i = 0;
    u32 cnt = mci_cnt;
    /* mclink0 在这里也有一份,在报文头中没有ccack信息 */
    if (cnt > n_ptr->mc_count)
        cnt = n_ptr->mc_count;

    for (time=0; time<2; time++) {
        list_for_each_entry(mcl, &n_ptr->mclinks, mclist) {
            if (!mcl->supported)
                continue;

            if (i >= cnt) {
                n_ptr->mcgid_chk = mcl->mcgid;
                return i;
            }

            /* 1th skip info had sent */
            if (1 == time && !find_mci_chk) {
                if (mcl->mcgid != n_ptr->mcgid_chk)
                    continue;
                else
                    find_mci_chk = 1;
            }
            
            if (unlikely(WORKING_WORKING != mcl->state))
                last_sent = mcl->acked;
            else
                last_sent = tipc_bclink_get_last_sent(mcl->mcgl);
            /* 0th skip info no changed. 检查有无未确认报文 */
            if (0 == time && mcl->last_in == mcl->last_sent &&
                (mcl->last_in_chk == mcl->last_in &&
                 mcl->last_sent_chk == last_sent) &&
                 mcl->acked == last_sent &&
                 WORKING_WORKING == mcl->state)
                continue;

            /* 检查是否已经填充该mci信息 */
            for (k=0; k<i; k++) {
                if (mcinfo[k].mcgid == mcl->mcgid)
                    break;
            }
            if (k < i) /* 重复 */
                continue;

            mcl->last_in_chk   = mcl->last_in;
            mcl->last_sent_chk = last_sent;
            
            mcinfo[i].mcgid = mcl->mcgid;
            
            mcinfo[i].flag = 0;
            if (test_bytes_bit(n_ptr->mc_ccack_assign, mcl->mcgid))
                mcinfo[i].flag = MCLINK_FLAG_CCACK;

            if (WORKING_UNKNOWN == mcl->state)
                mcinfo[i].flag |= MCLINK_FLAG_WU;
            else if (RESET_RESET == mcl->state)
                mcinfo[i].flag |= MCLINK_FLAG_RDY;
            else
                /* empty */

            if (!tipc_bclink_get_readable(mcl->mcgl))
                mcinfo[i].flag |= MCLINK_FLAG_NOREAD;


            mcinfo[i].last_in = htons(mod(mcl->last_in));
            mcinfo[i].last_sent = htons(mod(last_sent));

            i++;
        }
        /* 避免信息不一致。send more if possible */
    }

    /* 遍历完毕, 下次从第一个开始 */
    n_ptr->mcgid_chk = 0;

    return i;   
}

int tipc_node_recv_mcinfo(struct tipc_node *n_ptr, 
    void *mci_data, u32 bytes, u32 msgtype)
{
    void *beg = mci_data;
    void *end = mci_data + bytes;
    struct mcast_ackinfo *mci = NULL;
    struct mclink *mcl = NULL;

    u32 last_in;
    u32 last_sent;
    
#if 0
    if (TLV_ALIGN((u32)beg) != (u32)beg)
        return 0;
#endif

    for ( ;beg + sizeof(*mci) <= end; beg += sizeof(*mci)) {
        mci = (struct mcast_ackinfo *)beg;
        mcl = tipc_node_find_active_mclink(n_ptr, mci->mcgid);
        if (!mcl) {
            continue;
        }

        if ((mci->flag & MCLINK_FLAG_CCACK))
            set_bytes_bit(n_ptr->mc_ccack_recv, mci->mcgid);


        if ((mci->flag & MCLINK_FLAG_NOREAD)) {
            /* 缺省是可读，FLAG_NOREAD需要检查是否已经加入rding */
            if (test_bytes_bit(n_ptr->mc_rding, mci->mcgid)) {
                /* 如已经加入，则退出rding，再恢复状态即可 */
                u32 oldstate = mcl->state;
                
                tipc_bclink_remove_node(n_ptr, mcl);
                mcl->state = oldstate;
            }
            
            set_bytes_bit(n_ptr->mc_nord_recv, mci->mcgid);
        }

        /* 
         * acked 在node_established_contact()根据本地信息填充
         * last_in/last_sent 根据对端信息填充
         * WU: 该状态一直发送 FLAG_WU
         * WU: 收到对端FLAG_WU或FLAG_RDY进入RR
         * RR: 该状态一直发送 FLAG_RDY
         * RR: 等待对端离开WU，收到对端!FLAG_WU可以进入WW开始收报文
         * WW: 收报文状态
         */
        if (WORKING_UNKNOWN == mcl->state) {
            if ((MCLINK_FLAG_WU & mci->flag) ||
                (MCLINK_FLAG_RDY & mci->flag)) {
                /* 本端进入RR */
                last_sent = ntohs(mci->last_sent);
                mcl->last_in = mcl->last_sent = last_sent;
                
                tipc_node_reset_mclink(mcl);

                mcl->state = RESET_RESET;
            }
        } else if (RESET_RESET == mcl->state) {
            if ((MCLINK_FLAG_WU & mci->flag) == 0) {
                /* 对端已经离开WU */
                mcl->state = WORKING_WORKING;
            }
        } else {
            /* empty */
        }

        if (((MCLINK_FLAG_WU | MCLINK_FLAG_RDY) & mci->flag) ||
            (WORKING_WORKING != mcl->state)) {
            /* 多链路时报文时序不可控，过滤老报文 */
            continue;
        }

        if (likely(STATE_MSG == msgtype)) {     
            if (unlikely(WORKING_WORKING != mcl->state))
                continue;
            
            last_in = ntohs(mci->last_in);
            last_sent = ntohs(mci->last_sent);
            
            if (less(mcl->acked, last_in)) {
                tipc_bclink_acknowledge(n_ptr, last_in, mcl);
            }

            if (less(mod(mcl->last_in), last_sent)) {
                tipc_bclink_update_link_state(n_ptr, last_sent, mcl);
            }
        } else {
            /* 
             * acked 在node_established_contact()根据本地信息填充
             * last_in/last_sent 根据对端信息填充
             */
            if (MCLINK_NEED_SYNC(n_ptr, msgtype)) {
                last_sent = ntohs(mci->last_sent);
                mcl->last_in = mcl->last_sent = last_sent;
                
                tipc_node_reset_mclink(mcl);
            }
        }
    }

    return 1;
}

void tipc_node_check_mc(struct tipc_node *n_ptr)
{
    struct mclink *mcl = NULL;
    char name[32];
    
    list_for_each_entry(mcl, &n_ptr->mclinks, mclist) { 
        if (!mcl->supported)
            continue;

        snprintf(name, sizeof(name), "mc %u of %08x", mcl->mcgid, n_ptr->elm.addr);

        link_check_defragm_bufs(&mcl->defragm, name);
    }
}

void tipc_node_mcstat(struct tipc_node *n_ptr, struct print_buf *pb)
{
    struct mclink *mcl = NULL;
    
    tipc_printf(pb, "  MCId   sent/acked last-in/-sent  oos def defs       dups       sent-/recv-naks\n");
    
    list_for_each_entry(mcl, &n_ptr->mclinks, mclist) { 
        if (!mcl->supported)
            continue;
        tipc_printf(pb, "  mc%2u  %5u/%-5u %7u/%-5u  %-3u %-3u %-10u %-10u %5u/%u\n",
            mcl->mcgid,
            tipc_bclink_get_last_sent(mcl->mcgl), mcl->acked,
            mcl->last_in, mcl->last_sent,
            mcl->oos_state, mcl->deferred_size,
            mcl->deferes, mcl->duplicates,
            mcl->sent_nacks, mcl->recv_nacks);
    }
}

void tipc_nodes_mcstat(struct print_buf *pb)
{
    struct tipc_node *n_ptr;

    tipc_printf(pb, "Nodes multicast info\n");

    list_for_each_entry(n_ptr, &nodes_list, node_list) {
        char addr_str[16];
        
        tipc_addr_string_fill(addr_str, n_ptr->elm.addr);
        tipc_printf(pb, " %s\n", addr_str);
        
        tipc_node_lock(n_ptr);
        tipc_node_mcstat(n_ptr, pb);
        tipc_node_unlock(n_ptr);
    }
}

#endif  /* */

static void node_established_contact(struct tipc_node *n_ptr)
{
    struct mclink *mcl = NULL;
    dbg("node_established_contact:-> %x\n", n_ptr->elm.addr);

    /* Synchronize broadcast acks */

#ifndef CONFIG_TIPC_MCASTGID_MAX   /* */
    n_ptr->bclink.acked = tipc_bclink_get_last_sent();
#endif  /* */


    if (in_own_cluster(n_ptr->elm.addr)) {

        /* Add to multicast destination map, if applicable */

#ifdef CONFIG_TIPC_MCASTGID_MAX   /* mcl->acked */
        list_for_each_entry(mcl, &n_ptr->mclinks, mclist) {
            if (mcl->supported) {
                tipc_bclink_add_node(n_ptr, mcl);
            }
        }
#else
        if (n_ptr->bclink.supported)
            tipc_bclink_add_node(n_ptr->elm.addr);
#endif  /* */
    } else {

        /* Publish new inter-cluster (or inter-zone) route */

        tipc_k_signal((Handler)tipc_routetbl_publish, n_ptr->elm.addr);
    }

    /* Pass route & name table info to node, if necessary */
#if 0 /* move to link_activate() */
    if (in_own_zone(n_ptr->elm.addr)) {
        if (likely(n_ptr->flags & NF_MULTICLUSTER)) {
            tipc_k_signal((Handler)tipc_route_node_up,
                      n_ptr->elm.addr);
            tipc_k_signal((Handler)tipc_named_node_up,
                      n_ptr->elm.addr);
            /* name request, we know node is NF_MULTICLUSTER */
            tipc_k_signal((Handler)tipc_named_request,
                      n_ptr->elm.addr);
        } else {
            tipc_k_signal((Handler)tipc_named_node_up_uni,
                      n_ptr->elm.addr);
        }
    }
#endif  
}

#ifdef CONFIG_TIPC_MULTIPLE_LINKS
static inline void node_abort_link_changeover(struct tipc_node *n_ptr)
{
    struct link *l_ptr;
    int i;

    for (i = 0; i < TIPC_MAX_LINKS; i++) {
        l_ptr = n_ptr->links[i];
        if (l_ptr != NULL) {
            l_ptr->reset_checkpoint = l_ptr->next_in_no;
            l_ptr->exp_msg_count = 0;
            tipc_link_reset_fragments(l_ptr);
        }
    }
}
#endif

static void node_cleanup_finished(unsigned long node_addr)
{
    struct tipc_node *n_ptr;
     
    read_lock_bh(&tipc_net_lock);
    n_ptr = tipc_net_find_node(node_addr);
    if (n_ptr) {
        tipc_node_lock(n_ptr);
        n_ptr->cleanup_required &= ~WAIT_NAMES_GONE;
        tipc_node_unlock(n_ptr);
    }
    read_unlock_bh(&tipc_net_lock);
}

static void node_lost_contact(struct tipc_node *n_ptr)
{
    char addr_string[16];
    struct mclink *mcl = NULL; /* */
    
    tipc_addr_string_fill(addr_string, n_ptr->elm.addr);
    info("Lost contact with %s\n", addr_string);

    /* Clean up broadcast reception remains */
#ifdef CONFIG_TIPC_MCASTGID_MAX   /* */
    list_for_each_entry(mcl, &n_ptr->mclinks, mclist) { 
        tipc_node_reset_mclink(mcl);
        
        if (in_own_cluster(n_ptr->elm.addr) && mcl->supported) {
            /* move ack into remove_node for atomic */
            /*tipc_bclink_acknowledge(n_ptr, mod(mcl->acked + 10000));*/
            tipc_bclink_remove_node(n_ptr, mcl);
        }
    }

#else
    while (n_ptr->bclink.deferred_head) {
        struct sk_buff *buf = n_ptr->bclink.deferred_head;

        n_ptr->bclink.deferred_head = buf->next;
        buf_discard(buf);
    }
    n_ptr->bclink.deferred_size = 0;

    if (n_ptr->bclink.defragm) {
        buf_discard(n_ptr->bclink.defragm);
        n_ptr->bclink.defragm = NULL;
    }

    if (in_own_cluster(n_ptr->elm.addr) && n_ptr->bclink.supported) { 
        tipc_bclink_acknowledge(n_ptr, mod(n_ptr->bclink.acked + 10000));
        tipc_bclink_remove_node(n_ptr->elm.addr);
    }
#endif  /* */
    
#ifdef CONFIG_TIPC_MULTIPLE_LINKS
    node_abort_link_changeover(n_ptr);
#endif

    /* 
     * For lost node in own cluster:
     * - purge all associated name table entries and connections
     * - trigger similar purge in all other clusters/zones by notifying
     *   them of disappearance of node
     *
     * For lost node in other cluster (or zone):
     * - withdraw route to failed node
     */

    if (tipc_mode != TIPC_NET_MODE) {
        /* TODO: THIS IS A HACK TO PREVENT A KERNEL CRASH IF TIPC
           IS UNLOADED WHEN IT HAS ACTIVE INTER-CLUSTER LINKS;
           OTHERWISE THE ROUTINES INVOKED VIA SIGNALLING DON'T RUN UNTIL
           AFTER STUFF THEY DEPEND ON HAS BEEN SHUT DOWN 
           
           THE CODE NEEDS TO BE CLEANED UP TO DO THIS BETTER, SINCE
           FAILING TO RUN THE CLEANUP CODE COULD LEAVE ENTIRES IN THE
           ROUTING TABLE AND NAME TABLE ... */
        return;
    }

    if (in_own_cluster(n_ptr->elm.addr)) {
        tipc_netsub_notify(&n_ptr->elm, n_ptr->elm.addr);
        tipc_k_signal((Handler)tipc_routetbl_withdraw_node,
                  n_ptr->elm.addr);
    } else {
            tipc_k_signal((Handler)tipc_routetbl_withdraw,
                  n_ptr->elm.addr);
    }
    

    /* Prevent re-contact with node until all cleanup is done */
    n_ptr->cleanup_required = WAIT_PEER_DOWN | WAIT_NAMES_GONE;
    tipc_k_signal((Handler)node_cleanup_finished, n_ptr->elm.addr);
}

#if 0
void node_print(struct print_buf *buf, struct tipc_node *n_ptr, char *str)
{
    u32 i;

    tipc_printf(buf, "\n\n%s", str);
    for (i = 0; i < TIPC_MAX_BEARERS; i++) {
        if (!n_ptr->links[i])
            continue;
        tipc_printf(buf, "Links[%u]: %x, ", i, n_ptr->links[i]);
    }
    tipc_printf(buf, "Active links: [%x,%x]\n",
            n_ptr->active_links[0], n_ptr->active_links[1]);
}
#endif

u32 tipc_available_nodes(const u32 domain)
{
    struct tipc_node *n_ptr;
    u32 cnt = 0;

    read_lock_bh(&tipc_net_lock);
    list_for_each_entry(n_ptr, &nodes_list, node_list) {
        if (!tipc_in_scope(domain, n_ptr->elm.addr))
            continue;
        if (tipc_node_is_up(n_ptr))
            cnt++;
    }
    read_unlock_bh(&tipc_net_lock);
    return cnt;
}

#ifdef CONFIG_TIPC_CONFIG_SERVICE
static inline int tipc_in_scope_mask(u32 domain, u32 addr, u32 mask)
{
    if (!domain)
        return 1;
    if (!mask)
        return tipc_in_scope(domain, addr);
    return (domain & mask) == (addr & mask);
}

struct sk_buff *tipc_node_get_nodes(const void *req_tlv_area, int req_tlv_space)
{
    u32 domain;
    struct sk_buff *buf;
    struct tipc_node *n_ptr;
    struct tipc_node_info node_info;
    u32 payload_size;
    u32 dom_mask = 0;
    const void *tlv = req_tlv_area;
    int tlv_len = req_tlv_space;

    if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_NET_ADDR))
        return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

    domain = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
    if (!tipc_addr_domain_valid(domain))
        return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
                           " (network address)");
    tlv += TLV_SPACE(sizeof(u32));
    tlv_len -= TLV_SPACE(sizeof(u32));
    if (tlv_len > 0 && TLV_CHECK(tlv, tlv_len, TIPC_TLV_UNSIGNED)) {
        dom_mask = *(u32 *)TLV_DATA(tlv);
        dom_mask = ntohl(dom_mask);
    }

    read_lock_bh(&tipc_net_lock);
    if (!node_count) {
        read_unlock_bh(&tipc_net_lock);
        return tipc_cfg_reply_none();
    }

    /* Get space for all neighboring nodes */

    payload_size = TLV_SPACE(sizeof(node_info)) * node_count;
    if (payload_size > TIPC_MAX_TLV_SPACE) {
        payload_size = TIPC_MAX_TLV_SPACE; /* 防止2T8无法查询 */
    }
    buf = tipc_cfg_reply_alloc(payload_size);
    if (!buf) {
        read_unlock_bh(&tipc_net_lock);
        return NULL;
    }

    /* Add TLVs for all nodes in scope */

    list_for_each_entry(n_ptr, &nodes_list, node_list) {
        if (!tipc_in_scope_mask(domain, n_ptr->elm.addr, dom_mask))
            continue;
        node_info.addr = htonl(n_ptr->elm.addr);
        node_info.up = htonl(tipc_node_is_up(n_ptr));
        tipc_cfg_append_tlv(buf, TIPC_TLV_NODE_INFO,
                    &node_info, sizeof(node_info));
    }

    read_unlock_bh(&tipc_net_lock);
    return buf;
}

static int tipc_cfg_append_nlink(struct sk_buff *buf, struct tipc_node *n_ptr)
{
    static struct tipc_node_link_info *nl_info = NULL; /* 局部较大，使用全局 */
    struct tipc_nlink_info *nlink = NULL;
    int nl_max = sizeof(*nl_info) + sizeof(*nlink) * TIPC_MAX_LINKS;
    struct link *l_ptr = NULL;
    char *s = NULL;
    int i = 0;

    if (!nl_info) {
        nl_info = kzalloc(nl_max, GFP_ATOMIC);
        if (!nl_info)
            return 0;
    }
    
    memset(nl_info, 0, nl_max);
    nl_info->dest = htonl(n_ptr->elm.addr);
    nl_info->up = htonl(tipc_node_is_up(n_ptr));
    nl_info->nlinks_cnt = htonl(n_ptr->link_cnt);
    
    nlink = &nl_info->nlinks[0];
    for (i = 0; i < TIPC_MAX_LINKS; i++) {
        if (!n_ptr->links[i])
            continue;
        l_ptr = n_ptr->links[i];
        nlink->self_bid = BID2P(l_ptr->b_ptr->identity);
        nlink->peer_bid = BID2P(l_ptr->peer_bearer_id);
        nlink->up = tipc_link_is_up(l_ptr);
        /* 仅link down，小于3个周期不上报. 避免闪断告警 
        if (tipc_node_is_up(n_ptr) &&
            (!tipc_link_is_up(l_ptr) && l_ptr->fsm_msg_cnt < 3))
            nlink->up = 1;*/
        nlink->error_count = htonl(l_ptr->retx_count);
        nlink->reserved = l_ptr->fsm_msg_cnt; /* fsm_msg_cnt计数不会超过255 */

        s = strchr(l_ptr->b_ptr->publ.name, ':') + 1;
        strncpy(nlink->self_dev, s, sizeof(nlink->self_dev) - 1);
        s = strrchr(l_ptr->name, ':') + 1;
        strncpy(nlink->peer_dev, s, sizeof(nlink->peer_dev) - 1);

        nlink++; /* 填充后++ */
    }
    
    return tipc_cfg_append_tlv(buf, TIPC_TLV_NODE_LINK_INFO,
                    nl_info, (void *)nlink - (void *)nl_info);  
}

struct sk_buff *tipc_node_get_links(const void *req_tlv_area, int req_tlv_space)
{
    u32 domain;
    struct sk_buff *buf;
    struct tipc_node *n_ptr;
    struct tipc_link_info link_info;
    u32 payload_size;
    u32 i; /* */
    u32 dom_mask = 0;
    const void *tlv = req_tlv_area;
    int tlv_len = req_tlv_space;
    u32 nodelink = 0;

    if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_NET_ADDR))
        return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

    domain = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
    if (!tipc_addr_domain_valid(domain))
        return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
                           " (network address)");

    tlv += TLV_SPACE(sizeof(u32));
    tlv_len -= TLV_SPACE(sizeof(u32));
    if (tlv_len > 0 && TLV_CHECK(tlv, tlv_len, TIPC_TLV_UNSIGNED)) {
        dom_mask = *(u32 *)TLV_DATA(tlv);
        dom_mask = ntohl(dom_mask);
        
        tlv += TLV_SPACE(sizeof(u32));
        tlv_len -= TLV_SPACE(sizeof(u32));
        if (dom_mask && tlv_len > 0 && TLV_CHECK(tlv, tlv_len, TIPC_TLV_UNSIGNED)) {
            nodelink = *(u32 *)TLV_DATA(tlv);
            nodelink = ntohl(nodelink);

            if (TIPC_TLV_NODE_LINK_INFO != nodelink)
                nodelink = 0;
        }
    }

    if (tipc_mode != TIPC_NET_MODE)
        return tipc_cfg_reply_none();
    
    read_lock_bh(&tipc_net_lock);

    /* Get space for all unicast links + broadcast link */
    if (nodelink)
        payload_size = TLV_SPACE(sizeof(struct tipc_node_link_info)) * node_count + 
                    TLV_SPACE(sizeof(struct tipc_nlink_info)) * link_count;
    else
        payload_size = TLV_SPACE(sizeof(link_info)) * (link_count + CONFIG_TIPC_MCASTGID_MAX);
    if (payload_size > TIPC_MAX_TLV_SPACE) {
        payload_size = TIPC_MAX_TLV_SPACE; /* 防止2T8无法查询 */
    }
    buf = tipc_cfg_reply_alloc(payload_size);
    if (!buf) {
        read_unlock_bh(&tipc_net_lock);
        return NULL;
    }

    /* Add TLV for broadcast link */
#ifdef CONFIG_TIPC_MCASTGID_MAX /* */
    for (i=0; i<CONFIG_TIPC_MCASTGID_MAX; i++) {
        if (dom_mask || !tipc_in_scope(domain, addr_cluster(tipc_own_addr)))
            continue;
        if (NULL == tipc_bclink_find_mcglink(i))
            continue;
        link_info.dest = htonl(addr_cluster(tipc_own_addr));
        link_info.up = htonl(1);
        snprintf(link_info.str, sizeof(link_info.str),"%s%u", tipc_bclink_name, i);
        tipc_cfg_append_tlv(buf, TIPC_TLV_LINK_INFO, &link_info, sizeof(link_info));        
    }
#else
    link_info.dest = htonl(tipc_own_addr & 0xfffff00);
    link_info.up = htonl(1);
    snprintf(link_info.str, sizeof(link_info.str), tipc_bclink_name);
    tipc_cfg_append_tlv(buf, TIPC_TLV_LINK_INFO, &link_info, sizeof(link_info));
#endif /* */
    /* Add TLVs for any other links in scope */

    list_for_each_entry(n_ptr, &nodes_list, node_list) {
        u32 i;

        if (!tipc_in_scope_mask(domain, n_ptr->elm.addr, dom_mask))
            continue;
        tipc_node_lock(n_ptr);
        if (nodelink) {
            tipc_cfg_append_nlink(buf, n_ptr);
        } else {
            for (i = 0; i < TIPC_MAX_LINKS; i++) {
                if (!n_ptr->links[i])
                    continue;
                memset(&link_info.str, 0, sizeof(link_info.str));
                link_info.dest = htonl(n_ptr->elm.addr);
                link_info.up = htonl(tipc_link_is_up(n_ptr->links[i]));
                strncpy(link_info.str, n_ptr->links[i]->name, sizeof(link_info.str) - 1);
                tipc_cfg_append_tlv(buf, TIPC_TLV_LINK_INFO,
                            &link_info, sizeof(link_info));
            }
        }
        tipc_node_unlock(n_ptr);
    }

    read_unlock_bh(&tipc_net_lock);
    return buf;
}

void tipc_node_get_link_state(struct tipc_link_state *link_state, struct link *l_ptr)
{
    memset(link_state, 0, sizeof(struct tipc_link_state));
    link_state->self_bid = BID2P(l_ptr->b_ptr->identity);
    link_state->peer_bid = BID2P(l_ptr->peer_bearer_id);
    link_state->self = htonl(tipc_own_addr);
    link_state->peer = htonl(l_ptr->owner->elm.addr);
    link_state->self_bid = BID2P(l_ptr->b_ptr->identity);
    link_state->peer_bid = BID2P(l_ptr->peer_bearer_id);
    link_state->up = tipc_link_is_up(l_ptr);
    link_state->active = tipc_link_is_active(l_ptr);
    link_state->error_count = htonl(l_ptr->retx_count);
    strncpy(link_state->self_dev, strchr(l_ptr->b_ptr->publ.name, ':') + 1, 
        sizeof(link_state->self_dev) - 1);
    strncpy(link_state->peer_dev, strrchr(l_ptr->name, ':') + 1, 
        sizeof(link_state->peer_dev) - 1);
    memcpy(link_state->self_addr, l_ptr->b_ptr->publ.addr.value, 
        sizeof(link_state->self_addr));
    memcpy(link_state->peer_addr, l_ptr->media_addr.value, 
        sizeof(link_state->peer_addr));
    return;
}
static int tipc_cfg_append_link_state(struct sk_buff *buf, struct tipc_node *n_ptr)
{
    struct tipc_link_state link_state; 
    struct tipc_node_links_state link_state_info;
    struct link *l_ptr = NULL;
    int i = 0;
    int cnt = 0;
    int res = 0;
    memset(&link_state_info, 0, sizeof(struct tipc_node_links_state));
    for (i = 0; i < TIPC_MAX_LINKS; ++i) 
    {
        l_ptr = n_ptr->links[i];
        if ((!n_ptr->links[i]) || (TIPC_MAX_BEARERS == l_ptr->peer_bearer_id))
            continue;
        tipc_node_get_link_state(&link_state, l_ptr);
        memcpy( &link_state_info.sz_linkstate[cnt], &link_state, 
            sizeof(struct tipc_link_state));
        cnt++;    
    }
    link_state_info.link_num = cnt;
    if(cnt)
    {
        res = tipc_cfg_append_tlv(buf, TIPC_TLV_NODE_LINK_STATE,
            &link_state_info, sizeof(struct tipc_node_links_state));   
        if(!res)
            err("tipc_cfg_append_tlv error, res = %d\n", res);
    }
    info("tipc_cfg_append_link_state leave...cnt = %d\n", cnt);
    return res;
}
struct sk_buff *tipc_get_links_states(const void *req_tlv_area, int req_tlv_space)
{
    u32 domain;
    struct sk_buff *buf;
    struct tipc_node *n_ptr;
    u32 payload_size;
    u32 dom_mask = 0;
    const void *tlv = req_tlv_area;
    int tlv_len = req_tlv_space;
    u32 node_addr = 0;
    u32 flag = 0;
    info("tipc_get_links_states enter...\n");
    if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_NET_ADDR))
    {
        return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);
    }
    domain = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
    if (!tipc_addr_domain_valid(domain))
    {
        return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
                           " (network address)");
    }
    tlv += TLV_SPACE(sizeof(u32));
    tlv_len -= TLV_SPACE(sizeof(u32));
    if (tlv_len > 0 && TLV_CHECK(tlv, tlv_len, TIPC_TLV_UNSIGNED)) 
    {
        dom_mask = *(u32 *)TLV_DATA(tlv);
        dom_mask = ntohl(dom_mask);
        tlv += TLV_SPACE(sizeof(u32));
        tlv_len -= TLV_SPACE(sizeof(u32));
        if (/*dom_mask &&*/ tlv_len > 0 && TLV_CHECK(tlv, tlv_len, TIPC_TLV_UNSIGNED)) 
        {
            node_addr = *(u32 *)TLV_DATA(tlv);
            node_addr = ntohl(node_addr);
            info("node_addr = %d\n", node_addr);
            if (!node_addr)
            {
                flag = 1;
            }
        }
    }
    if (tipc_mode != TIPC_NET_MODE)
        return tipc_cfg_reply_none();
    read_lock_bh(&tipc_net_lock);
    if (!flag)
        payload_size = TLV_SPACE(sizeof(struct tipc_node_links_state));
    else/* 所有node的链路状态信息 */
        payload_size = TLV_SPACE(sizeof(struct tipc_node_links_state)) * node_count;
    if (payload_size > TIPC_MAX_TLV_SPACE) 
        payload_size = TIPC_MAX_TLV_SPACE; /* 防止2T8无法查询 */
    buf = tipc_cfg_reply_alloc(payload_size);
    if (!buf) 
    {
        read_unlock_bh(&tipc_net_lock);
        return NULL;
    }
    list_for_each_entry(n_ptr, &nodes_list, node_list) 
    {
        if (!tipc_in_scope_mask(domain, n_ptr->elm.addr, dom_mask))
            continue;
        tipc_node_lock(n_ptr);
        if (flag)
        {
            info("tipc_cfg_append_link_state, n_ptr->elm.addr = %d\n", n_ptr->elm.addr);
            (void)tipc_cfg_append_link_state(buf, n_ptr);
            tipc_node_unlock(n_ptr);            
            continue;
        }
        if (node_addr == n_ptr->elm.addr) 
        {
            info("tipc_cfg_append_link_state, node_addr = %d\n", node_addr);
            (void)tipc_cfg_append_link_state(buf, n_ptr);
            tipc_node_unlock(n_ptr);
            read_unlock_bh(&tipc_net_lock);
            return buf;
        } 
    }
    read_unlock_bh(&tipc_net_lock);
    return buf;
}
static int g_tipc_link_state_subscrib_cnt = 0;
static struct TIPC_SUBSCRIB_S g_tipc_link_state_subscrib_info[MAX_LINK_STATE_SUBSCRIB_NUM];
int tipc_link_state_subscrib_check(struct TIPC_SUBSCRIB_S *pTipc_subscrib_info)
{
    int i = 0;
    if(0 == g_tipc_link_state_subscrib_cnt)
    {
        memset(g_tipc_link_state_subscrib_info, 0, MAX_LINK_STATE_SUBSCRIB_NUM * sizeof(int));   
    }
    for(i = 0; i < g_tipc_link_state_subscrib_cnt; ++i)
    {
        if(pTipc_subscrib_info->uiPid == g_tipc_link_state_subscrib_info[i].uiPid)
        {
            info("modify subscrib info\n");
            memcpy(&g_tipc_link_state_subscrib_info[i], pTipc_subscrib_info, sizeof(struct TIPC_SUBSCRIB_S));
            return 0;
        }
    }
    if(g_tipc_link_state_subscrib_cnt < MAX_LINK_STATE_SUBSCRIB_NUM)
    {
        info("add a new subscrib info\n");
        memcpy(&g_tipc_link_state_subscrib_info[i], pTipc_subscrib_info, sizeof(struct TIPC_SUBSCRIB_S));
        g_tipc_link_state_subscrib_cnt++;
        return 0;
    }
    err("\n out of range only allow %d subscrib", i);
    return 1;
}
struct sk_buff *tipc_link_state_create_skb(struct tipc_node_links_state *ls_ptr, int len)
{
    struct nlmsg {
        struct nlmsghdr n;
        struct genlmsghdr g;
        char payload[0];
    };
    struct nlmsg *msg = NULL;
    struct sk_buff *skb = NULL;
    struct tipc_link_state *plinkstate = NULL;
    u32 msg_size = NLMSG_LENGTH(GENL_HDRLEN + len);
    u32 i;
    skb = buf_acquire(msg_size);
    if(NULL == skb)
    {
        err("\nbuf_acquire no buffers");
        return NULL;
    }
    msg = (struct nlmsg*)skb->data;
    msg->n.nlmsg_len = msg_size;
    msg->n.nlmsg_type = 0;
    msg->n.nlmsg_flags = NLM_F_ACK;
    msg->n.nlmsg_seq = 0;
    msg->n.nlmsg_pid = 0;
    msg->g.cmd = TIPC_GENL_CMD;
    msg->g.version = 0;
    memcpy(&msg->payload[0], &ls_ptr->link_num, sizeof(u32));
    plinkstate = (struct tipc_link_state *)(&msg->payload[0] + sizeof(u32));
    for(i = 0; i < ls_ptr->link_num; ++i)
    {
        memcpy(plinkstate,  &ls_ptr->sz_linkstate[i], sizeof(struct tipc_link_state));
        plinkstate++;
    }
    return skb;
}

extern struct genl_family tipc_genl_family;
int tipc_node_send_skb( struct tipc_node_links_state *ls_ptr,
                                 struct TIPC_SUBSCRIB_S *pSubscrib_info)
{
    struct sk_buff *skb;
    u32 res = 0;
    u32 len = 0;
    len = sizeof(u32) + (ls_ptr->link_num) * sizeof(struct tipc_link_state);
    skb = tipc_link_state_create_skb(ls_ptr, len);
    if(NULL == skb)
    {
        res = -ENOBUFS;
        goto out;
    }
    if(pSubscrib_info->uiMcgId)
    {
        /* info("genlmsg_multicast mcg_id =  %d\n", pSubscrib_info->uiMcgId) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
        res = genlmsg_multicast(&tipc_genl_family, skb, 0, pSubscrib_info->uiMcgId, GFP_ATOMIC);
#else
        res = genlmsg_multicast(skb, 0, pSubscrib_info->uiMcgId, GFP_ATOMIC);
#endif
        goto out;
    }
    if (pSubscrib_info->uiPid) {      
        /* info("genlmsg_unicast pid = %d\n", pSubscrib_info->uiPid) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
        res = genlmsg_unicast(&init_net, skb, pSubscrib_info->uiPid);       
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 22)
        res = genlmsg_unicast(skb, pSubscrib_info->uiPid);
#else       
        res = genlmsg_unicast(skb, pSubscrib_info->uiPid);
#endif
        goto out;
    }
out:
    return res;
}
int tipc_node_is_subscribed(struct tipc_node *n_ptr, 
            struct TIPC_SUBSCRIB_S *pSubscrib_info)
{
    int domain, dom_mask, i;
    /* info("tipc_node_is_subscribed enter \n"); */
    domain   = pSubscrib_info->stLinkWatch.domain;
    dom_mask = pSubscrib_info->stLinkWatch.mask;

    if (!pSubscrib_info->stLinkWatch.node_num) {
        return 0;
    }

    for (i = 0; i < pSubscrib_info->stLinkWatch.node_num; ++i) {
        if (pSubscrib_info->stLinkWatch.priv[i] == n_ptr->elm.addr) {
            info("tipc_node_is_subscribed node_addr eque!! return 0, i = %d\n", i);
            return 0;
        }
    }
    /* info("tipc_node_is_subscribed node_addr not eque!! return 1\n"); */
    return 1;
}
int tipc_node_send_link_state(struct TIPC_SUBSCRIB_S *pSubscrib_info)
{
    struct tipc_node *n_ptr = NULL;
    struct link *l_ptr = NULL;
    struct tipc_link_state link_state = {0};
    struct tipc_node_links_state sz_link_state = {0};
    int res = 0;
    int i   = 0;
    int cnt = 0;
    read_lock_bh(&tipc_net_lock);
    list_for_each_entry(n_ptr, &nodes_list, node_list) {
        res = tipc_node_is_subscribed(n_ptr, pSubscrib_info);
        if (res) {
            info("send link state:tipc_node is not subscribed\n");
            continue;
        }
        /*init the cnt  for each nodes_list*/
        cnt = 0;
        
        tipc_node_lock(n_ptr);
        memset(&sz_link_state, 0, sizeof(struct tipc_node_links_state));
        for (i = 0; i < TIPC_MAX_LINKS; ++i) {            
            if (!n_ptr->links[i])
                continue;
            l_ptr = n_ptr->links[i];
            tipc_node_get_link_state(&link_state, l_ptr);
            memcpy(&sz_link_state.sz_linkstate[cnt],  
                &link_state, sizeof(struct tipc_link_state));
            cnt++;
        }
        sz_link_state.link_num = cnt;
        /* info("tipc_node_send_skb\n"); */
        if (cnt) {
            res = tipc_node_send_skb(&sz_link_state, pSubscrib_info);
            if (res && tipc_ratelimit(++sz_link_state.fail_times, 1)) {
                info("%s tipc_node_send_skb res = %d\n", l_ptr->name, res);
            }
        }
        tipc_node_unlock(n_ptr);
        continue;
    }
    read_unlock_bh(&tipc_net_lock);
    return res;
}
struct sk_buff *tipc_node_link_state_issuance(const void *req_tlv_area, 
                                                        int req_tlv_space)
{
    int res = 0;
    struct TIPC_SUBSCRIB_S tipc_subscrib_info = {0};
    memcpy(&tipc_subscrib_info, (struct TIPC_SUBSCRIB_S *)req_tlv_area,
        sizeof(struct TIPC_SUBSCRIB_S));
    res = tipc_link_state_subscrib_check(&tipc_subscrib_info);
    if(res)
    {
        info("tipc_link_state_subscrib_check return err %d\n", res);
        return NULL;
    }
    res = tipc_node_send_link_state(&tipc_subscrib_info);
    if(res < 0)
    {
        info("tipc_node_send_link_state return err %d\n", res);
        return NULL;
    }
    return tipc_cfg_reply_none();
}
void tipc_print_link_state(struct tipc_node_links_state *plink_state)
{
    int i = 0;
    struct tipc_link_state *p_ls = NULL;
    printk("\n---------------------------------------------------------------------------------------------------\n");  
    printk("Self     Peer     SelfBid PeerBid SelfDev PeerDev Up Act ErrCnt SelfAddr          PeerAddr         \n");    
    printk("---------------------------------------------------------------------------------------------------\n");
    for (i = 0; i < ntohl(plink_state->link_num); ++i) 
    {
        p_ls = &plink_state->sz_linkstate[i];
        printk("%-9u%-9u%-8u%-8u%-8s%-8s%-3u%-4u%-7u",
            p_ls->self, p_ls->peer, 
            p_ls->self_bid, p_ls->peer_bid, 
            p_ls->self_dev, p_ls->peer_dev, 
            p_ls->up,p_ls->active,
            ntohl(p_ls->error_count));
        printk("%02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x\n",
            p_ls->self_addr[4],p_ls->self_addr[5],
            p_ls->self_addr[6],p_ls->self_addr[7],
            p_ls->self_addr[8],p_ls->self_addr[9],
            p_ls->peer_addr[4],p_ls->peer_addr[5],
            p_ls->peer_addr[6],p_ls->peer_addr[7],
            p_ls->peer_addr[8],p_ls->peer_addr[9]);
    }
    return;
}
int tipc_issuance_link_state(struct link *l_ptr)
{
    int domain, dom_mask, i;
    int res = 0;
    struct tipc_node * n_ptr = l_ptr->owner;
    struct TIPC_SUBSCRIB_S *p_subscrib = NULL;
    struct tipc_link_state link_state = {0};
    struct tipc_node_links_state sz_link_state = {0};
    for (i = 0; i < g_tipc_link_state_subscrib_cnt; ++i) {
        p_subscrib = &g_tipc_link_state_subscrib_info[i];
        domain   = p_subscrib->stLinkWatch.domain;
        dom_mask = p_subscrib->stLinkWatch.mask;
        res = tipc_node_is_subscribed(n_ptr, p_subscrib);
        if (res) {
            info("tipc_node_is_subscribed return not subscribed, i= %d\n", i);
            continue;
        }
        memset(&sz_link_state, 0, sizeof(struct tipc_node_links_state));
        tipc_node_get_link_state(&link_state, l_ptr);
        memcpy(&sz_link_state.sz_linkstate[0],  
                &link_state, sizeof(struct tipc_link_state));
        sz_link_state.link_num = 1;
        (void)tipc_node_send_skb(&sz_link_state, p_subscrib);       
    }
    return res;
}
#endif
