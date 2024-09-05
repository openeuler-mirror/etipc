/*
 * net/tipc/tipc_discover.c: TIPC neighbor discovery code
 * 
 * Copyright (c) 2003-2006, Ericsson AB
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
#include "tipc_dbg.h"
#include "tipc_link.h"
#include "tipc_net.h"
#include "tipc_discover.h"
#include "tipc_cfgsrv.h"
#include "tipc_port.h"
#include "tipc_name_table.h"

#define TIPC_DISC_INIT 125	/* min delay during bearer start up */
#define TIPC_DISC_FAST 1000	/* normal delay if bearer has no links */
#define TIPC_DISC_SLOW 60000	/* normal delay if bearer has links */
#define TIPC_DISC_INACTIVE 0xffffffff	/* There is no timer */

#ifdef CONFIG_TIPC_CONFIG_SERVICE
#ifdef PROTO_MULTI_DISCOVERY_OBJECT

/**
 * disc_addr_match - determine if node discovery addresses overlap
 * 
 * See if address pair [ma2,ta2] matches address pair [ma1,ta1] 
 * (i.e. the contents of [ma1,ta1] can be overridden by [ma2,ta2]) 
 *
 * The following rules apply:
 *
 * - Broadcast matches broadcast if ta1 is within scope of ta2 or vice versa
 * - Unicast matches unicast if ma1 is equal to ma2.
 * - Always match if ta1 and ta2 are complete and equal.
 */
 
static int disc_addr_match(struct tipc_media_addr *ma1, u32 ta1,
                           struct tipc_media_addr *ma2, u32 ta2)
{
        if (ma2->broadcast && ma1->broadcast) {
                if (tipc_in_scope(ta1,ta2) || tipc_in_scope(ta1,ta2))
                        return 1;
        } 
        
        if (!ma2->broadcast && !ma1->broadcast) {
                if (!memcmp(ma1,ma2,sizeof(struct tipc_media_addr)))
                        return 1;
        }

        if (tipc_node(ta1) && (ta1 == ta2))
                return 1;

        return 0;
}

struct sk_buff *tipc_disc_cmd_create_link(const void *disc_tlv_area, 
					  int disc_tlv_space) 
{
        char *cmd_str;
	char cmd[TIPC_MAX_BEARER_NAME + TIPC_MAX_MEDIA_ADDR + TIPC_MAX_ADDR + 1];
	char *if_name;
        char *addr_string;
        struct bearer *b_ptr;
	struct discoverer *d_ptr;
	struct discoverer *temp_d_ptr;
        struct tipc_media_addr media_addr;
        u32 domain = 0;
	u32 zone = 0;
	u32 cluster = 0;
	u32 node = 0;

	if (!TLV_CHECK(disc_tlv_area, disc_tlv_space, TIPC_TLV_CREATE_LINK))
                return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

        cmd_str = (char *)TLV_DATA(disc_tlv_area);
        strncpy(cmd, cmd_str, sizeof(cmd));

        /* Find TIPC or media address, second parameter */

        addr_string = strchr(cmd, ',');
        if (addr_string == NULL)
                return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);
        *addr_string = '\0';
        addr_string++;

        /* Find bearer, first parameter */

        if_name = cmd;
        write_lock_bh(&tipc_net_lock);
        b_ptr = tipc_bearer_find(if_name);
        if (b_ptr == NULL) 
                goto error;

        /* If translation to media address fails, try if TIPC address */

        if (b_ptr->media->str2addr(&media_addr, addr_string)) {

                if (sscanf(addr_string,"%u.%u.%u", &zone, &cluster, &node) != 3)
                        goto error;

                domain = tipc_addr(zone, cluster, node);

                if (!tipc_addr_domain_valid(domain))
                        goto error;

                memcpy(&media_addr, &b_ptr->media->bcast_addr, sizeof(media_addr));
        } 


        if (in_own_cluster(domain) && !is_slave(domain) && !is_slave(tipc_own_addr))
                goto error;

        /* 
         * Check if corresponding discoverers already exist, and remove.
         */

	list_for_each_entry_safe(d_ptr, temp_d_ptr, &b_ptr->disc_list, disc_list) {
                if (disc_addr_match(&d_ptr->dest, d_ptr->domain,
				    &media_addr, domain)) {
                        tipc_disc_deactivate(d_ptr);
                        tipc_disc_delete(d_ptr);
                }
	}

        if (tipc_disc_create(b_ptr, &media_addr, domain)) {
                write_unlock_bh(&tipc_net_lock);
                return tipc_cfg_reply_none();		
        }
error:
        write_unlock_bh(&tipc_net_lock);
        return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);
}

#endif
#endif

static void disc_update_msg(struct sk_buff *buf, struct bearer *b_ptr)
{
	u32 pos = INT_H_SIZE;
	u8  mcmap[1+TIPC_MCMAP_BYTES] = {0};
	u32 rate = htonl(tipc_media_rate(b_ptr->media)); /* byte-order */

	/* becareful, must be 4 bytes aligned */
	pos += TLV_SET(&buf->data[pos], DSC_DT_RATE, &rate, sizeof(rate));

	mcmap[0] = CONFIG_TIPC_MCASTGID_MAX;
	(void)tipc_bclink_get_mcmap(&mcmap[1], TIPC_MCMAP_BYTES);
	pos += TLV_SET(&buf->data[pos], DSC_DT_MCAST, mcmap, sizeof(mcmap));
	dbg_assert(pos <= INT_H_SIZE + DSC_DT_LEN);

	msg_set_size(buf_msg(buf), pos);
}

/** 
 * disc_init_msg - initialize a link setup message
 * @type: message type (request or response)
 * @dest_domain: network domain of node(s) which should respond to message
 * @b_ptr: ptr to bearer issuing message
 */

static struct sk_buff *disc_init_msg(u32 type, u32 dest_domain,
				     struct bearer *b_ptr)
{
	/* plus dsc data */
	struct sk_buff *buf = buf_acquire(INT_H_SIZE + DSC_DT_LEN);
	struct tipc_msg *msg;
	u32 sig;

	if (buf) {
		memset(buf, 0, INT_H_SIZE + DSC_DT_LEN);
		msg = buf_msg(buf);
		tipc_msg_init(msg, LINK_CONFIG, type, INT_H_SIZE, dest_domain);
		msg_set_non_seq(msg, 1);
		sig = tipc_random & 0xffff;
		msg_set_node_sig(msg, (sig ? sig : 1));
		msg_set_node_flags(msg, NF_MULTICLUSTER);
		msg_set_dest_domain(msg, dest_domain);
		msg_set_bc_netid(msg, tipc_net_id);
		if (b_ptr->media->addr2msg(&b_ptr->publ.addr, &msg->hdr[5])) {
			buf_discard(buf);
			buf = NULL;

			return NULL;
		}

		disc_update_msg(buf, b_ptr);
	}
	return buf;
}

int tipc_node_update_disc(struct tipc_node *n_ptr, u32 rate, u8 *mcpeer, u32 mccnt)
{
	u8  mcme[TIPC_MCMAP_BYTES];
	u32 i = 0;
	
	
	if (n_ptr->rate < rate)
		n_ptr->rate = rate;

	if (mccnt > CONFIG_TIPC_MCASTGID_MAX)
		mccnt = CONFIG_TIPC_MCASTGID_MAX;

	if (!memcmp(mcpeer, n_ptr->mc_peer, BITS_TO_BYTES(mccnt)))
		return 0;

	memcpy(n_ptr->mc_peer, mcpeer, BITS_TO_BYTES(mccnt));
	(void)tipc_bclink_get_mcmap(mcme, TIPC_MCMAP_BYTES);

	/* create mclist */
	for (i=0; i<mccnt; i++) {
		if (test_bytes_bit(mcpeer, i) &&
			test_bytes_bit(mcme, i) ) {
			tipc_node_enable_mclink(n_ptr, i);
		} else {
			tipc_node_disable_mclink(n_ptr, i);
		}
	}

	return 1;
}

int tipc_disc_parse_data(struct tipc_msg *msg, u32 *rate, u8 *mcmap, u32 mcmap_len)
{
	struct tlv_desc *tlv = NULL;
	u32 tlv_len = 0;
	u8 *beg = msg_data(msg);
	u8 *end = beg + msg_size(msg) - msg_hdr_sz(msg);
    u32 has_mc = 0;

	/* space & align */
	if (msg_size(msg) < msg_hdr_sz(msg) + sizeof(*tlv) 
	    /*||
		TLV_ALIGN((u32)beg) != (u32)beg*/) {/*modify by hwx */
		return 0;
	}
	
	dbg_assert(1+TIPC_MCMAP_BYTES == mcmap_len);

	while (beg < end) {
		tlv = (struct tlv_desc *)beg;
		tlv_len = ntohs(tlv->tlv_len);

		switch (ntohs(tlv->tlv_type)) {
		case DSC_DT_RATE:
			{
				*rate = *(u32 *)TLV_DATA(tlv);
				*rate = ntohl(*rate);
			}
			break;
		case DSC_DT_MCAST:
			{
                has_mc = 1;
				if (mcmap_len > tlv_len - TLV_LENGTH(0)) {
					mcmap_len = tlv_len - TLV_LENGTH(0);
				}
				memcpy(mcmap, (u8 *)TLV_DATA(tlv), mcmap_len);
			}
			break;
		default:
			tlv_len = sizeof(*tlv);
            /* continue */
		}

		beg += TLV_ALIGN(tlv_len);
	}


	return has_mc;
}

/**
 * tipc_disc_send_doubt_msg - send discovery doubt message
 * @d_ptr: ptr to discoverer structure
 * @doubt_node: node which being doubt
 *
 * 'b_ptr->publ.lock' must be locked by caller on entry
 * 'tipc_net_lock' must be write-locked by caller on entry
 */

void tipc_disc_send_doubt_msg(struct discoverer *d_ptr, u32 doubt_node)
{
	struct sk_buff *buf = NULL;
	if (!d_ptr)
        return;

    if (d_ptr->bearer->publ.blocked)
        return;


    buf = disc_init_msg(DSC_DOUBT_MSG, doubt_node, d_ptr->bearer);
    if (!buf)
        return;

    tipc_bearer_send(d_ptr->bearer, buf, &d_ptr->dest);

    buf_discard(buf);
}

/**
 * disc_recv_doubt_msg - check discovery reset message
 * @d_ptr: ptr to discoverer structure
 */
void disc_recv_doubt_msg(u32 orig, u32 signature, u32 doubt_node)
{
	struct tipc_node *n_ptr;
    char addr_doubt[16];
    char addr_orig[16];

    /* 检查报文来源可靠性 */
    n_ptr = tipc_net_find_node(orig);
    if (!n_ptr)
        return;

    if (!tipc_node_is_up(n_ptr) || signature != n_ptr->signature)
        return;

    /* 检查doubt node是否self */
    if (doubt_node == tipc_own_addr) {
        /* do nothing */
        return;
    }

    /* 检查doubt node是否up */
    n_ptr = tipc_net_find_node(doubt_node);
    if (!n_ptr)
        return;

    if (!tipc_node_is_up(n_ptr))
        return;

    tipc_addr_string_fill(addr_doubt, doubt_node);
    tipc_addr_string_fill(addr_orig, orig);
	dbg("Received msg from %s: node %s will be down\n", addr_orig, addr_doubt);

    tipc_link_doubt_node(n_ptr);
}



/**
 * disc_dupl_alert - issue node address duplication alert
 * @b_ptr: pointer to bearer detecting duplication
 * @node_addr: duplicated node address
 * @media_addr: media address advertised by duplicated node
 */

static void disc_dupl_alert(struct bearer *b_ptr, u32 node_addr, 
			    struct tipc_media_addr *media_addr)
{
#ifdef CONFIG_TIPC_SYSTEM_MSGS
	char node_addr_str[16];
	char media_addr_str[64];
	struct print_buf pb;

	tipc_addr_string_fill(node_addr_str, node_addr);
	tipc_printbuf_init(&pb, media_addr_str, sizeof(media_addr_str));
	tipc_media_addr_printf(&pb, media_addr);
	tipc_printbuf_validate(&pb);
	warn("Duplicate %s using %s seen on <%s>\n",
	     node_addr_str, media_addr_str, b_ptr->publ.name);
#endif
}

/**
 * tipc_disc_recv_msg - handle incoming link setup message (request or response)
 * @buf: buffer containing message
 * @b_ptr: bearer that message arrived on
 */

void tipc_disc_recv_msg(struct sk_buff *buf, struct bearer *b_ptr)
{
	struct link *link;
	struct tipc_media_addr media_addr;
	struct sk_buff *rbuf;
	struct tipc_msg *msg = buf_msg(buf);
	u32 dest = msg_dest_domain(msg);
	u32 orig = msg_prevnode(msg);
	u32 net_id = msg_bc_netid(msg);
	u32 type = msg_type(msg);
	u32 signature = msg_node_sig(msg);
	u32 node_flags = msg_node_flags(msg);
	struct tipc_node *n_ptr;
	struct discoverer *d_ptr;
	int link_fully_up;
	int found_disc;

	u8  mcmap[1+TIPC_MCMAP_BYTES] = {0};
	u32 rate = 0;
	u32 has_data = 0;
	u32 res = 0;

	res = b_ptr->media->msg2addr(&media_addr, &msg->hdr[5]);
	msg_dbg(msg, "RECV:");
    /* discovery recv */
    b_ptr->publ.recv_disc_count++;
	has_data = tipc_disc_parse_data(msg, &rate, mcmap, sizeof(mcmap));
	buf_discard(buf);

	/* Validate network address of requesting node */

	if (net_id != tipc_net_id || res)
		return;

#ifdef CONFIG_TIPC_UNICLUSTER_FRIENDLY
	if ((node_flags & NF_MULTICLUSTER) == 0 && !in_own_cluster(orig))
		return;
#else
	if ((node_flags & NF_MULTICLUSTER) == 0)
		return;
#endif

	if (!tipc_addr_domain_valid(dest))
		return;
	if (!tipc_addr_node_valid(orig))
		return;

	if (orig == tipc_own_addr) {
		/* from own node such as multi-chassis or ATCA. */
		if ((tipc_random & 0xffff) == signature)
			return;
		
		if (memcmp(&media_addr, &b_ptr->publ.addr, sizeof(media_addr)))
			disc_dupl_alert(b_ptr, tipc_own_addr, &media_addr);
		return;
	}

	if (DSC_DOUBT_MSG == type) {
        disc_recv_doubt_msg(orig, signature, dest);
        return;
	}
    
	if (!tipc_in_scope(dest, tipc_own_addr))
		return;
	found_disc = 0;
	list_for_each_entry(d_ptr, &b_ptr->disc_list, disc_list) {
#if 0
		if (disc_addr_match(&d_ptr->dest, d_ptr->domain,
				    &media_addr, orig))
#endif
		if (tipc_in_scope(d_ptr->domain, orig)) {
			found_disc = 1;
			break;
		}
	}
	if (!found_disc)
		return;
#if 0
	if (is_slave(tipc_own_addr) && is_slave(orig))
		return;
	if (is_slave(orig) && !in_own_cluster(orig))
		return;
#endif

	/* We can accept discovery messages from requesting node */

	n_ptr = tipc_net_find_node(orig);
	if (n_ptr == NULL) {
		n_ptr = tipc_node_create(orig);
		if (n_ptr == NULL)
			return;
	}
	tipc_node_lock(n_ptr);

	/* Don't talk to neighbor during cleanup after last session */

	if (n_ptr->cleanup_required & WAIT_NAMES_GONE) {
		tipc_node_unlock(n_ptr);                
		return;
	}

	/*
	 * Ensure discovery message's signature is correct
	 *
	 * If signature is incorrect and there is at least one working link
	 * to the node, reject the request (must be from a duplicate node).
	 *
	 * If signature is incorrect and there is no working link to the node,
	 * accept the new signature but "invalidate" all existing links to the
	 * node so they won't re-activate without a new discovery message.
	 * (Note: It might be better to delete these "stale" link endpoints,
	 * but this could be tricky [see tipc_link_delete()].)
	 */

	if (signature != n_ptr->signature) {
		d_ptr->chk_dup = 1; /* 该d_ptr需要检查是否冲突 */
		n_ptr->dup_cnt++; /* 该n_ptr需要检查是否冲突 */
		
		if (n_ptr->working_links > 0) {
			disc_dupl_alert(b_ptr, orig, &media_addr);
			/* 超时后清除框冲突未复位框遗留的sig冲突问题 */
			if (n_ptr->dup_tim_cnt > n_ptr->link_cnt * 2 + 1) {
				info("Change %x signature for timeout %u/%u\n",
					n_ptr->elm.addr, n_ptr->dup_cnt, n_ptr->dup_tim_cnt);
				n_ptr->signature = signature;
			}
			tipc_node_unlock(n_ptr);                
			return;
		} else {
			struct link *curr_link;
			int i;

			for (i = 0; i < TIPC_MAX_LINKS; i++) {
				if ((curr_link = n_ptr->links[i]) != NULL) {
					tipc_delete_link(curr_link); /* 2012-2 :删除 */
				}
			}
			/* 2012-2 :有则删除完再重建，否则新老单板换插会错误告警 */
			if (n_ptr->link_cnt > 0) {
				info("node 0x%x 's cur link cnt %d\n", n_ptr->elm.addr, n_ptr->link_cnt);
				tipc_node_unlock(n_ptr);
				return;
			}
		}
	} else {
		n_ptr->dup_cnt = 0; /* 框冲突期间可能交替正确和不正确的，无法处理冲突，所以不检测 */
		n_ptr->dup_tim_cnt = 0;
	}

	/*
	 * Handle cases where we already have a working link on the bearer
	 *
	 * If the discovery message's media address doesn't match the link's,
	 * the duplicate link request is rejected.
	 *
	 * If the discovery message's media address matches the link's,
	 * the message is just a re-request for something we've already done,
	 * so we can skip ahead.
	 */

	/* multi-link */
#ifdef CONFIG_TIPC_LINK_TAG
	link = tipc_node_find_link_byaddr(n_ptr, b_ptr, &media_addr);
#else
	link = n_ptr->links[b_ptr->identity];
#endif
	if (tipc_link_is_up(link)) {
		if (memcmp(&link->media_addr, &media_addr, sizeof(media_addr))) {
			disc_dupl_alert(b_ptr, orig, &media_addr);
			tipc_node_unlock(n_ptr);                
			return;
		}
		goto link_ok;
	}


	/*
	 * Create link endpoint for this bearer if none currently exists, 
	 * otherwise reconfigure link endpoint to use specified media address
	 */

	if (link == NULL) {
#ifndef CONFIG_TIPC_MULTIPLE_LINKS
		if (n_ptr->link_cnt > 0) {
			char node_addr_str[16];

			tipc_addr_string_fill(node_addr_str, orig);
			warn("Ignoring request for second link to node %s\n",
				node_addr_str);
			tipc_node_unlock(n_ptr);
			return;
		}
#endif
		link = tipc_link_create(b_ptr, orig, &media_addr);
		if (link == NULL) {
			warn("Memory squeeze; Failed to create link\n");
			info("New node 0x%x's media addr %02x:%02x:%02x:%02x:%02x:%02x\n",
				orig, media_addr.value[4], media_addr.value[5], media_addr.value[6],
				media_addr.value[7], media_addr.value[8], media_addr.value[9]);
			tipc_node_unlock(n_ptr);
			return;
		}
	} else {
		memcpy(&link->media_addr, &media_addr, sizeof(media_addr));
		tipc_link_reset(link, NULL, 0, 0, 0);
	}

	/* Accept node info in discovery message */

link_ok:
	n_ptr->signature = signature;
	n_ptr->flags = node_flags;
        link_fully_up = link_working_working(link);
	/* */
	if (in_own_cluster(orig) && has_data) {
		(void)tipc_node_update_disc(n_ptr, rate, mcmap+1, mcmap[0]);
	}
        tipc_node_unlock(n_ptr);             
   
	/* Send response to discovery message, if necessary */

	if ((type == DSC_RESP_MSG) || link_fully_up)
		return;
	if (b_ptr->publ.blocked)
		return;
	rbuf = disc_init_msg(DSC_RESP_MSG, orig, b_ptr);
	if (rbuf != NULL) {
		msg_dbg(buf_msg(rbuf), "SEND:");
		tipc_bearer_send(b_ptr, rbuf, &media_addr);
		buf_discard(rbuf);
	}
}

/**
 * tipc_disc_deactivate - deactivate discoverer searching
 * @d_ptr: ptr to discoverer structure
 */

void tipc_disc_deactivate(struct discoverer *d_ptr)
{
        k_cancel_timer(&d_ptr->timer);
        d_ptr->timer_intv = TIPC_DISC_INACTIVE;
} 

/**
 * tipc_disc_update - update frequency of periodic link setup requests
 * @d_ptr: ptr to discovery structure
 * 
 * Reinitiates discovery process if discoverer has no associated nodes
 * and is either not currently searching or is searching at the slow rate
 */

void tipc_disc_update(struct discoverer *d_ptr) 
{
        if (d_ptr->num_nodes == 0) {
		if ((d_ptr->timer_intv == TIPC_DISC_INACTIVE) ||
		    (d_ptr->timer_intv > TIPC_DISC_FAST)) {
			d_ptr->timer_intv = TIPC_DISC_INIT;
			k_start_timer(&d_ptr->timer, d_ptr->timer_intv);
		}
	}
} 

/**
 * tipc_disc_send_msg - send discovery request message
 * @d_ptr: ptr to discoverer structure
 */

void tipc_disc_send_msg(struct discoverer *d_ptr)
{
	if (!d_ptr->bearer->publ.blocked) {
		msg_dbg(buf_msg(d_ptr->buf), "SEND:");
        /* discoverer send */
        d_ptr->bearer->publ.send_disc_count++;
		disc_update_msg(d_ptr->buf, d_ptr->bearer); /* */
		tipc_bearer_send(d_ptr->bearer, d_ptr->buf, &d_ptr->dest);
	}
}
static void disc_check_dupl(struct discoverer *d_ptr) 
{
	struct bearer *b_ptr = d_ptr->bearer;
	struct link *l_ptr;
	struct link *temp_l_ptr;

	if (!d_ptr->chk_dup)
		return;

	d_ptr->chk_dup = 0; /* 先清除，如果没有冲突节点则下次不需要检测 */
	
	list_for_each_entry_safe(l_ptr, temp_l_ptr, &b_ptr->links, link_list) {
		struct tipc_node *n_ptr = l_ptr->owner;
		if (n_ptr->dup_cnt && tipc_link_is_up(l_ptr)) {
			n_ptr->dup_tim_cnt++;
			d_ptr->chk_dup = 1;
		}
	}
}

/**
 * disc_timeout - send a periodic discovery request
 * @d_ptr: ptr to discoverer structure
 * 
 * Called whenever a link setup request timer associated with a bearer expires.
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static void disc_timeout(struct timer_list *timer)
#else
static void disc_timeout(struct discoverer *d_ptr)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	struct discoverer *d_ptr = container_of(timer, struct discoverer, timer);
	struct bearer *b_ptr = d_ptr->bearer;
#else
	struct bearer *b_ptr = d_ptr->bearer;
#endif
	int max_delay;

	spin_lock_bh(&b_ptr->publ.lock);

	/* See if discovery object can be deactivated */

	if ((tipc_node(d_ptr->domain) != 0) && (d_ptr->num_nodes != 0)) {
		d_ptr->timer_intv = TIPC_DISC_INACTIVE;
		goto exit;
	}

	/* 
	 * Send discovery message, then update discovery timer
	 *
	 * Keep doubling time between requests until limit is reached;
	 * hold at fast polling rate if don't have any associated nodes,
	 * otherwise hold at slow polling rate
	 */
        tipc_disc_send_msg(d_ptr);

        d_ptr->timer_intv *= 2;
	max_delay = (d_ptr->num_nodes == 0) ? TIPC_DISC_FAST : TIPC_DISC_SLOW;
    if (d_ptr->timer_intv > max_delay) {
                d_ptr->timer_intv = max_delay;
    }
		if (d_ptr->timer_intv >= TIPC_DISC_SLOW) {
			disc_check_dupl(d_ptr);
		}

	k_start_timer(&d_ptr->timer, d_ptr->timer_intv);
exit:
	spin_unlock_bh(&b_ptr->publ.lock);
}

/**
 * tipc_disc_create - start sending periodic discovery requests
 * @b_ptr: ptr to bearer issuing requests
 * @dest: destination address for discovery message
 * @domain: network domain of node(s) to be discovered
 * 
 * Returns 1 if successful, otherwise 0.
 *
 * 'tipc_net_lock' must be write-locked by caller on entry
 */

int tipc_disc_create(struct bearer *b_ptr, struct tipc_media_addr *dest,
                     u32 domain)
{
	struct discoverer *d_ptr;

	d_ptr = kmalloc(sizeof(*d_ptr), GFP_ATOMIC);
	if (!d_ptr)
		return 0;

	d_ptr->buf = disc_init_msg(DSC_REQ_MSG, domain, b_ptr);
	if (!d_ptr->buf) {
		kfree(d_ptr);
		return 0;
	}

	d_ptr->bearer = b_ptr;
        list_add(&d_ptr->disc_list, &b_ptr->disc_list);
	memcpy(&d_ptr->dest, dest, sizeof(*dest));
        d_ptr->domain = domain;
	d_ptr->num_nodes = 0;
	d_ptr->timer_intv = TIPC_DISC_INIT;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	k_init_timer(&d_ptr->timer, (timer_handler)disc_timeout);
#else
	k_init_timer(&d_ptr->timer, (Handler)disc_timeout, (unsigned long)d_ptr);
#endif
        k_start_timer(&d_ptr->timer, d_ptr->timer_intv);
	tipc_disc_send_msg(d_ptr);
	return 1;
} 

/**
 * tipc_disc_delete - stop sending periodic link setup requests
 * @disc: ptr to link request structure
 * Timer must be cancelled or expired before doing this call
 */

void tipc_disc_delete(struct discoverer *d_ptr) 
{
	if (!d_ptr)
		return;

	k_term_timer(&d_ptr->timer);
	buf_discard(d_ptr->buf);
        list_del_init(&d_ptr->disc_list);
	kfree(d_ptr);
}

