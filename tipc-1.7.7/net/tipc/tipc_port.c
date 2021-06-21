/*
 * net/tipc/tipc_port.c: TIPC port code
 *
 * Copyright (c) 1992-2007, Ericsson AB
 * Copyright (c) 2004-2008, 2010, Wind River Systems
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
#include "tipc_dbg.h"
#include "tipc_port.h"
#include "tipc_addr.h"
#include "tipc_link.h"
#include "tipc_node.h"
#include "tipc_name_table.h"
#include "tipc_user_reg.h"
#include "tipc_msg.h"
#include "tipc_bcast.h"

extern unsigned int g_tipc_dbg_switch;

/* Connection management: */
#define PROBING_INTERVAL 3600000	/* [ms] => 1 h */
#define CONFIRMED 0
#define PROBING 1

#define MAX_REJECT_SIZE 1024

#ifndef CONFIG_TIPC_PSHCNT_MAX
#define CONFIG_TIPC_PSHCNT_MAX 10000
#endif
#define CONFIG_TIPC_PSCNT_MAX 320000 // 3备业务量上，ps稳定状态在10万左右，2T8环境反复复位线卡框理论在28万左右
#define PS_NEED(ps, dnode, dref) ((ps) && (!(dnode) || (dnode) == (ps)->node) &&\
                                         (!(dref) || (dref) == (ps)->ref))

static struct sk_buff *msg_queue_head = NULL;
static struct sk_buff *msg_queue_tail = NULL;

static atomic_t ps_count = ATOMIC_INIT(0); /* */
static atomic_t psh_count = ATOMIC_INIT(0); /* */

DEFINE_SPINLOCK(tipc_port_list_lock);
/* Protects global ports list AND each link's waiting ports list */

static DEFINE_SPINLOCK(queue_lock);

static LIST_HEAD(ports);
static void port_handle_node_down(unsigned long ref);
static struct sk_buff* port_build_self_abort_msg(struct port *,u32 err);
static struct sk_buff* port_build_peer_abort_msg(struct port *,u32 err);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static void port_timeout(struct timer_list *timer);
#else
static void port_timeout(unsigned long ref);
#endif
static void port_del_hps(struct port *p_ptr); /* */
static inline int port_ps0_sent(struct port *p_ptr);
static inline void port_ps0_sent_congested(struct port *p_ptr);
static inline void port_ps0_sent_res(struct port *p_ptr, int res);
extern void tipc_port_msg_stats(struct sk_buff *buf, struct port *p_ptr, TIPC_PORT_MSG_TYPE_E msgtype);

static u32 port_peernode(struct port *p_ptr)
{
	return msg_destnode(&p_ptr->publ.phdr);
}

static u32 port_peerport(struct port *p_ptr)
{
	return msg_destport(&p_ptr->publ.phdr);
}

static void port_set_msg_importance(struct tipc_msg *msg, u32 importance)
{
	/* use port's default if value is TIPC_PORT_IMPORTANCE or invalid */

	if (importance <= TIPC_CRITICAL_IMPORTANCE)
		msg_set_importance(msg, importance);
}

/**
 * tipc_multicast - send a multicast message to local and remote destinations
 */

int tipc_multicast(u32 ref, struct tipc_name_seq const *seq, u32 domain,
		   u32 num_sect, struct iovec const *msg_sect)
{
	struct tipc_msg *hdr;
	struct sk_buff *buf;
	struct sk_buff *ibuf = NULL;
	struct port_list dports = {0, NULL, };
	struct port *oport = tipc_port_deref(ref);
	int ext_targets;
	int res;

	if (unlikely(!oport))
		return -EINVAL;

	/* */
	res = port_ps0_sent(oport);
	if (unlikely(res))
		return res;
	
	/* Create multicast message */

	hdr = &oport->publ.phdr;
	msg_set_hdr_sz(hdr, MCAST_H_SIZE);
	msg_set_type(hdr, TIPC_MCAST_MSG);
	msg_set_destport(hdr, 0);
	msg_set_destnode(hdr, 0);
	msg_set_nametype(hdr, seq->type);
	msg_set_namelower(hdr, seq->lower);
	msg_set_nameupper(hdr, seq->upper);
	res = tipc_msg_build(hdr, msg_sect, num_sect, MAX_MSG_SIZE,
			     !oport->user_port, &buf);
	if (unlikely(!buf)) {
        port_ps0_sent_res(oport, res);
		return res;
	}
	buf->priority = oport->publ.sk_priority; /* tipc_priority */

	/* Figure out where to send multicast message */

	ext_targets = tipc_nametbl_mc_translate(seq->type, seq->lower, seq->upper,
						TIPC_NODE_SCOPE, &dports);

	/* Send message to destinations (duplicate it only if necessary) */

	if (ext_targets) {
		if (dports.count != 0) {
			ibuf = skb_copy(buf, GFP_ATOMIC);
			if (ibuf == NULL) {
				tipc_port_list_free(&dports);
				buf_discard(buf);
				port_ps0_sent_res(oport, -ENOMEM);
				return -ENOMEM;
			}
		}
		res = tipc_bclink_send_msg(buf);
		if ((res < 0) && (dports.count != 0)) {
			buf_discard(ibuf);
		}
	} else {
		ibuf = buf;
	}

	if (res >= 0) {
		/*  修改需合入主线2010-1-25 */
		if (unlikely(!ext_targets && !dports.count))
			res = -ENOENT;
		if (ibuf)
			tipc_port_recv_mcast(ibuf, &dports);
	} else {
		tipc_port_list_free(&dports);
	}
	/* */
	if (likely(res != -ELINKCONG)) {
		if (unlikely(res == -ENOENT))
			oport->publ.sentm_reject++; 
    	port_ps0_sent_res(oport, res); /* */
        return res;
	}
	port_ps0_sent_congested(oport);
	return res;
}

/**
 * tipc_port_recv_mcast - deliver multicast message to all destination ports
 *
 * If there is no port list, perform a lookup to create one
 */

void tipc_port_recv_mcast(struct sk_buff *buf, struct port_list *dp)
{
	struct tipc_msg* msg;
	struct port_list dports = {0, NULL, };
	struct port_list *item = dp;
	int cnt = 0;

	msg = buf_msg(buf);

	/* Create destination port list, if one wasn't supplied */

	if (dp == NULL) {
		tipc_nametbl_mc_translate(msg_nametype(msg),
				     msg_namelower(msg),
				     msg_nameupper(msg),
				     TIPC_CLUSTER_SCOPE,
				     &dports);
		item = dp = &dports;
	}

	/* Deliver a copy of message to each destination port */

	if (dp->count != 0) {
		msg_set_destnode(msg, tipc_own_addr);
		if (dp->count == 1) {
			msg_set_destport(msg, dp->ports[0]);
			tipc_port_recv_msg(buf);
			tipc_port_list_free(dp);
			return;
		}
		for (; cnt < dp->count; cnt++) {
			int index = cnt % PLSIZE;
			struct sk_buff *b = skb_clone(buf, GFP_ATOMIC);

			if (b == NULL) {
				warn("Unable to deliver multicast message(s)\n");
				msg_dbg(msg, "LOST:");
				goto exit;
			}
			if ((index == 0) && (cnt != 0)) {
				item = item->next;
			}
			msg_set_destport(buf_msg(b), item->ports[index]);
			tipc_port_recv_msg(b);
		}
	}
exit:
	buf_discard(buf);
	tipc_port_list_free(dp);
}

/**
 * tipc_createport_raw - create a generic TIPC port
 *
 * Returns pointer to (locked) TIPC port, or NULL if unable to create it
 */

struct tipc_port *tipc_createport_raw(void *usr_handle,
			u32 (*dispatcher)(struct tipc_port *, struct sk_buff *),
			void (*wakeup)(struct tipc_port *),
			const u32 importance)
{
	struct port *p_ptr;
	struct tipc_msg *msg;
	u32 ref;

	p_ptr = kzalloc(sizeof(*p_ptr), GFP_ATOMIC);
	if (!p_ptr) {
		warn("Port creation failed, no memory\n");
		return NULL;
	}
	ref = tipc_ref_acquire(p_ptr, &p_ptr->publ.lock);
	if (!ref) {
		warn("Port creation failed, reference table exhausted\n");
		kfree(p_ptr);
		return NULL;
	}

	p_ptr->publ.hps = kcalloc(TIPC_PS_HASH_SZ * 2, 
			sizeof(struct hlist_head), GFP_ATOMIC);
	if (!p_ptr->publ.hps) {
		warn("Hps creation failed, no memory\n");
		kfree(p_ptr);
		return NULL;
	}
    p_ptr->publ.hpsh = &p_ptr->publ.hps[TIPC_PS_HASH_SZ];

	p_ptr->publ.usr_handle = usr_handle;
	p_ptr->publ.max_pkt = MAX_PKT_DEFAULT;
	p_ptr->publ.ref = ref;
	p_ptr->publ.sk_priority = TIPC_PRI_DATA_PIPE;/* tipc_priority */
	p_ptr->publ.ps.node = addr_cluster(tipc_own_addr); /* */
	p_ptr->publ.ps.ref  = 0; /* */
	p_ptr->sent = 0; /* */
	INIT_LIST_HEAD(&p_ptr->wait_list);
	INIT_LIST_HEAD(&p_ptr->subscription.sub_list);
	p_ptr->dispatcher = dispatcher;
	p_ptr->wakeup = wakeup;
	p_ptr->user_port = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	k_init_timer(&p_ptr->timer, (timer_handler)port_timeout);
#else
	k_init_timer(&p_ptr->timer, (Handler)port_timeout, ref);
#endif
	INIT_LIST_HEAD(&p_ptr->publications);

	/*
	 * Must hold port list lock while initializing message header template
	 * to ensure node's own network address isn't being altered
	 */
	
	spin_lock_bh(&tipc_port_list_lock);
	msg = &p_ptr->publ.phdr;
	tipc_msg_init(msg, importance, TIPC_NAMED_MSG, LONG_H_SIZE, 0);
	msg_set_origport(msg, ref);
	list_add_tail(&p_ptr->port_list, &ports);
	spin_unlock_bh(&tipc_port_list_lock);
	return &(p_ptr->publ);
}

int tipc_deleteport(u32 ref)
{
	struct port *p_ptr;
	struct sk_buff *buf = NULL;

	tipc_withdraw(ref, 0, NULL);
	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return -EINVAL;

	tipc_ref_discard(ref);
	/* del hps */
	port_del_hps(p_ptr);	
	tipc_port_unlock(p_ptr);

	k_cancel_timer(&p_ptr->timer);
	if (p_ptr->publ.connected) {
		buf = port_build_peer_abort_msg(p_ptr, TIPC_ERR_NO_PORT);
		tipc_netsub_unbind(&p_ptr->subscription);
	}
	if (p_ptr->user_port) {
		tipc_reg_remove_port(p_ptr->user_port);
		kfree(p_ptr->user_port);
	}

	spin_lock_bh(&tipc_port_list_lock);
	list_del(&p_ptr->port_list);
	list_del(&p_ptr->wait_list);
	spin_unlock_bh(&tipc_port_list_lock);
	k_term_timer(&p_ptr->timer);
	kfree(p_ptr);
	dbg("Deleted port %u\n", ref);
	tipc_net_route_msg(buf);
	return 0;
}

/**
 * tipc_get_port() - return port associated with 'ref'
 *
 * Note: Port is not locked.
 */

struct tipc_port *tipc_get_port(const u32 ref)
{
	return (struct tipc_port *)tipc_ref_deref(ref);
}

/**
 * tipc_get_handle - return user handle associated to port 'ref'
 */

void *tipc_get_handle(const u32 ref)
{
	struct port *p_ptr;
	void * handle;

	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return NULL;
	handle = p_ptr->publ.usr_handle;
	tipc_port_unlock(p_ptr);
	return handle;
}

static int port_unreliable(struct port *p_ptr)
{
	return msg_src_droppable(&p_ptr->publ.phdr);
}

int tipc_portunreliable(u32 ref, unsigned int *isunreliable)
{
	struct port *p_ptr;

	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return -EINVAL;
	*isunreliable = port_unreliable(p_ptr);
	tipc_port_unlock(p_ptr);
	return 0;
}

int tipc_set_portunreliable(u32 ref, unsigned int isunreliable)
{
	struct port *p_ptr;

	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return -EINVAL;
	msg_set_src_droppable(&p_ptr->publ.phdr, (isunreliable != 0));
	tipc_port_unlock(p_ptr);
	return 0;
}

static int port_unreturnable(struct port *p_ptr)
{
	return msg_dest_droppable(&p_ptr->publ.phdr);
}

int tipc_portunreturnable(u32 ref, unsigned int *isunrejectable)
{
	struct port *p_ptr;

	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return -EINVAL;
	*isunrejectable = port_unreturnable(p_ptr);
	tipc_port_unlock(p_ptr);
	return 0;
}

int tipc_set_portunreturnable(u32 ref, unsigned int isunrejectable)
{
	struct port *p_ptr;

	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return -EINVAL;
	msg_set_dest_droppable(&p_ptr->publ.phdr, (isunrejectable != 0));
	tipc_port_unlock(p_ptr);
	return 0;
}

/*
 * port_build_proto_msg(): build a port level protocol
 * or a connection abortion message. Called with
 * tipc_port lock on.
 */
static struct sk_buff *port_build_proto_msg(u32 destport, u32 destnode,
					    u32 origport, u32 orignode,
					    u32 usr, u32 type, u32 err,
					    u32 ack)
{
	struct sk_buff *buf;
	struct tipc_msg *msg;

	buf = buf_acquire(LONG_H_SIZE);
	if (buf) {
		msg = buf_msg(buf);
		tipc_msg_init(msg, usr, type, LONG_H_SIZE, destnode);
		msg_set_errcode(msg, err);
		msg_set_destport(msg, destport);
		msg_set_origport(msg, origport);
		msg_set_orignode(msg, orignode);
		msg_set_msgcnt(msg, ack);
		msg_dbg(msg, "PORT>SEND>:");
	}
	return buf;
}

int tipc_reject_msg(struct sk_buff *buf, u32 err)
{
	struct tipc_msg *msg = buf_msg(buf);
	u32 data_sz;
	u32 hdr_sz;
	u32 msg_imp;

	struct sk_buff *rbuf;
	struct tipc_msg *rmsg;
	u32 rmsg_sz;

	msg_dbg(msg, "port->rej: ");

	/* discard rejected message if it shouldn't be returned to sender */

	while ((msg_user(msg) == MSG_FRAGMENTER) && 
	       (msg_type(msg) == FIRST_FRAGMENT)) {
		skb_pull(buf, INT_H_SIZE);
		msg = buf_msg(buf);
	}
	data_sz = msg_data_sz(msg);

	if (!msg_isdata(msg) && (msg_user(msg) != CONN_MANAGER)) 
		goto exit;
	if (msg_errcode(msg) || msg_dest_droppable(msg))
		goto exit;

	/* construct returned message */

	msg_imp = msg_importance(msg);
	hdr_sz = msg_hdr_sz(msg);

	if (data_sz > MAX_REJECT_SIZE)
		rmsg_sz = MAX_REJECT_SIZE;
	else
		rmsg_sz = data_sz;
	rmsg_sz += hdr_sz;

	rbuf = buf_acquire(rmsg_sz);
	if (rbuf == NULL)
		goto exit;

	rmsg = buf_msg(rbuf);
	skb_copy_to_linear_data(rbuf, msg, rmsg_sz);

	/*
	 * update fields of returned message header that need to be fixed up
	 *
	 * note: the "prev node" field is always updated when the returned
	 * message is sent, so we don't have to do it here ...
	 */

	if (msg_connected(msg)) {
		if (msg_imp < TIPC_CRITICAL_IMPORTANCE)
			msg_set_importance(rmsg, ++msg_imp);
	}
	msg_set_non_seq(rmsg, 0);
	msg_set_size(rmsg, rmsg_sz); 
	msg_set_errcode(rmsg, err);
	msg_reset_reroute_cnt(rmsg);
	msg_swap_words(rmsg, 4, 5);
	if (!msg_short(rmsg))
		msg_swap_words(rmsg, 6, 7);
	else
		msg_set_destnode_cache(rmsg, msg_prevnode(rmsg));

	/* 
	 * notify sender's peer when a connection is broken due to congestion
	 *
	 * use original message (with data portion omitted) to notify peer;
	 * don't have to worry about buffer being cloned, since that only
	 * happens with multicast messages, which are connectionless ...
	 */

	if ((err == TIPC_ERR_OVERLOAD) && msg_connected(msg)) {
		msg_set_importance(msg, msg_imp);
		msg_set_size(msg, hdr_sz); 
		skb_trim(buf, hdr_sz);
		msg_set_errcode(msg, err);
		msg_set_destnode_cache(msg, tipc_own_addr);
		tipc_net_route_msg(buf);
		buf = NULL;
	}

	/* send returned message & dispose of rejected message */

	tipc_net_route_msg(rbuf);
exit:
	buf_discard(buf);
	return -ENOENT; /* tell app no nametype/addr */
}

int tipc_port_reject_sections(struct port *p_ptr, struct tipc_msg *hdr,
			      struct iovec const *msg_sect, u32 num_sect,
			      int err)
{
	struct sk_buff *buf;
	int res;

	p_ptr->publ.sent_reject++; /* */
	res = tipc_msg_build(hdr, msg_sect, num_sect, MAX_MSG_SIZE, 
			     !p_ptr->user_port, &buf);
	if (!buf)
		return res;

	return tipc_reject_msg(buf, err);
}


static inline u32 hpsh_hash(u32 type, u32 instance)
{
	return (type | instance) % TIPC_PS_HASH_SZ;
}

static inline u32 hps_hash(u32 node, u32 port)
{
	return ((port & 0xfff) ^ (port >> 12) ^ (node & 0xfff)) % TIPC_PS_HASH_SZ;
}

static void port_del_hps(struct port *p_ptr)
{
	if (p_ptr->publ.hps) {
		struct hlist_head *ps_head;
		struct hlist_node *ps_node, *ps_nn;
		struct port_msg_stat *ps;
		struct port_msg_stat_hlist *psh;
		u32 i;
		
		for (i=0; i<TIPC_PS_HASH_SZ; i++) {
			ps_head = &p_ptr->publ.hpsh[i];
			
			tipc_hlist_for_each_entry_safe(psh, ps_node, ps_nn, ps_head, psh_list) {
                hlist_del_init(&psh->psh_list);
				kfree(psh);
				atomic_dec(&psh_count);
			}
		}

		for (i=0; i<TIPC_PS_HASH_SZ; i++) {
			ps_head = &p_ptr->publ.hps[i];
			
			tipc_hlist_for_each_entry_safe(ps, ps_node, ps_nn, ps_head, ps_list) {
                hlist_del_init(&ps->ps_list);
				kfree(ps);
				atomic_dec(&ps_count);
			}
		}
        
		kfree(p_ptr->publ.hps);
		p_ptr->publ.hps = NULL;
		p_ptr->publ.hpsh = NULL;
	}
}

static struct port_msg_stat *port_find_hps(struct tipc_port *tp_ptr,
				u32 node, u32 port)
{
	struct hlist_head *ps_head;
	struct hlist_node *ps_node;
	struct port_msg_stat *ps;
	u32 idx = hps_hash(node, port);


	ps_head = &tp_ptr->hps[idx];
	tipc_hlist_for_each_entry(ps, ps_node, ps_head, ps_list) {
		if (ps->node == node && ps->ref == port) {
			return ps;
		}
	}

	return NULL;	
}

static struct port_msg_stat *port_add_hps(struct tipc_port *tp_ptr,
				u32 node, u32 port)
{
	struct hlist_head *ps_head;
	u32 idx = hps_hash(node, port);
	struct port_msg_stat *ps;
	static u32 ps_overload = 0;

	/* 防止目标地址错误，导致占用内存过多，返回null不应影响其它处理 */
	if (atomic_read(&ps_count) > CONFIG_TIPC_PSCNT_MAX) {
        ps_overload++;
        if (tipc_ratelimit(ps_overload, 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_PORT)) {
            warn("Ps overload %d ,create too much(%u), maybe process recreate too much\n",ps_overload, ps_count);
        }
		return NULL;
	}
	atomic_inc(&ps_count);

	ps = kzalloc(sizeof(*ps), GFP_ATOMIC);
	if (!ps) {
		warn("Ps(%d,%d) creation failed, no memory\n",
			node, port);
		return NULL;
	}
	
	ps->node = node;
	ps->ref  = port;
	
	ps_head = &tp_ptr->hps[idx];

	hlist_add_head(&ps->ps_list, ps_head);
	return ps;
}

static inline struct port_msg_stat *port_find_hps_add(
				struct tipc_port *tp_ptr,
				u32 node, u32 port)
{
    struct port_msg_stat *ps = NULL;
	ps = port_find_hps(tp_ptr, node, port);
	if (!ps) {
		ps = port_add_hps(tp_ptr, node, port);
	}

    return ps;
}

/* exclude tport.ps */
static struct port_msg_stat *port_update_last_ps_recv(struct tipc_port *tp_ptr,
				u32 node, u32 port)
{
	struct port_msg_stat *ps = tp_ptr->last_ps_recv;
	
	if (ps && ps->node == node && ps->ref == port) {
		return ps;
	}

	tp_ptr->last_ps_recv = NULL;

	/* 2011-7-30 只在发送时根据type/instance创建，避免创建无用的 */
	ps = port_find_hps(tp_ptr, node, port);

	tp_ptr->last_ps_recv = ps;
	return ps;
}

static struct port_msg_stat_hlist *port_find_hpsh(struct tipc_port *tp_ptr,
				u32 type, u32 low, u32 upper)
{
	struct hlist_head *psh_head;
	struct hlist_node *psh_node;
	struct port_msg_stat_hlist *psh;
	u32 idx = hpsh_hash(type, low);


	psh_head = &tp_ptr->hpsh[idx];
	tipc_hlist_for_each_entry(psh, psh_node, psh_head, psh_list) {
		if (psh->type == type && low == psh->low && psh->upper == upper) {
			return psh;
		}
	}

	return NULL;	
}



static struct port_msg_stat_hlist *port_add_hpsh(struct tipc_port *tp_ptr,
				u32 type, u32 low, u32 upper)
{
	struct hlist_head *psh_head;
	u32 idx = hpsh_hash(type, low);
	struct port_msg_stat_hlist *psh;
    static u32 psh_overload = 0;

	/* 防止目标地址错误，导致占用内存过多，返回null不应影响其它处理 */
	if (atomic_read(&psh_count) > CONFIG_TIPC_PSHCNT_MAX) {
        psh_overload++;
        if (tipc_ratelimit(psh_overload, 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_PORT)) {
            warn("Psh overload %d, create too much(%u), maybe dest is wrong. \n",psh_overload, psh_count);
        }
		return NULL;
	}
	atomic_inc(&psh_count);

	psh = kzalloc(sizeof(*psh), GFP_ATOMIC);
	if (!psh) {
		warn("Ps{0x%x,%u,%u} creation failed, no memory\n",
			type, low, upper);
		return NULL;
	}
	
	psh->type = type;
	psh->low  = low;
    psh->upper = upper;
	
	psh_head = &tp_ptr->hpsh[idx];

	hlist_add_head(&psh->psh_list, psh_head);
	return psh;
}


static struct port_msg_stat *port_psh_find_ps(struct tipc_port *tp_ptr,
        struct port_msg_stat_hlist *psh, u32 node, u32 ref)
{
    struct port_msg_stat *ps = NULL;
    u32 i = psh->cur;
    struct port *tmp;

    /* 遍历查找是否有匹配的 */
    do {
        ps = psh->msg_stat[i];
        if (ps && node == ps->node && ref == ps->ref) {
            return ps;
        }

        i = (i + 1) % TIPC_PS_REF_RCD;
    } while (i != psh->cur);


    /* 遍历查找添加位置，此时 i == psh->cur  */
    tmp = tipc_port_lock(tp_ptr->ref);
    if (!tmp)
        return NULL;
    i = psh->cur;
    do {
        ps = psh->msg_stat[i];
        if (!ps) {
            break;
        }

        i = (i + 1) % TIPC_PS_REF_RCD;
    } while (i != psh->cur);

    if (ps) {
        /* 没有空闲位置，此时i == psh->cur，腾空下一个位置 */
        i = (psh->cur + 1) % TIPC_PS_REF_RCD;
        psh->cur = i;

        ps = psh->msg_stat[i];
        /* 检查是否需要删除 */
        if (ps && ps->refcount > 0) {
            if (--ps->refcount == 0) {

                /* 删除之 */

                hlist_del_init(&ps->ps_list);

                                     kfree(ps);

                                     atomic_dec(&ps_count);

            }
        }



        /* 在[i]处重新添加一个 */
        psh->msg_stat[i] = NULL;
    } else {
        psh->cur = i;    
    }


    /* 查找添加 */
    ps = port_find_hps_add(tp_ptr, node, ref);
    if (ps) {
        psh->accu++;
        psh->msg_stat[i] = ps;
        ps->refcount++;
	}
    tipc_port_unlock(tmp);
    return ps;
}

/* exclude tport.ps */
static struct port_msg_stat *port_update_last_ps_sent(struct tipc_port *tp_ptr,
				u32 type, u32 low, u32 upper, u32 node, u32 ref)
{
	struct port_msg_stat *ps = tp_ptr->last_ps_sent;
	struct port_msg_stat_hlist *psh = NULL;
	
	if (ps && (ps->node == node && ps->ref == ref)) {
		return ps;
	}

	tp_ptr->last_ps_sent = NULL;

	psh = port_find_hpsh(tp_ptr, type, low, upper);
	if (!psh) {
		psh = port_add_hpsh(tp_ptr, type, low, upper);
		if (!psh)
			return NULL;		
	}

    /* 0:0 不用ps记录 */
    if (unlikely(!node && !ref)) {
        /* 记录发送地址不存在的情况 */
        if ((tipc_ratelimit(++psh->sent_reject, 4) || tipc_dbg_is_on(TIPC_DBG_SWITCH_PORT)) && psh->accu) {
			warn("Port %u reject portname {0x%x,%u,%u} 0x%x\n",
                tp_ptr->ref, type, low, upper, psh->sent_reject);
        }
        return NULL;
    }

    ps = port_psh_find_ps(tp_ptr, psh, node, ref);
	tp_ptr->last_ps_sent = ps;
	return ps;
}

static inline int port_connectionless(struct tipc_port *tp_ptr)
{
	return msg_dest_droppable(&tp_ptr->phdr);
}

/* not include mc ps */
struct port_msg_stat *tipc_find_ps_recv(struct tipc_port *tp_ptr,
				u32 node, u32 port)
{
	if (!port_connectionless(tp_ptr))
		return &tp_ptr->ps;
	
	return port_update_last_ps_recv(tp_ptr, node, port);
}

static inline int port_ps_sent_pause(struct port *p_ptr, struct port_msg_stat *ps)
{
	if (likely(!ps->stopped)) {
		return TIPC_OK;
	} else {
		p_ptr->publ.stopped = 1;
		if (tipc_ratelimit(++ps->stat.sent_congested, 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_PORT)) {
		    warn("Port %u send to %x:%u congested 0x%x, sent 0x%x\n", 
                p_ptr->publ.ref, ps->node, ps->ref, ps->stat.sent_congested, ps->stat.sent);
		}
		
		/* 2011-7-30 增加可靠性防止出错，若干次尝试后解除反压 */
		if (unlikely(ps->stat.sent_congested % 0x40 == 0)) {
			ps->stopped = 0;
			p_ptr->publ.stopped = 0;
			return TIPC_OK;
		}		
		
		return -ELINKCONG;
	}	
}


/* connection ps or multicast ps */
static inline int port_ps0_sent(struct port *p_ptr)
{
	return port_ps_sent_pause(p_ptr, &p_ptr->publ.ps);
}

static inline void port_ps0_sent_congested(struct port *p_ptr)
{
    struct port_msg_stat *ps = &p_ptr->publ.ps;
	if (tipc_ratelimit(++ps->stat.sent_congested, 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_PORT))
		warn("Port_ps0 %u send to %x:%u link congested 0x%x, sent 0x%x\n", 
			p_ptr->publ.ref, ps->node, ps->ref, ps->stat.sent_congested, ps->stat.sent);
}

static inline void port_ps0_sent_res(struct port *p_ptr, int res)
{
    struct port_msg_stat *ps = &p_ptr->publ.ps;
    
	if (unlikely(res < 0)) {
		if (tipc_ratelimit(++ps->stat.sent_fail, 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_PORT)) {
		    warn("Port_ps0 %u send to %x:%u failed %d, (total suc %u fail %u)\n", 
                p_ptr->publ.ref, ps->node, ps->ref, res, ps->stat.sent, ps->stat.sent_fail);
		}
    } else {
	    ps->stat.sent++;
        p_ptr->sent++;
    }
}

/* connectionless ps */
static int port_ps_sent(struct port *p_ptr,
				u32 type, u32 instance, u32 node, u32 ref)
{
	struct port_msg_stat *ps = NULL;


	ps = port_update_last_ps_sent(&p_ptr->publ, type, instance, instance, node, ref);

	if (unlikely(!ps))
		return TIPC_OK; /* no side-effect */

	return port_ps_sent_pause(p_ptr, ps);
}

static inline void port_ps_sent_congested(struct port *p_ptr)
{
	struct port_msg_stat *ps = p_ptr->publ.last_ps_sent;
	if (likely(ps)) {
		if (tipc_ratelimit(++ps->stat.sent_congested, 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_PORT))
			warn("Port %u send to %x:%u link congested 0x%x, sent 0x%x\n", 
				p_ptr->publ.ref, ps->node, ps->ref, ps->stat.sent_congested, ps->stat.sent);
	}
}

static inline void port_ps_sent_res(struct port *p_ptr, int res)
{
    struct port_msg_stat *ps = p_ptr->publ.last_ps_sent;
	if (unlikely(res < 0)) {
        if (ps && (tipc_ratelimit(++ps->stat.sent_fail, 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_PORT))) {
		    warn("Port %u send to %x:%u failed %d, (total suc %u fail %u)\n", 
                p_ptr->publ.ref, ps->node, ps->ref, res, ps->stat.sent, ps->stat.sent_fail);
        }
	} else {
        if (ps)
		    ps->stat.sent++;
	    p_ptr->sent++;
	}
}

static void port_cancel_stopped(struct port *p_ptr)
{
	struct hlist_head *ps_head;
	struct hlist_node *ps_node;
	struct port_msg_stat *ps = &p_ptr->publ.ps;
	u32 i;

	if (ps->stopped) {
		ps->stopped = 0;
		ps->stat.timout_pause++;
	}
	
	if (p_ptr->publ.hps) {
		for (i=0; i<TIPC_PS_HASH_SZ; i++) {
			ps_head = &p_ptr->publ.hps[i];
			
			tipc_hlist_for_each_entry(ps, ps_node, ps_head, ps_list) {
				if (ps->stopped) {
					ps->stopped = 0;
					ps->stat.timout_pause++;
				}
			}
		}
	}
	
	p_ptr->publ.stopped = 0;
	if (p_ptr->wakeup)
		p_ptr->wakeup(&p_ptr->publ);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static void port_timeout(struct timer_list *timer)
#else
static void port_timeout(unsigned long ref)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	struct port *p_ptr = container_of(timer, struct port, timer);
	struct sk_buff *buf = NULL;
	p_ptr = tipc_port_lock(p_ptr->publ.ref);
#else
	struct port *p_ptr = tipc_port_lock(ref);
	struct sk_buff *buf = NULL;
#endif

	if (!p_ptr)
		return;
	
	/* rdm flow-control */
	port_cancel_stopped(p_ptr);

	if (!p_ptr->publ.connected) {
		/* 2011-7-30 增加可靠性防止错误进入反压状态 */
		k_start_timer(&p_ptr->timer, TIPC_PAUSE_MS_LIMIT*3);
		tipc_port_unlock(p_ptr);
		return;
	}

	/* Last probe answered ? */
	if (p_ptr->probing_state == PROBING) {
		buf = port_build_self_abort_msg(p_ptr, TIPC_ERR_NO_PORT);
	} else {
		buf = port_build_proto_msg(port_peerport(p_ptr),
					   port_peernode(p_ptr),
					   p_ptr->publ.ref,
					   tipc_own_addr,
					   CONN_MANAGER,
					   CONN_PROBE,
					   TIPC_OK, 
					   0);
		p_ptr->probing_state = PROBING;
		k_start_timer(&p_ptr->timer, p_ptr->probing_interval);
	}
	tipc_port_unlock(p_ptr);
	tipc_net_route_msg(buf);
}

/* rdm flow-control */
void port_recv_pause(struct port *p_ptr, u32 orignode, u32 origport, u32 type, u32 msec)
{
	struct port_msg_stat *ps;

	if (CONN_MCPAUSE == type)
		ps = &p_ptr->publ.ps;
	else
		ps = tipc_find_ps_recv(&p_ptr->publ, orignode, origport);

	if (unlikely(!ps))
		return; /* no side-effect */

	
	dbg("port_recv_pause: port %p, orignode %u, origport %u, type %u, pause %umsec\n",
		p_ptr->publ.ref, orignode, origport, type, msec);

	/* if unpause */
	if (0 == msec) {
		ps->stat.recv_pause[1]++;
		if (ps->stopped) {
			ps->stopped = 0;
			p_ptr->publ.stopped = 0;
			if (p_ptr->wakeup)
				p_ptr->wakeup(&p_ptr->publ);
		}

		return;
	}

	if (tipc_ratelimit(++ps->stat.recv_pause[0], 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_PORT))
        info("Port %u recv pause from %x:%u  0x%x\n", p_ptr->publ.ref, orignode, origport, ps->stat.recv_pause[0]);
	/* pause 10msec max */
	if (msec > TIPC_PAUSE_MS_LIMIT)
		msec = TIPC_PAUSE_MS_LIMIT;
	ps->stopped = msec;

	/* timer to unpause */
	k_start_timer(&p_ptr->timer, msec);
}

/* rdm flow-control, refer tipc_acknowledge */
void tipc_pause(struct tipc_port *tp_ptr, u32 dnode, u32 dport, u32 mc, u32 msec)
{	
	struct sk_buff *buf = NULL;
	u32 type = CONN_PAUSE;
	if (mc)
		type = CONN_MCPAUSE;
	
	dbg("tipc_do_pause: port %u, dport %u, dnode %u, pause %u msec\n",
		tp_ptr->ref, dport, dnode, msec);
	
	if (dnode == tipc_own_addr) {
		struct port *p_ptr = tipc_port_deref(dport);
		if (!p_ptr)
			return;

		port_recv_pause(p_ptr, dnode, tp_ptr->ref, type, msec);
		
		return;
	}


	/* remote node */
	buf = port_build_proto_msg(dport,
				   dnode,
				   tp_ptr->ref,
				   tipc_own_addr,
				   CONN_MANAGER,
				   type,
				   TIPC_OK, 
				   msec);
	
	tipc_net_route_msg(buf);
}

static void port_handle_node_down(unsigned long ref)
{
	struct port *p_ptr = tipc_port_lock(ref);
	struct sk_buff* buf = NULL;

	if (!p_ptr)
		return;
	buf = port_build_self_abort_msg(p_ptr, TIPC_ERR_NO_NODE);
	tipc_port_unlock(p_ptr);
	tipc_net_route_msg(buf);
}


static struct sk_buff *port_build_self_abort_msg(struct port *p_ptr, u32 err)
{
	u32 imp = msg_importance(&p_ptr->publ.phdr);

	if (!p_ptr->publ.connected)
		return NULL;
	if (imp < TIPC_CRITICAL_IMPORTANCE)
		imp++;
	return port_build_proto_msg(p_ptr->publ.ref,
				    tipc_own_addr,
				    port_peerport(p_ptr),
				    port_peernode(p_ptr),
				    imp,
				    TIPC_CONN_MSG,
				    err, 
				    0);
}


static struct sk_buff *port_build_peer_abort_msg(struct port *p_ptr, u32 err)
{
	u32 imp = msg_importance(&p_ptr->publ.phdr);

	if (!p_ptr->publ.connected)
		return NULL;
	if (imp < TIPC_CRITICAL_IMPORTANCE)
		imp++;
	return port_build_proto_msg(port_peerport(p_ptr),
				    port_peernode(p_ptr),
				    p_ptr->publ.ref,
				    tipc_own_addr,
				    imp,
				    TIPC_CONN_MSG,
				    err, 
				    0);
}

void tipc_port_recv_proto_msg(struct sk_buff *buf)
{
	struct tipc_msg *msg = buf_msg(buf);
	struct port *p_ptr = tipc_port_lock(msg_destport(msg));
	struct sk_buff *r_buf = NULL;
	struct sk_buff *abort_buf = NULL;
	u32 err = TIPC_OK;

	msg_dbg(msg, "PORT<RECV<:");

	if (!p_ptr) {
		err = TIPC_ERR_NO_PORT;
	} else if (p_ptr->publ.connected) {
		if ((port_peernode(p_ptr) != msg_orignode(msg)) ||
		    (port_peerport(p_ptr) != msg_origport(msg))) {
			err = TIPC_ERR_NO_PORT;
		} else if (msg_type(msg) == CONN_ACK) {
			int wakeup = tipc_port_congested(p_ptr) && 
				     p_ptr->publ.congested &&
				     p_ptr->wakeup;
			p_ptr->acked += msg_msgcnt(msg);
			if (tipc_port_congested(p_ptr))
				goto exit;
			p_ptr->publ.congested = 0;
			if (!wakeup)
				goto exit;
			p_ptr->wakeup(&p_ptr->publ);
			goto exit;
		}
	} else if (p_ptr->publ.published) {
		err = TIPC_ERR_NO_PORT;
	}

	/* rdm flow-control */
	if (msg_type(msg) == CONN_PAUSE || msg_type(msg) == CONN_MCPAUSE) {
		/* check p_ptr here! */
		if (p_ptr) {
			port_recv_pause(p_ptr,
				msg_orignode(msg), msg_origport(msg),
				msg_type(msg), msg_msgcnt(msg));
		}
		goto exit;
	}
	
	if (err) {
		r_buf = port_build_proto_msg(msg_origport(msg),
					     msg_orignode(msg),
					     msg_destport(msg),
					     tipc_own_addr,
					     TIPC_HIGH_IMPORTANCE,
					     TIPC_CONN_MSG,
					     err,
					     0);
		goto exit;
	}

	/* All is fine */
	if (msg_type(msg) == CONN_PROBE) {
		r_buf = port_build_proto_msg(msg_origport(msg),
					     msg_orignode(msg),
					     msg_destport(msg),
					     tipc_own_addr,
					     CONN_MANAGER,
					     CONN_PROBE_REPLY,
					     TIPC_OK,
					     0);
	}
	p_ptr->probing_state = CONFIRMED;
exit:
	if (p_ptr)
		tipc_port_unlock(p_ptr);
	tipc_net_route_msg(r_buf);
	tipc_net_route_msg(abort_buf);
	buf_discard(buf);
}

#ifdef CONFIG_TIPC_CONFIG_SERVICE

static void port_print(struct port *p_ptr, struct print_buf *buf, int full_id)
{
	struct publication *publ;

	if (full_id)
		tipc_printf(buf, "<%u.%u.%u:%u>:",
			    tipc_zone(tipc_own_addr), tipc_cluster(tipc_own_addr),
			    tipc_node(tipc_own_addr), p_ptr->publ.ref);
	else
		tipc_printf(buf, "%-10u:", p_ptr->publ.ref);

	if (p_ptr->publ.connected) {
		u32 dport = port_peerport(p_ptr);
		u32 destnode = port_peernode(p_ptr);

		tipc_printf(buf, " connected to <%u.%u.%u:%u>",
			    tipc_zone(destnode), tipc_cluster(destnode),
			    tipc_node(destnode), dport);
		if (p_ptr->publ.conn_type != 0)
			tipc_printf(buf, " via {%u,%u}",
				    p_ptr->publ.conn_type,
				    p_ptr->publ.conn_instance);
	}
	else if (p_ptr->publ.published) {
		tipc_printf(buf, " bound to");
		list_for_each_entry(publ, &p_ptr->publications, pport_list) {
			if (publ->lower == publ->upper)
				tipc_printf(buf, " {0x%x,%u}", publ->type,
					    publ->lower);
			else
				tipc_printf(buf, " {0x%x,%u,%u}", publ->type,
					    publ->lower, publ->upper);
		}
	}
        tipc_printf(buf, "\n");
}

/* enhance info */
static int port_print_ps(struct port_msg_stat *ps, struct print_buf *buf, int tag)
{
    char tmp[32];
    if (!ps) {
        return 0;
    }
    if (!ps->stat.sent && !ps->stat.sent_fail && !ps->stat.sent_congested && !ps->stat.recv) {
        return 0;
    }

	if (ps->node == addr_cluster(tipc_own_addr) && ps->ref == 0)
		sprintf(tmp, "  <%u.%u.0  : multicast>",
			    tipc_zone(tipc_own_addr), tipc_cluster(tipc_own_addr));
	else if (ps->node == 0 && ps->ref == 0)
		sprintf(tmp, "  <0.0.0  :0 rejected>");
	else
		sprintf(tmp, " %c<%u.%u.%-3u:%-10u>", tag ? 'v' : ' ',
			    tipc_zone(ps->node), tipc_cluster(ps->node),
                            tipc_node(ps->node), ps->ref);

	tipc_printf(buf, "%-22s", tmp);
	

	tipc_printf(buf, "%-10u %-10u %-9u %7u/%-7u %u\n",
			ps->stat.sent + ps->stat.sent_fail,
			ps->stat.sent,
			ps->stat.sent_congested,
			ps->stat.recv_pause[0],
			ps->stat.recv_pause[1],
			ps->stat.timout_pause);


    if (ps->stat.recv){
        /* 22 */
        tipc_printf(buf, "  <rxref%u :%-10u>", ps->refcount, ps->ref);
        
		tipc_printf(buf, "%-10u %-10u %-9u %7u/%-7u %u\n",
			ps->stat.recv,
			ps->stat.recv - ps->stat.recv_reject,
			ps->stat.recv_reject,
			ps->stat.sent_pause[0],
			ps->stat.sent_pause[1],
			ps->stat.recv_mcast);
	}

	return 1;
}

static void port_print_psh(struct port_msg_stat_hlist *psh, struct print_buf *buf, u32 destnode, u32 destref)
{
	struct port_msg_stat *ps = NULL;
	u32 k;
    int pr_type = 0;

    for (k=0; k<TIPC_PS_REF_RCD; k++) {
        ps = psh->msg_stat[k];
        if (PS_NEED(ps, destnode, destref)) {
	        pr_type += port_print_ps(ps, buf, k == psh->cur);
        }
    }

    if (pr_type && psh->msg_stat[psh->cur]) {
        ps = psh->msg_stat[psh->cur];
        tipc_printf(buf, 
            "  <%u.%u.%-3u:%-10u> -------- {0x%x,%u,%u} %uth",
            tipc_zone(ps->node), tipc_cluster(ps->node),
            tipc_node(ps->node), ps->ref,
            psh->type, psh->low, psh->upper, psh->accu);
        if (psh->sent_reject)
            tipc_printf(buf, " sentrej %u\n", psh->sent_reject);
        else
            tipc_printf(buf, "\n");
    } else if (psh->sent_reject && !destnode && !destref) {
        tipc_printf(buf, 
            "  <0.0.0  :%-10u> -------- {0x%x,%u,%u} %uth sentrej %u\n", 0,
            psh->type, psh->low, psh->upper, psh->accu, psh->sent_reject);
    } else {
        /* empty */
    }
}

static void port_print_stat(struct port *p_ptr, struct print_buf *buf, int flag, u32 destnode, u32 destref)
{    
	if (!p_ptr->sent && !p_ptr->publ.sent_failed && !p_ptr->publ.recv)
		return;
	if (destnode || destref)
        goto skip_total;

	if (p_ptr->publ.connected) {
		tipc_printf(buf, " sent:%u acked:%u  probe-state:%s interval:%u\n",
				p_ptr->sent, p_ptr->acked,
				p_ptr->probing_state ? "probing" : "confirmed",
				p_ptr->probing_interval);		
	}
	tipc_printf(buf, " sent_total=sent_succs+failed    ,    nowait+retry     ,  rejected mc_rejected\n");
	tipc_printf(buf, " %-10u=%-10u %-10u %10u %-10u %10u %10u\n",
		p_ptr->sent + p_ptr->publ.sent_failed,
		p_ptr->sent,
		p_ptr->publ.sent_failed,
		p_ptr->publ.nowait,
		p_ptr->publ.wait,
		p_ptr->publ.sent_reject,
		p_ptr->publ.sentm_reject);

	
	tipc_printf(buf, " recv_total=recv_succs+failed    ,  rejected+rejected_b,queue_size queue_max\n");
	tipc_printf(buf, " %-10u=%-10u %-10u %10u %-10u %10u %10u\n",
		p_ptr->publ.recv,
		p_ptr->publ.recv - p_ptr->publ.recv_reject - p_ptr->publ.recv_reject_backlog,
		p_ptr->publ.recv_reject + p_ptr->publ.recv_reject_backlog,
		p_ptr->publ.recv_reject,
		p_ptr->publ.recv_reject_backlog,
		p_ptr->publ.sk_que_sz,
		p_ptr->publ.sk_que_max);
	

skip_total:
    tipc_printf(buf, "  <Z.C.nod:reference >sent_total sent-succs,retry    ,rxpause/unpause timeout\n");
    tipc_printf(buf, "  <rxref  :reference >recv_total recv-succs+rejected ,txpause/unpause,recv-mcast\n");

    if (PS_NEED(&p_ptr->publ.ps, destnode, destref)) {
        (void)port_print_ps(&p_ptr->publ.ps, buf, 0);
    }

	if (p_ptr->publ.hps) {
		struct hlist_head *ps_head;
		struct hlist_node *ps_node;
		struct port_msg_stat *ps = NULL;
		u32 i;
		struct port_msg_stat_hlist *psh;
		
		for (i=0; i<TIPC_PS_HASH_SZ; i++) {
			ps_head = &p_ptr->publ.hpsh[i];
			
			tipc_hlist_for_each_entry(psh, ps_node, ps_head, psh_list) {
                port_print_psh(psh, buf, destnode, destref);
			}
		}

		for (i=0; i<TIPC_PS_HASH_SZ; i++) {
			ps_head = &p_ptr->publ.hps[i];
			
			tipc_hlist_for_each_entry(ps, ps_node, ps_head, ps_list) {
				if (!ps->refcount && PS_NEED(ps, destnode, destref)) {
					port_print_ps(ps, buf, 0);
				}
			}
		}
	}
}

#define MAX_PORT_QUERY TIPC_MAX_TLV_SPACE

struct sk_buff *tipc_port_get_ports(void)
{
	struct sk_buff *buf;
	struct tlv_desc *rep_tlv;
	struct print_buf pb;
	struct port *p_ptr;
	int str_len;

	buf = tipc_cfg_reply_alloc(TLV_SPACE(MAX_PORT_QUERY));
	if (!buf)
		return NULL;
	rep_tlv = (struct tlv_desc *)buf->data;

	tipc_printbuf_init(&pb, TLV_DATA(rep_tlv), MAX_PORT_QUERY);
	spin_lock_bh(&tipc_port_list_lock);
	list_for_each_entry(p_ptr, &ports, port_list) {
		spin_lock_bh(p_ptr->publ.lock);
		port_print(p_ptr, &pb, 0);
		spin_unlock_bh(p_ptr->publ.lock);
	}
	spin_unlock_bh(&tipc_port_list_lock);
	str_len = tipc_printbuf_validate(&pb);

	skb_put(buf, TLV_SPACE(str_len));
	TLV_SET(rep_tlv, TIPC_TLV_ULTRA_STRING, NULL, str_len);

	return buf;
}

#if 1 /* */

#define MAX_PORT_STATS TIPC_MAX_TLV_SPACE

struct sk_buff *port_show_stats(const void *req_tlv_area, int req_tlv_space)
{
	u32 ref;
	struct port *p_ptr = NULL; /* */
	struct sk_buff *buf;
	struct tlv_desc *rep_tlv;
	struct print_buf pb;
	int str_len;
    const void *tlv = req_tlv_area;
    int tlv_len = req_tlv_space;
	u32 destnode = 0;
    u32 destref = 0;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_PORT_REF))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);


	ref = *(u32 *)TLV_DATA(req_tlv_area);
	ref = ntohl(ref);
    tlv += TLV_SPACE(sizeof(u32));
    tlv_len -= TLV_SPACE(sizeof(u32));
    if (tlv_len > 0 && TLV_CHECK(tlv, tlv_len, TIPC_TLV_NET_ADDR)) {
        destnode = *(u32 *)TLV_DATA(tlv);
        destnode = ntohl(destnode);
        tlv += TLV_SPACE(sizeof(u32));
        tlv_len -= TLV_SPACE(sizeof(u32));
        if (tlv_len > 0 && TLV_CHECK(tlv, tlv_len, TIPC_TLV_PORT_REF)) {
            destref = *(u32 *)TLV_DATA(tlv);
            destref = ntohl(destref);
        }
    }

	/* 0 means show all port's stat*/
	if (ref > 0) { 
		p_ptr = tipc_port_lock(ref);
		if (!p_ptr)
			return tipc_cfg_reply_error_string("port not found");
	}
	
	buf = tipc_cfg_reply_alloc(TLV_SPACE(MAX_PORT_STATS));
	if (!buf) {
		if (p_ptr)
			tipc_port_unlock(p_ptr);
		return NULL;
	}
	rep_tlv = (struct tlv_desc *)buf->data;

	tipc_printbuf_init(&pb, TLV_DATA(rep_tlv), MAX_PORT_STATS);
	/* */
	if (p_ptr) { 
		port_print(p_ptr, &pb, 1);
		/* NEED TO FILL IN ADDITIONAL PORT STATISTICS HERE */
		port_print_stat(p_ptr, &pb, 1, destnode, destref);
		tipc_port_unlock(p_ptr);
	} else {
		spin_lock_bh(&tipc_port_list_lock);
		list_for_each_entry(p_ptr, &ports, port_list) {
			spin_lock_bh(p_ptr->publ.lock);
			port_print(p_ptr, &pb, 1);
			port_print_stat(p_ptr, &pb, 1, destnode, destref);
			spin_unlock_bh(p_ptr->publ.lock);
		}
		spin_unlock_bh(&tipc_port_list_lock);
	}

	str_len = tipc_printbuf_validate(&pb);

	skb_put(buf, TLV_SPACE(str_len));
	TLV_SET(rep_tlv, TIPC_TLV_ULTRA_STRING, NULL, str_len);

	return buf;
}

/* */
struct sk_buff *port_reset_stats(const void *req_tlv_area, int req_tlv_space)
{
	u32 ref;
	struct port *p_ptr;
	struct port_msg_stat *ps;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_PORT_REF))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	ref = *(u32 *)TLV_DATA(req_tlv_area);
	ref = ntohl(ref);

	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return tipc_cfg_reply_error_string("port not found");

	ps = &p_ptr->publ.ps;
	memset(&ps->stat, 0, sizeof(ps->stat));

	if (p_ptr->publ.hps) {
		struct hlist_head *ps_head;
		struct hlist_node *ps_node;
		u32 i;
		
		for (i=0; i<TIPC_PS_HASH_SZ; i++) {
			ps_head = &p_ptr->publ.hps[i];
			
			tipc_hlist_for_each_entry(ps, ps_node, ps_head, ps_list) {
				memset(&ps->stat, 0, sizeof(ps->stat));
			}
		}
	}
	p_ptr->publ.sk_que_max = 0;
	tipc_port_unlock(p_ptr);

	return tipc_cfg_reply_none();;
}


#endif

#endif

void tipc_port_reinit(void)
{
	struct port *p_ptr;
	struct tipc_msg *msg;

	spin_lock_bh(&tipc_port_list_lock);
	list_for_each_entry(p_ptr, &ports, port_list) {
		msg = &p_ptr->publ.phdr;
		spin_lock_bh(p_ptr->publ.lock);
		msg_set_prevnode(msg, tipc_own_addr);
		msg_set_orignode(msg, tipc_own_addr);
		msg_set_destnode(msg, tipc_own_addr);
		spin_unlock_bh(p_ptr->publ.lock);
	}
	spin_unlock_bh(&tipc_port_list_lock);
}


/*
 *  port_dispatcher_sigh(): Signal handler for messages destinated
 *                          to the tipc_port interface.
 */

static void port_dispatcher_sigh(void *dummy)
{
	struct sk_buff *buf;

	spin_lock_bh(&queue_lock);
	buf = msg_queue_head;
	msg_queue_head = NULL;
	spin_unlock_bh(&queue_lock);

	while (buf) {
		struct port *p_ptr;
		struct user_port *up_ptr;
		struct tipc_portid orig;
		struct tipc_name_seq dseq;
		void *usr_handle;
		int connected;
		int published;
		u32 message_type;

		struct sk_buff *next = buf->next;
		struct tipc_msg *msg = buf_msg(buf);
		u32 dref = msg_destport(msg);

		message_type = msg_type(msg);
		if (message_type > TIPC_DIRECT_MSG)
			goto reject;	/* Unsupported message type */

		p_ptr = tipc_port_lock(dref);
		if (!p_ptr)
			goto reject;	/* Port deleted while msg in queue */

		orig.ref = msg_origport(msg);
		orig.node = msg_orignode(msg);
		up_ptr = p_ptr->user_port;
		usr_handle = up_ptr->usr_handle;
		connected = p_ptr->publ.connected;
		published = p_ptr->publ.published;

		if (unlikely(msg_errcode(msg)))
			goto err;

		switch (message_type) {

		case TIPC_CONN_MSG:{
				tipc_conn_msg_event cb = up_ptr->conn_msg_cb;
				u32 peer_port = port_peerport(p_ptr);
				u32 peer_node = port_peernode(p_ptr);

				tipc_port_unlock(p_ptr);
				if (unlikely(!cb))
					goto reject;
				if (unlikely(!connected)) {
					if (tipc_connect2port(dref, &orig))
						goto reject;
				} else if ((msg_origport(msg) != peer_port) ||
					   (msg_orignode(msg) != peer_node))
					goto reject;
				/* TODO: Don't access conn_unacked field
					 while port is unlocked ... */
				if (unlikely(++p_ptr->publ.conn_unacked >=
					     TIPC_FLOW_CONTROL_WIN))
					tipc_acknowledge(dref,
							 p_ptr->publ.conn_unacked);
				skb_pull(buf, msg_hdr_sz(msg));
				cb(usr_handle, dref, &buf, msg_data(msg),
				   msg_data_sz(msg));
				break;
			}
		case TIPC_DIRECT_MSG:{
				tipc_msg_event cb = up_ptr->msg_cb;

				tipc_port_unlock(p_ptr);
				if (unlikely(!cb || connected))
					goto reject;
				skb_pull(buf, msg_hdr_sz(msg));
				cb(usr_handle, dref, &buf, msg_data(msg),
				   msg_data_sz(msg), msg_importance(msg),
				   &orig);
				break;
			}
		case TIPC_MCAST_MSG:
		case TIPC_NAMED_MSG:{
				tipc_named_msg_event cb = up_ptr->named_msg_cb;

				tipc_port_unlock(p_ptr);
				if (unlikely(!cb || connected || !published))
					goto reject;
				dseq.type =  msg_nametype(msg);
				dseq.lower = msg_nameinst(msg);
				dseq.upper = (message_type == TIPC_NAMED_MSG)
					? dseq.lower : msg_nameupper(msg);
				skb_pull(buf, msg_hdr_sz(msg));
				cb(usr_handle, dref, &buf, msg_data(msg),
				   msg_data_sz(msg), msg_importance(msg),
				   &orig, &dseq);
				break;
			}
		}
		if (buf)
			buf_discard(buf);
		buf = next;
		continue;
err:
		switch (message_type) {

		case TIPC_CONN_MSG:{
				tipc_conn_shutdown_event cb =
					up_ptr->conn_err_cb;
				u32 peer_port = port_peerport(p_ptr);
				u32 peer_node = port_peernode(p_ptr);

				tipc_port_unlock(p_ptr);
				if (!cb || !connected)
					break;
				if ((msg_origport(msg) != peer_port) ||
				    (msg_orignode(msg) != peer_node))
					break;
				tipc_disconnect(dref);
				skb_pull(buf, msg_hdr_sz(msg));
				cb(usr_handle, dref, &buf, msg_data(msg),
				   msg_data_sz(msg), msg_errcode(msg));
				break;
			}
		case TIPC_DIRECT_MSG:{
				tipc_msg_err_event cb = up_ptr->err_cb;

				tipc_port_unlock(p_ptr);
				if (!cb || connected)
					break;
				skb_pull(buf, msg_hdr_sz(msg));
				cb(usr_handle, dref, &buf, msg_data(msg),
				   msg_data_sz(msg), msg_errcode(msg), &orig);
				break;
			}
		case TIPC_MCAST_MSG:
		case TIPC_NAMED_MSG:{
				tipc_named_msg_err_event cb =
					up_ptr->named_err_cb;

				tipc_port_unlock(p_ptr);
				if (!cb || connected)
					break;
				dseq.type =  msg_nametype(msg);
				dseq.lower = msg_nameinst(msg);
				dseq.upper = (message_type == TIPC_NAMED_MSG)
					? dseq.lower : msg_nameupper(msg);
				skb_pull(buf, msg_hdr_sz(msg));
				cb(usr_handle, dref, &buf, msg_data(msg),
				   msg_data_sz(msg), msg_errcode(msg), &dseq);
				break;
			}
		}
		if (buf)
			buf_discard(buf);
		buf = next;
		continue;
reject:
		tipc_reject_msg(buf, TIPC_ERR_NO_PORT);
		buf = next;
	}
}

/*
 *  port_dispatcher(): Dispatcher for messages destinated
 *  to the tipc_port interface. Called with port locked.
 */

static u32 port_dispatcher(struct tipc_port *dummy, struct sk_buff *buf)
{
	buf->next = NULL;
	spin_lock_bh(&queue_lock);
	if (msg_queue_head) {
		msg_queue_tail->next = buf;
		msg_queue_tail = buf;
	} else {
		msg_queue_tail = msg_queue_head = buf;
		tipc_k_signal((Handler)port_dispatcher_sigh, 0);
	}
	spin_unlock_bh(&queue_lock);
	return 0;
}

/*
 * Wake up port after congestion: Called with port locked,
 *
 */

static void port_wakeup_sh(unsigned long ref)
{
	struct port *p_ptr;
	struct user_port *up_ptr;
	tipc_continue_event cb = NULL;
	void *uh = NULL;

	p_ptr = tipc_port_lock(ref);
	if (p_ptr) {
		up_ptr = p_ptr->user_port;
		if (up_ptr) {
			cb = up_ptr->continue_event_cb;
			uh = up_ptr->usr_handle;
		}
		tipc_port_unlock(p_ptr);
	}
	if (cb)
		cb(uh, ref);
}


static void port_wakeup(struct tipc_port *p_ptr)
{
	tipc_k_signal((Handler)port_wakeup_sh, p_ptr->ref);
}

void tipc_acknowledge(u32 ref, u32 ack)
{
	struct port *p_ptr;
	struct sk_buff *buf = NULL;

	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return;
	if (p_ptr->publ.connected) {
		p_ptr->publ.conn_unacked -= ack;
		buf = port_build_proto_msg(port_peerport(p_ptr),
					   port_peernode(p_ptr),
					   ref,
					   tipc_own_addr,
					   CONN_MANAGER,
					   CONN_ACK,
					   TIPC_OK, 
					   ack);
	}
	tipc_port_unlock(p_ptr);
	tipc_net_route_msg(buf);
}

/*
 * tipc_createport(): user level call. Will add port to
 *                    registry if non-zero user_ref.
 */

int tipc_createport(u32 user_ref,
		    void *usr_handle,
		    unsigned int importance,
		    tipc_msg_err_event error_cb,
		    tipc_named_msg_err_event named_error_cb,
		    tipc_conn_shutdown_event conn_error_cb,
		    tipc_msg_event msg_cb,
		    tipc_named_msg_event named_msg_cb,
		    tipc_conn_msg_event conn_msg_cb,
		    tipc_continue_event continue_event_cb,/* May be zero */
		    u32 *portref)
{
	struct user_port *up_ptr;
	struct port *p_ptr;

	up_ptr = kmalloc(sizeof(*up_ptr), GFP_ATOMIC);
	if (!up_ptr) {
		warn("Port creation failed, no memory\n");
		return -ENOMEM;
	}
	p_ptr = (struct port *)tipc_createport_raw(NULL, port_dispatcher,
						   port_wakeup, importance);
	if (!p_ptr) {
		kfree(up_ptr);
		return -ENOMEM;
	}

	p_ptr->user_port = up_ptr;
	up_ptr->user_ref = user_ref;
	up_ptr->usr_handle = usr_handle;
	up_ptr->ref = p_ptr->publ.ref;
	up_ptr->err_cb = error_cb;
	up_ptr->named_err_cb = named_error_cb;
	up_ptr->conn_err_cb = conn_error_cb;
	up_ptr->msg_cb = msg_cb;
	up_ptr->named_msg_cb = named_msg_cb;
	up_ptr->conn_msg_cb = conn_msg_cb;
	up_ptr->continue_event_cb = continue_event_cb;
	INIT_LIST_HEAD(&up_ptr->uport_list);
	tipc_reg_add_port(up_ptr);
	*portref = p_ptr->publ.ref;
	tipc_port_unlock(p_ptr);
	return 0;
}

int tipc_ownidentity(u32 ref, struct tipc_portid *id)
{
	id->ref = ref;
	id->node = tipc_own_addr;
	return 0;
}

int tipc_portimportance(u32 ref, unsigned int *importance)
{
	struct port *p_ptr;

	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return -EINVAL;
	*importance = (unsigned int)msg_importance(&p_ptr->publ.phdr);
	tipc_port_unlock(p_ptr);
	return 0;
}

int tipc_set_portimportance(u32 ref, unsigned int imp)
{
	struct port *p_ptr;

	if (imp > TIPC_CRITICAL_IMPORTANCE)
		return -EINVAL;

	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return -EINVAL;
	msg_set_importance(&p_ptr->publ.phdr, (u32)imp);
	tipc_port_unlock(p_ptr);
	return 0;
}


int tipc_publish(u32 ref, unsigned int scope, struct tipc_name_seq const *seq)
{
	struct port *p_ptr;
	struct publication *publ;
	u32 key;
	int res = -EINVAL;

	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return -EINVAL;
	if (p_ptr->publ.connected)
		goto exit;
	if (seq->lower > seq->upper)
		goto exit;
	if ((scope < TIPC_ZONE_SCOPE) || (scope > TIPC_NODE_SCOPE))
		goto exit;
	key = ref + p_ptr->pub_count + 1;
	if (key == ref) {
		res = -EADDRINUSE;
		goto exit;
	}
	publ = tipc_nametbl_publish(seq->type, seq->lower, seq->upper,
				    scope, p_ptr->publ.ref, key);
	if (publ) {
		list_add(&publ->pport_list, &p_ptr->publications);
		p_ptr->pub_count++;
		p_ptr->publ.published = 1;
		res = 0;
	}
	info("Port %u bound to {0x%x,%u,%u}\n", ref, seq->type, seq->lower, seq->upper);
exit:
	tipc_port_unlock(p_ptr);
	return res;
}

int tipc_withdraw(u32 ref, unsigned int scope, struct tipc_name_seq const *seq)
{
	struct port *p_ptr;
	struct publication *publ;
	struct publication *tpubl;
	int res = -EINVAL;

	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return -EINVAL;
	if (!seq) {
		list_for_each_entry_safe(publ, tpubl,
					 &p_ptr->publications, pport_list) {
			tipc_nametbl_withdraw(publ->type, publ->lower,
					      publ->ref, publ->key);
			res = 0; /* has bound */
		}
		if (0 == res)
			info("Port %u unbound all. %s %s\n", ref,
				p_ptr->publ.congested ? "congested" : "",
				p_ptr->publ.ps.stopped ? "mc congested" : "");
		res = 0;
	} else {
		list_for_each_entry_safe(publ, tpubl,
					 &p_ptr->publications, pport_list) {
			if (publ->scope != scope)
				continue;
			if (publ->type != seq->type)
				continue;
			if (publ->lower != seq->lower)
				continue;
			if (publ->upper != seq->upper)
				break;
			tipc_nametbl_withdraw(publ->type, publ->lower,
					      publ->ref, publ->key);
			res = 0;
			info("Port %u unbound {0x%x,%u,%u}\n", ref, seq->type, seq->lower, seq->upper);
			break;
		}
	}
	if (list_empty(&p_ptr->publications))
		p_ptr->publ.published = 0;
	tipc_port_unlock(p_ptr);
	return res;
}

int tipc_connect2port(u32 ref, struct tipc_portid const *peer)
{
	struct port *p_ptr;
	struct tipc_msg *msg;
	int res = -EINVAL;

	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return -EINVAL;
	if (p_ptr->publ.published || p_ptr->publ.connected)
		goto exit;
	if (!peer->ref)
		goto exit;

	msg = &p_ptr->publ.phdr;
	msg_set_destnode(msg, peer->node);
	msg_set_destport(msg, peer->ref);
	msg_set_orignode(msg, tipc_own_addr);
	msg_set_origport(msg, p_ptr->publ.ref);
	msg_set_type(msg, TIPC_CONN_MSG);
	if (!may_route(peer->node))
		msg_set_hdr_sz(msg, SHORT_H_SIZE);
	else
		msg_set_hdr_sz(msg, LONG_H_SIZE);

	p_ptr->probing_interval = PROBING_INTERVAL;
	p_ptr->probing_state = CONFIRMED;
	p_ptr->publ.connected = 1;
	p_ptr->publ.ps.node = peer->node; /* */
	p_ptr->publ.ps.ref  = peer->ref;  /* */
	k_start_timer(&p_ptr->timer, p_ptr->probing_interval);

	if (!addr_in_node(peer->node))
		tipc_netsub_bind(&p_ptr->subscription, peer->node,
				 (net_ev_handler)port_handle_node_down,
				 (void *)(unsigned long)ref);
	res = 0;
exit:
	tipc_port_unlock(p_ptr);
	p_ptr->publ.max_pkt = tipc_link_get_max_pkt(peer->node, ref);
	return res;
}

/**
 * tipc_disconnect_port - disconnect port from peer
 *
 * Port must be locked.
 */

int tipc_disconnect_port(struct tipc_port *tp_ptr)
{
	int res;

	if (tp_ptr->connected) {
		tp_ptr->connected = 0;
		tp_ptr->ps.node = 0; /* */
		tp_ptr->ps.ref  = 0;  /* */
		
		/* let timer expire on it's own to avoid deadlock! */
		tipc_netsub_unbind(&((struct port *)tp_ptr)->subscription);
		res = 0;
	} else {
		res = -ENOTCONN;
	}
	return res;
}

/*
 * tipc_disconnect(): Disconnect port from peer.
 *                    This is a node local operation.
 */

int tipc_disconnect(u32 ref)
{
	struct port *p_ptr;
	int res;

	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return -EINVAL;
	res = tipc_disconnect_port((struct tipc_port *)p_ptr);
	tipc_port_unlock(p_ptr);
	return res;
}

/*
 * tipc_shutdown(): Send a SHUTDOWN msg to peer and disconnect
 */
int tipc_shutdown(u32 ref)
{
	struct port *p_ptr;
	struct sk_buff *buf = NULL;

	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return -EINVAL;

	if (p_ptr->publ.connected) {
		u32 imp = msg_importance(&p_ptr->publ.phdr);
		if (imp < TIPC_CRITICAL_IMPORTANCE)
			imp++;
		buf = port_build_proto_msg(port_peerport(p_ptr),
					   port_peernode(p_ptr),
					   ref,
					   tipc_own_addr,
					   imp,
					   TIPC_CONN_MSG,
					   TIPC_CONN_SHUTDOWN, 
					   0);
	}
	tipc_port_unlock(p_ptr);
	tipc_net_route_msg(buf);
	return tipc_disconnect(ref);
}

int tipc_isconnected(u32 ref, int *isconnected)
{
	struct port *p_ptr;

	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return -EINVAL;
	*isconnected = p_ptr->publ.connected;
	tipc_port_unlock(p_ptr);
	return 0;
}

int tipc_peer(u32 ref, struct tipc_portid *peer)
{
	struct port *p_ptr;
	int res;

	p_ptr = tipc_port_lock(ref);
	if (!p_ptr)
		return -EINVAL;
	if (p_ptr->publ.connected) {
		peer->ref = port_peerport(p_ptr);
		peer->node = port_peernode(p_ptr);
		res = 0;
	} else
		res = -ENOTCONN;
	tipc_port_unlock(p_ptr);
	return res;
}

int tipc_ref_valid(u32 ref)
{
	/* Works irrespective of type */
	return !!tipc_ref_deref(ref);
}

static inline int port_msg_from_peer(struct port *p_ptr, struct tipc_msg *msg)
{
	u32 peernode;
	u32 orignode;

	if (!msg_connected(msg) ||
	    (msg_origport(msg) != tipc_peer_port(p_ptr)))
		return 0;

	orignode = msg_orignode(msg);
	peernode = tipc_peer_node(p_ptr);
	return (orignode == peernode) ||
		(!orignode && (peernode == tipc_own_addr)) ||
		(!peernode && (orignode == tipc_own_addr));
}

/** 
 * tipc_port_recv_msg - receive message from lower layer and deliver to port user
 */
int tipc_port_recv_msg(struct sk_buff *buf)
{
    struct port *p_ptr;
    struct tipc_msg *msg = buf_msg(buf);
    u32 destport = msg_destport(msg);
    u32 dsz = msg_data_sz(msg);
    u32 err;

    /* forward unresolved named message */
    if (unlikely(destport == 0)) {
        tipc_net_route_msg(buf);
        return dsz;
    }

    /* validate destination & pass to port, otherwise reject message */
    p_ptr = tipc_port_lock(destport);
    if (likely(p_ptr)) {
        p_ptr->publ.recv++; /* */
        if (likely(p_ptr->publ.connected)) {
            if (unlikely(!port_msg_from_peer(p_ptr, msg))) {
                err = TIPC_ERR_NO_PORT;
                tipc_port_unlock(p_ptr);
                goto reject;
            }
        }
        #ifdef CONFIG_TIPC_PORT_STATISTICS
        tipc_port_msg_stats(buf, p_ptr, TIPC_PORT_RCVMSG);/* 报文统计 */
        #endif
        err = p_ptr->dispatcher(&p_ptr->publ, buf);
        /* */
        if (unlikely(err)) {      
            p_ptr->publ.recv_reject++;
            tipc_port_unlock(p_ptr);
            goto reject;
        } else {
            tipc_port_unlock(p_ptr);
            return dsz;
        }
    } else {
        err = TIPC_ERR_NO_PORT;
    }
reject:
    dbg("port->rejecting, err = %x..\n",err);
    return tipc_reject_msg(buf, err);
}

/*
 *  tipc_port_recv_sections(): Concatenate and deliver sectioned
 *                        message for this node.
 */

int tipc_port_recv_sections(struct port *sender, unsigned int num_sect,
                                      struct iovec const *msg_sect)
{
    struct sk_buff *buf;
    int res;

    res = tipc_msg_build(&sender->publ.phdr, msg_sect, num_sect,
                         MAX_MSG_SIZE, !sender->user_port, &buf);
    if (likely(buf))
    {
        #ifdef CONFIG_TIPC_PORT_STATISTICS
        tipc_port_msg_stats(buf, sender, TIPC_PORT_SNDMSG);
        #endif
        tipc_port_recv_msg(buf);
    }
    return res;
}

/**
 * tipc_send - send message sections on connection
 */

int tipc_send(u32 ref, unsigned int num_sect, struct iovec const *msg_sect)
{
	struct port *p_ptr;
	u32 destnode;
	int res;

	p_ptr = tipc_port_deref(ref);
	if (!p_ptr || !p_ptr->publ.connected)
		return -EINVAL;
	/* */
	res = port_ps0_sent(p_ptr);
	if (unlikely(res))
		return res;

	p_ptr->publ.congested = 1;
	if (!tipc_port_congested(p_ptr)) {
		destnode = port_peernode(p_ptr);
		if (!addr_in_node(destnode))
			res = tipc_link_send_sections_fast(p_ptr, msg_sect,
							   num_sect, destnode);
		else
			res = tipc_port_recv_sections(p_ptr, num_sect,
						      msg_sect);

		if (likely(res != -ELINKCONG)) {
			p_ptr->publ.congested = 0;
    		port_ps0_sent_res(p_ptr, res); /* */
			return res;
		}
	}
	port_ps0_sent_congested(p_ptr); /* */
	if (port_unreliable(p_ptr)) {
		p_ptr->publ.congested = 0;
		/* Just calculate msg length and return */
		return tipc_msg_calc_data_size(msg_sect, num_sect);
	}
	return -ELINKCONG;
}

/**
 * tipc_send_buf - send message buffer on connection
 */

int tipc_send_buf(u32 ref, struct sk_buff *buf, unsigned int dsz)
{
	struct port *p_ptr;
	struct tipc_msg *msg;
	u32 destnode;
	u32 hsz;
	u32 sz;
	u32 res;

	p_ptr = tipc_port_deref(ref);
	if (!p_ptr || !p_ptr->publ.connected)
		return -EINVAL;
	/* */
	res = port_ps0_sent(p_ptr);
	if (unlikely(res))
		return res;

	msg = &p_ptr->publ.phdr;
	hsz = msg_hdr_sz(msg);
	sz = hsz + dsz;
	msg_set_size(msg, sz);
	if (skb_cow(buf, hsz))
		return -ENOMEM;

	skb_push(buf, hsz);
	skb_copy_to_linear_data(buf, msg, hsz);
	buf->priority = p_ptr->publ.sk_priority; /* tipc_priority */

	p_ptr->publ.congested = 1;
	if (!tipc_port_congested(p_ptr)) {
		destnode = port_peernode(p_ptr);
		if (!addr_in_node(destnode))
			res = tipc_send_buf_fast(buf, destnode);
		else {
			tipc_port_recv_msg(buf);
			res = sz;
		}

		if (likely(res != -ELINKCONG)) {
			p_ptr->publ.congested = 0;
    		port_ps0_sent_res(p_ptr, res); /* */
			return res;
		}
	}
	port_ps0_sent_congested(p_ptr); /* */
	if (port_unreliable(p_ptr)) {
		p_ptr->publ.congested = 0;
		return dsz;
	}
	return -ELINKCONG;
}

/**
 * tipc_forward2name - forward message sections to port name
 */

int tipc_forward2name(u32 ref,
                      struct tipc_name const *name,
                      u32 domain,
                      u32 num_sect,
                      struct iovec const *msg_sect,
                      struct tipc_portid const *orig,
                      unsigned int importance)
{
    struct port *p_ptr;
    struct tipc_msg *msg;
    u32 destnode = domain;
    u32 destport;
    int res;

    p_ptr = tipc_port_deref(ref);
    if (!p_ptr || p_ptr->publ.connected)
        return -EINVAL;

    destport = tipc_nametbl_translate(name->type, name->instance, &destnode);
    /* */
    res = port_ps_sent(p_ptr, name->type, name->instance, destnode, destport);
    if (unlikely(res))
        return res;

    msg = &p_ptr->publ.phdr;
    msg_set_hdr_sz(msg, LONG_H_SIZE);
    port_set_msg_importance(msg, importance);
    msg_set_type(msg, TIPC_NAMED_MSG);
    msg_set_nametype(msg, name->type);
    msg_set_nameinst(msg, name->instance);
    msg_set_lookup_scope(msg, addr_scope(domain));
    msg_set_orignode(msg, orig->node);
    msg_set_origport(msg, orig->ref);
    msg_set_destnode(msg, destnode);
    msg_set_destport(msg, destport);

    if (likely(destport || destnode)) {
        if (addr_in_node(destnode)) {
            res = tipc_port_recv_sections(p_ptr, num_sect, msg_sect);
        } else {
            if (!orig->node)
                msg_set_orignode(msg, tipc_own_addr);
            res = tipc_link_send_sections_fast(p_ptr, msg_sect, num_sect, destnode);
        }
        if (likely(res != -ELINKCONG)) {
            port_ps_sent_res(p_ptr, res); /* */
            return res;
        }
        port_ps_sent_congested(p_ptr); /* */
        if (port_unreliable(p_ptr)) {
            /* Just calculate msg length and return */
            return tipc_msg_calc_data_size(msg_sect, num_sect);
        }
        return -ELINKCONG;
    }
    return tipc_port_reject_sections(p_ptr, msg, msg_sect, num_sect, TIPC_ERR_NO_NAME);
}

/**
 * tipc_send2name - send message sections to port name
 */

int tipc_send2name(u32 ref,
                            struct tipc_name const *name,
                            unsigned int domain,
                            unsigned int num_sect,
                            struct iovec const *msg_sect)
{
    struct tipc_portid orig;

    orig.ref = ref;
    orig.node = tipc_own_addr;
    return tipc_forward2name(ref, name, domain, num_sect, msg_sect, &orig,
                             TIPC_PORT_IMPORTANCE);
}

/**
 * tipc_forward_buf2name - forward message buffer to port name
 */

int tipc_forward_buf2name(u32 ref,
			  struct tipc_name const *name,
			  u32 domain,
			  struct sk_buff *buf,
			  unsigned int dsz,
			  struct tipc_portid const *orig,
			  unsigned int importance)
{
	struct port *p_ptr;
	struct tipc_msg *msg;
	u32 destnode = domain;
	u32 destport;
	int res;

	p_ptr = (struct port *)tipc_ref_deref(ref);
	if (!p_ptr || p_ptr->publ.connected)
		return -EINVAL;

	if (skb_cow(buf, LONG_H_SIZE))
		return -ENOMEM;

	destport = tipc_nametbl_translate(name->type, name->instance,
					  &destnode);
	/* */
	res = port_ps_sent(p_ptr, name->type, name->instance, destnode, destport);
	if (unlikely(res))
		return res;
	
	msg = &p_ptr->publ.phdr;
	msg_set_hdr_sz(msg, LONG_H_SIZE);
	msg_set_size(msg, LONG_H_SIZE + dsz);
	port_set_msg_importance(msg, importance);
	msg_set_type(msg, TIPC_NAMED_MSG);
	msg_set_nametype(msg, name->type);
	msg_set_nameinst(msg, name->instance);
	msg_set_lookup_scope(msg, addr_scope(domain));
	msg_set_orignode(msg, orig->node);
	msg_set_origport(msg, orig->ref);
	msg_set_destnode(msg, destnode);
	msg_set_destport(msg, destport);

	skb_push(buf, LONG_H_SIZE);
	skb_copy_to_linear_data(buf, msg, LONG_H_SIZE);
	buf->priority = p_ptr->publ.sk_priority; /* tipc_priority */
	if (likely(destport || destnode)) {
		if (addr_in_node(destnode)) {
			res = tipc_port_recv_msg(buf);
		} else {
            if (!orig->node)
			    msg_set_orignode(msg, tipc_own_addr);
		    res = tipc_send_buf_fast(buf, destnode);
		}
		if (likely(res != -ELINKCONG)) {
    		port_ps_sent_res(p_ptr, res); /* */
			return res;
		}
		port_ps_sent_congested(p_ptr); /* */
		if (port_unreliable(p_ptr))
			return dsz;
		return -ELINKCONG;
	}
	p_ptr->publ.sent_reject++; /* */
	return tipc_reject_msg(buf, TIPC_ERR_NO_NAME);
}

/**
 * tipc_send_buf2name - send message buffer to port name
 */

int tipc_send_buf2name(u32 ref,
		       struct tipc_name const *dest,
		       u32 domain,
		       struct sk_buff *buf,
		       unsigned int dsz)
{
	struct tipc_portid orig;

	orig.ref = ref;
	orig.node = tipc_own_addr;
	return tipc_forward_buf2name(ref, dest, domain, buf, dsz, &orig,
				     TIPC_PORT_IMPORTANCE);
}

/**
 * tipc_forward2port - forward message sections to port identity
 */

int tipc_forward2port(u32 ref,
		      struct tipc_portid const *dest,
		      unsigned int num_sect,
		      struct iovec const *msg_sect,
		      struct tipc_portid const *orig,
		      unsigned int importance)
{
	struct port *p_ptr;
	struct tipc_msg *msg;
	int res;

	p_ptr = tipc_port_deref(ref);
	if (!p_ptr || p_ptr->publ.connected)
		return -EINVAL;
	/* */
	res = port_ps_sent(p_ptr, 0, 0, dest->node, dest->ref);
	if (unlikely(res))
		return res;
	
	msg = &p_ptr->publ.phdr;
	msg_set_hdr_sz(msg, DIR_MSG_H_SIZE);
	port_set_msg_importance(msg, importance);
	msg_set_type(msg, TIPC_DIRECT_MSG);
	msg_set_orignode(msg, orig->node);
	msg_set_origport(msg, orig->ref);
	msg_set_destnode(msg, dest->node);
	msg_set_destport(msg, dest->ref);

	if (addr_in_node(dest->node)) {
		res = tipc_port_recv_sections(p_ptr, num_sect, msg_sect);
	} else {
        if (!orig->node)
		    msg_set_orignode(msg, tipc_own_addr);
    	res = tipc_link_send_sections_fast(p_ptr, msg_sect, num_sect,
					   dest->node);
	}
	if (likely(res != -ELINKCONG)) {
    	port_ps_sent_res(p_ptr, res); /* */
		return res;
	}
	port_ps_sent_congested(p_ptr); /* */
	if (port_unreliable(p_ptr)) {
		/* Just calculate msg length and return */
		return tipc_msg_calc_data_size(msg_sect, num_sect);
	}
	return -ELINKCONG;
}

/**
 * tipc_send2port - send message sections to port identity
 */

int tipc_send2port(u32 ref,
		   struct tipc_portid const *dest,
		   unsigned int num_sect,
		   struct iovec const *msg_sect)
{
	struct tipc_portid orig;

	orig.ref = ref;
	orig.node = tipc_own_addr;
	return tipc_forward2port(ref, dest, num_sect, msg_sect, &orig,
				 TIPC_PORT_IMPORTANCE);
}

/**
 * tipc_forward_buf2port - forward message buffer to port identity
 */
int tipc_forward_buf2port(u32 ref,
			  struct tipc_portid const *dest,
			  struct sk_buff *buf,
			  unsigned int dsz,
			  struct tipc_portid const *orig,
			  unsigned int importance)
{
	struct port *p_ptr;
	struct tipc_msg *msg;
	int res;

	p_ptr = (struct port *)tipc_ref_deref(ref);
	if (!p_ptr || p_ptr->publ.connected)
		return -EINVAL;

	if (skb_cow(buf, DIR_MSG_H_SIZE))
		return -ENOMEM;

	/* */
	res = port_ps_sent(p_ptr, 0, 0, dest->node, dest->ref);
	if (unlikely(res))
		return res;
	
	msg = &p_ptr->publ.phdr;
	msg_set_hdr_sz(msg, DIR_MSG_H_SIZE);
	msg_set_size(msg, DIR_MSG_H_SIZE + dsz);
	port_set_msg_importance(msg, importance);
	msg_set_type(msg, TIPC_DIRECT_MSG);
	msg_set_orignode(msg, orig->node);
	msg_set_origport(msg, orig->ref);
	msg_set_destnode(msg, dest->node);
	msg_set_destport(msg, dest->ref);

	skb_push(buf, DIR_MSG_H_SIZE);
	skb_copy_to_linear_data(buf, msg, DIR_MSG_H_SIZE);
	buf->priority = p_ptr->publ.sk_priority; /* tipc_priority */

	if (addr_in_node(dest->node)) {
		res = tipc_port_recv_msg(buf);
	} else {
        if (!orig->node)
		    msg_set_orignode(msg, tipc_own_addr);
    	res = tipc_send_buf_fast(buf, dest->node);
    }
	if (likely(res != -ELINKCONG)) {
    	port_ps_sent_res(p_ptr, res); /* */
		return res;
	}
	port_ps_sent_congested(p_ptr); /* */
	if (port_unreliable(p_ptr))
		return dsz;
	return -ELINKCONG;
}

/**
 * tipc_send_buf2port - send message buffer to port identity
 */

int tipc_send_buf2port(u32 ref,
		       struct tipc_portid const *dest,
		       struct sk_buff *buf,
		       unsigned int dsz)
{
	struct tipc_portid orig;

	orig.ref = ref;
	orig.node = tipc_own_addr;
	return tipc_forward_buf2port(ref, dest, buf, dsz, &orig,
				     TIPC_PORT_IMPORTANCE);
}

