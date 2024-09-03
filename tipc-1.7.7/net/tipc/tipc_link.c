/*
 * net/tipc/tipc_link.c: TIPC link code
 *
 * Copyright (c) 1996-2007, Ericsson AB
 * Copyright (c) 2004-2008, 2010 Wind River Systems
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
#include "tipc_node.h"
#include "tipc_port.h"
#include "tipc_addr.h"
#include "tipc_name_distr.h"
#include "tipc_bearer.h"
#include "tipc_name_table.h"
#include "tipc_discover.h"
#include "tipc_cfgsrv.h"
#include "tipc_bcast.h"

extern unsigned int g_tipc_dbg_switch;

/*
 * Out-of-range value for link session numbers
 */

#define INVALID_SESSION 0x10000

/*
 * Limit for deferred reception queue:
 */

#define DEF_QUEUE_LIMIT 256u

/*
 * Link state events:
 */

#define  STARTING_EVT    856384768	/* link processing trigger */
#define  TRAFFIC_MSG_EVT 560815u	/* rx'd ??? */
#define  TIMEOUT_EVT     560817u	/* link timer expired */

/*
 * The following two 'message types' is really just implementation
 * data conveniently stored in the message header.
 * They must not be considered part of the protocol
 */
#define OPEN_MSG   0
#define CLOSED_MSG 1

/*
 * State value stored in 'exp_msg_count'
 */

#define START_CHANGEOVER 100000u

/* ��С���ͻ�����д�С*/
#define OUT_QUE_EXCESS   (500 - TIPC_DEF_LINK_WIN)

/**
 * struct link_name - deconstructed link name
 * @addr_local: network address of node at this end
 * @if_local: name of interface at this end
 * @addr_peer: network address of node at far end
 * @if_peer: name of interface at far end
 */

struct link_name {
	u32 addr_local;
	char if_local[TIPC_MAX_IF_NAME];
	u32 addr_peer;
	char if_peer[TIPC_MAX_IF_NAME];
};

/*
 * Global counter of fragmented messages issued by node
 */

static atomic_t link_fragm_msg_no = ATOMIC_INIT(0);


static void link_handle_out_of_seq_msg(struct link *l_ptr,
				       struct sk_buff *buf);
static void link_recv_proto_msg(struct link *l_ptr, struct sk_buff *buf);
static int  link_recv_changeover_msg(struct link **l_ptr, struct sk_buff **buf);
static void link_set_supervision_props(struct link *l_ptr, u32 tolerance);
static int  link_send_sections_long(struct port *sender,
				    struct iovec const *msg_sect,
				    u32 num_sect, u32 destnode);
/*static void link_check_defragm_bufs(struct link *l_ptr); */
static void link_state_event(struct link *l_ptr, u32 event);
static void link_reset_statistics(struct link *l_ptr);
static void link_remote_delete(struct link *l_ptr);


/*
 * Debugging code used by link routines only
 *
 * When debugging link problems on a system that has multiple links,
 * the standard TIPC debugging routines may not be useful since they
 * allow the output from multiple links to be intermixed.  For this reason
 * routines of the form "dbg_link_XXX()" have been created that will capture
 * debug info into a link's personal print buffer, which can then be dumped
 * to the system console upon request.
 *
 * To utilize the dbg_link_XXX() routines:
 * - set LINK_LOG_BUF_SIZE to the size of a link's print buffer 
 *   (must be at least TIPC_PB_MIN_SIZE)
 * - set DBG_OUTPUT_LINK where needed to indicate where the debug output
 *   should be directed (see example below)
 *
 * Notes:
 * - "l_ptr" must be valid when using dbg_link_XXX() routines
 * - when debugging a system that has only one link, it may be easier to set
 *   LINK_LOG_BUF_SIZE to 0 and simply point DBG_OUTPUT_LINK to the system
 *   console or TIPC's log buffer (see example below)
 * - it may also be sufficient in some situations to use TIPC's standard
 *   debugging routines and control the debugging output using DBG_OUTPUT
 */

#define LINK_LOG_BUF_SIZE 0

/*
 * DBG_OUTPUT_LINK is the destination print buffer chain for per-link debug
 * messages.  It defaults to the the null print buffer, but can be enabled
 * where needed to allow debug messages to be selectively generated.
 */

#define DBG_OUTPUT_LINK TIPC_NULL
#if 0
#define DBG_OUTPUT_LINK (&l_ptr->print_buf)
#define DBG_OUTPUT_LINK TIPC_LOG
#define DBG_OUTPUT_LINK TIPC_CONS
#endif

#ifdef CONFIG_TIPC_DEBUG

#define dbg_link(fmt, arg...)	   dbg_printf(DBG_OUTPUT_LINK, fmt, ##arg)
#define dbg_link_msg(msg, txt)	   dbg_msg(DBG_OUTPUT_LINK, msg, txt)
#define dbg_link_dump(fmt, arg...) dbg_dump(DBG_OUTPUT_LINK, fmt, ##arg)
#define dbg_link_state(txt)	\
	do {if (DBG_OUTPUT_LINK != TIPC_NULL) \
		{tipc_printf(DBG_OUTPUT_LINK, txt); \
		 dbg_print_link_state(DBG_OUTPUT_LINK, l_ptr);} \
	} while(0)


#else

#define dbg_link(fmt, arg...)	       	do {} while (0)
#define dbg_link_msg(msg, txt)	       	do {} while (0)
#define dbg_link_dump(fmt, arg...)	do {} while (0)
#define dbg_link_state(txt)		do {} while (0)
#endif

/* enable dump info */
#ifndef CHECK_LINK
#define info_link(fmt, arg...)	       	do {} while (0)

#define dbg_print_link(...)		do {} while (0)
#define dbg_print_buf_chain(...)	do {} while (0)
#define dbg_print_link_state(...)	do {} while (0)
#else
#define info_link(fmt, arg...)	   tipc_printf(TIPC_OUTPUT, fmt, ##arg)

static void dbg_print_link_state(struct print_buf *buf, struct link *l_ptr);
static void dbg_print_link(struct link *l_ptr, const char *str);
static void dbg_print_buf_chain(struct sk_buff *root_buf);
#endif
extern void tipc_port_msg_stats(struct sk_buff *buf, struct port *p_ptr, TIPC_PORT_MSG_TYPE_E msgtype);

/*
 *  Simple link routines
 */

static unsigned int align(unsigned int i)
{
	return (i + 3) & ~3u;
}

static void link_init_max_pkt(struct link *l_ptr)
{
	u32 max_pkt;

	max_pkt = ((l_ptr->b_ptr->publ.mtu - CK_SIZE) & ~3); /* �����ӡJABBER���� */
	if (max_pkt > MAX_MSG_SIZE)
		max_pkt = MAX_MSG_SIZE;

	l_ptr->max_pkt_target = max_pkt;
	if (l_ptr->max_pkt_target < MAX_PKT_DEFAULT)
		l_ptr->max_pkt = l_ptr->max_pkt_target;
	else
		l_ptr->max_pkt = MAX_PKT_DEFAULT;

	l_ptr->max_pkt_probes = 0;
}

static u32 link_next_sent(struct link *l_ptr)
{
	if (l_ptr->next_out)
		return buf_seqno(l_ptr->next_out);
	return mod(l_ptr->next_out_no);
}

static u32 link_last_sent(struct link *l_ptr)
{
	return mod(link_next_sent(l_ptr) - 1);
}

/*
 *  Simple non-static link routines (i.e. referenced outside this file)
 */

int tipc_link_is_up(struct link *l_ptr)
{
	if (!l_ptr)
		return 0;
	return (link_working_working(l_ptr) || link_working_unknown(l_ptr));
}

int tipc_link_is_active(struct link *l_ptr)
{
	return ((l_ptr->owner->active_links[0] == l_ptr) ||
		(l_ptr->owner->active_links[1] == l_ptr));
}

#ifdef CONFIG_TIPC_CONFIG_SERVICE

/**
 * link_name_validate - validate & (optionally) deconstruct link name
 * @name - ptr to link name string
 * @name_parts - ptr to area for link name components (or NULL if not needed)
 *
 * Returns 1 if link name is valid, otherwise 0.
 */

static int link_name_validate(const char *name, struct link_name *name_parts)
{
	char name_copy[TIPC_MAX_LINK_NAME];
	char *addr_local;
	char *if_local;
	char *addr_peer;
	char *if_peer;
	char dummy;
	u32 z_local, c_local, n_local;
	u32 z_peer, c_peer, n_peer;
	u32 if_local_len;
	u32 if_peer_len;

	/* copy link name & ensure length is OK */

	name_copy[TIPC_MAX_LINK_NAME - 1] = 0;
	/* need above in case non-Posix strncpy() doesn't pad with nulls */
	strncpy(name_copy, name, TIPC_MAX_LINK_NAME);
	if (name_copy[TIPC_MAX_LINK_NAME - 1] != 0)
		return 0;

	/* ensure all component parts of link name are present */

	addr_local = name_copy;
	if ((if_local = strchr(addr_local, ':')) == NULL)
		return 0;
	*(if_local++) = 0;
	if ((addr_peer = strchr(if_local, '-')) == NULL)
		return 0;
	*(addr_peer++) = 0;
	if_local_len = addr_peer - if_local;
	if ((if_peer = strchr(addr_peer, ':')) == NULL)
		return 0;
	*(if_peer++) = 0;
	if_peer_len = strlen(if_peer) + 1;

	/* validate component parts of link name */

	if ((sscanf(addr_local, "%u.%u.%u%c",
		    &z_local, &c_local, &n_local, &dummy) != 3) ||
	    (sscanf(addr_peer, "%u.%u.%u%c",
		    &z_peer, &c_peer, &n_peer, &dummy) != 3) ||
	    (z_local > 255) || (c_local > 4095) || (n_local > 4095) ||
	    (z_peer  > 255) || (c_peer  > 4095) || (n_peer  > 4095) ||
	    (if_local_len <= 1) || (if_local_len > TIPC_MAX_IF_NAME) ||
	    (if_peer_len  <= 1) || (if_peer_len  > TIPC_MAX_IF_NAME) ||
	    (strspn(if_local, tipc_alphabet) != (if_local_len - 1)) ||
	    (strspn(if_peer, tipc_alphabet) != (if_peer_len - 1)))
		return 0;

	/* return link name components, if necessary */

	if (name_parts) {
		name_parts->addr_local = tipc_addr(z_local, c_local, n_local);
		strcpy(name_parts->if_local, if_local);
		name_parts->addr_peer = tipc_addr(z_peer, c_peer, n_peer);
		strcpy(name_parts->if_peer, if_peer);
	}
	return 1;
}

#endif



int tipc_link_check_waiting(struct link *l_ptr)
{
    /* �ȼ�鷢�ʹ����Ƿ�ʱ���ƶ����������������checkpoint_out */
    if ((l_ptr->next_out_no - l_ptr->checkpoint_out) > l_ptr->out_queue_size) {
        l_ptr->wait_timout = 0;
        l_ptr->checkpoint_out = l_ptr->next_out_no;
        return 0;
    }
    
    /* ���û�з��͵ȴ��ߣ�����Ҫ��� */
	if (list_empty(&l_ptr->waiting_ports) && !l_ptr->out_queue_size) {
        l_ptr->wait_timout = 0;
		return 0;
	}


    /* ����Ƿ�ʱ */
    if (++l_ptr->wait_timout < l_ptr->abort_limit+1) {
		return 0;
    }

    l_ptr->wait_timout = 0;
    return 1;
}


/**
 * link_timeout - handle expiration of link timer
 * @l_ptr: pointer to link
 *
 * This routine must not grab "tipc_net_lock" to avoid a potential deadlock conflict
 * with tipc_link_delete().  (There is no risk that the node will be deleted by
 * another thread because tipc_link_delete() always cancels the link timer before
 * tipc_node_delete() is called.)
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static void link_timeout(struct timer_list *timer)
#else
static void link_timeout(struct link *l_ptr)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	struct link *l_ptr = container_of(timer, struct link, timer);
#endif
	tipc_node_lock(l_ptr->owner);

	/* update counters used in statistical profiling of send traffic */

	l_ptr->stats.accu_queue_sz += l_ptr->out_queue_size;
	l_ptr->stats.queue_sz_counts++;

	if (l_ptr->out_queue_size > l_ptr->stats.max_queue_sz)
		l_ptr->stats.max_queue_sz = l_ptr->out_queue_size;

	if (l_ptr->first_out) {
		struct tipc_msg *msg = buf_msg(l_ptr->first_out);
		u32 length = msg_size(msg);

		if ((msg_user(msg) == MSG_FRAGMENTER)
		    && (msg_type(msg) == FIRST_FRAGMENT)) {
			length = msg_size(msg_get_wrapped(msg));
		}
		if (length) {
			l_ptr->stats.msg_lengths_total += length;
			l_ptr->stats.msg_length_counts++;
			if (length <= 64)
				l_ptr->stats.msg_length_profile[0]++;
			else if (length <= 256)
				l_ptr->stats.msg_length_profile[1]++;
			else if (length <= 1024)
				l_ptr->stats.msg_length_profile[2]++;
			else if (length <= 4096)
				l_ptr->stats.msg_length_profile[3]++;
			else if (length <= 16384)
				l_ptr->stats.msg_length_profile[4]++;
			else if (length <= 32768)
				l_ptr->stats.msg_length_profile[5]++;
			else
				l_ptr->stats.msg_length_profile[6]++;
		}
	}

    l_ptr->timeout_cnt++;
	link_state_event(l_ptr, TIMEOUT_EVT);

	if (l_ptr->next_out)
		tipc_link_push_queue(l_ptr);
    
	/* do all other link processing performed on a periodic basis */
    /* ���ͼ��Ƶ�� */
	if (link_working_working(l_ptr) && (l_ptr->fsm_msg_cnt % 4 == 3)){
		link_check_defragm_bufs(&l_ptr->defragm_buf, l_ptr->name);

    	if (l_ptr == l_ptr->owner->active_links[0])
    		tipc_node_check_mc(l_ptr->owner);

        if (tipc_link_check_waiting(l_ptr)) {

            tipc_link_reset(l_ptr, "wait_timeout", 0, 0, 0);
            l_ptr->blocked = 1; /* ����Ƶ��up/down��ȷ���ܸ澯 */
        }
	}

    /* ����permit_changeover��Ϣ���ܲ�һ�£����changeover�Ƿ�ʱ
	 * ��ʱʱ��Ӧ�ô�����·���ϵ�ʱ��
	 */
    if (!tipc_link_is_up(l_ptr)) {
            if(l_ptr->peer_bearer_id < TIPC_MAX_BEARERS && l_ptr->fsm_msg_cnt > l_ptr->abort_limit + 10) {
                    if (l_ptr->exp_msg_count > 0) {
                            info("Link <%s> changeover timeout, exp %u\n", l_ptr->name, l_ptr->exp_msg_count);
                            l_ptr->exp_msg_count = 0;
                    } else {
                            /* ��ʱ�䲻up 2012-2:����ɾ�����������ϵ��廻���澯 */
                            l_ptr->retx_count = 0;
                            if (in_own_cluster(l_ptr->addr)) {
                                    tipc_delete_link(l_ptr);
                            }
                    }
            } else if (l_ptr->peer_bearer_id == TIPC_MAX_BEARERS && l_ptr->fsm_msg_cnt > 1200) {                          
            /*����֮��δactivate����·20min��ɾ��*/
                        info("Link <%s> fsm_msg_cnt is %u, delete link!\n", l_ptr->name, l_ptr->fsm_msg_cnt);
                        tipc_delete_link(l_ptr);  
            }
    }
	
	tipc_node_unlock(l_ptr->owner);
}

static void link_set_timer(struct link *l_ptr, u32 time)
{
	k_start_timer(&l_ptr->timer, time);
}

/**
 * tipc_link_create - create a new link
 * @b_ptr: pointer to associated bearer
 * @peer: network address of node at other end of link
 * @media_addr: media address to use when sending messages over link
 *
 * Returns pointer to link.
 */

struct link *tipc_link_create(struct bearer *b_ptr, const u32 peer,
			      const struct tipc_media_addr *media_addr)
{
	struct link *l_ptr;
	struct tipc_msg *msg;
	char *if_name;
#ifdef CMU_FLAG
    char *eth2_name = "eth2";
#endif

	l_ptr = kzalloc(sizeof(*l_ptr), GFP_ATOMIC);
	if (!l_ptr) {
		warn("Link creation failed, no memory\n");
		return NULL;
	}

	if (LINK_LOG_BUF_SIZE) {
		char *pb = kmalloc(LINK_LOG_BUF_SIZE, GFP_ATOMIC);

		if (!pb) {
			kfree(l_ptr);
			warn("Link creation failed, no memory for print buffer\n");
			return NULL;
		}
		tipc_printbuf_init(&l_ptr->print_buf, pb, LINK_LOG_BUF_SIZE);
	}

	l_ptr->addr = peer;
	if_name = strchr(b_ptr->publ.name, ':') + 1;
	sprintf(l_ptr->name, "%u.%u.%u:%s-%u.%u.%u:unknown",
		tipc_zone(tipc_own_addr), tipc_cluster(tipc_own_addr),
		tipc_node(tipc_own_addr),
		if_name,
		tipc_zone(peer), tipc_cluster(peer), tipc_node(peer));
	/* note: peer i/f is appended to link name by reset/activate */
	memcpy(&l_ptr->media_addr, media_addr, sizeof(*media_addr));
	l_ptr->checkpoint = 1;
	l_ptr->peer_session = INVALID_SESSION;
	l_ptr->peer_bearer_id = TIPC_MAX_BEARERS; /* ������Ч */
	l_ptr->b_ptr = b_ptr;
	link_set_supervision_props(l_ptr, b_ptr->tolerance);
	l_ptr->state = RESET_UNKNOWN;
	l_ptr->pmsg = (struct tipc_msg *)&l_ptr->proto_msg;
	msg = l_ptr->pmsg;
	tipc_msg_init(msg, LINK_PROTOCOL, RESET_MSG, INT_H_SIZE, l_ptr->addr);
	msg_set_size(msg, sizeof(l_ptr->proto_msg));
	msg_set_session(msg, (tipc_random & 0xffff));
	msg_set_bearer_id(msg, b_ptr->identity);
#ifdef CMU_FLAG
    strcpy((char *)msg_data(msg), eth2_name);
#else
	strcpy((char *)msg_data(msg), if_name);
#endif
	l_ptr->priority = b_ptr->priority;
	tipc_link_set_queue_limits(l_ptr, b_ptr->window);
	link_init_max_pkt(l_ptr);
	l_ptr->next_out_no = 1;
	INIT_LIST_HEAD(&l_ptr->waiting_ports);
	link_reset_statistics(l_ptr);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    do_gettimeofday_snapshot(&(l_ptr->init_tv));
#else
	do_gettimeofday(&(l_ptr->init_tv));
#endif
    
	l_ptr->owner = tipc_node_attach_link(l_ptr);
	if (!l_ptr->owner) {
		if (LINK_LOG_BUF_SIZE)
			kfree(l_ptr->print_buf.buf);
		kfree(l_ptr);
		return NULL;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	k_init_timer(&l_ptr->timer, (timer_handler)link_timeout);
#else
	k_init_timer(&l_ptr->timer, (Handler)link_timeout, (unsigned long)l_ptr);
#endif
	list_add_tail(&l_ptr->link_list, &b_ptr->links);

	tipc_k_signal((Handler)tipc_link_start, (unsigned long)l_ptr);

	dbg("tipc_link_create(): tolerance = %u,cont intv = %u, abort_limit = %u\n",
	    l_ptr->tolerance, l_ptr->continuity_interval, l_ptr->abort_limit);

	return l_ptr;
}

/**
 * tipc_link_delete - delete a link
 * @l_ptr: pointer to link
 *
 * Note: 'tipc_net_lock' is write_locked, bearer is locked.
 * This routine must not grab the node lock until after link timer cancellation
 * to avoid a potential deadlock situation.
 */

void tipc_link_delete(struct link *l_ptr)
{
	if (!l_ptr) {
		err("Attempt to delete non-existent link\n");
		return;
	}

	k_cancel_timer(&l_ptr->timer);
	tipc_node_lock(l_ptr->owner);
	tipc_link_reset(l_ptr, NULL, 0, 0, 0);
	/* tell peer reset */
	tipc_link_send_proto_msg(l_ptr, RESET_MSG, 0, 0, 0, 0, 0, 0);
	tipc_node_detach_link(l_ptr->owner, l_ptr);
	tipc_link_stop(l_ptr);
	list_del_init(&l_ptr->link_list);
	if (LINK_LOG_BUF_SIZE)
		kfree(l_ptr->print_buf.buf);
	/* ����Ƿ�Ҫɾ��node */
	tipc_node_unlock_delete(l_ptr->owner);
	k_term_timer(&l_ptr->timer);
    if (l_ptr->recvseq_info.seqno_list) {
        kfree(l_ptr->recvseq_info.seqno_list);
    }
	kfree(l_ptr);
}

/** 
 * link_remote_delete - delete a link on command from other end
 * @l_ptr: pointer to link
 * 
 * Note: The call comes via a tipc_k_signal. No locks are set at this moment.
 */

static void link_remote_delete(struct link *l_ptr)
{
        struct bearer *b_ptr = l_ptr->b_ptr;

	write_lock_bh(&tipc_net_lock);
        spin_lock_bh(&b_ptr->publ.lock);
        tipc_bearer_remove_discoverer(b_ptr,l_ptr->addr);
        tipc_link_delete(l_ptr);
        spin_unlock_bh(&b_ptr->publ.lock);
	write_unlock_bh(&tipc_net_lock);
}

void tipc_delete_link(struct link *l_ptr)
{
	if (l_ptr && !l_ptr->blocked) {
		l_ptr->blocked = 1;
		if (tipc_node_is_up(l_ptr->owner))
			info("Delete link <%s>\n", l_ptr->name);
		tipc_k_signal((Handler)link_remote_delete,(unsigned long)l_ptr);
	}
}

void tipc_link_start(struct link *l_ptr)
{
	dbg("tipc_link_start %x\n", l_ptr);
	link_state_event(l_ptr, STARTING_EVT);
}

void tipc_info_link_stats(struct link *l_ptr)
{
	char *status;

	/* ����ӡ�鲥״̬ */
	if (!strncmp(l_ptr->name, tipc_bclink_name, strlen(tipc_bclink_name)))
		return;

	if (tipc_link_is_active(l_ptr))
		status = "ACTIVE";
	else if (tipc_link_is_up(l_ptr))
		status = "STANDBY";
	else
		status = "DEFUNCT";

	info("Link stat <%s>\n", l_ptr->name);	
	info("  %s  MTU:%u  Priority:%u  Tolerance:%u ms"
			"  Window:%u packets\n", status, l_ptr->max_pkt, 
			l_ptr->priority, l_ptr->tolerance, l_ptr->queue_limit[0]);
	info("  RX packets:%u fragments:%u/%u bundles:%u/%u\n",
			l_ptr->next_in_no - l_ptr->stats.recv_info,
			l_ptr->stats.recv_fragments, l_ptr->stats.recv_fragmented,
			l_ptr->stats.recv_bundles, l_ptr->stats.recv_bundled);
	info("  TX packets:%u fragments:%u/%u bundles:%u/%u\n",
			l_ptr->next_out_no - l_ptr->stats.sent_info,
			l_ptr->stats.sent_fragments, l_ptr->stats.sent_fragmented,
			l_ptr->stats.sent_bundles, l_ptr->stats.sent_bundled);

	info("  Next-in-no:%u deferred-count:%u unacked:%u\n",
			mod(l_ptr->next_in_no), l_ptr->deferred_inqueue_sz,
			l_ptr->unacked_window);
	info("  Next-ou-no:%u outqueue-count:%u re-tx-no:%u re-tx-cnt:%u\n",
			mod(l_ptr->next_out_no), l_ptr->out_queue_size,
			l_ptr->retransm_queue_head, l_ptr->retransm_queue_size);
	info("  RX states:%u probes:%u naks:%u defs:%u dups:%u\n", 
			l_ptr->stats.recv_states, l_ptr->stats.recv_probes,
			l_ptr->stats.recv_nacks, l_ptr->stats.deferred_recv,
			l_ptr->stats.duplicates);
	info("  TX states:%u probes:%u naks:%u acks:%u dups:%u\n",
			l_ptr->stats.sent_states, l_ptr->stats.sent_probes,
			l_ptr->stats.sent_nacks, l_ptr->stats.sent_acks,
			l_ptr->stats.retransmitted);
	info("  Congestion bearer:%u link:%u  Send queue max:%u avg:%u\n",
			l_ptr->stats.bearer_congs, l_ptr->stats.link_congs,
			l_ptr->stats.max_queue_sz, l_ptr->stats.queue_sz_counts
			? (l_ptr->stats.accu_queue_sz / l_ptr->stats.queue_sz_counts)
			: 0);
	if (l_ptr->drop_outque || l_ptr->drop_defque)
		info("  Discard outqueue:%u deferqueue:%u\n",
			l_ptr->drop_outque, l_ptr->drop_defque);
	info("  Reset:%u  Checkcnt:%u failed:%u  Retx:%u\n",
			l_ptr->reset_count, 0, 0, l_ptr->retx_count);
	return;
}

/**
 * link_schedule_port - schedule port for deferred sending
 * @l_ptr: pointer to link
 * @origport: reference to sending port
 * @sz: amount of data to be sent
 *
 * Schedules port for renewed sending of messages after link congestion
 * has abated.
 */

/* remove static */
int link_schedule_port(struct link *l_ptr, u32 origport, u32 sz)
{
	struct port *p_ptr;

	spin_lock_bh(&tipc_port_list_lock);
	p_ptr = tipc_port_lock(origport);
	if (p_ptr) {
		if (!p_ptr->wakeup)
			goto exit;
		if (!list_empty(&p_ptr->wait_list))
			goto exit;
		p_ptr->publ.congested = 1;
		p_ptr->waiting_pkts = 1 + ((sz - 1) / l_ptr->max_pkt);
		list_add_tail(&p_ptr->wait_list, &l_ptr->waiting_ports);
exit:
		l_ptr->stats.link_congs++;
		if (unlikely(tipc_ratelimit(l_ptr->stats.link_congs, 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_LINK))) {
			warn("Link <%s> congest (port %u congs %u, queue size %u)\n", l_ptr->name,
					origport, l_ptr->stats.link_congs, l_ptr->out_queue_size);
			tipc_info_link_stats(l_ptr);
		}
		tipc_port_unlock(p_ptr);
	}
	spin_unlock_bh(&tipc_port_list_lock);
	return -ELINKCONG;
}

void tipc_link_wakeup_ports(struct link *l_ptr, int all)
{
	struct port *p_ptr;
	struct port *temp_p_ptr;
	int win = l_ptr->queue_limit[0] + OUT_QUE_EXCESS - l_ptr->out_queue_size;

	if (all)
		win = 100000;
	if (win <= 0)
		return;
	if (!spin_trylock_bh(&tipc_port_list_lock))
		return;
#if 0 /* see  OUT_QUE_EXCESS */  
	if (link_congested(l_ptr))
		goto exit;
#endif
	list_for_each_entry_safe(p_ptr, temp_p_ptr, &l_ptr->waiting_ports,
				 wait_list) {
		if (win <= 0)
			break;
		list_del_init(&p_ptr->wait_list);
		spin_lock_bh(p_ptr->publ.lock);
		p_ptr->publ.congested = 0;
		p_ptr->wakeup(&p_ptr->publ);
		win -= p_ptr->waiting_pkts;
		spin_unlock_bh(p_ptr->publ.lock);
	}

/*exit: */
	spin_unlock_bh(&tipc_port_list_lock);
}

/**
 * link_release_outqueue - purge link's outbound message queue
 * @l_ptr: pointer to link
 */

static void link_release_outqueue(struct link *l_ptr)
{
	struct sk_buff *buf = l_ptr->first_out;
	struct sk_buff *next;

	while (buf) {
		next = buf->next;
		buf_discard(buf);
		buf = next;
	}
	l_ptr->first_out = NULL;
	l_ptr->out_queue_size = 0;
}

/**
 * tipc_link_reset_fragments - purge link's inbound message fragments queue
 * @l_ptr: pointer to link
 */

void tipc_link_reset_fragments(struct link *l_ptr)
{
	struct sk_buff *buf = l_ptr->defragm_buf;
	struct sk_buff *next;

	while (buf) {
		next = buf->next;
		buf_discard(buf);
		buf = next;
	}
	l_ptr->defragm_buf = NULL;
}

/**
 * tipc_link_stop - purge all inbound and outbound messages associated with link
 * @l_ptr: pointer to link
 */

void tipc_link_stop(struct link *l_ptr)
{
	struct sk_buff *buf;
	struct sk_buff *next;

	buf = l_ptr->oldest_deferred_in;
	while (buf) {
		next = buf->next;
		buf_discard(buf);
		buf = next;
	}
    l_ptr->oldest_deferred_in = NULL;

	buf = l_ptr->first_out;
	while (buf) {
		next = buf->next;
		buf_discard(buf);
		buf = next;
	}
    l_ptr->first_out = NULL;

	tipc_link_reset_fragments(l_ptr);

	buf_discard(l_ptr->proto_msg_queue);
	l_ptr->proto_msg_queue = NULL;
}

void tipc_link_reset(struct link *l_ptr, char *description, u32 para1, u32 para2, u32 para3)
{
	struct sk_buff *buf;
	u32 prev_state = l_ptr->state;
	u32 checkpoint = l_ptr->next_in_no;
	/*int was_active_link = tipc_link_is_active(l_ptr);*/
    if (description && l_ptr){
        warn("reset link=%s, reason=%s, para=(%u,%u,%u),out=%u,reset=%u,rext=%u,in=%u,st=%u,sndcnt=%u,rcvcnt=%u, fcnt=%u\n",
            l_ptr->name, description, para1, para2, para3, l_ptr->next_out_no, l_ptr->reset_count, l_ptr->retx_count,
            l_ptr->next_in_no, l_ptr->state, l_ptr->stats.sent_states, l_ptr->stats.recv_states, l_ptr->fsm_msg_cnt);
    }
	dbg_print_link_state(TIPC_OUTPUT, l_ptr);

	msg_set_session(l_ptr->pmsg, ((msg_session(l_ptr->pmsg) + 1) & 0xffff));

	/* Link is down, accept any session */
	l_ptr->peer_session = INVALID_SESSION;

	/* Prepare for max packet size negotiation */
	link_init_max_pkt(l_ptr);

	l_ptr->state = RESET_UNKNOWN;
#ifndef CHECK_LINK	
	dbg_link_state("Resetting Link\n");
#endif
	if ((prev_state == RESET_UNKNOWN) || (prev_state == RESET_RESET))
		return;

	l_ptr->reset_count++;
	tipc_node_link_down(l_ptr->owner, l_ptr);
	/* a bearer maybe has multiple links to a node. */
	if (0 == --l_ptr->owner->bearer_link_act[l_ptr->b_ptr->identity])
		tipc_bearer_remove_dest(l_ptr->b_ptr, l_ptr->addr, &l_ptr->media_addr);
#if 0
	info("\nReset link <%s>\n", l_ptr->name);
	dbg_link_dump("\n\nDumping link <%s>:\n", l_ptr->name);
#endif
    /* ����linkά��permit_changeover, ����linkʱ����act��һ�� */
	if (/*was_active_link && */tipc_node_is_up(l_ptr->owner) &&
	    l_ptr->permit_changeover ) {
		l_ptr->reset_checkpoint = checkpoint;
		l_ptr->exp_msg_count = START_CHANGEOVER;
        if (l_ptr->out_queue_size) {
            dbg("Link <%s> changeover %u msg to peer\n",
                l_ptr->name, l_ptr->out_queue_size);
        }
	}

    if (l_ptr->exp_msg_count != START_CHANGEOVER && 
        (l_ptr->out_queue_size || l_ptr->deferred_inqueue_sz)) {
        
    	dbg("Discard link <%s> outqueue %u inqueue %u\n",
    	    l_ptr->name, l_ptr->out_queue_size, l_ptr->deferred_inqueue_sz);

    	l_ptr->drop_outque += l_ptr->out_queue_size;
    	l_ptr->drop_defque += l_ptr->deferred_inqueue_sz;
    }

	/* Clean up all queues: */

	link_release_outqueue(l_ptr);
	buf_discard(l_ptr->proto_msg_queue);
	l_ptr->proto_msg_queue = NULL;
	buf = l_ptr->oldest_deferred_in;
	while (buf) {
		struct sk_buff *next = buf->next;
		buf_discard(buf);
		buf = next;
	}
	if (!list_empty(&l_ptr->waiting_ports))
		tipc_link_wakeup_ports(l_ptr, 1);

	l_ptr->retransm_queue_head = 0;
	l_ptr->retransm_queue_size = 0;
	l_ptr->last_out = NULL;
	l_ptr->first_out = NULL;
	l_ptr->next_out = NULL;
	l_ptr->unacked_window = 0;
	l_ptr->checkpoint = 1;
	l_ptr->next_out_no = 1;
	l_ptr->deferred_inqueue_sz = 0;
	l_ptr->oldest_deferred_in = NULL;
	l_ptr->newest_deferred_in = NULL;
	l_ptr->fsm_msg_cnt = 0;
	l_ptr->stale_count = 0;
    l_ptr->timeout_cnt = 0;
	link_reset_statistics(l_ptr);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	do_gettimeofday_snapshot(&(l_ptr->init_tv)); /* ���³�ʼ��link init_tv */
#else
	do_gettimeofday(&(l_ptr->init_tv)); /* ���³�ʼ��link init_tv */
#endif
	
	tipc_issuance_link_state(l_ptr);  /* ��λ��·ʱ������������·down����Ϣ */
}


static void link_activate(struct link *l_ptr)
{
	struct tipc_node *n_ptr = l_ptr->owner;
	
	l_ptr->next_in_no = l_ptr->stats.recv_info = 1;
	tipc_node_link_up(l_ptr->owner, l_ptr);
	/* a bearer maybe has multiple links to a node. */
	if (0 == l_ptr->owner->bearer_link_act[l_ptr->b_ptr->identity]++)
		tipc_bearer_add_dest(l_ptr->b_ptr, l_ptr->addr, &l_ptr->media_addr);

	/* ÿ��link upʱ����nametable����Ϣ����߿ɿ���  */
	if (in_own_zone(n_ptr->elm.addr)) {
		if (likely(n_ptr->flags & NF_MULTICLUSTER)) {
			tipc_k_signal((Handler)tipc_route_node_up,
				      n_ptr->elm.addr);
			tipc_k_signal((Handler)tipc_named_node_up,
				      n_ptr->elm.addr);
		} else {
			tipc_k_signal((Handler)tipc_named_node_up_uni,
				      n_ptr->elm.addr);
		}
	}	
}

void link_check_fail_stats(struct link *l_ptr)
{
	/* ÿ24h˥��stats.nacksһ�룬����7��stats.nacks�޼�����cmfΪ0 */
	if (unlikely(time_after(jiffies, l_ptr->cmfs_jif))) {
		l_ptr->cmfs_jif = jiffies + 3600 * 24 * HZ; /* ��һ�ν��븳��ֵ���� */
		
		if (!l_ptr->stats.sent_nacks && 
			!l_ptr->stats.recv_nacks) {
			if (++l_ptr->cmfs_count >= 7) {
				l_ptr->cmfs_count = 0;
				
				l_ptr->retx_count = 0;
			}
		} else {
			l_ptr->cmfs_count = 0; /* �д���0 */
		}
		
		l_ptr->stats.sent_nacks /= 2;
		l_ptr->stats.recv_nacks /= 2;
	}

	return;
}

/**
 * link_state_event - link finite state machine
 * @l_ptr: pointer to link
 * @event: state machine event to process
 */

static void link_state_event(struct link *l_ptr, unsigned event)
{
	struct link *other;
	u32 cont_intv = CONT_INTV(l_ptr->tolerance / 2);
    u32 old_up = 0;
    u32 old_act =0;

    /* first_out�ǿձ�ʾ�����ݱ��ķ��ͣ������cont_intv_fast;
       �����ʾ�����ݱ��ģ�̽����tolerance������̽����cont_intv */


    if (!l_ptr->started) {
        if (event != STARTING_EVT) {
            return;    /* Not yet. */
        }

        /*
            link create -> STARTING_EVT ֮�������������down, �ᵼ��link����block״̬
            ����block״̬���������STARTING_EVT�¼�, �ᵼ��link״̬����ʱ���޷���������·
            �޷��ָ�; STARTING_EVT�¼�����ʱ�����block״̬
        */

    } else {
        if (link_blocked(l_ptr)) {
            if (event != TIMEOUT_EVT) {
                return;
            }
            
            l_ptr->fsm_msg_cnt++; /* */

            link_set_timer(l_ptr, cont_intv);
            
            /* ���ƶ˿����� */
            if (!l_ptr->blocked) {
                return;
            }

            if (l_ptr->blocked++ > (l_ptr->abort_limit / 2 + 1)) {
                l_ptr->blocked = 0;
            }

            return;	  /* Changeover going on */
        }
        dbg_link("STATE_EV: <%s> ", l_ptr->name);
    }

    old_up = tipc_link_is_up(l_ptr);
    old_act = tipc_link_is_active(l_ptr);
	switch (l_ptr->state) {
	case WORKING_WORKING:
    {
		dbg_link("WW/");
		switch (event) {
		case TRAFFIC_MSG_EVT:
			dbg_link("TRF-");
			/* fall through */
		case ACTIVATE_MSG:
			dbg_link("ACT\n");
			break;
		case TIMEOUT_EVT:
			dbg_link("TIM ");
			link_check_fail_stats(l_ptr);
			if (l_ptr->next_in_no != l_ptr->checkpoint) {
				l_ptr->checkpoint = l_ptr->next_in_no;
				/* �鲥�����ġ�������δȷ�ϡ��������������ͼ�� */
                if (tipc_bclink_acks_missing(l_ptr->owner) ||
                    (l_ptr->first_out) ||
					l_ptr->oldest_deferred_in) {
					tipc_link_send_proto_msg(l_ptr, STATE_MSG,
							    0, 0, 0, 0, 0, 0);
					l_ptr->fsm_msg_cnt++;

					/* bc��sc����δȷ�ϼӿ���Ƶ�ʣ������ش�Ҫ��Щ */
					l_ptr->continuity_interval = 
					    l_ptr->oldest_deferred_in ? cont_intv/4 : l_ptr->fast_intv;
				} else if (l_ptr->max_pkt < l_ptr->max_pkt_target) {
					tipc_link_send_proto_msg(l_ptr, STATE_MSG,
							    1, 0, 0, 0, 0, 0);
					l_ptr->fsm_msg_cnt++;
					/* probe�ڼ仹ԭ���Ƶ�� */
					l_ptr->continuity_interval = cont_intv/4;	
				} else {
					l_ptr->continuity_interval = l_ptr->tolerance;
                    /* ����standbyҪ���������� */
                    if (l_ptr->fast_standby && l_ptr->fast_standby++ > 4) {
                        if (!tipc_link_is_active(l_ptr))
                            tipc_node_link_active(l_ptr->owner, l_ptr);
                        l_ptr->fast_standby = 0; /* ��ʽ��� */
                    }
				}
                /* WWʹ���¼��: intv/4 or tolerance */
				link_set_timer(l_ptr, l_ptr->continuity_interval);
				break;
			}
			dbg_link(" -> WU\n");
			l_ptr->state = WORKING_UNKNOWN;
			l_ptr->fsm_msg_cnt = 0;
			tipc_link_send_proto_msg(l_ptr, STATE_MSG, 1, 0, 0, 0, 0, 0);

			/* fsm_msg_cnt������ֵ��������tolerance�ڼ�⵽���� */
			l_ptr->fsm_msg_cnt = l_ptr->continuity_interval / (CONT_INTV_MAX/4);
            if (l_ptr->fsm_msg_cnt > l_ptr->abort_limit/2)
                l_ptr->fsm_msg_cnt = l_ptr->abort_limit/2;

			link_set_timer(l_ptr, l_ptr->fast_intv); /* �ӿ��һ��WU���� */
			break;
		case RESET_MSG:
			dbg_link("RES -> RR\n");
			tipc_link_reset(l_ptr, "reset_msg_bypeer", 0, 0, 0);
			l_ptr->state = RESET_RESET;
			l_ptr->fsm_msg_cnt = 0;
			/* 
			 * WU/WW����������activate������resetһ������
			 * RU��Ҫ��������activate
			 */
#if 0
			tipc_link_send_proto_msg(l_ptr, ACTIVATE_MSG, 0, 0, 0, 0, 0, 0);
			l_ptr->fsm_msg_cnt++;
#endif            
			link_set_timer(l_ptr, cont_intv / 4);
			break;
		default:
			err("Unknown link event %u in WW state\n", event);
		}
		break;
	}
	case WORKING_UNKNOWN:
    {
		dbg_link("WU/");
		switch (event) {
		case TRAFFIC_MSG_EVT:
			dbg_link("TRF-");
			/* fall through */
		case ACTIVATE_MSG:
			dbg_link("ACT -> WW\n");
			l_ptr->state = WORKING_WORKING;
			l_ptr->fsm_msg_cnt = 0;
			link_set_timer(l_ptr, l_ptr->continuity_interval);
			break;
		case RESET_MSG:
			dbg_link("RES -> RR\n");

			tipc_link_reset(l_ptr, "working_probing", 0, 0, 0);
			l_ptr->state = RESET_RESET;
			l_ptr->fsm_msg_cnt = 0;
			/* 
			 * WU/WW����������activate������resetһ������
			 * RU��Ҫ��������activate
			 */
#if 0
			tipc_link_send_proto_msg(l_ptr, ACTIVATE_MSG, 0, 0, 0, 0, 0, 0);
			l_ptr->fsm_msg_cnt++;
#endif
			link_set_timer(l_ptr, cont_intv / 4);
			break;
		case TIMEOUT_EVT:
			dbg_link("TIM ");
			if (l_ptr->next_in_no != l_ptr->checkpoint) {
				dbg_link("-> WW \n");
				l_ptr->state = WORKING_WORKING;
				l_ptr->fsm_msg_cnt = 0;
				l_ptr->checkpoint = l_ptr->next_in_no;
				if (tipc_bclink_acks_missing(l_ptr->owner)) {
					tipc_link_send_proto_msg(l_ptr, STATE_MSG,
							    0, 0, 0, 0, 0, 0);
					l_ptr->fsm_msg_cnt++;
				}
				link_set_timer(l_ptr, l_ptr->continuity_interval);
			} else if (l_ptr->fsm_msg_cnt < l_ptr->abort_limit) {
				dbg_link("Probing %u/%u,timer = %u ms)\n",
					 l_ptr->fsm_msg_cnt, l_ptr->abort_limit,
					 cont_intv / 4);
                /* 2012-12 �����л� */
                if (tipc_link_is_active(l_ptr))
                    tipc_node_link_standby(l_ptr->owner, l_ptr);
				tipc_link_send_proto_msg(l_ptr, STATE_MSG, 
						    1, 0, 0, 0, 0, 0);
				l_ptr->fsm_msg_cnt++;
				link_set_timer(l_ptr, cont_intv / 4);
			} else {	/* Link has failed */
				dbg_link("-> RU (%u probes unanswered)\n",
					 l_ptr->fsm_msg_cnt);

				tipc_link_reset(l_ptr, "peer not responding", 0, 0, 0);
				l_ptr->state = RESET_UNKNOWN;
				l_ptr->fsm_msg_cnt = 0;
				tipc_link_send_proto_msg(l_ptr, RESET_MSG,
						    0, 0, 0, 0, 0, 0);
				l_ptr->fsm_msg_cnt++;
				link_set_timer(l_ptr, cont_intv);
			}
			
			break;
		default:
			err("Unknown link event %u in WU state\n", event);
		}
		break;
	}
	case RESET_UNKNOWN:
    {
		dbg_link("RU/");
		switch (event) {
		case TRAFFIC_MSG_EVT:
			dbg_link("TRF-\n");
			break;
		case ACTIVATE_MSG:
			other = l_ptr->owner->active_links[0];
			if (other && link_working_unknown(other)) {
				dbg_link("ACT\n");
				break;
			}
			dbg_link("ACT -> WW\n");
			l_ptr->state = WORKING_WORKING;
			l_ptr->fsm_msg_cnt = 0;
			link_activate(l_ptr);
			tipc_link_send_proto_msg(l_ptr, ACTIVATE_MSG, 1, 0, 0, 0, 0, 0);
			l_ptr->fsm_msg_cnt++;
			link_set_timer(l_ptr, cont_intv);
			break;
		case RESET_MSG:
			dbg_link("RES \n");
			dbg_link(" -> RR\n");
			l_ptr->state = RESET_RESET;
			l_ptr->fsm_msg_cnt = 0;
			tipc_link_send_proto_msg(l_ptr, ACTIVATE_MSG, 1, 0, 0, 0, 0, 0);
			l_ptr->fsm_msg_cnt++;
			link_set_timer(l_ptr, cont_intv);
			break;
		case STARTING_EVT:
			dbg_link("START-");
			l_ptr->started = 1;
			/* fall through */
		case TIMEOUT_EVT:
			dbg_link("TIM \n");
            tipc_bearer_send_discover(l_ptr->b_ptr,l_ptr->addr);
			tipc_link_send_proto_msg(l_ptr, RESET_MSG, 0, 0, 0, 0, 0, 0);
			l_ptr->fsm_msg_cnt++;
			link_set_timer(l_ptr, cont_intv);
			break;
		default:
			err("Unknown link event %u in RU state\n", event);
		}
		break;
	}
	case RESET_RESET:
    {
		dbg_link("RR/ ");
		switch (event) {
		case TRAFFIC_MSG_EVT:
			dbg_link("TRF-");
			/* fall through */
		case ACTIVATE_MSG:
			other = l_ptr->owner->active_links[0];
			if (other && link_working_unknown(other)) {
				dbg_link("ACT\n");
				break;
			}
			dbg_link("ACT -> WW\n");
			l_ptr->state = WORKING_WORKING;
			l_ptr->fsm_msg_cnt = 0;
			link_activate(l_ptr);
			tipc_link_send_proto_msg(l_ptr, STATE_MSG, 1, 0, 0, 0, 0, 0);
			l_ptr->fsm_msg_cnt++;
			link_set_timer(l_ptr, cont_intv);
			break;
		case RESET_MSG:
			dbg_link("RES\n");
			break;
		case TIMEOUT_EVT:
			dbg_link("TIM\n");
			tipc_link_send_proto_msg(l_ptr, ACTIVATE_MSG, 0, 0, 0, 0, 0, 0);
			l_ptr->fsm_msg_cnt++;
			link_set_timer(l_ptr, cont_intv);
			dbg_link("fsm_msg_cnt %u\n", l_ptr->fsm_msg_cnt);
			break;
		default:
			err("Unknown link event %u in RR state\n", event);
		}
		break;
	}
	default:
		err("Unknown link state %u/%u\n", l_ptr->state, event);
	}
    if (old_up != tipc_link_is_up(l_ptr) ||
        old_act != tipc_link_is_active(l_ptr))
    {
        tipc_issuance_link_state(l_ptr); /* ������·״̬�仯��Ϣ */
	}
}

/*
 * link_bundle_buf(): Append contents of a buffer to
 * the tail of an existing one.
 */

static int link_bundle_buf(struct link *l_ptr,
			   struct sk_buff *bundler,
			   struct sk_buff *buf)
{
	struct tipc_msg *bundler_msg = buf_msg(bundler);
	struct tipc_msg *msg = buf_msg(buf);
	u32 size = msg_size(msg);
	u32 bundle_size = msg_size(bundler_msg);
	u32 to_pos = align(bundle_size);
	u32 pad = to_pos - bundle_size;

	if (msg_user(bundler_msg) != MSG_BUNDLER)
		return 0;
	if (msg_type(bundler_msg) != OPEN_MSG)
		return 0;
	if (skb_tailroom(bundler) < (pad + size))
		return 0;
	if (l_ptr->max_pkt < (to_pos + size))
		return 0;

	skb_put(bundler, pad + size);
	skb_copy_to_linear_data_offset(bundler, to_pos, buf->data, size);
	msg_set_size(bundler_msg, to_pos + size);
	msg_set_msgcnt(bundler_msg, msg_msgcnt(bundler_msg) + 1);
	dbg("Packed msg # %u(%u octets) into pos %u in buf(#%u)\n",
	    msg_msgcnt(bundler_msg), size, to_pos, msg_seqno(bundler_msg));
	msg_dbg(msg, "PACKD:");
	buf_discard(buf);
	l_ptr->stats.sent_bundled++;
	return 1;
}

static void link_add_to_outqueue(struct link *l_ptr,
				 struct sk_buff *buf,
				 struct tipc_msg *msg)
{
	u32 ack = mod(l_ptr->next_in_no - 1);
	u32 seqno = mod(l_ptr->next_out_no++);

	msg_set_word(msg, 2, ((ack << 16) | seqno));
	msg_set_bcast_ack(msg, l_ptr->owner->bclink.last_in);
	buf->next = NULL;
	if (l_ptr->first_out) {
		l_ptr->last_out->next = buf;
		l_ptr->last_out = buf;
	} else {
		l_ptr->first_out = l_ptr->last_out = buf;

		/* �ռ���ʾ���±��ķ��ͣ�����һ��һ�𳡾������ش�ʱ�� */
		if (l_ptr->continuity_interval > l_ptr->fast_intv) {
			l_ptr->continuity_interval = l_ptr->fast_intv;
			link_set_timer(l_ptr, l_ptr->fast_intv);
		}
	}
	l_ptr->out_queue_size++;
}

/*
 * tipc_link_send_buf() is the 'full path' for messages, called from
 * inside TIPC when the 'fast path' in tipc_send_buf
 * has failed, and from link_send()
 */

int tipc_link_send_buf(struct link *l_ptr, struct sk_buff *buf)
{
	struct tipc_msg *msg = buf_msg(buf);
	u32 size = msg_size(msg);
	u32 dsz = msg_data_sz(msg);
	u32 queue_size = l_ptr->out_queue_size;
	u32 imp = tipc_msg_tot_importance(msg);
	u32 queue_limit = l_ptr->queue_limit[imp] + OUT_QUE_EXCESS; /* */
	u32 max_packet = l_ptr->max_pkt;

	msg_set_prevnode(msg, tipc_own_addr);	/* If routed message */

	/* Match msg importance against queue limits: */

	if (unlikely(queue_size >= queue_limit)) {
		if (imp <= TIPC_CRITICAL_IMPORTANCE) {
			return link_schedule_port(l_ptr, msg_origport(msg),
						  size);
		}
		msg_dbg(msg, "TIPC: Congestion, throwing away\n");
		buf_discard(buf);
		if (imp > CONN_MANAGER) {
			tipc_link_reset(l_ptr, "send queue full", imp, 0, 0);
		}
		return dsz;
	}

	/* Fragmentation needed ? */

	if (size > max_packet)
		return tipc_link_send_long_buf(l_ptr, buf);

	/* Packet can be queued or sent: */

	if (queue_size > l_ptr->stats.max_queue_sz)
		l_ptr->stats.max_queue_sz = queue_size;

	if (likely(!tipc_bearer_congested(l_ptr->b_ptr, l_ptr) &&
		   !link_congested(l_ptr))) {
		link_add_to_outqueue(l_ptr, buf, msg);

		if (likely(tipc_bearer_send(l_ptr->b_ptr, buf, &l_ptr->media_addr))) {
			l_ptr->unacked_window = 0;
		} else {
			tipc_bearer_schedule(l_ptr->b_ptr, l_ptr);
			l_ptr->stats.bearer_congs++;
			l_ptr->next_out = buf;
		}
		return dsz;
	}
	/* Congestion: can message be bundled ?: */

	if ((msg_user(msg) != CHANGEOVER_PROTOCOL) &&
	    (msg_user(msg) != MSG_FRAGMENTER)) {

		/* Try adding message to an existing bundle */

		if (l_ptr->next_out &&
		    link_bundle_buf(l_ptr, l_ptr->last_out, buf)) {
			tipc_bearer_resolve_congestion(l_ptr->b_ptr, l_ptr);
			return dsz;
		}

		/* Try creating a new bundle */

		if (size <= max_packet * 2 / 3) {
			struct sk_buff *bundler = buf_acquire(max_packet);
			struct tipc_msg bundler_hdr;

			if (bundler) {
				tipc_msg_init(&bundler_hdr, MSG_BUNDLER, OPEN_MSG,
					      INT_H_SIZE, l_ptr->addr);
				/* ^_^ MSG_BUNDLER ��ǰû��ʹ�ø��ֶ� */
				msg_set_nametype(&bundler_hdr, msg_nametype(buf_msg(buf)));				
				skb_copy_to_linear_data(bundler, &bundler_hdr,
							INT_H_SIZE);
				skb_trim(bundler, INT_H_SIZE);
				link_bundle_buf(l_ptr, bundler, buf);
				buf = bundler;
				msg = buf_msg(buf);
				l_ptr->stats.sent_bundles++;
			}
		}
	}
	if (!l_ptr->next_out)
		l_ptr->next_out = buf;
	link_add_to_outqueue(l_ptr, buf, msg);
	tipc_bearer_resolve_congestion(l_ptr->b_ptr, l_ptr);
	return dsz;
}

/*
 * tipc_link_send(): same as tipc_link_send_buf(), but the link to use has
 * not been selected yet, and the the owner node is not locked
 * Called by TIPC internal users, e.g. the name distributor
 */

int tipc_link_send(struct sk_buff *buf, u32 dest, u32 selector)
{
	struct link *l_ptr;
	struct tipc_node *n_ptr;
	int res = -ELINKCONG;

	read_lock_bh(&tipc_net_lock);
	n_ptr = tipc_net_select_node(dest);
	if (n_ptr) {
		tipc_node_lock(n_ptr);
		l_ptr = n_ptr->active_links[selector & 1];
		if (l_ptr) {
			dbg("tipc_link_send: found link %x for dest %x\n", l_ptr, dest);
			res = tipc_link_send_buf(l_ptr, buf);
		} else {
			dbg("Attempt to send msg to unreachable node:\n");
			msg_dbg(buf_msg(buf),">>>");
			buf_discard(buf);
		}
		tipc_node_unlock(n_ptr);
	} else {
		dbg("Attempt to send msg to unknown node:\n");
		msg_dbg(buf_msg(buf),">>>");
		buf_discard(buf);
	}
	read_unlock_bh(&tipc_net_lock);
	return res;
}

/*
 * link_send_buf_fast: Entry for data messages where the
 * destination link is known and the header is complete,
 * inclusive total message length. Very time critical.
 * Link is locked. Returns user data length.
 */

static int link_send_buf_fast(struct link *l_ptr, struct sk_buff *buf,
			      u32 *used_max_pkt)
{
	struct tipc_msg *msg = buf_msg(buf);
	int res = msg_data_sz(msg);

	if (likely(!link_congested(l_ptr))) {
		if (likely(msg_size(msg) <= l_ptr->max_pkt)) {
			if (likely(list_empty(&l_ptr->b_ptr->cong_links))) {
				link_add_to_outqueue(l_ptr, buf, msg);

				if (likely(tipc_bearer_send(l_ptr->b_ptr, buf,
							    &l_ptr->media_addr))) {
					l_ptr->unacked_window = 0;
					msg_dbg(msg,"SENT_FAST:");
					return res;
				}
				dbg("failed sent fast...\n");
				tipc_bearer_schedule(l_ptr->b_ptr, l_ptr);
				l_ptr->stats.bearer_congs++;
				l_ptr->next_out = buf;
				return res;
			}
		}
		else
			*used_max_pkt = l_ptr->max_pkt;
	}
	return tipc_link_send_buf(l_ptr, buf);  /* All other cases */
}

/*
 * tipc_send_buf_fast: Entry for data messages where the
 * destination node is known to be off-node and the header is complete,
 * inclusive total message length.
 * Returns user data length.
 */
int tipc_send_buf_fast(struct sk_buff *buf, u32 destnode)
{
	struct link *l_ptr;
	struct tipc_node *n_ptr;
	int res;
	u32 selector = msg_origport(buf_msg(buf)) & 1;
	u32 dummy;

	dbg_assert(!addr_in_node(destnode));

	read_lock_bh(&tipc_net_lock);
	n_ptr = tipc_net_select_node(destnode);

	if (likely(n_ptr)) {
		tipc_node_lock(n_ptr);
		l_ptr = n_ptr->active_links[selector];
		dbg("send_fast: buf %x selected %x, destnode = %x\n",
		    buf, l_ptr, destnode);
		if (likely(l_ptr)) {
			res = link_send_buf_fast(l_ptr, buf, &dummy);
			tipc_node_unlock(n_ptr);
			read_unlock_bh(&tipc_net_lock);
			return res;
		}
		tipc_node_unlock(n_ptr);
	}
	read_unlock_bh(&tipc_net_lock);
	/* res = msg_data_sz(buf_msg(buf)); */
	return tipc_reject_msg(buf, TIPC_ERR_NO_NODE);
	/* return res; */
}

struct link *tipc_link_select(struct port *sender,
	struct tipc_node *n_ptr, u32 selector, u32 next)
{
	struct link *act = n_ptr->active_links[selector & 1];
	/* ����dontroute��ʾ�����·״̬��ǿ�Ʊ���������·������֤���ĵ���˳�� */
	if (unlikely(sender->publ.msg_flags && act)) {
		int i = sender->publ.selector + next;
		int k = 0;
		struct link *l_ptr = NULL;
		for (k=0; k<TIPC_MAX_LINKS; k++, i++) {
			if (i >= TIPC_MAX_LINKS)
				i = 0;
			l_ptr = n_ptr->links[i];
            /* ȥ��fast_standby��·���Բ��Կ����л����� */
			if (!tipc_link_is_up(l_ptr) || (l_ptr->fast_standby))
				continue;
			if (l_ptr->priority < act->priority) /* ֻʹ��������ȼ�����· */
				continue;

			sender->publ.selector = i; /* for next */
			return l_ptr;
		}
	}

	return act; /* ����fast_standby�жϺ��������ѡ������· */
}
/*
 * tipc_link_send_sections_fast: Entry for messages where the
 * destination processor is known and the header is complete,
 * except for total message length.
 * Returns user data length or errno.
 */
int tipc_link_send_sections_fast(struct port *sender,
                                      struct iovec const *msg_sect,
                                      const u32 num_sect,
                                      u32 destaddr)
{
    struct tipc_msg *hdr = &sender->publ.phdr;
    struct link *l_ptr;
    struct sk_buff *buf;
    struct tipc_node *node;
    int res;
    u32 selector = msg_origport(hdr) & 1;

again:
    /*
     * Try building message using port's max_pkt hint.
     * (Must not hold any locks while building message.)
     */

    res = tipc_msg_build(hdr, msg_sect, num_sect, sender->publ.max_pkt,
                         !sender->user_port, &buf);
    read_lock_bh(&tipc_net_lock);
    node = tipc_net_select_node(destaddr);

    if (likely(node)) {
        tipc_node_lock(node);
        l_ptr = tipc_link_select(sender, node, selector, 1);
        if (likely(l_ptr)) {
            if (likely(buf)) {
                buf->priority = sender->publ.sk_priority; /* tipc_priority */
                #ifdef CONFIG_TIPC_PORT_STATISTICS
                tipc_port_msg_stats(buf, sender, TIPC_PORT_SNDMSG); /* ��������ͳ�� */
                #endif
                res = link_send_buf_fast(l_ptr, buf, &sender->publ.max_pkt);
                if (unlikely(res < 0))
                    buf_discard(buf);
exit:
                tipc_node_unlock(node);
                read_unlock_bh(&tipc_net_lock);
                return res;
            }

            /* Exit if build request was invalid */

            if (unlikely(res < 0))
                goto exit;

            /* Exit if link (or bearer) is congested */
            /* see OUT_QUE_EXCESS */
            if (l_ptr->out_queue_size >= l_ptr->queue_limit[0]+OUT_QUE_EXCESS ||
                !list_empty(&l_ptr->b_ptr->cong_links)) {
                res = link_schedule_port(l_ptr, sender->publ.ref, res);
                goto exit;
            }

            /* 
             * Message size exceeds max_pkt hint; update hint,
             * then re-try fast path or fragment the message
             */

            sender->publ.max_pkt = l_ptr->max_pkt;
            tipc_node_unlock(node);
            read_unlock_bh(&tipc_net_lock);


            if ((msg_hdr_sz(hdr) + res) <= sender->publ.max_pkt)
                goto again;

            return link_send_sections_long(sender, msg_sect, num_sect, destaddr);
        } else {
            info("tipc_link_select failed %u, dest=%x\n", selector, destaddr);
        }
        tipc_node_unlock(node);
    }
    read_unlock_bh(&tipc_net_lock);

    /* Couldn't find a link to the destination node */

    if (buf)
        return tipc_reject_msg(buf, TIPC_ERR_NO_NODE);
    if (res >= 0)
        return tipc_port_reject_sections(sender, hdr, msg_sect, num_sect, TIPC_ERR_NO_NODE);
    return res;
}

/*
 * link_send_sections_long(): Entry for long messages where the
 * destination node is known and the header is complete,
 * inclusive total message length.
 * Link and bearer congestion status have been checked to be ok,
 * and are ignored if they change.
 *
 * Note that fragments do not use the full link MTU so that they won't have
 * to undergo refragmentation if link changeover causes them to be sent
 * over another link with an additional tunnel header added as prefix.
 * (Refragmentation will still occur if the other link has a smaller MTU.)
 *
 * Returns user data length or errno.
 */
static int link_send_sections_long(struct port *sender,
				   struct iovec const *msg_sect,
				   u32 num_sect,
				   u32 destaddr)
{
	struct link *l_ptr;
	struct tipc_node *node;
	struct tipc_msg *hdr = &sender->publ.phdr;
	u32 dsz = msg_data_sz(hdr);
	u32 max_pkt,fragm_sz,rest;
	struct tipc_msg fragm_hdr;
	struct sk_buff *buf,*buf_chain,*prev;
	u32 fragm_crs,fragm_rest,hsz,sect_rest;
	const unchar *sect_crs;
	int curr_sect;
	u32 fragm_no;

again:
	fragm_no = 1;
	max_pkt = sender->publ.max_pkt - INT_H_SIZE * 3; /* wt: multi changeover */
		/* leave room for tunnel header in case of link changeover */
	fragm_sz = max_pkt - INT_H_SIZE;
		/* leave room for fragmentation header in each fragment */
	/* in case of (max_pkt < INT_H_SIZE * 4) */
	if (unlikely(fragm_sz > sender->publ.max_pkt)) {
		warn("MTU too small for fragment message\n");
		return -ENOMEM;
	}
	
	rest = dsz;
	fragm_crs = 0;
	fragm_rest = 0;
	sect_rest = 0;
	sect_crs = NULL;
	curr_sect = -1;

	/* Prepare reusable fragment header: */

	msg_dbg(hdr, ">FRAGMENTING>");
	tipc_msg_init(&fragm_hdr, MSG_FRAGMENTER, FIRST_FRAGMENT,
		      INT_H_SIZE, msg_destnode(hdr));
	msg_set_link_selector(&fragm_hdr, (sender->publ.ref & 1));
	msg_set_fragm_msg_no(&fragm_hdr, 
			     atomic_inc_return(&link_fragm_msg_no) & 0xffff);
	msg_set_fragm_no(&fragm_hdr, 1);

	/* ^_^ MSG_FRAGMENTER ��ǰû��ʹ�ø��ֶ� */
	msg_set_nametype(&fragm_hdr, msg_nametype(hdr));

	/* Prepare header of first fragment: */

	msg_set_size(&fragm_hdr, max_pkt);
	buf_chain = buf = buf_acquire(max_pkt);
	if (!buf)
		return -ENOMEM;
	buf->next = NULL;
	buf->priority = sender->publ.sk_priority; /* tipc_priority */
	skb_copy_to_linear_data(buf, &fragm_hdr, INT_H_SIZE);
	hsz = msg_hdr_sz(hdr);
	skb_copy_to_linear_data_offset(buf, INT_H_SIZE, hdr, hsz);
	msg_dbg(buf_msg(buf), ">BUILD>");

	/* Chop up message: */

	fragm_crs = INT_H_SIZE + hsz;
	fragm_rest = fragm_sz - hsz;

	do {		/* For all sections */
		u32 sz;

		if (!sect_rest) {
			sect_rest = msg_sect[++curr_sect].iov_len;
			sect_crs = (const unchar *)msg_sect[curr_sect].iov_base;
		}

		if (sect_rest < fragm_rest)
			sz = sect_rest;
		else
			sz = fragm_rest;

		if (likely(!sender->user_port)) {
			if (copy_from_user(buf->data + fragm_crs, sect_crs, sz)) {
error:
				for (; buf_chain; buf_chain = buf) {
					buf = buf_chain->next;
					buf_discard(buf_chain);
				}
				return -EFAULT;
			}
		} else
			skb_copy_to_linear_data_offset(buf, fragm_crs,
						       sect_crs, sz);
		sect_crs += sz;
		sect_rest -= sz;
		fragm_crs += sz;
		fragm_rest -= sz;
		rest -= sz;

		if (!fragm_rest && rest) {

			/* Initiate new fragment: */
			if (rest <= fragm_sz) {
				fragm_sz = rest;
				msg_set_type(&fragm_hdr,LAST_FRAGMENT);
			} else {
				msg_set_type(&fragm_hdr, FRAGMENT);
			}
			msg_set_size(&fragm_hdr, fragm_sz + INT_H_SIZE);
			msg_set_fragm_no(&fragm_hdr, ++fragm_no);
			prev = buf;
			buf = buf_acquire(fragm_sz + INT_H_SIZE);
			if (!buf)
				goto error;

			buf->next = NULL;
			prev->next = buf;
			buf->priority = sender->publ.sk_priority; /* tipc_priority */
			skb_copy_to_linear_data(buf, &fragm_hdr, INT_H_SIZE);
			fragm_crs = INT_H_SIZE;
			fragm_rest = fragm_sz;
			msg_dbg(buf_msg(buf),"  >BUILD>");
		}
	}
	while (rest > 0);

	/*
	 * Now we have a buffer chain. Select a link and check
	 * that packet size is still OK
	 */

	node = tipc_net_select_node(destaddr);

	if (likely(node)) {
		tipc_node_lock(node);
		l_ptr = tipc_link_select(sender, node, sender->publ.ref & 1, 0);
		if (!l_ptr) {
            info("section:tipc_link_select failed %u, dest=%x\n", sender->publ.ref, destaddr);
			tipc_node_unlock(node);
			goto reject;
		}
		if (l_ptr->max_pkt < max_pkt) {
			sender->publ.max_pkt = l_ptr->max_pkt;
			tipc_node_unlock(node);
			for (; buf_chain; buf_chain = buf) {
				buf = buf_chain->next;
				buf_discard(buf_chain);
			}
			goto again;
		}
	} else {
reject:
		for (; buf_chain; buf_chain = buf) {
			buf = buf_chain->next;
			buf_discard(buf_chain);
		}
		return tipc_port_reject_sections(sender, hdr, msg_sect, num_sect,
						 TIPC_ERR_NO_NODE);
	}

	/* Append whole chain to send queue: */

	buf = buf_chain;
	if (!l_ptr->next_out)
		l_ptr->next_out = buf_chain;
	l_ptr->stats.sent_fragmented++;
	while (buf) {
		struct sk_buff *next = buf->next;
		struct tipc_msg *msg = buf_msg(buf);

		l_ptr->stats.sent_fragments++;
		link_add_to_outqueue(l_ptr, buf, msg);
		msg_dbg(msg, ">ADD>");
		buf = next;
	}

	/* Send it, if possible: */

	tipc_link_push_queue(l_ptr);
	tipc_node_unlock(node);
	return dsz;
}

/*
 * tipc_link_push_packet: Push one unsent packet to the media
 */
u32 tipc_link_push_packet(struct link *l_ptr)
{
	struct sk_buff *buf = l_ptr->first_out;
	u32 r_q_size = l_ptr->retransm_queue_size;
	u32 r_q_head = l_ptr->retransm_queue_head;

	/* Step to position where retransmission failed, if any,    */
	/* consider that buffers may have been released in meantime */

	if (r_q_size && buf) {
		u32 last = lesser(mod(r_q_head + r_q_size),
				  link_last_sent(l_ptr));
		u32 first = buf_seqno(buf);

		while (buf && less(first, r_q_head)) {
			first = mod(first + 1);
			buf = buf->next;
		}
		l_ptr->retransm_queue_head = r_q_head = first;
		l_ptr->retransm_queue_size = r_q_size = mod(last - first);
	}

	/* Continue retransmission now, if there is anything: */

	if (r_q_size && buf) {
		msg_set_ack(buf_msg(buf), mod(l_ptr->next_in_no - 1));
		msg_set_bcast_ack(buf_msg(buf), l_ptr->owner->bclink.last_in);
		if (tipc_bearer_send(l_ptr->b_ptr, buf, &l_ptr->media_addr)) {
			msg_dbg(buf_msg(buf), ">DEF-RETR>");
			l_ptr->retransm_queue_head = mod(++r_q_head);
			l_ptr->retransm_queue_size = --r_q_size;
			l_ptr->stats.retransmitted++;
			return 0;
		} else {
			l_ptr->stats.bearer_congs++;
			msg_dbg(buf_msg(buf), "|>DEF-RETR>");
			return PUSH_FAILED;
		}
	}

	/* Send deferred protocol message, if any: */

	buf = l_ptr->proto_msg_queue;
	if (buf) {
		msg_set_ack(buf_msg(buf), mod(l_ptr->next_in_no - 1));
		msg_set_bcast_ack(buf_msg(buf),l_ptr->owner->bclink.last_in);
		if (tipc_bearer_send(l_ptr->b_ptr, buf, &l_ptr->media_addr)) {
			msg_dbg(buf_msg(buf), ">DEF-PROT>");
			l_ptr->unacked_window = 0;
			buf_discard(buf);
			l_ptr->proto_msg_queue = NULL;
			return 0;
		} else {
			msg_dbg(buf_msg(buf), "|>DEF-PROT>");
			l_ptr->stats.bearer_congs++;
			return PUSH_FAILED;
		}
	}

	/* Send one deferred data message, if send window not full: */

	buf = l_ptr->next_out;
	if (buf) {
		struct tipc_msg *msg = buf_msg(buf);
		u32 next = msg_seqno(msg);
		u32 first = buf_seqno(l_ptr->first_out);

		if (mod(next - first) < l_ptr->queue_limit[0]) {
			msg_set_ack(msg, mod(l_ptr->next_in_no - 1));
			msg_set_bcast_ack(msg, l_ptr->owner->bclink.last_in);
			if (msg_user(msg) == MSG_BUNDLER) /* set before check */
				msg_set_type(msg, CLOSED_MSG);
			if (tipc_bearer_send(l_ptr->b_ptr, buf, &l_ptr->media_addr)) {
				msg_dbg(msg, ">PUSH-DATA>");
				l_ptr->next_out = buf->next;
				return 0;
			} else {
				msg_dbg(msg, "|PUSH-DATA|");
				l_ptr->stats.bearer_congs++;
				return PUSH_FAILED;
			}
		}
	}
	return PUSH_FINISHED;
}

/*
 * push_queue(): push out the unsent messages of a link where
 *               congestion has abated. Node is locked
 */
void tipc_link_push_queue(struct link *l_ptr)
{
	u32 res;

	if (tipc_bearer_congested(l_ptr->b_ptr, l_ptr))
		return;

	do {
		res = tipc_link_push_packet(l_ptr);
	}
	while (!res);
	if (res == PUSH_FAILED)
		tipc_bearer_schedule(l_ptr->b_ptr, l_ptr);
}

void link_reset_all(unsigned long addr)
{
	struct tipc_node *n_ptr;
	char addr_string[16];
	u32 i;

	read_lock_bh(&tipc_net_lock);
	n_ptr = tipc_net_find_node((u32)addr);
	if (!n_ptr) {
		read_unlock_bh(&tipc_net_lock);
		return;	/* node no longer exists */
	}

	tipc_node_lock(n_ptr);

	tipc_addr_string_fill(addr_string, addr);
	warn("Resetting all links to %s\n", addr_string);

	for (i = 0; i < TIPC_MAX_LINKS; i++) {
		if (n_ptr->links[i]) {

			dbg_print_link_state(TIPC_OUTPUT, n_ptr->links[i]);
			tipc_link_reset(n_ptr->links[i],  "reset_all", addr, i, 0);
			/*
			 * ��������RESET����ֹ����linkʱ�����󣬶Զ˲��ܸ�֪��lost node
			 * t0 me link1 send reset
			 * t1 pe link1 recv reset, send activate
			 * t2 me link1 recv active, send state
			 * t3 me link2 send reset, �Զ��Ѿ���link1 up, ����֪lost node
			 */
			tipc_link_send_proto_msg(n_ptr->links[i], RESET_MSG, 0, 0, 0, 0, 0, 0);
		}
	}

	tipc_node_unlock(n_ptr);
	read_unlock_bh(&tipc_net_lock);
}

static void link_retransmit_failure(struct link *l_ptr, struct sk_buff *buf)
{
	warn("Retransmission failure on link <%s>\n", l_ptr->name);
	tipc_msg_dbg(TIPC_OUTPUT, buf_msg(buf), ">RETR-FAIL>");

	if (l_ptr->addr) {

		/* Handle failure on standard link */

		dbg_print_link_state(TIPC_OUTPUT, l_ptr);
		tipc_link_reset(l_ptr,"retransmit_fail", l_ptr->addr, 0, 0);

	} else {

		/* Handle failure on broadcast link */

		struct tipc_node *n_ptr;
		char addr_string[16];

		/* change to tipc_printf */
		tipc_printf(TIPC_OUTPUT, "Msg seq number: %u,  ", buf_seqno(buf));
		tipc_printf(TIPC_OUTPUT, "Outstanding acks: %u\n", (u32)(unsigned long)buf_handle(buf));
		
		/* recover retransmit requester */
		n_ptr = (struct tipc_node *)l_ptr->owner->node_list.next;
		/* tipc_node_lock(n_ptr); see tipc_bclink_recv_pkt() */

		tipc_addr_string_fill(addr_string, n_ptr->elm.addr);
#ifdef CONFIG_TIPC_MCASTGID_MAX   /* */		
		tipc_printf(TIPC_OUTPUT, "Multicast link info for %s\n", addr_string);
		tipc_node_mcstat(n_ptr, TIPC_OUTPUT); /* */
#else
		dbg_printf(TIPC_OUTPUT, "Broadcast link info for %s\n", addr_string);
		dbg_printf(TIPC_OUTPUT, "Supported: %d,  ", n_ptr->bclink.supported);
		dbg_printf(TIPC_OUTPUT, "Acked: %u\n", n_ptr->bclink.acked);
		dbg_printf(TIPC_OUTPUT, "Last in: %u,  ", n_ptr->bclink.last_in);
		dbg_printf(TIPC_OUTPUT, "Oos state: %u,  ", n_ptr->bclink.oos_state);
		dbg_printf(TIPC_OUTPUT, "Last sent: %u\n", n_ptr->bclink.last_sent);
#endif /* */	

		tipc_k_signal((Handler)link_reset_all, (unsigned long)n_ptr->elm.addr);

		/* tipc_node_unlock(n_ptr); see tipc_bclink_recv_pkt() */

		l_ptr->stale_count = 0;
	}
}

void tipc_link_retransmit(struct link *l_ptr, struct sk_buff *buf,
			  u32 retransmits)
{
	struct tipc_msg *msg;

	if (!buf)
		return;

	msg = buf_msg(buf);

    if (tipc_ratelimit(++l_ptr->retx_count, 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_LINK)){
		info("Retransmitting [%u,%u) on link %s, out:%u,retx: %u\n",
            msg_seqno(msg), retransmits, l_ptr->name, mod(l_ptr->next_out_no), l_ptr->retx_count);
    }

	if (tipc_bearer_congested(l_ptr->b_ptr, l_ptr)) {
		if (l_ptr->retransm_queue_size == 0) {
			msg_dbg(msg, ">NO_RETR->BCONG>");
			dbg_print_link(l_ptr, "   ");
			l_ptr->retransm_queue_head = msg_seqno(msg);
			l_ptr->retransm_queue_size = retransmits;
		} else {
			err("Unexpected retransmit on link %s (qsize=%d)\n",
			    l_ptr->name, l_ptr->retransm_queue_size);
		}
		return;
	} else {
		/* Detect repeated retransmit failures on uncongested bearer */

		if (l_ptr->last_retransmitted == msg_seqno(msg)) {
			/* 2011-8�����ٴ�������Ϊ�ش����ʧ�ܱ����й���. �鲥��Ӵ� */
			if (++l_ptr->stale_count > (l_ptr->addr ? 10 : 300)) {
				link_retransmit_failure(l_ptr, buf);
				return;
			}
		} else {
			l_ptr->last_retransmitted = msg_seqno(msg);
			l_ptr->stale_count = 1;
		}
	}

	while (retransmits && (buf != l_ptr->next_out) && buf) {
		msg = buf_msg(buf);
		msg_set_ack(msg, mod(l_ptr->next_in_no - 1));
		msg_set_bcast_ack(msg, l_ptr->owner->bclink.last_in);
		if (tipc_bearer_send(l_ptr->b_ptr, buf, &l_ptr->media_addr)) {
			msg_dbg(buf_msg(buf), ">RETR>");
			buf = buf->next;
			retransmits--;
			l_ptr->stats.retransmitted++;
		} else {
			tipc_bearer_schedule(l_ptr->b_ptr, l_ptr);
			l_ptr->stats.bearer_congs++;
			l_ptr->retransm_queue_head = buf_seqno(buf);
			l_ptr->retransm_queue_size = retransmits;
			return;
		}
	}

	/* */
	link_halve_window(l_ptr);

	l_ptr->retransm_queue_head = l_ptr->retransm_queue_size = 0;
}

/**
 * link_insert_deferred_queue - insert deferred messages back into receive chain
 */

static struct sk_buff *link_insert_deferred_queue(struct link *l_ptr,
						  struct sk_buff *buf, u32 *defer_flag)
{
	u32 seq_no;
    *defer_flag = TIPC_NEED_PRINT;
	if (l_ptr->oldest_deferred_in == NULL)
		return buf;

	seq_no = buf_seqno(l_ptr->oldest_deferred_in);
	if (seq_no == mod(l_ptr->next_in_no)) {
		l_ptr->newest_deferred_in->next = buf;
		buf = l_ptr->oldest_deferred_in;
		l_ptr->oldest_deferred_in = NULL;
		l_ptr->deferred_inqueue_sz = 0;
        *defer_flag = TIPC_NONEED_PRINT;
	}
	return buf;
}

/**
 * link_recv_buf_validate - validate basic format of received message
 *
 * This routine ensures a TIPC message has an acceptable header, and at least
 * as much data as the header indicates it should.  The routine also ensures
 * that the entire message header is stored in the main fragment of the message
 * buffer, to simplify future access to message header fields.
 *
 * Note: Having extra info present in the message header or data areas is OK.
 * TIPC will ignore the excess, under the assumption that it is optional info
 * introduced by a later release of the protocol.
 */

static int link_recv_buf_validate(struct sk_buff *buf)
{
	static u32 min_data_hdr_size[8] = {
		SHORT_H_SIZE, MCAST_H_SIZE, LONG_H_SIZE, DIR_MSG_H_SIZE,
		MAX_H_SIZE, MAX_H_SIZE, MAX_H_SIZE, MAX_H_SIZE
		};

	struct tipc_msg *msg;
	u32 tipc_hdr[2];
	u32 size;
	u32 hdr_size;
	u32 min_hdr_size;

	if (unlikely(buf->len < MIN_H_SIZE))
		return 0;

	msg = skb_header_pointer(buf, 0, sizeof(tipc_hdr), tipc_hdr);
	if (msg == NULL)
		return 0;

	if (unlikely(msg_version(msg) != TIPC_VERSION))
		return 0;

	size = msg_size(msg);
	hdr_size = msg_hdr_sz(msg);
	min_hdr_size = msg_isdata(msg) ?
		min_data_hdr_size[msg_type(msg)] : INT_H_SIZE;

	if (unlikely((hdr_size < min_hdr_size) ||
		     (size < hdr_size) ||
		     (buf->len < size) ||
		     (size - hdr_size > TIPC_MAX_USER_MSG_SIZE)))
		return 0;

	return pskb_may_pull(buf, hdr_size);
}
/* ��Ϊ�������ڲ���ģ��İ� */
int buf_emulate_bad(struct sk_buff *buf, u32 pos)
{
/* Used to test msg checking.
 * Set to N to cause every N'th frame to be discarded; 0 => don't discard any.
 */
#define TIPC_LINK_BAD_RATE  0

#if (TIPC_LINK_BAD_RATE)
    	static int the_count = 0;
		unsigned int ran = 0;
		get_random_bytes(&ran, sizeof(ran));
		ran %= 1000011u;

    	if (ran < tipc_check_len && tipc_check_rate == 0) {
    		the_count = 0;
            buf->data[pos] ^= 0x10; /* ��һ����� */
			return 1;
    	}
#endif
	return (buf || pos); /* �Ӽ���ָ���ֹ�޷��򲹶� */
}
/* ����lastseq���ܣ���Ҫ����lastseq��¼�ڴ�
������tipc_alloc_lastseq������Ȼ��ִ������
debugging tipc link log  switch   on slot xx
�����޸�ȫ�ֱ���g_tipc_dbg_switch = 4*/
/* �����߱�֤��node������������*/
void tipc_alloc_lastseq(struct link *l_ptr)
{
    u32 list_len = sizeof(u16) * TIPC_LASTSEQ_MAXRECORDNUM;
    if (!l_ptr) {
        return;
    }
    if (l_ptr->recvseq_info.seqno_list) {
        info("alreay alloc lastseq=%s\n", l_ptr->name);
        return;
    }
    l_ptr->recvseq_info.seqno_list = kzalloc(list_len, GFP_ATOMIC);
    if (l_ptr->recvseq_info.seqno_list) {
        l_ptr ->recvseq_info.curindex = 0;
        info("tipc success alloc lastseq=%s\n", l_ptr->name);
    }
}

/* �����߱�֤��node������������ */
void tipc_save_lastseq(struct link *l_ptr, u16 seqno)
{
    u16 temp_index = 0;
    if (!(l_ptr->recvseq_info.seqno_list)) {
        return;
    }
    temp_index = l_ptr ->recvseq_info.curindex;
    if (temp_index >= TIPC_LASTSEQ_MAXRECORDNUM) {
        temp_index = 0;
        l_ptr ->recvseq_info.curindex = 0;
    }
    l_ptr->recvseq_info.seqno_list[temp_index] = seqno;
    l_ptr ->recvseq_info.curindex++;
}


/* �����߱�֤��node������������ */
void tipc_print_lastseqinfo(struct link *l_ptr, u16 print_cnt, char *description, u32 seq_no)
{
    u16 index = 0;
    u16 loop = 0;
    u16 line = 0;
    u16 print_mod;
    u16 tmp_list[TIPC_LASTSEQ_MAXRECORDNUM] = {0};
    if (!l_ptr || !description  || !(l_ptr->recvseq_info.seqno_list)) {
        return;
    }
    info("%s link %s info, msg_no:%u, in:%u\n",
       l_ptr->name, description, seq_no, mod(l_ptr->next_in_no));

    if (print_cnt > TIPC_LASTSEQ_MAXRECORDNUM){
        print_cnt = TIPC_LASTSEQ_MAXRECORDNUM;
    }
    index = l_ptr->recvseq_info.curindex;
    if (index > TIPC_LASTSEQ_MAXRECORDNUM) {
        index = TIPC_LASTSEQ_MAXRECORDNUM;
    }
    for (loop = 0; loop < print_cnt; loop++) {
        if (index == 0) {
            index = (TIPC_LASTSEQ_MAXRECORDNUM - 1);
        }else {
            index--;
        }
        tmp_list[loop] = l_ptr->recvseq_info.seqno_list[index];
    }
    line = print_cnt / INDEX_MAX;
    /* ÿ�д�ӡ8����� */
    for (loop = 0; loop < line; loop++ ) {
        info("%05u %05u %05u %05u %05u %05u %05u %05u\n",
            tmp_list[INDEX_MAX * loop], tmp_list[INDEX_MAX * loop + INDEX_1],
            tmp_list[INDEX_MAX * loop + INDEX_2], tmp_list[INDEX_MAX * loop + INDEX_3],
            tmp_list[INDEX_MAX * loop + INDEX_4], tmp_list[INDEX_MAX * loop + INDEX_5],
            tmp_list[INDEX_MAX * loop + INDEX_6], tmp_list[INDEX_MAX * loop + INDEX_7]);

    }
    print_mod = print_cnt % INDEX_MAX;
    /* ��ӡδ����8��ʣ���� */
    switch(print_mod) {
        case INDEX_1:
            info("%05u\n", tmp_list[INDEX_MAX * loop]);
            break;
        case INDEX_2:
            info("%05u %05u\n", tmp_list[INDEX_MAX * loop], tmp_list[INDEX_MAX * loop + INDEX_1]);
            break;
        case INDEX_3:
            info("%05u %05u %05u\n",
                tmp_list[INDEX_MAX * loop], tmp_list[INDEX_MAX * loop + INDEX_1],
                tmp_list[INDEX_MAX * loop + INDEX_2]);
            break;
        case INDEX_4:
            info("%05u %05u %05u %05u\n",
                tmp_list[INDEX_MAX * loop], tmp_list[INDEX_MAX * loop + INDEX_1],
                tmp_list[INDEX_MAX * loop + INDEX_2], tmp_list[INDEX_MAX * loop + INDEX_3]);
            break;
        case INDEX_5:
            info("%05u %05u %05u %05u %05u\n",
                tmp_list[INDEX_MAX * loop], tmp_list[INDEX_MAX * loop + INDEX_1],
                tmp_list[INDEX_MAX * loop + INDEX_2], tmp_list[INDEX_MAX * loop + INDEX_3],
                tmp_list[INDEX_MAX * loop + INDEX_4]);
            break;
        case INDEX_6:
            info("%05u %05u %05u %05u %05u %05u\n",
                tmp_list[INDEX_MAX * loop], tmp_list[INDEX_MAX * loop + INDEX_1],
                tmp_list[INDEX_MAX * loop + INDEX_2], tmp_list[INDEX_MAX * loop + INDEX_3],
                tmp_list[INDEX_MAX * loop + INDEX_4], tmp_list[INDEX_MAX * loop + INDEX_5]);
            break;
         case INDEX_7:
            info("%05u %05u %05u %05u %05u %05u %05u\n",
                tmp_list[INDEX_MAX * loop], tmp_list[INDEX_MAX * loop + INDEX_1],
                tmp_list[INDEX_MAX * loop + INDEX_2], tmp_list[INDEX_MAX * loop + INDEX_3],
                tmp_list[INDEX_MAX * loop + INDEX_4], tmp_list[INDEX_MAX * loop + INDEX_5],
                tmp_list[INDEX_MAX * loop + INDEX_6]);
            break;
        default:
            break;
    }
}
/* �����߱�֤��node������������ */
void tipc_lastseqproc(struct link *l_ptr, u32 seq_no, u32 usr_type, u32 defer_flag)
{
    if (usr_type == LINK_PROTOCOL || defer_flag == TIPC_NONEED_PRINT) {
        return;
    }
    /* ��¼��proto�ͷ�defer���б��� */
    tipc_save_lastseq(l_ptr, (u16)seq_no);
    if (l_ptr->recvseq_info.need_print_lastseq== TIPC_NEED_PRINT) {
        l_ptr->recvseq_info.recv_cnt++;
        if (l_ptr->recvseq_info.recv_cnt >= TIPC_NORMAL_THRESHOLDNUM) {
            tipc_print_lastseqinfo(l_ptr, TIPC_NORMAL_PRINTNUM, "last", seq_no);
            l_ptr->recvseq_info.recv_cnt = 0;
            l_ptr->recvseq_info.need_print_lastseq= TIPC_NONEED_PRINT;
        }
    }
}

/* �����߱�֤��node������������ */
void tipc_defer_seqproc(struct link *l_ptr, u32 seq_no)
{
    /* ��Ҫ��ӡlastseq��Ϣ */
    l_ptr->recvseq_info.need_print_lastseq = TIPC_NEED_PRINT;
    tipc_print_lastseqinfo(l_ptr, TIPC_DEFFER_PRINTNUM, "defer", seq_no);
}


/**
 * tipc_recv_msg - process TIPC messages arriving from off-node
 * @head: pointer to message buffer chain
 * @tb_ptr: pointer to bearer message arrived on
 * 
 * Invoked with no locks held.  Bearer pointer must point to a valid bearer
 * structure (i.e. cannot be NULL), but bearer can be inactive.
 */

void tipc_recv_msg(struct sk_buff *head, struct tipc_bearer *tb_ptr)
{

    u32 defer_flag = TIPC_NEED_PRINT;
	read_lock_bh(&tipc_net_lock);
    tb_ptr->recv_count++;
	while (head) {
		struct bearer *b_ptr = (struct bearer *)tb_ptr;
		struct tipc_node *n_ptr;
		struct link *l_ptr;
		struct sk_buff *crs;
		struct sk_buff *buf;
		struct tipc_msg *msg;
		u32 type;
		u32 seq_no;
		u32 ackd;
		u32 released;

		buf = head;
		head = head->next;

        /* ʹ��reboot_notify����Ҫ���Ӹ��ж� */
        if (unlikely(TIPC_NET_MODE != tipc_mode)) {
            break;
        }
        
        if (!buf_msg(buf)) {
            warn("skb %p null data\n", buf); /* */
            break;
        }

		/* Ensure bearer is still enabled */

		if (unlikely(!b_ptr->active))
			goto cont;
       		
		/* Ensure message is well-formed */

		if (unlikely(!link_recv_buf_validate(buf))) {
			if (tipc_ratelimit(++tb_ptr->recv_buf_err_cnt, 1)) {
				info("The invalid msg from %s is %d.", tb_ptr->name, tb_ptr->recv_buf_err_cnt);
				tipc_dump_buf(buf);
			}
			goto cont;
		}

		/* 
		 * Ensure message is stored as a single contiguous unit;
		 * support for non-linear sk_buffs is under development ...
		 */

		if (unlikely(buf_linearize(buf))) {
			goto cont;
		}

		/* Handle arrival of a non-unicast link message */

		msg = buf_msg(buf);

		if (unlikely(msg_non_seq(msg))) {
			if (msg_user(msg) == LINK_CONFIG)
				tipc_disc_recv_msg(buf, b_ptr);
			else
				tipc_bclink_recv_pkt(buf);
			continue;
		}

		/* Discard non-routeable messages destined for another node */

		if (unlikely(!msg_isdata(msg) && 
			     (msg_destnode(msg) != tipc_own_addr))) {
			if ((msg_user(msg) != CONN_MANAGER) &&
			    (msg_user(msg) != MSG_FRAGMENTER))
				goto cont;
		}

		/* Locate neighboring node that sent message */

		n_ptr = tipc_net_find_node(msg_prevnode(msg));
		if (unlikely(!n_ptr))
			goto cont;
		tipc_node_lock(n_ptr);

		/* Locate unicast link endpoint that should handle message */
#ifdef CONFIG_TIPC_LINK_TAG   /* */
		l_ptr = tipc_node_find_link_bybuf(n_ptr, b_ptr, buf);
#else /* */
		l_ptr = n_ptr->links[b_ptr->identity];
#endif  /* */
		if (unlikely(!l_ptr)) {
			tipc_node_unlock(n_ptr);
			goto cont;
		}

		/* Verify that communication with node is currently allowed */

		if ((n_ptr->cleanup_required & WAIT_PEER_DOWN) &&
		    (msg_user(msg) == LINK_PROTOCOL) &&
		    (msg_type(msg) == RESET_MSG ||
		     msg_type(msg) == ACTIVATE_MSG) &&
		    !msg_redundant_link(msg))
		    n_ptr->cleanup_required &= ~WAIT_PEER_DOWN;

		if (n_ptr->cleanup_required) {
			tipc_node_unlock(n_ptr);
			goto cont;
		}


		/* Validate message sequence number info */

		seq_no = msg_seqno(msg);
		ackd = msg_ack(msg);

		/* TODO: Implement stronger sequence # checking someday ... */
	    /* */
		if ((msg_user(msg) == LINK_PROTOCOL && msg_type(msg) != STATE_MSG)) {
		    goto protocol_check;
		}

        if (tipc_dbg_is_on(TIPC_DBG_SWITCH_LINK)) {
            tipc_lastseqproc(l_ptr, seq_no, msg_user(msg), defer_flag);
        }

		if (tipc_link_is_up(l_ptr) && less_eq(l_ptr->next_out_no, ackd)) {
		    goto protocol_check;
		}
		/* Release acked messages */

		if (less(n_ptr->bclink.acked, msg_bcast_ack(msg)) &&
		    tipc_node_is_up(n_ptr) && n_ptr->bclink.supported) {
			/* add param &n_ptr->bclink */
			tipc_bclink_acknowledge(n_ptr, msg_bcast_ack(msg), &n_ptr->bclink);
		}

		released = 0;
		crs = l_ptr->first_out;
		while ((crs != l_ptr->next_out) &&
		       less_eq(buf_seqno(crs), ackd)) {
			struct sk_buff *next = crs->next;

			buf_discard(crs);
			crs = next;
			released++;
		}
		if (released) {
			l_ptr->first_out = crs;
			l_ptr->out_queue_size -= released;

			if (l_ptr->out_queue_size < TIPC_MIN_LINK_WIN)
				link_inc_window(l_ptr);
		}

		/* Try sending any messages link endpoint has pending */

		if (unlikely(l_ptr->next_out))
			tipc_link_push_queue(l_ptr);
		if (unlikely(!list_empty(&l_ptr->waiting_ports)))
			tipc_link_wakeup_ports(l_ptr, 0);
		if (unlikely(++l_ptr->unacked_window >= TIPC_MIN_LINK_WIN)) {
			l_ptr->stats.sent_acks++;
			tipc_link_send_proto_msg(l_ptr, STATE_MSG, 0, 0, 0, 0, 0, 0);
		}

		/* Now (finally!) process the incoming message */

protocol_check:
		if (likely(link_working_working(l_ptr))) {
deliver_check:    /* 2012-12 Fast�л���Ҫ������к� */
			if (likely(seq_no == mod(l_ptr->next_in_no))) {
				l_ptr->next_in_no++;
				if (unlikely(l_ptr->oldest_deferred_in))
					head = link_insert_deferred_queue(l_ptr,
									  head, &defer_flag);
deliver:
                                if (likely(msg_isdata(msg))) {
                                        tipc_node_unlock(n_ptr);
                                        if (likely(msg_short(msg) ||
						   (msg_destnode(msg) == tipc_own_addr))) 
                                                tipc_port_recv_msg(buf);
                                        else
                                                tipc_net_route_msg(buf);
                                        continue;
                                } 

				if (unlikely(msg_destnode(msg) != tipc_own_addr)) {
                                        tipc_node_unlock(n_ptr);
					if ((msg_user(msg) != MSG_FRAGMENTER) &&
					    (msg_user(msg) != CONN_MANAGER))
						goto cont;
					tipc_net_route_msg(buf);
					continue;
				}

                                switch (msg_user(msg)) {
                                case MSG_BUNDLER:
                                        l_ptr->stats.recv_bundles++;
                                        l_ptr->stats.recv_bundled += 
                                                msg_msgcnt(msg);
                                        tipc_node_unlock(n_ptr);
                                        tipc_link_recv_bundle(buf);
                                        continue;
				case NAME_DISTRIBUTOR:
                                        tipc_node_unlock(n_ptr);
					tipc_named_recv(buf);
                                        continue;
				case ROUTE_DISTRIBUTOR:
                                        tipc_node_unlock(n_ptr);
					tipc_route_recv(buf);
                                        continue;
                                case CONN_MANAGER:
                                        /* route message normally */
                                        break;
                                case MSG_FRAGMENTER:
                                        l_ptr->stats.recv_fragments++;
                                        if (tipc_link_recv_fragment(&l_ptr->defragm_buf, 
                                                                    &buf, &msg)) {
                                                l_ptr->stats.recv_fragmented++;
                                                goto deliver;
                                        }
                                        break;
#ifdef CONFIG_TIPC_MULTIPLE_LINKS
                                case CHANGEOVER_PROTOCOL:
                                        type = msg_type(msg);
                                        if (link_recv_changeover_msg(&l_ptr, &buf)) {
                                                msg = buf_msg(buf);
                                                seq_no = msg_seqno(msg);

                                                /* 2012-12 Fast�л���Ҫ������к� */
                                                goto deliver_check;
                                        }
                                        break;
#endif
				default:
					dbg("Unsupported message discarded (user=%d)\n",
					    msg_user(msg));
					buf_discard(buf);
					buf = NULL;
					break;
                                }
				tipc_node_unlock(n_ptr);
				tipc_net_route_msg(buf);
				continue;
			}
			link_handle_out_of_seq_msg(l_ptr, buf);
			head = link_insert_deferred_queue(l_ptr, head, &defer_flag);
			tipc_node_unlock(n_ptr);
			continue;
		}

		if (msg_user(msg) == LINK_PROTOCOL) {
			link_recv_proto_msg(l_ptr, buf);
			head = link_insert_deferred_queue(l_ptr, head, &defer_flag);
			tipc_node_unlock(n_ptr);
			continue;
		}
		msg_dbg(msg,"NSEQ<REC<");
		link_state_event(l_ptr, TRAFFIC_MSG_EVT);

		if (link_working_working(l_ptr)) {
			/* Re-insert in front of queue */
			msg_dbg(msg,"RECV-REINS:");
			buf->next = head;
			head = buf;
			tipc_node_unlock(n_ptr);
			continue;
		}
		tipc_node_unlock(n_ptr);
cont:
		buf_discard(buf);
	}
	read_unlock_bh(&tipc_net_lock);
}

/**
 * tipc_link_defer_pkt - Add out-of-sequence message to deferred reception queue
 *
 * Returns increase in queue length (i.e. 0 or 1)
 */

u32 tipc_link_defer_pkt(struct sk_buff **head, struct sk_buff **tail,
			struct sk_buff *buf, u32 buf_seq_no)
{
	struct sk_buff *curr;
	struct sk_buff **prev_link;

	buf->next = NULL;

	/* Handle most likely cases (add to empty queue, or at end of queue) */

	if (!(*head)) {
		*head = *tail = buf;
		return 1;
	}

	if (less(buf_seqno(*tail), buf_seq_no)) {
		(*tail)->next = buf;
		*tail = buf;
		return 1;
	}

	/* Locate insertion point in queue, then insert; discard if duplicate */

	for (prev_link = head, curr = *head; curr && buf_msg(curr);
	     prev_link = &curr->next, curr = curr->next) {
		u32 curr_seq_no = buf_seqno(curr);

		if (buf_seq_no == curr_seq_no) {
			buf_discard(buf);
			return 0;
		}
		
		/* Note: here less_eq() is equivalent to less(), but faster */

		if (less_eq(buf_seq_no, curr_seq_no))
			break;
	}

	if (unlikely(!(curr && buf_msg(curr)))) {
		warn("bad defer queue\n"); /* avoid except, but leak head to tail */
		*head = *tail = buf;
		return 1;
	}

	buf->next = curr;
	*prev_link = buf;
	return 1;
}

/**
 * link_handle_out_of_seq_msg - handle arrival of out-of-sequence packet
 */

static void link_handle_out_of_seq_msg(struct link *l_ptr,
				       struct sk_buff *buf)
{
	u32 seq_no = buf_seqno(buf);

	if (likely(msg_user(buf_msg(buf)) == LINK_PROTOCOL)) {
		link_recv_proto_msg(l_ptr, buf);
		return;
	}

	info_link("<%s> rx OOS msg: seq_no %u, expecting %u (%u), def(%u, %u)\n", l_ptr->name,
	    seq_no, mod(l_ptr->next_in_no), l_ptr->next_in_no,
	    l_ptr->oldest_deferred_in ? buf_seqno(l_ptr->oldest_deferred_in) : 0,
	    l_ptr->newest_deferred_in ? buf_seqno(l_ptr->newest_deferred_in) : 0);

	/* Record OOS packet arrival (force mismatch on next timeout) */

	l_ptr->checkpoint--;

	/*
	 * Discard packet if a duplicate; otherwise add it to deferred queue
	 * and notify peer of gap as per protocol specification
	 */

	if (less(seq_no, mod(l_ptr->next_in_no))) {
		l_ptr->stats.duplicates++;
		buf_discard(buf);
		return;
	}
    /*record defer seq no */
    if (tipc_dbg_is_on(TIPC_DBG_SWITCH_LINK)) {
        tipc_defer_seqproc(l_ptr, seq_no);
    }
	if (tipc_link_defer_pkt(&l_ptr->oldest_deferred_in,
				&l_ptr->newest_deferred_in,
				buf, seq_no)) {
		l_ptr->deferred_inqueue_sz++;
		l_ptr->stats.deferred_recv++;
		if ((l_ptr->deferred_inqueue_sz % 8) == 1)
			tipc_link_send_proto_msg(l_ptr, STATE_MSG, 0, 0, 0, 0, 0, 0);
	} else
		l_ptr->stats.duplicates++;
}

/*
 * Send protocol message to the other endpoint.
 */
void tipc_link_send_proto_msg(struct link *l_ptr, u32 msg_typ, int probe_msg,
                              u32 gap, u32 tolerance, u32 priority, u32 ack_mtu,
                              int stop)
{
	struct sk_buff *buf = NULL;
	struct tipc_msg *msg = l_ptr->pmsg;
	u32 msg_size = sizeof(l_ptr->proto_msg);
	struct tipc_node *n_ptr = l_ptr->owner; /* */
	struct mcast_ackinfo mcinfo[MCINFO_MAX];
	u32 mci_cnt = 0;


	/* Discard any previous message that was deferred due to congestion */
	if (l_ptr->proto_msg_queue) {
		buf_discard(l_ptr->proto_msg_queue);
		l_ptr->proto_msg_queue = NULL;
	}

	/* Abort send if link is blocked */
	if (link_blocked(l_ptr))
		return;

	/* Abort non-RESET send if communication with node is prohibited */

	if ((l_ptr->owner->cleanup_required) && (msg_typ != RESET_MSG))
		return;

	/* Create protocol message with "out-of-sequence" sequence number */

	msg_set_type(msg, msg_typ);
	/* */
	msg_set_net_plane(msg, link_net_plane(l_ptr));
	msg_set_bcast_ack(msg, n_ptr->bclink.last_in);
	if (unlikely(WORKING_WORKING != n_ptr->bclink.state))
		msg_set_last_bcast(msg, n_ptr->bclink.acked);
	else
		msg_set_last_bcast(msg,tipc_bclink_get_last_sent(n_ptr->bclink.mcgl));
	/* end */

	if (msg_typ == STATE_MSG) {
		u32 next_sent = mod(l_ptr->next_out_no);

		if (!tipc_link_is_up(l_ptr))
			return;
		if (l_ptr->next_out)
			next_sent = buf_seqno(l_ptr->next_out);
		msg_set_next_sent(msg, next_sent);
		if (l_ptr->oldest_deferred_in && gap < LINK_GAP_MAX) {
			u32 rec = buf_seqno(l_ptr->oldest_deferred_in);
			gap = mod(rec - mod(l_ptr->next_in_no));
			if (gap > TIPC_DEF_LINK_WIN) {
				warn("Gap %u between old_defer %u and next_in %u on link %s is too large\n", gap,
					rec, mod(l_ptr->next_in_no), l_ptr->name);
			}
		}
		msg_set_seq_gap(msg, gap);
		if (gap && gap < LINK_GAP_MAX) {
			l_ptr->stats.sent_nacks++;
			l_ptr->retx_count++;/*�ն������ش�����,��ֹ���򶪰���ѯ�޼���*/
		}
		msg_set_link_tolerance(msg, tolerance);
		msg_set_linkprio(msg, priority);
		msg_set_max_pkt(msg, ack_mtu);
		msg_set_ack(msg, mod(l_ptr->next_in_no - 1));
		msg_set_probe(msg, probe_msg != 0);
		if (probe_msg) {
			u32 mtu = l_ptr->max_pkt;

			if ((mtu < l_ptr->max_pkt_target) &&
			    link_working_working(l_ptr) &&
			    l_ptr->fsm_msg_cnt) {
				msg_size = (mtu + (l_ptr->max_pkt_target - mtu)/2 + 2) & ~3;
				if (l_ptr->max_pkt_probes == 10) {
					l_ptr->max_pkt_target = (msg_size - 4);
					l_ptr->max_pkt_probes = 0;
					msg_size = (mtu + (l_ptr->max_pkt_target - mtu)/2 + 2) & ~3;
				}
				l_ptr->max_pkt_probes++;
			}

			l_ptr->stats.sent_probes++;
		}
		l_ptr->stats.sent_states++;
	} else {		/* RESET_MSG or ACTIVATE_MSG */
		msg_set_ack(msg, mod(l_ptr->reset_checkpoint - 1));
		msg_set_seq_gap(msg, 0);
		msg_set_next_sent(msg, 1);
		msg_set_stop(msg, stop);
		msg_set_link_tolerance(msg, l_ptr->tolerance);
		msg_set_linkprio(msg, l_ptr->priority);
		msg_set_max_pkt(msg, l_ptr->max_pkt_target);

		if (msg_typ == RESET_MSG && (l_ptr->fsm_msg_cnt % 8 == 7)) {
		    dbg_link("Link <%s> send reset msg %s at msec %u\n",
		        l_ptr->name, (char *)msg_data(msg), jiffies_to_msecs(jiffies));
		}
	}

	msg_set_redundant_link(msg, tipc_node_has_redundant_links(l_ptr));
	msg_set_linkprio(msg, l_ptr->priority);

	/* Ensure sequence number will not fit : */

	msg_set_seqno(msg, mod(l_ptr->next_out_no + (0xffff/2)));
	msg_set_timestamp(msg, jiffies_to_msecs(jiffies)); /* */


	/* ����mcast infoռ�õĿռ�*/
	if (in_own_cluster(l_ptr->owner->elm.addr) &&
		msg_size < sizeof(l_ptr->proto_msg) + LINK_DT_LEN)
		msg_size = sizeof(l_ptr->proto_msg) + LINK_DT_LEN;

	msg_set_size(msg, msg_size);


	buf = buf_acquire(msg_size);
	if (!buf)
		return;

	skb_copy_to_linear_data(buf, msg, sizeof(l_ptr->proto_msg));

	/* mcinfo unacked>=�ǵ���ack������LINK_GAP_MAX�ñ��Ĳ�Я��mcinfo */
	if (in_own_cluster(l_ptr->owner->elm.addr)) {
		if (!(l_ptr->unacked_window >= TIPC_MIN_LINK_WIN))
			mci_cnt = tipc_node_get_mcinfo(n_ptr, mcinfo, MCINFO_MAX);
		TLV_SET(&buf->data[sizeof(l_ptr->proto_msg)], LINK_DT_MCAST,
			(void *)mcinfo, sizeof(mcinfo[0])*mci_cnt);
	}


	/* Defer message if bearer is already congested */

	if (tipc_bearer_congested(l_ptr->b_ptr, l_ptr)) {
		l_ptr->proto_msg_queue = buf;
		return;
	}

	/* Defer message if attempting to send results in bearer congestion */

	if (!tipc_bearer_send(l_ptr->b_ptr, buf, &l_ptr->media_addr)) {
		tipc_bearer_schedule(l_ptr->b_ptr, l_ptr);
		l_ptr->proto_msg_queue = buf;
		l_ptr->stats.bearer_congs++;
		return;
	}

	/* Discard message if it was sent successfully */

	msg_dbg(msg, ">>");
	l_ptr->unacked_window = 0;
	buf_discard(buf);
}

/*
 * Receive protocol message :
 * Note that network plane id propagates through the network, and may
 * change at any time. The node with lowest address rules
 */

static void link_recv_proto_msg(struct link *l_ptr, struct sk_buff *buf)
{
	u32 rec_gap = 0;
	u32 max_pkt_info;
	u32 max_pkt_ack;
	u32 msg_tol;
    u32 old_pri;
	struct tipc_msg *msg = buf_msg(buf);
	struct tlv_desc *tlv = NULL; /* */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    struct timespec64 tmp_tv;
#else
    struct timeval tmp_tv;
#endif

	dbg("AT(%u):", jiffies_to_msecs(jiffies));
	msg_dbg(msg, "<<");
	if (link_blocked(l_ptr))
		goto exit;

	/* record unnumbered packet arrival (force mismatch on next timeout) */

	l_ptr->checkpoint--;

	/* */
	if (link_net_plane(l_ptr) != msg_net_plane(msg))
		if (tipc_own_addr > msg_prevnode(msg))
			l_ptr->net_plane = msg_net_plane(msg);

	l_ptr->permit_changeover = msg_redundant_link(msg);


	switch (msg_type(msg)) {

	case RESET_MSG:
		if (!link_working_unknown(l_ptr) &&
		    (l_ptr->peer_session != INVALID_SESSION)) {
			if (less_eq(msg_session(msg), l_ptr->peer_session)) {
				dbg("Duplicate or old RESET: %u<->%u\n",
				    msg_session(msg), l_ptr->peer_session);
				break; /* duplicate or old reset: ignore */
			}
		}

		if (!msg_redundant_link(msg) &&
		    (link_working_working(l_ptr) ||
		     link_working_unknown(l_ptr)))
			l_ptr->owner->cleanup_required = WAIT_NODE_DOWN;
			/* peer has lost contact -- don't allow peer's links
			   to reactivate before we recognize loss & clean up */

                if (msg_stop(msg)) {
                        tipc_link_reset(l_ptr, "msg_stop", link_working_working(l_ptr), link_working_unknown(l_ptr), 0);
                        l_ptr->blocked = 1;
                        tipc_k_signal((Handler)link_remote_delete,(unsigned long)l_ptr);
                        break;
                }

		info_link("Link <%s> recv reset msg from %x:%x:%s msec %u %x %x %x \n",
				l_ptr->name, msg_orignode(msg), msg_prevnode(msg), 
				(char *)msg_data(msg), msg_timestamp(msg),
				msg_word(msg, 0), msg_word(msg, 1), msg_word(msg, 2));
		/* fallthrough */
	case ACTIVATE_MSG:
		/* Update link settings according other endpoint's values */

		/* safe strncpy instead strcpy */
		strncpy((strrchr(l_ptr->name, ':') + 1), (char *)msg_data(msg), TIPC_MAX_IF_NAME);
		
		if ((msg_tol = msg_link_tolerance(msg)) &&
		    (msg_tol > l_ptr->tolerance))
			link_set_supervision_props(l_ptr, msg_tol);

		if (msg_linkprio(msg) > l_ptr->priority)
			l_ptr->priority = msg_linkprio(msg);

		max_pkt_info = msg_max_pkt(msg);
		if (max_pkt_info) {
			if (max_pkt_info < l_ptr->max_pkt_target)
				l_ptr->max_pkt_target = max_pkt_info;
			if (l_ptr->max_pkt > l_ptr->max_pkt_target)
				l_ptr->max_pkt = l_ptr->max_pkt_target;
		} else {
			l_ptr->max_pkt = l_ptr->max_pkt_target;
		}
		l_ptr->owner->bclink.supported = 
			in_own_cluster(l_ptr->owner->elm.addr) &&
			(max_pkt_info != 0);

		l_ptr->peer_bearer_id = msg_bearer_id(msg);
		/* ����ͬһƽ���ڼ�1����ѡ����LRVR���� */
		if (CHASSIS_ID(l_ptr->owner->elm.addr) == CHASSIS_ID(tipc_own_addr) &&
			l_ptr->peer_bearer_id == l_ptr->b_ptr->identity &&
			l_ptr->priority == l_ptr->b_ptr->priority)
			l_ptr->priority += 1;
		
		link_state_event(l_ptr, msg_type(msg));

		l_ptr->peer_session = msg_session(msg);

		/* Synchronize broadcast link information */

		if (MCLINK_NEED_SYNC(l_ptr->owner, msg_type(msg))) {
			l_ptr->owner->bclink.last_sent =
				l_ptr->owner->bclink.last_in =
				msg_last_bcast(msg);
			l_ptr->owner->bclink.oos_state = 0;
		}
		
		break;
	case STATE_MSG:

		if ((msg_tol = msg_link_tolerance(msg)))
			link_set_supervision_props(l_ptr, msg_tol);

		if (msg_linkprio(msg) &&
		    (msg_linkprio(msg) != l_ptr->priority)) {
            old_pri = l_ptr->priority;
			l_ptr->priority = msg_linkprio(msg);
			tipc_link_reset(l_ptr, "PriorityChange", old_pri, l_ptr->priority, 0); /* Enforce change to take effect */
			break;
		}
		link_state_event(l_ptr, TRAFFIC_MSG_EVT);
		l_ptr->stats.recv_states++;
		if (link_reset_unknown(l_ptr))
			break;
		/* check for mcl */
		if (l_ptr->peer_session != msg_session(msg)) {
			tipc_link_reset(l_ptr, "diff session", l_ptr->peer_session, msg_session(msg), 0); /* Enforce change to take effect */
			break;
		}

		if (less_eq(mod(l_ptr->next_in_no), msg_next_sent(msg))) {
			rec_gap = mod(msg_next_sent(msg) -
				      mod(l_ptr->next_in_no));
			if (rec_gap > TIPC_DEF_LINK_WIN) {
				warn("Gap %u between peer first_out %u to next_in %u on link %s is too large\n", rec_gap,
					msg_next_sent(msg), mod(l_ptr->next_in_no), l_ptr->name);
			}
		}

		max_pkt_ack = msg_max_pkt(msg);
		if (max_pkt_ack > l_ptr->max_pkt) {
			dbg("Link <%s> updated MTU %u -> %u\n",
			    l_ptr->name, l_ptr->max_pkt, max_pkt_ack);
			l_ptr->max_pkt = max_pkt_ack;
			l_ptr->max_pkt_probes = 0;
		}

		max_pkt_ack = 0;
		if (msg_probe(msg)) {
			l_ptr->stats.recv_probes++;
			if (msg_size(msg) > sizeof(l_ptr->proto_msg)) {
				max_pkt_ack = msg_size(msg);
			}
		}

		/* Protocol message before retransmits, reduce loss risk */
		/* add &bclink */
		if (l_ptr->owner->bclink.supported)
			tipc_bclink_update_link_state(l_ptr->owner,
						      msg_last_bcast(msg),
						      &l_ptr->owner->bclink);

		if (rec_gap || (msg_probe(msg))) {
			tipc_link_send_proto_msg(l_ptr, STATE_MSG,
					    0, rec_gap, 0, 0, max_pkt_ack, 0);
		}
		if (msg_seq_gap(msg)) {
		    /* */
		    if ((!l_ptr->first_out || 
		        less(msg_ack(msg), mod(buf_seqno(l_ptr->first_out)-1))) &&
		        l_ptr->owner->working_links > 1) {
				u32 outseq;
				if (l_ptr->first_out){
						outseq = mod(buf_seqno(l_ptr->first_out)-1);
				} else {
						outseq = 0;
				}

		        tipc_link_reset(l_ptr, "bad ack-outseq-gap", msg_ack(msg), outseq, msg_seq_gap(msg));
		        tipc_link_send_proto_msg(l_ptr, RESET_MSG, 0, 0, 0, 0, 0, 0);

		        goto exit;
		    } else {
				msg_dbg(msg, "With Gap:");
				l_ptr->stats.recv_nacks++;
				/* ����������ಢ���б�����·���л���ǰ��· */
                if (LINK_RETX_MUCH(l_ptr, l_ptr->stats.recv_nacks, l_ptr->next_out_no) &&
                    l_ptr->owner->working_links > 1 && l_ptr->permit_changeover) {
                    /* ʱ������1������λ��· */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
                    do_gettimeofday_snapshot(&tmp_tv);
#else
                    do_gettimeofday(&tmp_tv);
#endif
                    if ((unsigned long)tmp_tv.tv_sec - (unsigned long)(l_ptr->init_tv.tv_sec) < LINK_RETX_TIMEOUT) {
                        tipc_link_reset(l_ptr, "retransmitting too much",
                            l_ptr->stats.recv_nacks, l_ptr->next_out_no, 0);
                        l_ptr->blocked = 1; /* ����Ƶ��up/down */
                    }
                }
				tipc_link_retransmit(l_ptr, l_ptr->first_out,
						     msg_seq_gap(msg));
			}
		}
		break;
	default:
		msg_dbg(buf_msg(buf), "<DISCARDING UNKNOWN<");
	}

	/* mci */
	if ( (msg_size(msg) > sizeof(l_ptr->proto_msg)+sizeof(*tlv)) &&
		(in_own_cluster(l_ptr->owner->elm.addr)) && 
		(msg_session(msg) == l_ptr->peer_session) && 
		tipc_link_is_up(l_ptr)) {
		tlv = (struct tlv_desc *)&buf->data[sizeof(l_ptr->proto_msg)];
		if (LINK_DT_MCAST == ntohs(tlv->tlv_type)) {
			(void)tipc_node_recv_mcinfo(l_ptr->owner, 
				TLV_DATA(tlv), ntohs(tlv->tlv_len) - TLV_LENGTH(0),
				msg_type(msg));
		}
	}

exit:
	buf_discard(buf);
}

/**
 * buf_extract - extracts embedded TIPC message from another message
 * @skb: encapsulating message buffer
 * @from_pos: offset to extract from
 *
 * Returns a new message buffer containing an embedded message.  The 
 * encapsulating message itself is left unchanged.
 */

static struct sk_buff *buf_extract(struct sk_buff *skb, u32 from_pos)
{
	struct tipc_msg *msg = (struct tipc_msg *)(skb->data + from_pos);
	u32 size = msg_size(msg);
	struct sk_buff *eb;

	if (size < MIN_H_SIZE || msg_size(buf_msg(skb)) < from_pos + size)
		return NULL;

	eb = buf_acquire(size);
	if (eb)
		skb_copy_to_linear_data(eb, msg, size);
	return eb;
}

#ifdef CONFIG_TIPC_MULTIPLE_LINKS

/*
 * link_tunnel(): Send one message via a link belonging to another bearer.
 * Owner node is locked.
 */
static void link_tunnel(struct link *l_ptr, struct tipc_msg *tunnel_hdr, 
			struct tipc_msg  *msg, u32 selector)
{
	struct link *tunnel;
	struct sk_buff *buf;
	u32 length = msg_size(msg);

	tunnel = l_ptr->owner->active_links[selector & 1];
	if (!tipc_link_is_up(tunnel)) {
        if (tipc_ratelimit(msg_seqno(msg), 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_LINK))
            warn("Link changeover error tunnel link %s no longer available\n", tunnel->name);
        return;
	}
	msg_set_size(tunnel_hdr, length + INT_H_SIZE);
	buf = buf_acquire(length + INT_H_SIZE);
	if (!buf) {
		warn("Link changeover error, "
		     "unable to send tunnel msg\n");
		return;
	}
	skb_copy_to_linear_data(buf, tunnel_hdr, INT_H_SIZE);
	skb_copy_to_linear_data_offset(buf, INT_H_SIZE, msg, length);
	dbg("%c->%c:", link_net_plane(l_ptr), link_net_plane(tunnel)); /* */
	msg_dbg(buf_msg(buf), ">SEND>");
	tipc_link_send_buf(tunnel, buf);
}



/*
 * changeover(): Send whole message queue via the remaining link
 *               Owner node is locked.
 */

void tipc_link_changeover(struct link *l_ptr)
{
	u32 msgcount = l_ptr->out_queue_size;
	struct sk_buff *crs = l_ptr->first_out;
	struct link *tunnel = l_ptr->owner->active_links[0];
	struct tipc_msg tunnel_hdr;
	int split_bundles;
	u32 selector = 0; /* ��Ƭ���ĵ�selector�ֶ���frag_msg_no����������ѡ�� */

	if (!tunnel)
		return;

	/* ����linkά��. 2012 ��tunnel���Է��� */
	if (0 && !l_ptr->permit_changeover) {
		return;
	}

	tipc_msg_init(&tunnel_hdr, CHANGEOVER_PROTOCOL, ORIGINAL_MSG,
		      INT_H_SIZE, l_ptr->addr);
	msg_set_bearer_id(&tunnel_hdr, l_ptr->peer_bearer_id);
	/* ����net_plane�ֶ�������ͬpeer_id���ǲ�ͬ��link
	 * ��������ICU֮����9����·��net_plane�����ã���Ϊbearerid */
	msg_set_net_plane(&tunnel_hdr, l_ptr->b_ptr->identity + 'A');
	msg_set_msgcnt(&tunnel_hdr, msgcount);
	dbg("Link changeover requires %u tunnel messages\n", msgcount);

	if (!l_ptr->first_out) {
		struct sk_buff *buf;

		buf = buf_acquire(INT_H_SIZE);
		if (buf) {
			skb_copy_to_linear_data(buf, &tunnel_hdr, INT_H_SIZE);
			msg_set_size(&tunnel_hdr, INT_H_SIZE);
			/* link_net_plane */
			dbg("%c->%c:", link_net_plane(l_ptr),
			    link_net_plane(tunnel));
			msg_dbg(&tunnel_hdr, "EMPTY>SEND>");
			tipc_link_send_buf(tunnel, buf);
		} else {
			warn("Link changeover error, "
			     "unable to send changeover msg\n");
		}
		return;
	}

	/* ��split�����ٱ��ĸ�����һ����� */
	split_bundles = 0 && (l_ptr->owner->active_links[0] !=
			 l_ptr->owner->active_links[1]);

	/* ��Ƭ���ĵ�selector�ֶ���frag_msg_no���ö౨��û��ѡ����Ϣ :-( */
	while (crs) {
		struct tipc_msg *msg = buf_msg(crs);
		if (msg_user(msg) <= TIPC_CRITICAL_IMPORTANCE) {
			selector = msg_link_selector(msg);
			break;
		}
		if (msg_user(msg) == MSG_FRAGMENTER && msg_type(msg) == FIRST_FRAGMENT) {
			selector = msg_link_selector(msg_get_wrapped(msg));
			break;
		}
		
		crs = crs->next;
	}

	crs = l_ptr->first_out;
	while (crs) {
		struct tipc_msg *msg = buf_msg(crs);
		if ((msg_user(msg) == MSG_BUNDLER) && split_bundles) {
			u32 bundle_size = msg_msgcnt(msg);
			struct tipc_msg *m = msg_get_wrapped(msg);
			unchar* pos = (unchar*)m;

			while (bundle_size--) {
				msg_set_seqno(m,msg_seqno(msg));
				link_tunnel(l_ptr, &tunnel_hdr, m,
					    msg_link_selector(m));
				pos += align(msg_size(m));
				m = (struct tipc_msg *)pos;
			}
		} else {
			link_tunnel(l_ptr, &tunnel_hdr, msg,
				    selector);
		}
		crs = crs->next;
	}
}

void tipc_link_send_duplicate(struct link *l_ptr, struct link *tunnel)
{
	struct sk_buff *iter;
	struct tipc_msg tunnel_hdr;

	tipc_msg_init(&tunnel_hdr, CHANGEOVER_PROTOCOL, DUPLICATE_MSG,
		      INT_H_SIZE, l_ptr->addr);
	msg_set_msgcnt(&tunnel_hdr, l_ptr->out_queue_size);
	msg_set_bearer_id(&tunnel_hdr, l_ptr->peer_bearer_id);
	/* ����net_plane�ֶ�������ͬpeer_id���ǲ�ͬ��link */
	msg_set_net_plane(&tunnel_hdr, l_ptr->b_ptr->identity + 'A');
	iter = l_ptr->first_out;
	while (iter) {
		struct sk_buff *outbuf;
		struct tipc_msg *msg = buf_msg(iter);
		u32 length = msg_size(msg);

		if (msg_user(msg) == MSG_BUNDLER)
			msg_set_type(msg, CLOSED_MSG);
		msg_set_ack(msg, mod(l_ptr->next_in_no - 1));	/* Update */
		msg_set_bcast_ack(msg, l_ptr->owner->bclink.last_in);
		msg_set_size(&tunnel_hdr, length + INT_H_SIZE);
		outbuf = buf_acquire(length + INT_H_SIZE);
		if (outbuf == NULL) {
			warn("Link changeover error, "
			     "unable to send duplicate msg\n");
			return;
		}
		skb_copy_to_linear_data(outbuf, &tunnel_hdr, INT_H_SIZE);
		skb_copy_to_linear_data_offset(outbuf, INT_H_SIZE, iter->data,
					       length);
		/* */
		dbg("%c->%c:", link_net_plane(l_ptr),
		    link_net_plane(tunnel));
		msg_dbg(buf_msg(outbuf), ">SEND>");
		tipc_link_send_buf(tunnel, outbuf);
        dbg("Link %s send tunnel TA %u\n", l_ptr->name, msg_seqno(msg));
		if (!tipc_link_is_up(l_ptr))
			return;
		iter = iter->next;
	}
}

/*
 *  link_recv_changeover_msg(): Receive tunneled packet sent
 *  via other link. Node is locked. Return extracted buffer.
 */

static int link_recv_changeover_msg(struct link **l_ptr,
				    struct sk_buff **buf)
{
	struct sk_buff *tunnel_buf = *buf;
	struct link *dest_link;
	struct tipc_msg *msg;
	struct tipc_msg *tunnel_msg = buf_msg(tunnel_buf);
	u32 msg_typ = msg_type(tunnel_msg);
	u32 msg_count = msg_msgcnt(tunnel_msg);
	u32 peer_bid = msg_net_plane(tunnel_msg) - 'A';

	/* */
	dest_link = tipc_node_find_link_byplane((*l_ptr)->owner, 
			msg_bearer_id(tunnel_msg), peer_bid);
	if (!dest_link) {
		msg_dbg(tunnel_msg, "NOLINK/<REC<");
		err("No link for changeover message on link <%s>, bearer %u-%u\n",
		    (*l_ptr)->name, msg_bearer_id(tunnel_msg), peer_bid);
		goto exit;
	}
	if (dest_link == *l_ptr) {
		err("Unexpected changeover message on link <%s>\n",
		    (*l_ptr)->name);
		goto exit;
	}
	/* link_net_plane*/
	dbg("%c<-%c:", link_net_plane(dest_link),
	    link_net_plane(*l_ptr));
	*l_ptr = dest_link;
	msg = msg_get_wrapped(tunnel_msg);

	if (msg_typ == DUPLICATE_MSG) {
		if (less(msg_seqno(msg), mod(dest_link->next_in_no))) {
			msg_dbg(tunnel_msg, "DROP/<REC<");
			goto exit;
		}
		*buf = buf_extract(tunnel_buf,INT_H_SIZE);
		if (*buf == NULL) {
			warn("Link changeover error, duplicate msg dropped\n");
			goto exit;
		}
		msg_dbg(tunnel_msg, "TNL<REC<");
		buf_discard(tunnel_buf);
		dbg("Link <%s> recv tunnel TA msg %u\n", dest_link->name, msg_seqno(msg));
		return 1;
	}

	/* First original message ?: */

	if (tipc_link_is_up(dest_link)) {
		msg_dbg(tunnel_msg, "UP/FIRST/<REC<");

		tipc_link_reset(dest_link, "peer_changeover", msg_count, 0, 0);
		dest_link->exp_msg_count = msg_count;
		dbg("Expecting %u tunnelled messages\n", msg_count);
		if (!msg_count)
			goto exit;
	} else if (dest_link->exp_msg_count == START_CHANGEOVER) {
		msg_dbg(tunnel_msg, "BLK/FIRST/<REC<");
		dest_link->exp_msg_count = msg_count;
		dbg("Expecting %u tunnelled messages\n", msg_count);
		if (!msg_count)
			goto exit;
		dbg("Link <%s> changeover initiated %u msg by peer\n",
		     dest_link->name, msg_count);
	}

	/* Receive original message */

	if (dest_link->exp_msg_count == 0) {
		/* Ϊ0�����������:һ������·�ս����������˲�һ�£���ӡ����ȷ���£�
		 * ��һ����·�л��ж���ı��ģ��ر�splitӦ�ܽ�����౨������ 2011-6-4
		 */
		warn("Link <%s> changeover got too many tunnelled messages %u\n",
		     dest_link->name, msg_count);
		msg_dbg(tunnel_msg, "OVERDUE/DROP/<REC<");
		dbg_print_link(dest_link, "LINK:");
		goto exit;
	}
	dest_link->exp_msg_count--;
    if (!dest_link->exp_msg_count)
		dbg("Link <%s> changeover end by peer\n", dest_link->name);
	if (less(msg_seqno(msg), dest_link->reset_checkpoint)) {
		msg_dbg(tunnel_msg, "DROP/DUPL/<REC<");
		goto exit;
	} else {
		*buf = buf_extract(tunnel_buf, INT_H_SIZE);
		if (*buf != NULL) {
			msg_dbg(tunnel_msg, "TNL<REC<");
			buf_discard(tunnel_buf);
            dbg("Link <%s> recv tunnel TB msg %u\n", dest_link->name, msg_seqno(msg));
			return 1;
		} else {
			warn("Link changeover error, original msg dropped\n");
		}
	}
exit:
	*buf = NULL;
	buf_discard(tunnel_buf);
	return 0;
}

#endif

/*
 *  Bundler functionality:
 */
void tipc_link_recv_bundle(struct sk_buff *buf)
{
	u32 msgcount = msg_msgcnt(buf_msg(buf));
	u32 pos = INT_H_SIZE;
	struct sk_buff *obuf;
	struct tipc_msg *omsg;

	msg_dbg(buf_msg(buf), "<BNDL<: ");
	while (msgcount--) {
		obuf = buf_extract(buf, pos);
		if (obuf == NULL) {
			warn("Link unable to unbundle message(s)\n");
			break;
		}
		omsg = buf_msg(obuf);
		pos += align(msg_size(omsg));
		msg_dbg(omsg, "     /");
		msg_set_destnode_cache(omsg, tipc_own_addr);
		tipc_net_route_msg(obuf);
	}
	buf_discard(buf);
}

/*
 *  Fragmentation/defragmentation:
 */


/*
 * tipc_link_send_long_buf: Entry for buffers needing fragmentation.
 * The buffer is complete, inclusive total message length.
 * Returns user data length.
 */
int tipc_link_send_long_buf(struct link *l_ptr, struct sk_buff *buf)
{
	struct tipc_msg *inmsg = buf_msg(buf);
	struct tipc_msg fragm_hdr;
	u32 insize = msg_size(inmsg);
	u32 dsz = msg_data_sz(inmsg);
	unchar *crs = buf->data;
	u32 rest = insize;
	u32 pack_sz = l_ptr->max_pkt;
	u32 fragm_sz = pack_sz - INT_H_SIZE * 3; /* multi changeover */
	u32 fragm_no = 1;
	u32 destaddr;

	/* in case of (max_pkt < INT_H_SIZE * 3) */
	if (unlikely(fragm_sz > l_ptr->max_pkt)) {
		warn("MTU too small for fragment message\n");
		dsz = -ENOMEM;
		goto exit;
	}

	if (msg_short(inmsg))
		destaddr = l_ptr->addr;
	else
		destaddr = msg_destnode(inmsg);

	if (msg_routed(inmsg))
		msg_set_prevnode(inmsg, tipc_own_addr);

	/* Prepare reusable fragment header: */

	tipc_msg_init(&fragm_hdr, MSG_FRAGMENTER, FIRST_FRAGMENT,
		      INT_H_SIZE, destaddr);
	msg_set_link_selector(&fragm_hdr, msg_link_selector(inmsg));
	msg_set_fragm_msg_no(&fragm_hdr, 
			     atomic_inc_return(&link_fragm_msg_no) & 0xffff);
	msg_set_fragm_no(&fragm_hdr, fragm_no);
	l_ptr->stats.sent_fragmented++;

	/* ^_^ MSG_FRAGMENTER ��ǰû��ʹ�ø��ֶ� */
	msg_set_nametype(&fragm_hdr, msg_nametype(inmsg));

	/* Chop up message: */

	while (rest > 0) {
		struct sk_buff *fragm;

		if (rest <= fragm_sz) {
			fragm_sz = rest;
			msg_set_type(&fragm_hdr, LAST_FRAGMENT);
		}
		fragm = buf_acquire(fragm_sz + INT_H_SIZE);
		if (fragm == NULL) {
			warn("Link unable to fragment message\n");
			dsz = -ENOMEM;
			goto exit;
		}
		msg_set_size(&fragm_hdr, fragm_sz + INT_H_SIZE);
		skb_copy_to_linear_data(fragm, &fragm_hdr, INT_H_SIZE);
		skb_copy_to_linear_data_offset(fragm, INT_H_SIZE, crs,
					       fragm_sz);
		fragm->priority = buf->priority; /* tipc_priority */

		/*  Send queued messages first, if any: */

		l_ptr->stats.sent_fragments++;
		tipc_link_send_buf(l_ptr, fragm);
		if (!tipc_link_is_up(l_ptr))
			return dsz;
		msg_set_fragm_no(&fragm_hdr, ++fragm_no);
		rest -= fragm_sz;
		crs += fragm_sz;
		msg_set_type(&fragm_hdr, FRAGMENT);
	}
exit:
	buf_discard(buf);
	return dsz;
}

/* 
 * A partially reassembled message must store certain values so that subsequent 
 * fragments can be incorporated correctly.  The following routines store these
 * values in temporarily available fields in the partially reassembled message,
 * thereby making dynamic memory allocation unecessary.
 */

static inline u32 get_long_msg_orig(struct sk_buff *buf)
{
	return (u32)(unsigned long)buf_handle(buf);
}

static inline void set_long_msg_orig(struct sk_buff *buf, u32 orig)
{
	 buf_set_handle(buf, (void *)(unsigned long)orig);
}

static inline u32 get_long_msg_seqno(struct sk_buff *buf)
{
	return buf_seqno(buf);
}

static inline void set_long_msg_seqno(struct sk_buff *buf, u32 seqno)
{
	msg_set_seqno(buf_msg(buf), seqno);
}

static inline u32 get_fragm_size(struct sk_buff *buf)
{
	return msg_ack(buf_msg(buf));
}

static inline void set_fragm_size(struct sk_buff *buf, u32 sz)
{
	msg_set_ack(buf_msg(buf), sz);
}

static inline u32 get_expected_frags(struct sk_buff *buf)
{
	return msg_bcast_ack(buf_msg(buf));
}

static inline void set_expected_frags(struct sk_buff *buf, u32 exp)
{
	msg_set_bcast_ack(buf_msg(buf), exp);
}

static inline u32 get_timer_cnt(struct sk_buff *buf)
{
	return msg_reroute_cnt(buf_msg(buf));
}

static inline void reset_timer_cnt(struct sk_buff *buf)
{
	msg_reset_reroute_cnt(buf_msg(buf));
}

static inline void incr_timer_cnt(struct sk_buff *buf)
{
	msg_incr_reroute_cnt(buf_msg(buf));
}

/*
 * tipc_link_recv_fragment(): Called with node lock on. Returns
 * the reassembled buffer if message is complete.
 */
int tipc_link_recv_fragment(struct sk_buff **pending, struct sk_buff **fb,
			    struct tipc_msg **m)
{
	struct sk_buff *pbuf = *pending;
	struct sk_buff *fbuf = *fb;
	struct sk_buff *prev = NULL;
	struct tipc_msg *fragm = buf_msg(fbuf);
	u32 long_msg_orig = msg_orignode(fragm);
	u32 long_msg_seq_no = msg_fragm_msg_no(fragm);

	*fb = NULL;
	msg_dbg(fragm,"FRG<REC<");

	/* Is there an incomplete message waiting for this fragment? */

	while (pbuf && ((get_long_msg_orig(pbuf) != long_msg_orig)
			|| (get_long_msg_seqno(pbuf) != long_msg_seq_no))) {
		prev = pbuf;
		pbuf = pbuf->next;
	}

	if (!pbuf && (msg_type(fragm) == FIRST_FRAGMENT)) {
		struct tipc_msg *imsg = (struct tipc_msg *)msg_data(fragm);
		u32 msg_sz = msg_size(imsg);
		u32 fragm_sz = msg_data_sz(fragm);
        /* ���ӷ�Ƭ���ļ�顣����link���򣬷�Ƭ���ı�Ȼ˳���� */
		u32 exp_fragm = 1; /* frag_no��1��ʼ���� */
		u32 max =  TIPC_MAX_USER_MSG_SIZE + LONG_H_SIZE;

		if (msg_type(imsg) == TIPC_MCAST_MSG)
			max = TIPC_MAX_USER_MSG_SIZE + MCAST_H_SIZE;
		if ((msg_sz > max) || (msg_sz < LONG_H_SIZE)) {
			info("fragment packet len is abnormal: len %u\n", msg_sz);
			msg_dbg(fragm,"<REC<Oversized: ");
			buf_discard(fbuf);
			return 0;
		}
		pbuf = buf_acquire(msg_sz);
		if (pbuf != NULL) {
			pbuf->next = *pending;
			*pending = pbuf;
			skb_copy_to_linear_data(pbuf, imsg,
						msg_data_sz(fragm));

			/*  Prepare buffer for subsequent fragments. */

			set_long_msg_orig(pbuf, long_msg_orig); 
			set_long_msg_seqno(pbuf, long_msg_seq_no); 
			set_fragm_size(pbuf, fragm_sz); 
			set_expected_frags(pbuf, exp_fragm); /* */
			reset_timer_cnt(pbuf);
		} else {
			warn("Link unable to reassemble fragmented message msg_sz 0x%x\n", msg_sz);
		}
		buf_discard(fbuf);
		return 0;
	} else if (pbuf && (msg_type(fragm) != FIRST_FRAGMENT)) {
		u32 dsz = msg_data_sz(fragm);
		u32 fsz = get_fragm_size(pbuf);
		u32 crs = ((msg_fragm_no(fragm) - 1) * fsz);
		u32 exp_frags = get_expected_frags(pbuf) + 1; /* */
		if (msg_fragm_no(fragm) != exp_frags ||
			(crs + dsz > msg_size(buf_msg(pbuf))) ||
			(msg_type(fragm) == FRAGMENT && dsz != fsz)) {
			warn("Discard seq %u, %uth frag sz %u, orig %x long %u total %u frgsz %u expect %uth\n",
                msg_seqno(fragm), msg_fragm_no(fragm), dsz,
                long_msg_orig, get_long_msg_seqno(pbuf), msg_size(buf_msg(pbuf)),
                fsz, exp_frags);
			buf_discard(fbuf);
			return 0;
		}
		skb_copy_to_linear_data_offset(pbuf, crs,
					       msg_data(fragm), dsz);
		buf_discard(fbuf);
		reset_timer_cnt(pbuf);

		/* Is message complete? */

		if (crs + dsz == msg_size(buf_msg(pbuf))) {/* */
			if (prev)
				prev->next = pbuf->next;
			else
				*pending = pbuf->next;
			*fb = pbuf;
			*m = buf_msg(pbuf);
			return 1;
		}
		set_expected_frags(pbuf,exp_frags);
		return 0;
	}
	warn(" Discarding seq %u, orphan fragment %uth of long %u orig %x\n",
            msg_seqno(fragm), msg_fragm_no(fragm), long_msg_seq_no, long_msg_orig);
	msg_dbg(fragm,"ORPHAN:");
	dbg("Pending long buffers:\n");
	dbg_print_buf_chain(*pending);
	buf_discard(fbuf);
	return 0;
}

/**
 * link_check_defragm_bufs - flush stale incoming message fragments
 * @l_ptr: pointer to link
 */

void link_check_defragm_bufs(struct sk_buff **defragm_buf, const char *name)
{
	struct sk_buff *prev = NULL;
	struct sk_buff *next = NULL;
	struct sk_buff *buf = *defragm_buf;

	if (!buf)
		return;

	while (buf) {
		u32 cnt = get_timer_cnt(buf);

		next = buf->next;
		if (cnt < 10) { /* 4-->10 */
			incr_timer_cnt(buf);
			prev = buf;
		} else {
			warn("Link <%s> discard long %u, total %u frgsz %u expect %uth\n",
                name, get_long_msg_seqno(buf),
                msg_size(buf_msg(buf)), get_fragm_size(buf),
                get_expected_frags(buf) + 1);
			msg_dbg(buf_msg(buf), "LONG:");
			/*dbg_print_link(l_ptr, "curr:");*/
			dbg("Pending long buffers:\n");
			dbg_print_buf_chain(*defragm_buf);
			if (prev)
				prev->next = buf->next;
			else
				*defragm_buf = buf->next;
			buf_discard(buf);
		}
		buf = next;
	}
}



static void link_set_supervision_props(struct link *l_ptr, u32 tolerance)
{
	l_ptr->tolerance = tolerance;
	/* */
	l_ptr->continuity_interval = CONT_INTV(tolerance / 2) / 4;

	l_ptr->abort_limit = tolerance / l_ptr->continuity_interval;

    l_ptr->fast_intv = max(tolerance / 256, CONT_INTV_FAST); /* ���ټ������ */
    if (l_ptr->fast_intv >= l_ptr->continuity_interval)
        l_ptr->fast_intv = l_ptr->continuity_interval - 1;
}


void tipc_link_set_queue_limits(struct link *l_ptr, u32 window)
{
	l_ptr->win_limit = window; /* */
	/* Data messages from this node, inclusive FIRST_FRAGM */
	l_ptr->queue_limit[TIPC_LOW_IMPORTANCE] = window;
	l_ptr->queue_limit[TIPC_MEDIUM_IMPORTANCE] = (window / 3) * 4;
	l_ptr->queue_limit[TIPC_HIGH_IMPORTANCE] = (window / 3) * 5;
	l_ptr->queue_limit[TIPC_CRITICAL_IMPORTANCE] = (window / 3) * 6;
	/* Transiting data messages,inclusive FIRST_FRAGM */
	l_ptr->queue_limit[TIPC_LOW_IMPORTANCE + 4] = 300;
	l_ptr->queue_limit[TIPC_MEDIUM_IMPORTANCE + 4] = 600;
	l_ptr->queue_limit[TIPC_HIGH_IMPORTANCE + 4] = 900;
	l_ptr->queue_limit[TIPC_CRITICAL_IMPORTANCE + 4] = 1200;
	l_ptr->queue_limit[CONN_MANAGER] = 1200;
	l_ptr->queue_limit[ROUTE_DISTRIBUTOR] = 1200;
	l_ptr->queue_limit[CHANGEOVER_PROTOCOL] = 2500;
	l_ptr->queue_limit[NAME_DISTRIBUTOR] = 3000;
	/* FRAGMENT and LAST_FRAGMENT packets */
	l_ptr->queue_limit[MSG_FRAGMENTER] = 4000;
}

#ifdef CONFIG_TIPC_CONFIG_SERVICE

/**
 * link_find_link - locate link by name
 * @name - ptr to link name string
 * @node - ptr to area to be filled with ptr to associated node
 *
 * Caller must hold 'tipc_net_lock' to ensure node and bearer are not deleted;
 * this also prevents link deletion.
 *
 * Returns pointer to link (or 0 if invalid link name).
 */

static struct link *link_find_link(const char *name, struct tipc_node **node)
{
	struct link_name link_name_parts;
	struct bearer *b_ptr;
	struct link *l_ptr;
#ifdef CONFIG_TIPC_LINK_TAG   /* */
	struct tipc_node *n_ptr = NULL;
	u32 bearer_id = 0;
	u32 bid = 0;
#endif
	if (!link_name_validate(name, &link_name_parts))
		return NULL;

	b_ptr = tipc_bearer_find(link_name_parts.if_local);
	if (!b_ptr)
		return NULL;

	*node = tipc_net_find_node(link_name_parts.addr_peer); 
	if (!*node)
		return NULL;
	
#ifdef CONFIG_TIPC_LINK_TAG   /* */
	n_ptr = *node;
	bid = bearer_id = b_ptr->identity;
	do {
		l_ptr = n_ptr->links[bid];
 		if (l_ptr && l_ptr->b_ptr == b_ptr) {
			if (!strcmp(l_ptr->name, name)) {
				return l_ptr;
			}
 		}
		
		bid = (bid + 1) % TIPC_MAX_LINKS;
	} while (bid != bearer_id);

	return NULL;
#else	
	l_ptr = (*node)->links[b_ptr->identity];
	if (!l_ptr || strcmp(l_ptr->name, name))
		return NULL;
#endif

	return l_ptr;
}


/**
 * value_is_valid -- check if priority/link tolerance/window is within range
 *
 * @cmd - value type (TIPC_CMD_SET_LINK_*)
 * @new_value - the new value
 *
 * Returns 1 if value is within range, 0 if not.
 */
static int value_is_valid(u16 cmd, u32 new_value)
{
	switch (cmd) {
	case TIPC_CMD_SET_LINK_TOL:
		return (new_value >= TIPC_MIN_LINK_TOL) &&
			(new_value <= TIPC_MAX_LINK_TOL);
	case TIPC_CMD_SET_LINK_PRI:
		return (new_value >= TIPC_MIN_LINK_PRI) &&
			(new_value <= TIPC_MAX_LINK_PRI);
	case TIPC_CMD_SET_LINK_WINDOW:
		return (new_value >= TIPC_MIN_LINK_WIN) &&
			(new_value <= TIPC_MAX_LINK_WIN);
	}
	return 0;
}


/**
 * cmd_set_link_value - change priority/tolerance/window size of link, bearer or media
 * @name - ptr to link, bearer or media name string
 * @new_value - the new link priority or new bearer default link priority
 * @cmd - which link/bearer property to set (TIPC_CMD_SET_LINK_*)
 *
 * Caller must hold 'tipc_net_lock' to ensure link/bearer are not deleted.
 *
 * Returns 0 if value updated and negative value on error.
 */
static int cmd_set_link_value(const char *name, u32 new_value, u16 cmd)
{
	struct tipc_node *node;
	struct link *l_ptr;
	struct bearer *b_ptr;
	struct tipc_media *m_ptr;

	l_ptr = link_find_link(name, &node);
	if (l_ptr) {
		/*
		 * acquire node lock for tipc_link_send_proto_msg().
		 * see "TIPC locking policy" in tipc_net.c.
		 */
		tipc_node_lock(node);
		switch (cmd) {
		case TIPC_CMD_SET_LINK_TOL:
			link_set_supervision_props(l_ptr, new_value);
			tipc_link_send_proto_msg(l_ptr, STATE_MSG,
				0, 0, new_value, 0, 0, 0);
			break;
		case TIPC_CMD_SET_LINK_PRI:
			l_ptr->priority = new_value;
			tipc_link_send_proto_msg(l_ptr, STATE_MSG,
				0, 0, 0, new_value, 0, 0);
			break;
		case TIPC_CMD_SET_LINK_WINDOW:
			tipc_link_set_queue_limits(l_ptr, new_value);
			break;
		}
		tipc_node_unlock(node);
		return 0;
	}

	b_ptr = tipc_bearer_find(name);
	if (b_ptr) {
		switch (cmd) {
		case TIPC_CMD_SET_LINK_TOL:
			b_ptr->tolerance = new_value;
			return 0;
		case TIPC_CMD_SET_LINK_PRI:
			b_ptr->priority = new_value;
			return 0;
		case TIPC_CMD_SET_LINK_WINDOW:
			b_ptr->window = new_value;
			return 0;
		}
		return -EINVAL;
	}

	m_ptr = tipc_media_find_name(name);
	if (!m_ptr)
		return -ENODEV;
	switch (cmd) {
	case TIPC_CMD_SET_LINK_TOL:
		m_ptr->tolerance = new_value;
		return 0;
	case TIPC_CMD_SET_LINK_PRI:
		m_ptr->priority = new_value;
		return 0;
	case TIPC_CMD_SET_LINK_WINDOW:
		m_ptr->window = new_value;
		return 0;
	}
	return -EINVAL;
}


struct sk_buff *tipc_link_cmd_config(const void *req_tlv_area, int req_tlv_space,
				     u16 cmd)
{
	struct tipc_link_config *args;
	u32 new_value;
	int res;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_LINK_CONFIG))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	args = (struct tipc_link_config *)TLV_DATA(req_tlv_area);
	new_value = ntohl(args->value);

	if (!value_is_valid(cmd, new_value))
		return tipc_cfg_reply_error_string("cannot change, value invalid");

	if (!strncmp(args->name, tipc_bclink_name, strlen(tipc_bclink_name))) {
		if ((cmd == TIPC_CMD_SET_LINK_WINDOW) &&
		    (tipc_bclink_set_queue_limits(new_value, args->name) == 0))
			return tipc_cfg_reply_none();
		return tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
						   " (cannot change setting on broadcast link)");
	}

	read_lock_bh(&tipc_net_lock);
	res = cmd_set_link_value(args->name, new_value, cmd);
	read_unlock_bh(&tipc_net_lock);
	if (res)
		return tipc_cfg_reply_error_string("cannot change link setting");

	return tipc_cfg_reply_none();
}

#endif

/**
 * link_reset_statistics - reset link statistics
 * @l_ptr: pointer to link
 */

static void link_reset_statistics(struct link *l_ptr)
{
	memset(&l_ptr->stats, 0, sizeof(l_ptr->stats));
	l_ptr->stats.sent_info = l_ptr->next_out_no;
	l_ptr->stats.recv_info = l_ptr->next_in_no;
}

#ifdef CONFIG_TIPC_CONFIG_SERVICE

struct sk_buff *tipc_link_cmd_reset_stats(const void *req_tlv_area, int req_tlv_space)
{
	char *link_name;
	struct link *l_ptr;
	struct tipc_node *node;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_LINK_NAME))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	/* bclname */
	link_name = (char *)TLV_DATA(req_tlv_area);
	if (!strncmp(link_name, tipc_bclink_name, strlen(tipc_bclink_name))) {
		if (tipc_bclink_reset_stats(link_name))
			return tipc_cfg_reply_error_string("link not found");
		return tipc_cfg_reply_none();
	}

	read_lock_bh(&tipc_net_lock);
	l_ptr = link_find_link(link_name, &node);
	if (!l_ptr) {
		read_unlock_bh(&tipc_net_lock);
		return tipc_cfg_reply_error_string("link not found");
	}

	tipc_node_lock(node);
	link_reset_statistics(l_ptr);
	l_ptr->retx_count = 0; /* ����澯 */	
	tipc_node_unlock(node);
	read_unlock_bh(&tipc_net_lock);
	return tipc_cfg_reply_none();
}

#ifdef PROTO_MULTI_DISCOVERY_OBJECT
struct sk_buff *tipc_link_cmd_delete(const void *req_tlv_area, int req_tlv_space)
{
        char *cmd_str;
	char *link_name;
	struct link *l_ptr,*temp_l_ptr;
	struct tipc_node *n_ptr;
        struct bearer *b_ptr;
	char *if_name,*domain_str;
	char  cmd[TIPC_MAX_LINK_NAME + 1];
        u32 domain,zone,cluster,node;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_LINK_NAME))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

        cmd_str = (char*) TLV_DATA(req_tlv_area);
        strncpy(cmd,cmd_str,sizeof(cmd));

	/* bclname */
	link_name = cmd_str;
	if (!strncmp(link_name, tipc_bclink_name, strlen(tipc_bclink_name))) {
		if (tipc_bclink_reset_stats(link_name))
			return tipc_cfg_reply_error_string("link not found");
		return tipc_cfg_reply_none();
	}

        write_lock_bh(&tipc_net_lock);

        /* Scope comprising several links ? */

        if (strchr(link_name,'/') != NULL)
                goto error;

        if (strchr(link_name,'-') == NULL) {

                if_name = cmd_str;

                domain_str = strchr(if_name,',');
                if (domain_str == NULL)
                        goto error;
                *domain_str = 0;
                domain_str++;

                if (sscanf(domain_str,"%u.%u.%u",&zone,&cluster,&node) != 3)
                        goto error;

                domain = tipc_addr(zone,cluster,node);

                if (!tipc_addr_domain_valid(domain))
                        goto error;

                b_ptr = tipc_bearer_find(if_name);

                if (b_ptr == NULL) 
                        goto error;
        } else {
                l_ptr = link_find_link(link_name, &n_ptr); 
                if (!l_ptr) 
                        goto error;
                domain = l_ptr->addr;
                b_ptr = l_ptr->b_ptr;
        }

        if (in_own_cluster(domain))
                goto error;

	spin_lock_bh(&b_ptr->publ.lock);

        tipc_bearer_remove_discoverer(b_ptr,domain);

	list_for_each_entry_safe(l_ptr, temp_l_ptr, &b_ptr->links, link_list) {

                if (tipc_in_scope(domain,l_ptr->addr)) {
                        if (in_own_cluster(l_ptr->addr))
                                continue;
                        n_ptr = l_ptr->owner;
                        tipc_node_lock(n_ptr);
                        tipc_link_reset(l_ptr, NULL, l_ptr->addr, 0, 0);

                        /* Tell other end to not re-establish */

                        tipc_link_send_proto_msg(l_ptr,RESET_MSG, 
                                                 0, 0, 0, 0, 0, 1);
                        l_ptr->blocked = 1;
                        tipc_node_unlock(n_ptr);
                        tipc_link_delete(l_ptr);
                }
	}
	spin_unlock_bh(&b_ptr->publ.lock);
	write_unlock_bh(&tipc_net_lock);
	return tipc_cfg_reply_none();

 error:
	write_unlock_bh(&tipc_net_lock);
        return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);
}
#endif

/**
 * percent - convert count to a percentage of total (rounding up or down)
 */

static u32 percent(u32 count, u32 total)
{
	return (count * 100 + (total / 2)) / total;
}

static char *tipc_get_state_name(u32 state)
{
    switch (state) {
        case WORKING_WORKING:
            return "WW";
        case WORKING_UNKNOWN:
            return "WU";
        case RESET_RESET:
            return "RR";
        case RESET_UNKNOWN:
            return "RU";
        default:
            return "UN";
    }
}

/**
 * tipc_link_stats - print link statistics
 * @name: link name
 * @buf: print buffer area
 * @buf_size: size of print buffer area
 *
 * Returns length of print buffer data string (or 0 if error)
 */

static int tipc_link_stats(const char *name, char *buf, const u32 buf_size)
{
	struct print_buf pb;
	struct link *l_ptr;
	struct tipc_node *node;
	char *status;
	u32 profile_total = 0;

	/* bclname */
	if (!strncmp(name, tipc_bclink_name, strlen(tipc_bclink_name)))
		return tipc_bclink_stats(buf, buf_size, name);

	tipc_printbuf_init(&pb, buf, buf_size);

	read_lock_bh(&tipc_net_lock);
	l_ptr = link_find_link(name, &node);
	if (!l_ptr) {
		read_unlock_bh(&tipc_net_lock);
		return 0;
	}
	tipc_node_lock(node);

	if (tipc_link_is_active(l_ptr))
		status = "ACTIVE";
	else if (tipc_link_is_up(l_ptr))
		status = "STANDBY";
	else
		status = "DEFUNCT";
	tipc_printf(&pb, "Link <%s>  ----  ", l_ptr->name);
	tipc_media_addr_printf(&pb, &l_ptr->media_addr);
	tipc_printf(&pb, "\n");
	
	tipc_printf(&pb, "  %s  MTU:%u  Priority:%u  Tolerance:%u ms"
		         "  Window:%u packets\n", 
		    status, l_ptr->max_pkt, 
		    l_ptr->priority, l_ptr->tolerance, l_ptr->queue_limit[0]);
    tipc_printf(&pb, "  State:%s Blocked:%d ExpMsg:%d PeerSession:%d TimeOut:%d\n", 
        tipc_get_state_name(l_ptr->state), l_ptr->blocked, l_ptr->exp_msg_count,
        l_ptr->peer_session, l_ptr->timeout_cnt);
	tipc_printf(&pb, "  RX packets:%u fragments:%u/%u bundles:%u/%u\n",
		    l_ptr->next_in_no - l_ptr->stats.recv_info,
		    l_ptr->stats.recv_fragments,
		    l_ptr->stats.recv_fragmented,
		    l_ptr->stats.recv_bundles,
		    l_ptr->stats.recv_bundled);
	tipc_printf(&pb, "  TX packets:%u fragments:%u/%u bundles:%u/%u\n",
		    l_ptr->next_out_no - l_ptr->stats.sent_info,
		    l_ptr->stats.sent_fragments,
		    l_ptr->stats.sent_fragmented,
		    l_ptr->stats.sent_bundles,
		    l_ptr->stats.sent_bundled);
	profile_total = l_ptr->stats.msg_length_counts;
	if (!profile_total)
		profile_total = 1;
	tipc_printf(&pb, "  TX profile sample:%u packets  average:%u octets\n"
			 "  0-64:%u%% -256:%u%% -1024:%u%% -4096:%u%% "
			 "-16354:%u%% -32768:%u%% -66000:%u%%\n",
		    l_ptr->stats.msg_length_counts,
		    l_ptr->stats.msg_lengths_total / profile_total,
		    percent(l_ptr->stats.msg_length_profile[0], profile_total),
		    percent(l_ptr->stats.msg_length_profile[1], profile_total),
		    percent(l_ptr->stats.msg_length_profile[2], profile_total),
		    percent(l_ptr->stats.msg_length_profile[3], profile_total),
		    percent(l_ptr->stats.msg_length_profile[4], profile_total),
		    percent(l_ptr->stats.msg_length_profile[5], profile_total),
		    percent(l_ptr->stats.msg_length_profile[6], profile_total));
	tipc_printf(&pb, "  Next-in-no:%u deferred-count:%u unacked:%u\n",
		    mod(l_ptr->next_in_no),
		    l_ptr->deferred_inqueue_sz,
		    l_ptr->unacked_window);
	tipc_printf(&pb, "  Next-ou-no:%u outqueue-count:%u re-tx-no:%u re-tx-cnt:%u\n",
		    mod(l_ptr->next_out_no),
		    l_ptr->out_queue_size,
		    l_ptr->retransm_queue_head,
		    l_ptr->retransm_queue_size);
	tipc_printf(&pb, "  RX states:%u probes:%u naks:%u defs:%u dups:%u\n", 
		    l_ptr->stats.recv_states,
		    l_ptr->stats.recv_probes,
		    l_ptr->stats.recv_nacks,
		    l_ptr->stats.deferred_recv,
		    l_ptr->stats.duplicates);
	tipc_printf(&pb, "  TX states:%u probes:%u naks:%u acks:%u dups:%u\n",
		    l_ptr->stats.sent_states,
		    l_ptr->stats.sent_probes,
		    l_ptr->stats.sent_nacks,
		    l_ptr->stats.sent_acks,
		    l_ptr->stats.retransmitted);
	tipc_printf(&pb, "  Congestion bearer:%u link:%u  Send queue max:%u avg:%u\n",
		    l_ptr->stats.bearer_congs,
		    l_ptr->stats.link_congs,
		    l_ptr->stats.max_queue_sz,
		    l_ptr->stats.queue_sz_counts
		    ? (l_ptr->stats.accu_queue_sz / l_ptr->stats.queue_sz_counts)
		    : 0);
	if (l_ptr->drop_outque || l_ptr->drop_defque)
		tipc_printf(&pb, "  Discard outqueue:%u deferqueue:%u\n",
		    l_ptr->drop_outque,
		    l_ptr->drop_defque);
	tipc_printf(&pb, "  Reset:%u  Checkcnt:%u failed:%u  Retx:%u\n",
			l_ptr->reset_count, 0, 0, l_ptr->retx_count);

	if (l_ptr == node->active_links[0]) {
		tipc_node_mcstat(node, &pb);
	}
    
	tipc_node_unlock(node);
	read_unlock_bh(&tipc_net_lock);
	return tipc_printbuf_validate(&pb);
}

#define MAX_LINK_STATS_INFO 2000

struct sk_buff *tipc_link_cmd_show_stats(const void *req_tlv_area, int req_tlv_space)
{
	struct sk_buff *buf;
	struct tlv_desc *rep_tlv;
	int str_len;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_LINK_NAME))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	buf = tipc_cfg_reply_alloc(TLV_SPACE(MAX_LINK_STATS_INFO));
	if (!buf)
		return NULL;

	rep_tlv = (struct tlv_desc *)buf->data;

	str_len = tipc_link_stats((char *)TLV_DATA(req_tlv_area),
				  (char *)TLV_DATA(rep_tlv), MAX_LINK_STATS_INFO);
	if (!str_len) {
		buf_discard(buf);
		return tipc_cfg_reply_error_string("link not found");
	}

	skb_put(buf, TLV_SPACE(str_len));
	TLV_SET(rep_tlv, TIPC_TLV_ULTRA_STRING, NULL, str_len);

	return buf;
}

void tipc_link_doubt_node(struct tipc_node *n_ptr)
{
	u32 i;
	struct link *l_ptr;
    
	tipc_node_lock(n_ptr);
	for (i = 0; i < TIPC_MAX_LINKS; i++) {
        l_ptr = n_ptr->links[i];
		if (!tipc_link_is_up(l_ptr))
			continue;

        /* reset <l_ptr> after 3 timeout��Լ375ms */
        if (l_ptr->fsm_msg_cnt < l_ptr->abort_limit - 3) {
            l_ptr->checkpoint = l_ptr->next_in_no;
            l_ptr->state = WORKING_UNKNOWN;
            l_ptr->fsm_msg_cnt = l_ptr->abort_limit - 3;

            link_state_event(l_ptr, TIMEOUT_EVT);
        }
	}
	tipc_node_unlock(n_ptr);    
}

/* */
struct sk_buff *tipc_link_cmd_doubt_node(const void *req_tlv_area, int req_tlv_space)
{
	u32 dest;
	struct tipc_node *n_ptr;


	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_NET_ADDR))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	dest = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
	if (!tipc_addr_node_valid(dest))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (node address)");

	if (tipc_mode != TIPC_NET_MODE)
		return tipc_cfg_reply_none();
	
	read_lock_bh(&tipc_net_lock);

	n_ptr = tipc_net_find_node(dest);
    if (!n_ptr) {
        read_unlock_bh(&tipc_net_lock);
        return tipc_cfg_reply_error_string("node not found");;
    }

    tipc_link_doubt_node(n_ptr);    
    tipc_bearers_send_doubt(dest);
    
	warn("Node %x will be down\n", dest);
	read_unlock_bh(&tipc_net_lock);
	return tipc_cfg_reply_none();
}


#endif

#if 0
int link_control(const char *name, u32 op, u32 val)
{
	int res = -EINVAL;
	struct link *l_ptr;
	u32 bearer_id;
	struct tipc_node *node;
	u32 a;

	a = link_name2addr(name, &bearer_id);
	read_lock_bh(&tipc_net_lock);
	node = tipc_net_find_node(a);

	if (node) {
		tipc_node_lock(node);
		l_ptr = node->links[bearer_id];
		if (l_ptr) {
			if (op == TIPC_REMOVE_LINK) {
				struct bearer *b_ptr = l_ptr->b_ptr;
				spin_lock_bh(&b_ptr->publ.lock);
				tipc_link_delete(l_ptr);
				spin_unlock_bh(&b_ptr->publ.lock);
			}
			if (op == TIPC_CMD_BLOCK_LINK) {
				tipc_link_reset(l_ptr);
				l_ptr->blocked = 1;
			}
			if (op == TIPC_CMD_UNBLOCK_LINK) {
				l_ptr->blocked = 0;
			}
			res = 0;
		}
		tipc_node_unlock(node);
	}
	read_unlock_bh(&tipc_net_lock);
	return res;
}
#endif

/**
 * tipc_link_get_max_pkt - get maximum packet size to use when sending to destination
 * @dest: network address of destination node
 * @selector: used to select from set of active links
 *
 * If no active link can be found, uses default maximum packet size.
 */

u32 tipc_link_get_max_pkt(u32 dest, u32 selector)
{
	struct tipc_node *n_ptr;
	struct link *l_ptr;
	u32 res = MAX_PKT_DEFAULT;

	if (dest == tipc_own_addr)
		return MAX_MSG_SIZE;

	read_lock_bh(&tipc_net_lock);
	n_ptr = tipc_net_select_node(dest);
	if (n_ptr) {
		tipc_node_lock(n_ptr);
		l_ptr = n_ptr->active_links[selector & 1];
		if (l_ptr)
			res = l_ptr->max_pkt;
		tipc_node_unlock(n_ptr);
	}
	read_unlock_bh(&tipc_net_lock);
	return res;
}

#if 0
static void link_dump_rec_queue(struct link *l_ptr)
{
	struct sk_buff *crs;

	if (!l_ptr->oldest_deferred_in) {
		info("Reception queue empty\n");
		return;
	}
	info("Contents of Reception queue:\n");
	crs = l_ptr->oldest_deferred_in;
	while (crs) {
		if (crs->data == (void *)0x0000a3a3) {
			info("buffer %x invalid\n", crs);
			return;
		}
		msg_dbg(buf_msg(crs), "In rec queue: \n");
		crs = crs->next;
	}
}
#endif

#ifdef CHECK_LINK /* enable dump info, def CONFIG_TIPC_DEBUG */

static void link_dump_send_queue(struct link *l_ptr)
{
	if (l_ptr->next_out) {
		info("\nContents of unsent queue:\n");
		dbg_print_buf_chain(l_ptr->next_out);
	}
	info("\nContents of send queue:\n");
	if (l_ptr->first_out) {
		dbg_print_buf_chain(l_ptr->first_out);
	}
	info("Empty send queue\n");
}

static void dbg_print_link_state(struct print_buf *buf, struct link *l_ptr)
{
	if (link_reset_reset(l_ptr) || link_reset_unknown(l_ptr)) {
		tipc_printf(buf, "Link %s already reset\n", l_ptr->name);
		return;
	}

	tipc_printf(buf, "Link %x<%s>:", l_ptr->addr, l_ptr->b_ptr->publ.name);
	tipc_printf(buf, ": NXO(%u):", mod(l_ptr->next_out_no));
	tipc_printf(buf, "NXI(%u):", mod(l_ptr->next_in_no));
	tipc_printf(buf, "SQUE");
	if (l_ptr->first_out) {
		tipc_printf(buf, "[%u..", buf_seqno(l_ptr->first_out));
		if (l_ptr->next_out)
			tipc_printf(buf, "%u..", buf_seqno(l_ptr->next_out));
		tipc_printf(buf, "%u]", buf_seqno(l_ptr->last_out));
		if ((mod(buf_seqno(l_ptr->last_out) -
			 buf_seqno(l_ptr->first_out))
		     != (l_ptr->out_queue_size - 1))
		    || (l_ptr->last_out->next != 0)) {
			tipc_printf(buf, "\nSend queue inconsistency\n");
			tipc_printf(buf, "first_out= %x ", l_ptr->first_out);
			tipc_printf(buf, "next_out= %x ", l_ptr->next_out);
			tipc_printf(buf, "last_out= %x ", l_ptr->last_out);
			link_dump_send_queue(l_ptr);
		}
	} else
		tipc_printf(buf, "[]");
	tipc_printf(buf, "SQSIZ(%u)", l_ptr->out_queue_size);
	if (l_ptr->oldest_deferred_in) {
		u32 o = buf_seqno(l_ptr->oldest_deferred_in);
		u32 n = buf_seqno(l_ptr->newest_deferred_in);
		tipc_printf(buf, ":RQUE[%u..%u]", o, n);
		if (l_ptr->deferred_inqueue_sz != mod((n + 1) - o)) {
			tipc_printf(buf, ":RQSIZ(%u)",
				    l_ptr->deferred_inqueue_sz);
		}
	}
	if (link_working_unknown(l_ptr))
		tipc_printf(buf, ":WU");
	if (link_reset_reset(l_ptr))
		tipc_printf(buf, ":RR");
	if (link_reset_unknown(l_ptr))
		tipc_printf(buf, ":RU");
	if (link_working_working(l_ptr))
		tipc_printf(buf, ":WW");
	tipc_printf(buf, "\n");
}

static void dbg_print_link(struct link *l_ptr, const char *str)
{
	if (DBG_OUTPUT != TIPC_NULL) {
		tipc_printf(DBG_OUTPUT, str);
		dbg_print_link_state(DBG_OUTPUT, l_ptr);
	}
}

static void dbg_print_buf_chain(struct sk_buff *root_buf)
{
	if (DBG_OUTPUT != TIPC_NULL) {
		struct sk_buff *buf = root_buf;

		while (buf) {
			msg_dbg(buf_msg(buf), "In chain: ");
			buf = buf->next;
		}
	}
}

#endif
