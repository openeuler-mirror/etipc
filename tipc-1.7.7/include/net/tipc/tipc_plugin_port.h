/*
 * include/net/tipc/tipc_port.h: Include file for port access by TIPC plugins
 * 
 * Copyright (c) 1994-2007, Ericsson AB
 * Copyright (c) 2005-2007, Wind River Systems
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

#ifndef _NET_TIPC_PORT_H_
#define _NET_TIPC_PORT_H_

#ifdef __KERNEL__

#include <linux/tipc.h>
#include <linux/skbuff.h>
#include <net/tipc/tipc_plugin_msg.h>

#define TIPC_FLOW_CONTROL_WIN 512

#define TIPC_PS_HASH_SZ    32
/* 因为基于type/instance的通信关系是不变的，但是重起Location后
   socket portref是变化的，所以修改为基于type/instance来统计。
   允许一个type/ins对应最多四个node/port，有些port应该是废弃的，
   可以循环使用记录node/port的msg_stat。

   发送报文所使用的type/instance是不同的，但是接收到本port的报文
   的type/instance基本是相同的，所以recv_stat基于node/ref统计，在
   msg_stat中增加基于node/ref的hash列表。
 */
#define TIPC_PS_REF_RCD    4

struct port_msg_stat {
	u32 node;
	u32 ref;
	struct hlist_node ps_list;

	/* ensure sizeof(ps) <= 64, change refcount/pause_msec/stopped total 32 */
	u8 pause_msec; /* sent pause */
	u8 stopped;    /* recv CONN_MANAGER, CONNLESS_STOP */
	u16 refcount;   /* 记录引用该stat的type个数。支持type与port的关系 m:n */

	struct {
		u32 sent;      /* sent success only */
		u32 sent_fail; /* not include congested */
		u32 sent_congested;

		u32 recv;
		u32 recv_mcast;
		u32 recv_reject;
		u32 sent_pause[2]; /* 0 pause, 1 unpause */
		u32 recv_pause[2];
		u32 timout_pause;
	} stat;
};

struct port_msg_stat_hlist {
	u32 type;
	u32 low;
	u32 upper;
	struct hlist_node psh_list;

    u32 cur;  /* 当前使用的msg_stat */
    u32 accu; /* 总共使用的msg_stat */
    u32 sent_reject; /* 记录nod:ref=0:0 */
    struct port_msg_stat *msg_stat[TIPC_PS_REF_RCD];
};

struct msg_stats_info  /* 特定报文统计info */
{
    u32 rcvmsg_flag;   /* 报文统计使能标记 */
    u32 sndmsg_flag;
    u32 rcvmsg_cnts;   /* 报文统计计数 */
    u32 sndmsg_cnts;
    struct msg_filter_info rcvmsg_filter;
    struct msg_filter_info sndmsg_filter;
};

/**
 * struct tipc_port - native TIPC port info available to privileged users
 * @usr_handle: pointer to additional user-defined information about port
 * @lock: pointer to spinlock for controlling access to port
 * @connected: non-zero if port is currently connected to a peer port
 * @conn_type: TIPC type used when connection was established
 * @conn_instance: TIPC instance used when connection was established
 * @conn_unacked: number of unacknowledged messages received from peer port
 * @published: non-zero if port has one or more associated names
 * @congested: non-zero if cannot send because of link or port congestion
 * @max_pkt: maximum packet size "hint" used when building messages sent by port
 * @ref: unique reference to port in TIPC object registry
 * @phdr: preformatted message header used when sending messages
 */

struct tipc_port {
        void *usr_handle;
        spinlock_t *lock;
	int connected;
        u32 conn_type;
        u32 conn_instance;
	u32 conn_unacked;
	int published;
	u32 congested;
	u32 max_pkt;
	u32 ref;
	struct tipc_msg phdr;

	u32 last_read_tim;  /* last read time */
	u32 sk_priority;  /* tipc_priority */
	/* flow-control */
	u32 sk_que_sz; /* = skb_queue_len(&sk->sk_receive_queue) + sk_bk_sz，用于显示 */
	u32 sk_que_max;
    u32 sk_bk_sz;  /* backlog size. spin_lock(&((__sk)->sk_lock.slock)) */

	u32 stopped;

	struct port_msg_stat *last_ps_sent;
	struct port_msg_stat *last_ps_recv;

	struct hlist_head   *hpsh;
	struct hlist_head   *hps;
	struct port_msg_stat ps; /* mc or connect ps */
	
	u32 sent_failed;
	u32 sent_reject;
	u32 sentm_reject;
	u32 nowait;
	u32 wait;
	
	u32 recv;
	u32 recv_reject;
	u32 recv_reject_backlog;        
	u32 msg_flags;
	u32 selector;

    struct msg_stats_info msg_stats;  //改成动态申请
};

void tipc_pause(struct tipc_port *tp_ptr, u32 dnode, u32 dport, u32 mc, u32 msec);
struct port_msg_stat *tipc_find_ps_recv(struct tipc_port *tp_ptr,
				u32 node, u32 port);


struct tipc_port *tipc_createport_raw(void *usr_handle,
			u32 (*dispatcher)(struct tipc_port *, struct sk_buff *),
			void (*wakeup)(struct tipc_port *),
			const u32 importance);

int tipc_reject_msg(struct sk_buff *buf, u32 err);

int tipc_send_buf_fast(struct sk_buff *buf, u32 destnode);

void tipc_acknowledge(u32 port_ref, u32 ack);

struct tipc_port *tipc_get_port(const u32 ref);

void *tipc_get_handle(const u32 ref);

/*
 * The following routines require that the port be locked on entry
 */

int tipc_disconnect_port(struct tipc_port *tp_ptr);

#endif

#endif

