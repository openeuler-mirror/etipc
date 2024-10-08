/*
 * net/tipc/tipc_msg.h: Include file for TIPC message header routines
 *
 * Copyright (c) 2000-2007, Ericsson AB
 * Copyright (c) 2005-2008, Wind River Systems
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

#ifndef _TIPC_MSG_H
#define _TIPC_MSG_H

#include "tipc_core.h"
#include "tipc_addr.h"

/*
 * Private TIPC message header definitions
 *
 * The following definitions are used internally by TIPC itself.
 * They supplement the public definitions found in tipc_plugin_msg.h.
 */


#define TIPC_VERSION              2

#define SHORT_H_SIZE              24	/* Connected, in-cluster messages */
#define DIR_MSG_H_SIZE            32	/* Directly addressed messages */
#define LONG_H_SIZE               40	/* Named messages */
#define MCAST_H_SIZE              44	/* Multicast messages */
#define INT_H_SIZE                40	/* Internal messages */
#define MIN_H_SIZE                24	/* Smallest legal TIPC header size */
#define MAX_H_SIZE                60	/* Largest possible TIPC header size */

#define MAX_MSG_SIZE (MAX_H_SIZE + TIPC_MAX_USER_MSG_SIZE)


/*
 * The following definitions are used with TIPC data message headers
 *
 * Note: Some of these definitions are generic, and also used with 
 * TIPC internal message headers
 */   

static inline void msg_set_word(struct tipc_msg *m, u32 w, u32 val)
{
	m->hdr[w] = htonl(val);
}

static inline void msg_set_bits(struct tipc_msg *m, u32 w,
				u32 pos, u32 mask, u32 val)
{
	val = (val & mask) << pos;
	mask = mask << pos;
	m->hdr[w] &= ~htonl(mask);
	m->hdr[w] |= htonl(val);
}

static inline void msg_swap_words(struct tipc_msg *msg, u32 a, u32 b)
{
	u32 temp = msg->hdr[a];

	msg->hdr[a] = msg->hdr[b];
	msg->hdr[b] = temp;
}

/*
 * Word 0
 */

static inline u32 msg_version(struct tipc_msg *m)
{
	return msg_bits(m, 0, 29, 7);
}

static inline void msg_set_version(struct tipc_msg *m)
{
	msg_set_bits(m, 0, 29, 7, TIPC_VERSION);
}

static inline u32 msg_user(struct tipc_msg *m)
{
	return msg_bits(m, 0, 25, 0xf);
}

static inline u32 msg_isdata(struct tipc_msg *m)
{
	return (msg_user(m) <= TIPC_CRITICAL_IMPORTANCE);
}

static inline void msg_set_user(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 0, 25, 0xf, n);
}

static inline void msg_set_importance(struct tipc_msg *m, u32 i)
{
	msg_set_user(m, i);
}

static inline void msg_set_hdr_sz(struct tipc_msg *m,u32 n)
{
	msg_set_bits(m, 0, 21, 0xf, n>>2);
}

static inline int msg_non_seq(struct tipc_msg *m)
{
	return msg_bits(m, 0, 20, 1);
}

static inline void msg_set_non_seq(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 0, 20, 1, n);
}

static inline int msg_dest_droppable(struct tipc_msg *m)
{
	return msg_bits(m, 0, 19, 1);
}

static inline void msg_set_dest_droppable(struct tipc_msg *m, u32 d)
{
	msg_set_bits(m, 0, 19, 1, d);
}

static inline int msg_src_droppable(struct tipc_msg *m)
{
	return msg_bits(m, 0, 18, 1);
}

static inline void msg_set_src_droppable(struct tipc_msg *m, u32 d)
{
	msg_set_bits(m, 0, 18, 1, d);
}

static inline void msg_set_size(struct tipc_msg *m, u32 sz)
{
	msg_set_bits(m, 0, 0, 0x1ffff, sz);
}


/*
 * Word 1
 */

static inline void msg_set_type(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 1, 29, 0x7, n);
}

static inline void msg_set_errcode(struct tipc_msg *m, u32 err)
{
	msg_set_bits(m, 1, 25, 0xf, err);
}

static inline u32 msg_reroute_cnt(struct tipc_msg *m)
{
	return msg_bits(m, 1, 21, 0xf);
}

static inline void msg_incr_reroute_cnt(struct tipc_msg *m)
{
	msg_set_bits(m, 1, 21, 0xf, msg_reroute_cnt(m) + 1);
}

static inline void msg_reset_reroute_cnt(struct tipc_msg *m)
{
	msg_set_bits(m, 1, 21, 0xf, 0);
}

static inline u32 msg_lookup_scope(struct tipc_msg *m)
{
	return msg_bits(m, 1, 19, 0x3);
}

static inline void msg_set_lookup_scope(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 1, 19, 0x3, n);
}

static inline u32 msg_bcast_ack(struct tipc_msg *m)
{
	return msg_bits(m, 1, 0, 0xffff);
}

static inline void msg_set_bcast_ack(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 1, 0, 0xffff, n);
}

/*
 * Word 2
 */

static inline u32 msg_ack(struct tipc_msg *m)
{
	return msg_bits(m, 2, 16, 0xffff);
}

static inline void msg_set_ack(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 2, 16, 0xffff, n);
}

static inline u32 msg_seqno(struct tipc_msg *m)
{
	return msg_bits(m, 2, 0, 0xffff);
}

static inline void msg_set_seqno(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 2, 0, 0xffff, n);
}

/*
 * TIPC may utilize the "link ack #" and "link seq #" fields of a short
 * message header to hold the destination node for the message, since the
 * normal "dest node" field isn't present.  This cache is only referenced
 * when required, so populating the cache of a longer message header is
 * harmless (as long as the header has the two link sequence fields present).
 *
 * Note: Host byte order is OK here, since the info never goes off-card.
 */

static inline u32 msg_destnode_cache(struct tipc_msg *m)
{
	return m->hdr[2];
}

static inline void msg_set_destnode_cache(struct tipc_msg *m, u32 dnode)
{
	m->hdr[2] = dnode;
}

/*
 * Words 3-10
 */


static inline void msg_set_prevnode(struct tipc_msg *m, u32 a)
{
	msg_set_word(m, 3, a);
}

static inline void msg_set_origport(struct tipc_msg *m, u32 p)
{
	msg_set_word(m, 4, p);
}

static inline void msg_set_destport(struct tipc_msg *m, u32 p)
{
	msg_set_word(m, 5, p);
}

static inline void msg_set_mc_netid(struct tipc_msg *m, u32 p)
{
	msg_set_word(m, 5, p);
}

static inline void msg_set_orignode(struct tipc_msg *m, u32 a)
{
	msg_set_word(m, 6, a);
}

static inline void msg_set_destnode(struct tipc_msg *m, u32 a)
{
	msg_set_word(m, 7, a);
}

static inline u32 msg_routed(struct tipc_msg *m)
{
	if (likely(msg_short(m)))
		return 0;
	return(msg_destnode(m) ^ msg_orignode(m)) >> 11;
}

static inline void msg_set_nametype(struct tipc_msg *m, u32 n)
{
	msg_set_word(m, 8, n);
}

static inline u32 msg_timestamp(struct tipc_msg *m)
{
	return msg_word(m, 8);
}

static inline void msg_set_timestamp(struct tipc_msg *m, u32 n)
{
	msg_set_word(m, 8, n);
}

static inline void msg_set_namelower(struct tipc_msg *m, u32 n)
{
	msg_set_word(m, 9, n);
}

static inline void msg_set_nameinst(struct tipc_msg *m, u32 n)
{
	msg_set_namelower(m, n);
}

static inline void msg_set_nameupper(struct tipc_msg *m, u32 n)
{
	msg_set_word(m, 10, n);
}

static inline struct tipc_msg *msg_get_wrapped(struct tipc_msg *m)
{
	return (struct tipc_msg *)msg_data(m);
}

#ifdef CONFIG_TIPC_MCASTGID_MAX   /* */
int nametype2mcgid(u32 nametype);
int mcgid2nametype_dummy(u32 mcgid);

static inline void msg_set_nametype_dummy(struct tipc_msg *m, u32 mcgid)
{
	return msg_set_nametype(m, mcgid2nametype_dummy(mcgid));
}

static inline u32 msg_nametype2mcgid(struct tipc_msg *m)
{
	return nametype2mcgid(msg_nametype(m));
}

#endif  /* */


/*
 * The following definitions are used with TIPC internal message headers only
 */   

/* 
 * Internal message users (types 0-3 are for application messages)
 *
 * Note: Pre-TIPC 1.7 releases treat incoming USER_TYPE_9 messages as route
 * distribution messages.
 */

#define  USER_TYPE_4          4		/* NOT USED */
#define  BCAST_PROTOCOL       5
#define  MSG_BUNDLER          6
#define  LINK_PROTOCOL        7
#define  CONN_MANAGER         8
#define  USER_TYPE_9          9		/* NOT USED (see Note above) */
#define  CHANGEOVER_PROTOCOL  10
#define  NAME_DISTRIBUTOR     11
#define  MSG_FRAGMENTER       12
#define  LINK_CONFIG          13
#define  ROUTE_DISTRIBUTOR    14
#define  USER_TYPE_15         15	/* NOT USED */

/*
 *  Connection management protocol messages
 */

#define CONN_PROBE        0
#define CONN_PROBE_REPLY  1
#define CONN_ACK          2
#define CONN_PAUSE        3 /* port rdm flow-control */
#define CONN_MCPAUSE      4 /* port rdm flow-control */

/* 
 * Name/route distributor messages
 */

#define DIST_PUBLISH	0
#define DIST_WITHDRAW	1
#define DIST_PURGE	2
#define DIST_REQUEST	3  /* request name/route */

/*
 * Link configuration message node-capability indicator flags
 */

#define NF_DONT_USE_1	0x0001		/* uni-cluster nodes may set this */
#define NF_DONT_USE_2	0x0002		/* uni-cluster nodes may set this */
#define NF_MULTICLUSTER	0x1000		/* node is multi-cluster capable */

/*
 * Word 1
 */

static inline u32 msg_seq_gap(struct tipc_msg *m)
{
	return msg_bits(m, 1, 16, 0x1fff);
}

static inline void msg_set_seq_gap(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 1, 16, 0x1fff, n);
}

static inline u32 msg_node_flags(struct tipc_msg *m)
{
	return msg_bits(m, 1, 16, 0x1fff);
}

static inline void msg_set_node_flags(struct tipc_msg *m, u32 n) 
{
	msg_set_bits(m, 1, 16, 0x1fff, n);
}

static inline u32 msg_node_sig(struct tipc_msg *m)
{
	return msg_bits(m, 1, 0, 0xffff);
}

static inline void msg_set_node_sig(struct tipc_msg *m, u32 n) 
{
	msg_set_bits(m, 1, 0, 0xffff, n);
}


/*
 * Word 2
 */

static inline u32 msg_dest_domain(struct tipc_msg *m)
{
	return msg_word(m, 2);
}

static inline void msg_set_dest_domain(struct tipc_msg *m, u32 n)
{
	msg_set_word(m, 2, n);
}

static inline u32 msg_bcgap_after(struct tipc_msg *m)
{
	return msg_bits(m, 2, 16, 0xffff);
}

static inline void msg_set_bcgap_after(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 2, 16, 0xffff, n);
}

static inline u32 msg_bcgap_to(struct tipc_msg *m)
{
	return msg_bits(m, 2, 0, 0xffff);
}

static inline void msg_set_bcgap_to(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 2, 0, 0xffff, n);
}


/*
 * Word 4
 */

static inline u32 msg_last_bcast(struct tipc_msg *m)
{
	return msg_bits(m, 4, 16, 0xffff);
}

static inline void msg_set_last_bcast(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 4, 16, 0xffff, n);
}

static inline u32 msg_fragm_no(struct tipc_msg *m)
{
	return msg_bits(m, 4, 16, 0xffff);
}

static inline void msg_set_fragm_no(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 4, 16, 0xffff, n);
}

static inline u32 msg_next_sent(struct tipc_msg *m)
{
	return msg_bits(m, 4, 0, 0xffff);
}

static inline void msg_set_next_sent(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 4, 0, 0xffff, n);
}

static inline u32 msg_fragm_msg_no(struct tipc_msg *m)
{
	return msg_bits(m, 4, 0, 0xffff);
}

static inline void msg_set_fragm_msg_no(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 4, 0, 0xffff, n);
}

static inline u32 msg_bc_netid(struct tipc_msg *m)
{
	return msg_word(m, 4);
}

static inline void msg_set_bc_netid(struct tipc_msg *m, u32 id)
{
	msg_set_word(m, 4, id);
}

static inline u32 msg_link_selector(struct tipc_msg *m)
{
	return msg_bits(m, 4, 0, 1);
}

static inline void msg_set_link_selector(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 4, 0, 1, n);
}

/*
 * Word 5
 */

static inline u32 msg_session(struct tipc_msg *m)
{
	return msg_bits(m, 5, 16, 0xffff);
}

static inline void msg_set_session(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 5, 16, 0xffff, n);
}

static inline u32 msg_probe(struct tipc_msg *m)
{
	return msg_bits(m, 5, 0, 1);
}

static inline void msg_set_probe(struct tipc_msg *m, u32 val)
{
	msg_set_bits(m, 5, 0, 1, (val & 1));
}

static inline char msg_net_plane(struct tipc_msg *m)
{
	return msg_bits(m, 5, 1, 7) + 'A';
}

static inline void msg_set_net_plane(struct tipc_msg *m, char n)
{
	msg_set_bits(m, 5, 1, 7, (n - 'A'));
}

static inline u32 msg_linkprio(struct tipc_msg *m)
{
	return msg_bits(m, 5, 4, 0x1f);
}

static inline void msg_set_linkprio(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 5, 4, 0x1f, n);
}

static inline u32 msg_bearer_id(struct tipc_msg *m)
{
	return msg_bits(m, 5, 9, 0x7);
}

static inline void msg_set_bearer_id(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 5, 9, 0x7, n);
}

static inline u32 msg_stop(struct tipc_msg *m)
{
	return msg_bits(m, 5, 13, 0x1);
}

static inline void msg_set_stop(struct tipc_msg *m, u32 s)
{
	msg_set_bits(m, 5, 13, 0x1, s);
}

static inline u32 msg_redundant_link(struct tipc_msg *m)
{
	return msg_bits(m, 5, 12, 0x1);
}

static inline void msg_set_redundant_link(struct tipc_msg *m, u32 r)
{
	msg_set_bits(m, 5, 12, 0x1, r);
}


/*
 * Word 9
 */

static inline u32 msg_item_size(struct tipc_msg *m)
{
	return msg_bits(m, 9, 24, 0xff);
}

static inline void msg_set_item_size(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 9, 24, 0xff, n);
}

static inline u32 msg_msgcnt(struct tipc_msg *m)
{
	return msg_bits(m, 9, 16, 0xffff);
}

static inline void msg_set_msgcnt(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 9, 16, 0xffff, n);
}

static inline u32 msg_bcast_tag(struct tipc_msg *m)
{
	return msg_bits(m, 9, 16, 0xffff);
}

static inline void msg_set_bcast_tag(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 9, 16, 0xffff, n);
}

static inline u32 msg_max_pkt(struct tipc_msg *m)
{
	return (msg_bits(m, 9, 16, 0xffff) * 4);
}

static inline void msg_set_max_pkt(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 9, 16, 0xffff, (n / 4));
}

static inline u32 msg_link_tolerance(struct tipc_msg *m)
{
	return msg_bits(m, 9, 0, 0xffff);
}

static inline void msg_set_link_tolerance(struct tipc_msg *m, u32 n)
{
	msg_set_bits(m, 9, 0, 0xffff, n);
}

/*
 * Segmentation message types
 */

#define FIRST_FRAGMENT     0
#define FRAGMENT           1
#define LAST_FRAGMENT      2

/*
 * Link management protocol message types
 */

#define STATE_MSG       0
#define RESET_MSG       1
#define ACTIVATE_MSG    2

/*
 * Changeover tunnel message types
 */
#define DUPLICATE_MSG    0
#define ORIGINAL_MSG     1


/*
 * Config protocol message types
 */

#define DSC_REQ_MSG          0
#define DSC_RESP_MSG         1
#define DSC_DOUBT_MSG        2  /* */

#ifdef CONFIG_TIPC_MCASTGID_MAX   /* */
/*
		TIPC private message data format:


       1 0 9 8 7 6 5 4|3 2 1 0 9 8 7 6|5 4 3 2 1 0 9 8|7 6 5 4 3 2 1 0 
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w0:|vers | user  |hdr sz |n|d|s|-|          message size           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   wx:|...............................|      ................         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   wx:|        data_len               |   data_type                   |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   wx:|                      data_value                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   wx:|        data_len               |   data_type                   |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   wx:|                      data_value                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 借用TLV处理,所有的len,type都从word开始,中间可能包括pad对齐数据
*/


/*
 * Config protocol message data type
 */
#define DSC_DT_RATE  0xf101
#define DSC_DT_MCAST 0xf102


#define DSC_DT_LEN (TLV_SPACE(sizeof(u32))+TLV_SPACE(1+TIPC_MCMAP_BYTES))


/*
 * Link protocol message data type
 */
#define LINK_DT_MCAST  0xf201

#define LINK_DT_LEN      (TLV_SPACE(sizeof(struct mcast_ackinfo)*MCINFO_MAX))

struct mcast_ackinfo {
	u8 mcgid;
	u8 flag; /* lowest bit ccack */
	__be16 last_in;
	__be16 last_sent;
};

/* 
 * 每次最多发送4个mcast_ackinfo, 减少每次的处理开销
 */
#define MCINFO_MAX  4
#endif  /* */

int  tipc_msg_build(struct tipc_msg *hdr, 
		    struct iovec const *msg_sect, u32 num_sect,
		    int max_size, int usrmem, struct sk_buff** buf);
void tipc_msg_init(struct tipc_msg *m, u32 user, u32 type, 
		   u32 hsize, u32 destnode);
int  tipc_msg_calc_data_size(struct iovec const *msg_sect, u32 num_sect);
u32  tipc_msg_tot_importance(struct tipc_msg *m);

#endif
