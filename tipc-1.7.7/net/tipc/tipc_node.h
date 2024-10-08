/*
 * net/tipc/tipc_node.h: Include file for TIPC node management routines
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

#ifndef _TIPC_NODE_H
#define _TIPC_NODE_H

#include "tipc_addr.h"
#include "tipc_bearer.h"
#include "tipc_net.h"

/* Flags used to block (re)establishment of contact with a neighboring node */

#define WAIT_PEER_DOWN	0x0001	/* wait to see that peer's links are down */
#define WAIT_NAMES_GONE	0x0002	/* wait for peer's publications to be purged */
#define WAIT_NODE_DOWN	0x0004	/* wait until peer node is declared down */

/**
 * struct tipc_node - TIPC node structure
 * @elm: generic network element structure for node
 * @node_list: adjacent entries in sorted list of nodes
 * @active_links: pointers to active links to node
 * @links: pointers to all links to node
 * @working_links: number of working links to node (both active and standby)
 * @link_cnt: number of links to node
 * @working_links: number of working links to node (both active and standby)
 * @permit_changeover: non-zero if node has redundant links to this system
 * @block_setup: bit mask of conditions preventing link establishment to node
 * @signature: random node instance identifier (always 0 for a uni-cluster node)
 * @flags: bit array indicating node's capabilities
 * @bclink: broadcast-related info
 *    @supported: non-zero if node supports TIPC b'cast capability
 *    @acked: sequence # of last outbound b'cast message acknowledged by node
 *    @last_in: sequence # of last in-sequence b'cast message received from node
 *    @last_sent: sequence # of last b'cast message sent by node
 *    @oos_state: state tracker for handling OOS b'cast messages
 *    @deferred_size: number of OOS b'cast messages in deferred queue
 *    @deferred_head: oldest OOS b'cast message received from node
 *    @deferred_tail: newest OOS b'cast message received from node
 *    @defragm: list of partially reassembled b'cast message fragments from node
 */
#ifdef CONFIG_TIPC_MCASTGID_MAX   /* */

#define MCLINK_FLAG_CCACK      0x1
#define MCLINK_FLAG_WU         0x2
#define MCLINK_FLAG_RDY        0x4
#define MCLINK_FLAG_NOREAD     0x8
#define MCLINK_NEED_SYNC(node, msg_typ) (((node)->working_links == 0) || \
            ((node)->working_links == 1 && (msg_typ) == ACTIVATE_MSG))

struct mclink {
	struct list_head mclist;

	int mcgid;
	struct mcglink *mcgl;
	
	int supported;
	u32 state;
	u32 acked;
	u32 last_in;
	u32 last_sent;
	u32 oos_state;
	u32 ccacked;
	u32 deferred_size;
	struct sk_buff *deferred_head;
	struct sk_buff *deferred_tail;
	struct sk_buff *defragm;
	
	u32 sent_nacks;
	u32 recv_nacks;
	u32 deferes;
	u32 duplicates;
	u32 last_in_chk;
	u32 last_sent_chk;
	u32 ack_err_cnt; // 错误ack计数
};
#endif

struct tipc_node {
	struct net_element elm;			/* MUST BE FIRST */
	struct list_head node_list;
	struct link *active_links[2];
	struct link *links[TIPC_MAX_LINKS];
	int link_cnt;
	int working_links;
	int permit_changeover;
	int cleanup_required;
	u16 signature;
	u16 flags;
	u16 dup_cnt;
	u16 dup_tim_cnt;
#ifdef CONFIG_TIPC_MCASTGID_MAX   /* */
	int state; /* 用于状态同步，否则在广播发送过程
			中node up可能存在两端广播信息不一致。 */
	u8  bearer_link_act[TIPC_MAX_BEARERS];
	u8  bearer_link_cnt[TIPC_MAX_BEARERS];
	u32 rate; /* Mbytes rate */
	
	u32 mcgid_chk; /* 下次待发送mcinfo */
	u32 mc_count;
	/*u8  mc_map[TIPC_MCMAP_BYTES];  用supported替代 */
	u8  mc_peer[TIPC_MCMAP_BYTES]; /* 从对端收到的对端支持的mc */

	u8  mc_nord_recv[TIPC_MCMAP_BYTES]; /* 从mcinfo得到的对端不支持读 */
	u8  mc_rding[TIPC_MCMAP_BYTES]; /* 在接收节点中 */

	u8 mc_ccack_assign[TIPC_MCMAP_BYTES];
	u8 mc_ccack_recv[TIPC_MCMAP_BYTES];

	struct list_head mclinks;
	struct mclink    bclink; /* mclink0 */
#else
	struct {
		int supported;
		u32 acked;
		u32 last_in;
		u32 last_sent;
		u32 oos_state;
		u32 deferred_size;
		struct sk_buff *deferred_head;
		struct sk_buff *deferred_tail;
		struct sk_buff *defragm;
	} bclink;
#endif /* */
};

struct tipc_node *tipc_node_create(u32 addr);
void tipc_node_delete(struct tipc_node *n_ptr);
void tipc_node_link_up(struct tipc_node *n_ptr, struct link *l_ptr);
void tipc_node_link_down(struct tipc_node *n_ptr, struct link *l_ptr);
u32 tipc_node_has_redundant_links(struct link *l_ptr);
int tipc_node_is_up(struct tipc_node *n_ptr);
struct tipc_node *tipc_node_attach_link(struct link *l_ptr);
void tipc_node_detach_link(struct tipc_node *n_ptr, struct link *l_ptr);
struct sk_buff *tipc_node_get_nodes(const void *req_tlv_area, int req_tlv_space);
struct sk_buff *tipc_node_get_links(const void *req_tlv_area, int req_tlv_space);
/* */
struct link *tipc_node_find_link_byaddr(struct tipc_node *n_ptr, struct bearer *b_ptr, struct tipc_media_addr *media_addr);
struct link *tipc_node_find_link_bybuf(struct tipc_node *n_ptr, struct bearer *b_ptr, struct sk_buff *buf);
struct link *tipc_node_find_link_byplane(struct tipc_node *n_ptr, u32 bid, u32 net_plane);
void tipc_node_link_active(struct tipc_node *n_ptr, struct link *l_ptr);
void tipc_node_link_standby(struct tipc_node *n_ptr, struct link *l_ptr);

#ifdef CONFIG_TIPC_MCASTGID_MAX   /* */
struct mclink *tipc_node_find_active_mclink(struct tipc_node *n_ptr, u32 mcgid);
int tipc_node_get_mcinfo(struct tipc_node *n_ptr, 
	struct mcast_ackinfo mcinfo[], u32 mci_cnt);
int tipc_node_recv_mcinfo(struct tipc_node *n_ptr, 
	void *mci_data, u32 bytes, u32 msgtype);
struct mclink *tipc_node_create_mclink(struct tipc_node *n_ptr, u32 mcgid);
void tipc_node_reset_mclink(struct mclink *mcl);
void tipc_node_enable_mclink(struct tipc_node *n_ptr, u32 mcgid);
void tipc_node_disable_mclink(struct tipc_node *n_ptr, u32 mcgid);
void tipc_nodes_enable_mclink(u32 mcgid);
void tipc_nodes_disable_mclink(u32 mcgid);
void tipc_node_check_mc(struct tipc_node *n_ptr);
void tipc_node_mcstat(struct tipc_node *n_ptr, struct print_buf *pb);
void tipc_nodes_mcstat(struct print_buf *pb);
void tipc_node_unlock_delete(struct tipc_node *n_ptr);
#endif


struct sk_buff *tipc_get_links_states(const void *req_tlv_area, int req_tlv_space);
struct sk_buff *tipc_node_link_state_issuance(const void *req_tlv_area, int req_tlv_space);
int tipc_issuance_link_state(struct link *l_ptr);
static inline void tipc_node_lock(struct tipc_node *n_ptr)
{
        net_element_lock(&n_ptr->elm);	
}

static inline void tipc_node_unlock(struct tipc_node *n_ptr)
{
        net_element_unlock(&n_ptr->elm);	
}


#endif
