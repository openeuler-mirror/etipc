/*
 * net/tipc/tipc_bcast.c: TIPC broadcast code
 *
 * Copyright (c) 2004-2006, Ericsson AB
 * Copyright (c) 2004, Intel Corporation.
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
#include "tipc_msg.h"
#include "tipc_dbg.h"
#include "tipc_link.h"
#include "tipc_net.h"
#include "tipc_node.h"
#include "tipc_port.h"
#include "tipc_addr.h"
#include "tipc_name_distr.h"
#include "tipc_bearer.h"
#include "tipc_name_table.h"
#include "tipc_bcast.h"

/* V5在多框上测试MTU为1404时性能较佳。TIPC 组播MTU需静态指定 */
#define MAX_PKT_DEFAULT_MCAST (MAX_PKT_DEFAULT)	/* bcast link max packet size (fixed) */

#define BCLINK_WIN_DEFAULT 20		/* bcast link window size (default) */

#define BCLINK_LOG_BUF_SIZE 0

/*
 * Loss rate for incoming broadcast frames; used to test retransmission code.
 * Set to N to cause every N'th frame to be discarded; 0 => don't discard any.
 */

#define TIPC_BCAST_LOSS_RATE 0

/**
 * struct bcbearer_pair - a pair of bearers used by broadcast link
 * @primary: pointer to primary bearer
 * @secondary: pointer to secondary bearer
 *
 * Bearers must have same priority and same set of reachable destinations
 * to be paired.
 */

struct bcbearer_pair {
	struct bearer *primary;
	struct bearer *secondary;
};

/**
 * mcglink->link: 表示负责本端的发送mcast
 * node->mclink:  表示本端的接收mcast信息
 * 原来只有一个bclink,这里修改为x个mcglink和mclink;
 * 在node->mclink中有指向mcglink的引用
 */
 
/**
 * struct mcglink - link used for multicast messages
 * @link: (non-standard) broadcast link structure
 * @mcgid: multicast group id
 * @pack_queue_size: partial ack queue size
 * @first_pack: first partial ack packet
 * @min_rate: if node's rate less min_rate, assign it to ccack
 * @ccack_count: congest control ack count computed by mcast_nodes
 * @mcast_nodes: map of the multicast capable nodes in cluster
 * 
 * Handles sequence numbering, fragmentation, bundling, free msg memory, etc.
 */
#define BCAST_CCACK_REC  12 /* big enough */
#define BCAST_SEND_WIN   8
#define CCACK_SEL_MASK  0x7F
#define NODE_CHASSIS(nod)  ((nod >> 5) & CCACK_SEL_MASK) /* 对应TIPC地址分配 */
#define TYPE2MCG_RSHIFT_DEF  12
#define TYPE2MCG_MASK_DEF    0xF

extern unsigned int g_tipc_dbg_switch;

struct mcglink {
	struct link link;
	u32    mcgid;
    
 
	u32    pack_queue_size; /* partial/positive ack */
	struct sk_buff *first_pack;
	struct sk_buff *last_pack;
	
	/*
	 * first_pack是尚未得到全部ack确认的报文，也即尚未释放内存的第一个报文
	 * last_pack表示已经发送的最后一个组播报文
	 * 得到了全部ccack确认后first_out向last_out移动
	 * last_out表示待发送队列的最后一个报文
	 * 
	 *    [-------pack_queue_size-----]
	 *                   [-----out_queue_size----]
	 *
	 * first_pack =1=first_out=2=>last_pack =3=last_out->null
	 * =1=表示发送发送窗口前的报文都已经确认
	 * =2=表示first_out刚调用tipc_bcbearer_send()发送
	 * =3=表示发送窗口中的报文都已经发送，也即
	 *	link_add_to_outqueue()后立即调用tipc_bcbearer_send()
	 *
	 * first_pack-1->first_out-2->last_pack-3->last_out->null
	 * -1-表示发送发送窗口前的报文得到部分ack确认
	 * -2-表示发送窗口中的last_pack前的报文得到部分接收ccack节点确认
	 * -3-表示发送窗口中last_pack后的报文还没有调用tipc_bcbearer_send()
	 *
	 * first_pack-1->last_pack->null 22 first_out-3->last_out->null
	 *  22 表示两者断开了链接，存在于接收到ccack确认后first_out为空，
	 *	发送者调用了link_add_to_outqueue()但还没有调用tipc_bcbearer_send()
	 *
	 * 还存在其它组合情况，不影响处理
	 */
	 
	u32    pack_queue_max;
	u32    retrans_pps_max;

	u32    reset_count; /* reset 链路次数 */
	u32    error; /* 出现错误，需要reset恢复 */

	u32    flag; /* RDONYL/WRONLY/SYSTEM etc. */

	u32    min_rate;

	u32    ccack_count; /* congest control ack count */
	u32    ccack_nodes[BCAST_CCACK_REC];
	struct tipc_node_map mcast_nodes;
    u8     ccack_bits[BITS_TO_BYTES(CCACK_SEL_MASK)];
};

/**
 * struct bcbearer - bearer used by broadcast link
 * @bearer: (non-standard) broadcast bearer structure
 * @media: (non-standard) broadcast media structure
 * @bpairs: array of bearer pairs
 * @bpairs_temp: temporary array of bearer pairs used by tipc_bcbearer_sort()
 * @remains: temporary node map used by tipc_bcbearer_send()
 * @remains_new: temporary node map used tipc_bcbearer_send()
 * @mcgcount: supported multicast group count
 * @mcg_map:  map of supported multicast group
 * @mcglinks:  list of multicast group link(mcglink)
 * @node: (non-standard) node structure representing b'cast link's peer node
 *
 * Note: The fields labelled "temporary" are incorporated into the bearer
 * to avoid consuming potentially limited stack space through the use of
 * large local variables within multicast routines.  Concurrent access is
 * prevented through use of the spinlock "bc_lock".
 */

struct bcbearer {
	struct bearer bearer;
	struct tipc_media media;
	struct bcbearer_pair bpairs[TIPC_MAX_BEARERS];
	struct bcbearer_pair bpairs_temp[TIPC_MAX_LINK_PRI + 1];
	struct tipc_node_map remains;
	struct tipc_node_map remains_new;

	u8  mc_map[TIPC_MCMAP_BYTES]; /* supported */
	u32 mcgl_count;
	struct mcglink *mcgls[CONFIG_TIPC_MCASTGID_MAX+1];
	u32  mcgls_ref[CONFIG_TIPC_MCASTGID_MAX+1];
	u32  type2mcgid_rshift;
	u32  type2mcgid_mask; /* rshift, then mask */

	struct tipc_node node;
};

/**
 * struct bclink - link used for broadcast messages
 * @link: (non-standard) broadcast link structure
 * @node: (non-standard) node structure representing b'cast link's peer node
 * @bcast_nodes: map of b'cast capable nodes in cluster
 * 
 * Handles sequence numbering, fragmentation, bundling, etc.
 */

#ifndef CONFIG_TIPC_MCASTGID_MAX
#error "please define CONFIG_TIPC_MCASTGID_MAX first"
struct bclink {
	struct link link;
	struct tipc_node node;
	struct tipc_node_map bcast_nodes;
};


static struct bcbearer *bcbearer = NULL;
static struct bclink *bclink = NULL;
static struct link *bcl = NULL;
#else
static struct bcbearer *bcbearer = NULL;
#endif
static DEFINE_SPINLOCK(bc_lock);

char tipc_bclink_name[] = "multicast-link";

#ifndef CHECK_BCLINK
#define BCLINK_CHECK_QUEUE(mcgl)
#define BCLINK_DUMP_QUEUE(mcgl)
#define info_bclink(fmt, arg...)	       	do {} while (0)
#else
static void bclink_check_queue(struct mcglink *mcgl);
static void bclink_dump_queue(struct mcglink *mcgl);

#define BCLINK_CHECK_QUEUE(mcgl) bclink_check_queue(mcgl)
#define BCLINK_DUMP_QUEUE(mcgl)  bclink_dump_queue(mcgl)
#define info_bclink(fmt, arg...)	   tipc_printf(TIPC_OUTPUT, fmt, ##arg)
#endif

#define BCLINK_SEND_NOUSE_NMAP 

static void bclink_acknowledge(struct tipc_node *n_ptr, u32 acked, struct mclink *mcl);
void tipc_mcglink_reset(struct mcglink *mcgl);
static void bclink_send_nack(struct tipc_node *n_ptr, struct mclink *mcl);

static u32 bcbuf_acks(struct sk_buff *buf)
{
	return (u32)(unsigned long)buf_handle(buf);
}

static void bcbuf_set_acks(struct sk_buff *buf, u32 acks)
{
	buf_set_handle(buf, (void *)(unsigned long)acks);
}

static void bcbuf_decr_acks(struct sk_buff *buf)
{
    bcbuf_set_acks(buf, bcbuf_acks(buf) - 1);
}

static u32 bcbuf_ccacks(struct sk_buff *buf)
{
	return (u32)(unsigned long)TIPC_SKB_CB(buf)->priv;
}

static void bcbuf_set_ccacks(struct sk_buff *buf, u32 ccacks)
{
	TIPC_SKB_CB(buf)->priv = (void *)(unsigned long)ccacks;;
}

static void bcbuf_decr_ccacks(struct sk_buff *buf)
{
    bcbuf_set_ccacks(buf, bcbuf_ccacks(buf) - 1);
}

/* 业务组播和硬件组播的转换关系 2010-1-25 暂时不使用广播 */
int nametype2mcgid(u32 type)
{
    u32 rshift = TYPE2MCG_RSHIFT_DEF;
    u32 mask = TYPE2MCG_MASK_DEF;
    if (bcbearer) {
        rshift = bcbearer->type2mcgid_rshift;
        mask   = bcbearer->type2mcgid_mask;
    }

    return (type >> rshift) & mask;
}

int mcgid2nametype_dummy(u32 mcgid)
{
    u32 shift = TYPE2MCG_RSHIFT_DEF;
    u32 mask = TYPE2MCG_MASK_DEF;
    if (bcbearer) {
        shift = bcbearer->type2mcgid_rshift;
        mask  = bcbearer->type2mcgid_mask;
    }

    return (mcgid & mask) << shift;
}

u32 tipc_bclink_mcg_count()
{
	return bcbearer ? bcbearer->mcgl_count : 0;
}

struct mcglink *tipc_bclink_find_mcglink(u32 mcgid)
{
	struct mcglink *mcgl = NULL;
	
	if (mcgid < CONFIG_TIPC_MCASTGID_MAX && bcbearer &&
        test_bytes_bit(bcbearer->mc_map, mcgid))
		mcgl = bcbearer->mcgls[mcgid];

	return mcgl;
}


static void bclink_mcgl_stat(struct mcglink *mcgl, struct print_buf *pb)
{
	int stop = sizeof(mcgl->mcast_nodes.map) / sizeof(u32);
	int w;
	int b;
	u32 map;
	u32 cnt = 0;

	if (!mcgl->mcast_nodes.count)
		return;

	tipc_printf(pb, "  Nodes:%3u  {", mcgl->mcast_nodes.count);
	for (w = 0; w < stop; w++) {
		map = mcgl->mcast_nodes.map[w];
		if (map == 0) continue;
		
		for (b = 0 ; b < WSIZE; b++) {
			if ((map & (1 << b)) == 0)
				continue;

			tipc_printf(pb, " %u", w*WSIZE+b);
			++cnt;
			if (cnt % 10 == 0 && cnt < mcgl->mcast_nodes.count)
				tipc_printf(pb, "\n              ");				
		}
	}

	tipc_printf(pb, " }\n  CCack Nodes:%3u min_rate:%2u  {",
		mcgl->ccack_count, mcgl->min_rate);
	for (w=0; w<BCAST_CCACK_REC; w++) {
		if (!mcgl->ccack_nodes[w])
			continue;

		tipc_printf(pb, " %u", tipc_node(mcgl->ccack_nodes[w]));
	}
	tipc_printf(pb, " }\n");
}

/*
 *  ccack -----(2^(ccack*2)*2 - 1) == mcast-nodes.count
 *  0   -------   2-1
 *  1   -------   8-1
 *  2   -------   32-1
 *  3   -------   128-1
 *  4   -------   512-1
 *  5   -------   2048-1
 *  6   -------   8192-1
 */
static inline int bclink_need_add_ccack(struct mcglink *mcgl, u32 addr)
{
	return (!test_bytes_bit(mcgl->ccack_bits, NODE_CHASSIS(addr))) ||
        ((2 << (2 * mcgl->ccack_count)) - 1 <= mcgl->mcast_nodes.count);
}

static void bclink_add_ccack(struct mcglink *mcgl, struct tipc_node *n_ptr)
{
    struct mclink *mcl = NULL;
	u32 i = 0;
	if (test_bytes_bit(n_ptr->mc_ccack_assign, mcgl->mcgid)) {
        return;
	}
	
	if (mcgl->ccack_count >= BCAST_CCACK_REC) {
        return;
	}
    
	for (i=0; i<BCAST_CCACK_REC; i++) {
		if (!mcgl->ccack_nodes[i]) {
			mcgl->ccack_nodes[i] = n_ptr->elm.addr;
			mcgl->ccack_count++;
			set_bytes_bit(n_ptr->mc_ccack_assign, mcgl->mcgid);
            mcl = tipc_node_find_active_mclink(n_ptr, mcgl->mcgid);
            if (mcl)
                mcl->ccacked = tipc_bclink_get_last_sent(mcgl);
            set_bytes_bit(mcgl->ccack_bits, NODE_CHASSIS(n_ptr->elm.addr));
			return;
		}
	}	
}

static void bclink_rem_ccack(struct mcglink *mcgl, struct tipc_node *n_ptr)
{
	u32 i = 0;

	if (!test_bytes_bit(n_ptr->mc_ccack_assign, mcgl->mcgid)) {
        return;
	}
    
	for (i=0; i<BCAST_CCACK_REC; i++) {
		if (mcgl->ccack_nodes[i] == n_ptr->elm.addr) {
			mcgl->ccack_nodes[i] = 0;
			mcgl->ccack_count--;
			clr_bytes_bit(n_ptr->mc_ccack_assign, mcgl->mcgid);
			return;
		}
	}	
}

/* find min-rate and add a ccack node if need */
static void bclink_check_ccack(struct mcglink *mcgl)
{
	struct tipc_node *n_ptr = NULL;
	struct tipc_node *n_min = NULL;
	u32 min_rate = TIPC_MAX_LINK_PRI;
	u32 min_rate_cc = TIPC_MAX_LINK_PRI;
	u32 addr = 0;
	int stop = sizeof(mcgl->mcast_nodes.map) / sizeof(u32);
	int w;
	int b;
	u32 map;

    memset(mcgl->ccack_bits, 0, sizeof(mcgl->ccack_bits));

	for (w = 0; w < stop; w++) {
		map = mcgl->mcast_nodes.map[w];
		if (map == 0)
			continue;
		
		for (b = 0 ; b < WSIZE; b++) {
			if ((map & (1 << b)) == 0)
				continue;
			
			addr = tipc_own_addr;
			addr = tipc_addr(tipc_zone(addr), 
				tipc_cluster(addr), w*WSIZE+b);
			
			n_ptr = tipc_net_find_node(addr);
			if (!n_ptr || !tipc_node_is_up(n_ptr))
				continue;			
	
			if (test_bytes_bit(n_ptr->mc_ccack_assign, mcgl->mcgid)) {
                set_bytes_bit(mcgl->ccack_bits, NODE_CHASSIS(addr));
				if (min_rate_cc > n_ptr->rate)
					min_rate_cc = n_ptr->rate;
				continue;
			}
			
			if (min_rate > n_ptr->rate) {
				min_rate = n_ptr->rate;
				n_min = n_ptr;
			}
		}		
	}

	/* old min had been removed */
	mcgl->min_rate = min_rate_cc;

	/* add new min */
	if (n_min) {
		bclink_add_ccack(mcgl, n_min);
        set_bytes_bit(mcgl->ccack_bits, NODE_CHASSIS(n_min->elm.addr));

		if (mcgl->min_rate > n_min->rate)
			mcgl->min_rate = n_min->rate;
	}

	return ;
}


/** 
 * tipc_bclink_add_node - add node to nodemap of each mcglists, assign ccack_map
 * @node: pointer of node
 * 
 * 
 */

/* node加入退出bclink 应该作为原子操作 */   
void tipc_bclink_add_node(struct tipc_node *n_ptr, struct mclink *mcl)
{
	struct mcglink *mcgl = NULL;
	
	spin_lock_bh(&bc_lock);

	mcgl = mcl->mcgl;
	
    mcl->acked = tipc_bclink_get_last_sent(mcgl);
	mcl->state = WORKING_UNKNOWN;

    if (test_bytes_bit(n_ptr->mc_nord_recv, mcl->mcgid)) {
        /* n_ptr非接收节点，只需修改状态返回即可 */
        spin_unlock_bh(&bc_lock);
        return;
    }
    set_bytes_bit(n_ptr->mc_rding, mcl->mcgid);

    /* 对端可接收，则将其加入到mcast_nodes中 */
	tipc_nmap_add(&mcgl->mcast_nodes, n_ptr->elm.addr);
	if (mcgl->min_rate > n_ptr->rate) {
		mcgl->min_rate = n_ptr->rate;
		bclink_add_ccack(mcgl, n_ptr);
	} else if (unlikely(bclink_need_add_ccack(mcgl, n_ptr->elm.addr))) {
		bclink_add_ccack(mcgl, n_ptr);
	} else {
	    /* nothing */
	}

    
	spin_unlock_bh(&bc_lock);
}

/*
 * Node is locked, bc_lock unlocked.
 */
void tipc_bclink_remove_node(struct tipc_node *n_ptr, struct mclink *mcl)
{
	struct mcglink *mcgl = NULL;

	spin_lock_bh(&bc_lock);

	mcgl = mcl->mcgl;
	mcl->state = RESET_UNKNOWN;

    if (!test_bytes_bit(n_ptr->mc_rding, mcl->mcgid)) {
        /* n_ptr非接收节点，只需修改状态返回即可 */
        spin_unlock_bh(&bc_lock);
        return;
    }

	/* must remove before ack */
	tipc_nmap_remove(&mcgl->mcast_nodes, n_ptr->elm.addr);
	if (test_bytes_bit(n_ptr->mc_ccack_assign, mcl->mcgid))
	{	
		bclink_rem_ccack(mcgl, n_ptr);
		bclink_check_ccack(mcgl);
        set_bytes_bit(n_ptr->mc_ccack_assign, mcl->mcgid); /* ack临时使用 */
	}
    if (!mcgl->mcast_nodes.count) {
        /* 这里要先清除未发送报文，以免bclink_acknowledge()->
          ->tipc_link_push_queue()->tipc_link_push_packet()->
          tipc_bcbearer_send()中无法处理。
         */
        tipc_mcglink_reset(mcgl);
    }
    
	bclink_acknowledge(n_ptr, tipc_bclink_get_last_sent(mcgl), mcl);
	clr_bytes_bit(n_ptr->mc_ccack_assign, mcl->mcgid); /* 必须清除 */

    clr_bytes_bit(n_ptr->mc_rding, mcl->mcgid);

	spin_unlock_bh(&bc_lock);
}

static void bclink_set_last_sent(struct mcglink *mcgl)
{
	struct link *bcl = &mcgl->link;
	
	if (bcl->next_out)
		bcl->fsm_msg_cnt = mod(buf_seqno(bcl->next_out) - 1);
	else
		bcl->fsm_msg_cnt = mod(bcl->next_out_no - 1);

	/* bcl->stats.sent_info++; 使用next_out_no计算，与单播Tx一致 */
}

u32 tipc_bclink_get_last_sent(struct mcglink *mcgl)
{
	return mcgl->link.fsm_msg_cnt;
}

static void bclink_update_last_sent(struct mclink *mcl, u32 seqno)
{
	mcl->last_sent = greater(mcl->last_sent, seqno);
}

/** 
 * bclink_ack_allowed - test if ACK or NACK message can be sent at this moment
 * 
 * This mechanism endeavours to prevent all nodes in network from trying
 * to ACK or NACK at the same time.
 * 
 * Note: TIPC uses a different trigger to distribute ACKs than it does to
 *       distribute NACKs, but tries to use the same spacing (divide by 16). 
 */

static inline int bclink_ack_allowed(u32 n, u32 isccack)
{
	if (isccack)
		return ((n - tipc_own_addr) % TIPC_MCAST_CCACK_WIN == 0);
	else
		return ((n - tipc_own_addr) % TIPC_MCAST_ACK_WIN == 0);
}

/** 
 * bclink_nack_allowed - test if NACK message can be sent at this moment
 * 
 * This mechanism endeavours to prevent all nodes in network from trying
 * to ACK or NACK at the same time.
 * 
 * Note: 
 */

static inline int bclink_nack_allowed(u32 n, struct tipc_node *n_ptr, struct mclink *mcl)
{
    /* 只有一条链路必然是发生了丢包 */
    if (n_ptr->working_links == 1 && mcl->last_in < mcl->last_sent)
        return bclink_ack_allowed(n, 1);


    /* deferred报文个数如此多，需要NACK。*/
    if (mcl->deferred_size >= BCLINK_WIN_DEFAULT/2 &&
        test_bytes_bit(n_ptr->mc_ccack_recv, mcl->mcgid))
        return bclink_ack_allowed(n, 1);

    return 0;
}

#ifdef CHECK_BCLINK

static void bclink_dump_queue(struct mcglink *mcgl)
{
	struct sk_buff *crs;
	struct link *bcl = &mcgl->link;
	u32  cnt_pack = 0;
	u32  cnt_out = 0;

	if (bcl->net_plane != mcgl->mcgid)
		return;

	info_bclink("bclink_dump_queue: %d\n", mcgl->mcgid);

	crs = mcgl->first_pack;
	if (mcgl->pack_queue_size)
		info_bclink("pack(%d): ", mcgl->pack_queue_size);
	while (crs) {
		cnt_pack++;
		info_bclink("%u-%d-%d,", buf_seqno(crs), bcbuf_acks(crs), bcbuf_ccacks(crs));
		if (crs == mcgl->last_pack)
			info_bclink(" :(%d): ", cnt_pack);;
		
		crs = crs->next;
	}
	if (mcgl->pack_queue_size)
		info_bclink(" :(%d)\n", cnt_pack);


	crs = bcl->first_out;
	if (bcl->out_queue_size)
		info_bclink("fout(%d): ", bcl->out_queue_size);	
	while (crs) {
		cnt_out++;
		info_bclink("%u-%d-%d,", buf_seqno(crs), bcbuf_acks(crs), bcbuf_ccacks(crs));
		crs = crs->next;
	}
	if (bcl->out_queue_size)
		info_bclink(" :(%d)\n", cnt_out);
}

static void bclink_check_queue(struct mcglink *mcgl)
{
	struct sk_buff *crs;
	struct link *bcl = &mcgl->link;
	u32  cnt_pack = 0;
	u32  cnt_out = 0;
	u32  dump = 0;

	if (bcl->net_plane != mcgl->mcgid)
		return;
	crs = mcgl->first_pack;
	while (crs) {
		cnt_pack++;
		if (crs == mcgl->last_pack)
			break;


		if (crs->next && mod(buf_seqno(crs)+1) != buf_seqno(crs->next))
			dump = 1;
			
		crs = crs->next;
	}

	crs = bcl->first_out;
	while (crs) {
		cnt_out++;
		if (crs->next && mod(buf_seqno(crs)+1) != buf_seqno(crs->next))
			dump = 1;		
		crs = crs->next;
	}

	if (cnt_pack != mcgl->pack_queue_size ||
		cnt_out != bcl->out_queue_size ||
		dump ) {
		bclink_dump_queue(mcgl);
		bcl->net_plane = CONFIG_TIPC_MCASTGID_MAX;
	}
}

#endif

/**
 * bclink_retransmit_pkt - retransmit broadcast packets
 * @after: sequence number of last packet to *not* retransmit
 * @to: sequence number of last packet to retransmit
 *
 * Called with bc_lock locked
 */

static void bclink_retransmit_pkt(struct mcglink *mcgl, u32 after, u32 to)
{
	struct sk_buff *buf;
	struct link *bcl = &mcgl->link;
	u32 retransmits;

	/* 2015-11-4  避免多个接收端丢报文导致组播重传报文太多*/
	if (mcgl->retrans_pps_max == 0) {
		/* 规避bclink_timeout 中read_trylock 失败 */
		if (bcl->timer.expires < jiffies) {
			info("%s's timer is pending, start again.", bcl->name);
			k_start_timer(&bcl->timer, bcl->tolerance);
			mcgl->retrans_pps_max = retransmits;
		} else {
			return;
		}
	}

	retransmits = mod(to - after);

	if (mcgl->retrans_pps_max >= retransmits) {
		mcgl->retrans_pps_max -= retransmits;
	} else {
		retransmits = mcgl->retrans_pps_max;
		mcgl->retrans_pps_max = 0;
	}

	buf = mcgl->first_pack;
	
	/* f_p <= f_o <= l_p <=l_o */
	if (bcl->first_out && 
		less_eq(buf_seqno(bcl->first_out), after))
		buf = bcl->first_out;

	while (buf && less_eq(buf_seqno(buf), after)) {
		buf = buf->next;
	}
	
	BCLINK_CHECK_QUEUE(mcgl);

	tipc_link_retransmit(bcl, buf, retransmits);
}

/**
 * tipc_bclink_acknowledge - handle acknowledgement of broadcast packets
 * @n_ptr: node that sent acknowledgement info
 * @acked: broadcast sequence # that has been acknowledged
 * @mcl: node receive multicast link info
 *
 * Node is locked, bc_lock unlocked.
 */

/* 为了保证node_lost_contact()处理bclink的原子性，该函数在
   tipc_bclink_remove_node()中加锁调用
 */
static void bclink_acknowledge(struct tipc_node *n_ptr, u32 acked, struct mclink *mcl)
{
	struct sk_buff *crs;
	struct sk_buff *next;
	unsigned int released = 0;
	struct mcglink *mcgl = mcl->mcgl; 
	struct link *bcl = &mcgl->link;
	u32 isccack = test_bytes_bit(n_ptr->mc_ccack_assign, mcl->mcgid);
	u32 seqno;

	if (less_eq(acked, mcl->acked))
		return;
	
	if (bcl->net_plane != mcgl->mcgid)
		return;      

	BCLINK_CHECK_QUEUE(mcgl);
	/* 检查是否有错误的ack */
	if (unlikely(less(tipc_bclink_get_last_sent(mcgl), acked))) {
		mcl->ack_err_cnt++;
		if (tipc_ratelimit(mcl->ack_err_cnt, 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_BCAST)) {
			info("%x badack %u, %s lastsent %u acked %u\n", n_ptr->elm.addr,
				acked, bcl->name, tipc_bclink_get_last_sent(mcgl), mcl->acked);
		}
		return;
	}

    if (!test_bytes_bit(n_ptr->mc_rding, mcl->mcgid)) {
        /* n_ptr非接收节点，只需修改acked返回即可 */
        mcl->acked = acked;
        return;
    }

	/* Skip over packets that node has previously acknowledged */
	crs = mcgl->first_pack;
	/* f_p <= f_o <= l_p <=l_o */
	if (bcl->first_out && 
		less_eq(buf_seqno(bcl->first_out), mcl->acked))
		crs = bcl->first_out;
	
	/* crs == buf(mcl->acked+1) */
	while (crs && less_eq(buf_seqno(crs), mcl->acked)) {
		crs = crs->next;
	}

	/* Update packets that node is now acknowledging */

    /* 确保fp<=crs<=lp=no-1，防止错误ack导致确认未发送报文 */
	while (crs && crs != bcl->next_out && less_eq(buf_seqno(crs), acked)) {
		next = crs->next;
		seqno = buf_seqno(crs);

		if (isccack && mod(mcl->ccacked+1) == seqno && bcbuf_ccacks(crs) > 0) {
            mcl->ccacked = seqno;
			bcbuf_decr_ccacks(crs); /* must > 0 */
			if (bcbuf_ccacks(crs) == 0) {
				/* capable to send next msg */
#ifdef CHECK_BCLINK
				/* if error? out_queue_size will error */
				if (unlikely(crs != bcl->first_out)) {
					err("bcack: acked%u, mcl->acked%u, crs%u != f_o%u l_o%u\n",
						acked, mcl->acked,
						buf_seqno(crs),
						buf_seqno(bcl->first_out),
						buf_seqno(bcl->last_out));
					BCLINK_DUMP_QUEUE(mcgl);
					bcl->net_plane = CONFIG_TIPC_MCASTGID_MAX;
 					break;
				} else
#endif				
				{
					bcl->first_out = next;
					bcl->out_queue_size--;
					released = 1;
				}
			}
		}
		
		/* next has not sent yet */
		if (crs == mcgl->last_pack)
			next = NULL;
		bcbuf_decr_acks(crs);
		if (bcbuf_acks(crs) == 0) {
			/* free the msg buf */
#ifdef CHECK_BCLINK
			/* if error? leaks first_pack --to-- crs, and pack_queue_size will error */
			if (unlikely(crs != mcgl->first_pack)) {
				err("bcack: acked%u, mcl->acked%u, crs%u != f_p%u l_p%u\n",
					acked, mcl->acked,
					buf_seqno(crs),
					buf_seqno(mcgl->first_pack),
					buf_seqno(mcgl->last_pack));
				BCLINK_DUMP_QUEUE(mcgl);
				bcl->net_plane = CONFIG_TIPC_MCASTGID_MAX;
 				break;
			} else 
#endif			
			{
                if (unlikely(bcl->first_out == crs)) {
                    warn("Adjust %s out queue\n", bcl->name);
                    bcl->first_out = crs->next; /* 不能用next */
					bcl->out_queue_size--;
                    mcgl->error |= 1; /* 标记出现错误，需要错误恢复处理 */
                }
				mcgl->first_pack = next;
				mcgl->pack_queue_size--;
				buf_discard(crs);
				released = 1;
			}
		}
		
		crs = next;
		mcl->acked = seqno;
	}
	

	/* 所有接收者都收到报文了 */
	if (mcgl->pack_queue_size < TIPC_MIN_LINK_WIN)
		link_inc_window(bcl);

	BCLINK_CHECK_QUEUE(mcgl);

	/* 仅在广播ack信息错误时发生，为了避免影响广播发送，这里重置为0 */
	if (unlikely(!bcl->first_out && bcl->out_queue_size)) {
		warn("Reset %s outque %u\n", bcl->name, bcl->out_queue_size);
		bcl->out_queue_size = 0;
		mcgl->error |= 1; /* 标记出现错误，需要错误恢复处理 */
	}
	if (unlikely(!mcgl->first_pack && mcgl->pack_queue_size)) {
		warn("Reset %s packque %u\n", bcl->name, mcgl->pack_queue_size);
		mcgl->pack_queue_size = 0;
		mcgl->error |= 1; /* 标记出现错误，需要错误恢复处理 */
	}
	

	/* Try resolving broadcast link congestion, if necessary */

	if (unlikely(bcl->next_out)) {
		tipc_link_push_queue(bcl);
		bclink_set_last_sent(mcgl);
	}
	if (unlikely(!list_empty(&bcl->waiting_ports)))
		tipc_link_wakeup_ports(bcl, 0);
}

void tipc_bclink_acknowledge(struct tipc_node *n_ptr, u32 acked, struct mclink *mcl)
{
	if (WORKING_WORKING != mcl->state)
		return;
	spin_lock_bh(&bc_lock);
	bclink_acknowledge(n_ptr, acked, mcl);
	spin_unlock_bh(&bc_lock);
}

/**
 * tipc_bclink_update_link_state - update broadcast link state
 *
 * tipc_net_lock and node lock set
 */

void tipc_bclink_update_link_state(struct tipc_node *n_ptr, u32 last_sent, struct mclink *mcl)
{
	if (WORKING_WORKING != mcl->state)
		return;
    /* 本节点mcgl不可读，直接更新即可 */
    if (!tipc_bclink_get_readable(mcl->mcgl)) {
        mcl->last_in = mcl->last_sent = last_sent;
        return;
    }

	/* Ignore "stale" link state info */

	if (less_eq(last_sent, mcl->last_in))
		return;

	/* Update link synchronization state; quit if in sync */

	bclink_update_last_sent(mcl, last_sent);

	if (mcl->last_sent == mcl->last_in)
		return;
 
	/* Update out-of-sync state; quit if loss is still unconfirmed */

	if ((++mcl->oos_state) == 1) {
		if (mcl->deferred_size < (TIPC_MIN_LINK_WIN / 2))
		    return;
		/* 非CCACK节点延迟发送 */
		if (!test_bytes_bit(n_ptr->mc_ccack_recv, mcl->mcgid))
			return;
		mcl->oos_state++;
	}

	/* Don't NACK if one has been recently sent (or seen) */

	if (mcl->oos_state & 0x1)
		return;

	/* 超时失败，这里要快于发送端重传失败检测. mcl0要避免丢弃 */
    if (mcl->oos_state > 50 && 0 != mcl->mcgid) {
        /* 简化故障处理，丢弃deferred队列的报文 */
        char addr_string[16];
        
        warn("Sync node %s mclink %u timeout, discard (%u,%u]\n",
            tipc_addr_string_fill(addr_string, n_ptr->elm.addr),
            mcl->mcgid, mcl->last_in, mod(mcl->last_sent - 1));

        mcl->last_in = mcl->last_sent;
        tipc_node_reset_mclink(mcl);
        /* 通知peer更改状态 */
		tipc_link_send_proto_msg(n_ptr->active_links[0],
			STATE_MSG, 0, 0, 0, 0, 0, 0);
        return;
    }

	/* Send NACK */
    bclink_send_nack(n_ptr, mcl);
	mcl->oos_state++;
}

/** 
 * bclink_send_nack- send a NACK msg
 * 
 * tipc_net_lock and node lock set
 */

static void bclink_send_nack(struct tipc_node *n_ptr, struct mclink *mcl)
{
	struct mcglink *mcgl = mcl->mcgl;
	struct link *l_ptr = n_ptr->active_links[(mcl->oos_state/2)&1];
	struct sk_buff *buf;

    /* 多次后尝试使用组播发送NACK */
    if (((mcl->oos_state / 2) % TIPC_MCAST_ACK_WIN) == TIPC_MCAST_ACK_WIN - 1) {
        l_ptr = &mcgl->link;
    }

	buf = buf_acquire(INT_H_SIZE);
	if (buf) {
		struct tipc_msg *msg = buf_msg(buf);

		tipc_msg_init(msg, BCAST_PROTOCOL, STATE_MSG,
			      INT_H_SIZE, n_ptr->elm.addr);
		msg_set_non_seq(msg, 1);
       	msg_set_nametype_dummy(msg, mcl->mcgid);
		msg_set_mc_netid(msg, tipc_net_id);
		msg_set_bcast_ack(msg, mcl->last_in); 
		msg_set_bcgap_after(msg, mcl->last_in);
		/* bclink负载分担丢包类似1 3 5 7。用deferred_tail重传时间5s-->0.5s */
		msg_set_bcgap_to(msg, mcl->deferred_head
				 ? buf_seqno(mcl->deferred_tail) - 1
				 : mcl->last_sent);

		/* 改为使用单播发送*/
 		if (l_ptr && tipc_bearer_send(l_ptr->b_ptr, buf, &l_ptr->media_addr)) {
			/*spin_lock_bh(&bc_lock); 非关键数据，可不保护减少开销 */
			mcgl->link.stats.sent_nacks++;
			mcl->sent_nacks++;
			/* spin_unlock_bh(&bc_lock); */
 		}

		buf_discard(buf);
	}
}

/**
 * bclink_peek_nack - monitor retransmission requests sent by other nodes
 *
 * Delay any upcoming NACK by this node if another node has already
 * requested the first message this node is going to ask for.
 *
 * Only tipc_net_lock set.
 */

static void bclink_peek_nack(struct tipc_msg *msg, u32 mcgid)
{
	struct tipc_node *n_ptr;
	struct mclink *mcl = NULL;

	n_ptr = tipc_net_find_node(msg_destnode(msg));
	if (unlikely(!n_ptr))
		return;

	tipc_node_lock(n_ptr);
	mcl = tipc_node_find_active_mclink(n_ptr, mcgid);
	if (!mcl) {
		tipc_node_unlock(n_ptr);
		return ;
	}

	if (tipc_node_is_up(n_ptr) && mcl->supported &&
	    (mcl->last_in != mcl->last_sent) &&
	    (mcl->last_in == msg_bcgap_after(msg)))
		mcl->oos_state = 2;

	tipc_node_unlock(n_ptr);
}

/**
 * tipc_bclink_send_msg - broadcast a packet to all nodes in cluster
 */

int tipc_bclink_send_msg(struct sk_buff *buf)
{
	int res;
	struct mcglink *mcgl = NULL;
	struct link *bcl = NULL;

	spin_lock_bh(&bc_lock);
	mcgl = tipc_bclink_find_mcglink(msg_nametype2mcgid(buf_msg(buf)));
	

	if (!mcgl || !mcgl->mcast_nodes.count) {
		res = -ENOENT;
		buf_discard(buf);
		goto exit;
	}

	if (mcgl->flag & TIPC_MCGLINK_FLG_NO_WRITE) {
		res = -EACCES;
		buf_discard(buf);
		goto exit;
	}
    
	BCLINK_CHECK_QUEUE(mcgl);
	
	bcl = &mcgl->link;

	if (mcgl->pack_queue_size >= TIPC_MCAST_ACK_WIN*4 ||
        bcl->out_queue_size >= TIPC_MCAST_ACK_WIN) {
		res = link_schedule_port(bcl, msg_origport(buf_msg(buf)),
					msg_data_sz(buf_msg(buf)));
		buf_discard(buf);
		goto exit;
	}

	res = tipc_link_send_buf(bcl, buf);
	if (unlikely(res == -ELINKCONG))
		buf_discard(buf);
	else if (unlikely(res < 0))
		goto exit;
	else
		bclink_set_last_sent(mcgl);

	if (mcgl->pack_queue_max < mcgl->pack_queue_size)
		mcgl->pack_queue_max = mcgl->pack_queue_size;
	
	if (bcl->out_queue_size > bcl->stats.max_queue_sz)
		bcl->stats.max_queue_sz = bcl->out_queue_size;
	bcl->stats.queue_sz_counts++;
	bcl->stats.accu_queue_sz += bcl->out_queue_size;
exit:
	spin_unlock_bh(&bc_lock);
	return res;
}

/**
 * tipc_bclink_recv_pkt - receive a broadcast packet, and deliver upwards
 *
 * tipc_net_lock is read_locked, no other locks set
 */

void tipc_bclink_recv_pkt(struct sk_buff *buf)
{
	struct tipc_msg *msg;
	struct tipc_node *node;
	u32 mcgid;
	struct mclink *mcl = NULL;
	struct mcglink *mcgl = NULL;
	struct link *bcl = NULL;
	u32 isccack = 0;

	u32 seqno;
	u32 next_in;
	int deferred;

#if (TIPC_BCAST_LOSS_RATE)
	static int rx_count = 0;

	if (++rx_count == TIPC_BCAST_LOSS_RATE) {
		rx_count = 0;
		goto exit;
	}
#endif

	/* Screen out unwanted broadcast messages */

	msg = buf_msg(buf);
	if (msg_mc_netid(msg) != tipc_net_id)
		goto exit;
	
	node = tipc_net_find_node(msg_prevnode(msg));
	if (unlikely(!node))
		goto exit;

	tipc_node_lock(node);
	if (unlikely(!tipc_node_is_up(node) || !node->bclink.supported))
		goto unlock;
	
	mcgid = msg_nametype2mcgid(msg);
	mcl = tipc_node_find_active_mclink(node, mcgid);
	if (unlikely(!mcl) || WORKING_WORKING != mcl->state) {
		dbg("tipc_bclink_recv_pkt: msg %u invalid nametype %u or state %u\n", 
			msg_seqno(msg), msg_nametype(msg), mcl->state);
		goto unlock;		
	}
	
	mcgl = mcl->mcgl;
	bcl = &mcgl->link;

	/* Handle broadcast protocol message */

	if (unlikely(msg_user(msg) == BCAST_PROTOCOL)) {
        if (test_bytes_bit(node->mc_nord_recv, mcgid))
            goto unlock;

		if (msg_destnode(msg) == tipc_own_addr) {
			/*tipc_node_unlock(node); move to end, lock node before bcl */
			spin_lock_bh(&bc_lock);
			bclink_acknowledge(node, msg_bcast_ack(msg), mcl);
			bcl->stats.recv_nacks++;
			if (tipc_ratelimit(++mcl->recv_nacks, 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_BCAST))
				info("mcl %d recv 0x%x naks from node %x\n", mcgid, mcl->recv_nacks, msg_prevnode(msg));				
			/* remember retransmit requester */
			bcl->owner->node_list.next = 
				(struct list_head *)node;
			bclink_retransmit_pkt(mcgl, msg_bcgap_after(msg),
					      msg_bcgap_to(msg));

            /* 丢失报文较多的节点使用流控ack控制发送速度 */
            if (!test_bytes_bit(node->mc_ccack_assign, mcgid) &&
                (mcl->recv_nacks % TIPC_MCAST_CCACK_WIN == 0)) {
                bclink_add_ccack(mcgl, node);
            }
            
			spin_unlock_bh(&bc_lock);
			tipc_node_unlock(node);
		} else {
			tipc_node_unlock(node);
			bclink_peek_nack(msg, mcgid);
		}
		goto exit;
	}

	if (unlikely(mcgl->flag & TIPC_MCGLINK_FLG_NO_READ)) {
        if (unlikely(tipc_ratelimit(++bcl->stats.recv_info, 1)))
            info("%s not permit recv msg\n", mcgl->link.name);
        goto unlock;
	}

	/* Handle in-sequence broadcast message */

	seqno = msg_seqno(msg);
	next_in = mod(mcl->last_in + 1);

	if (seqno == next_in) {
		bclink_update_last_sent(mcl, seqno);
receive:
		mcl->last_in = seqno;
		mcl->oos_state = 0;

		spin_lock_bh(&bc_lock);
		bcl->stats.recv_info++;

		/*
		 * Unicast an ACK periodically, ensuring that
		 * all nodes in the cluster don't ACK at the same time
		 */
		isccack = test_bytes_bit(node->mc_ccack_recv, mcgid); 
		if (unlikely(bclink_ack_allowed(seqno, isccack))) {
			tipc_link_send_proto_msg(
				node->active_links[0] /* a[0] 相对稳定 */,
				STATE_MSG, 0, LINK_GAP_MAX, 0, 0, 0, 0); /* GAP_MAX:无gap */
			bcl->stats.sent_acks++;
		}

		/* Deliver message to destination */

		if (likely(msg_isdata(msg))) {
			spin_unlock_bh(&bc_lock);
			tipc_node_unlock(node);
			tipc_port_recv_mcast(buf, NULL);
		} else if (msg_user(msg) == MSG_BUNDLER) {
			bcl->stats.recv_bundles++;
			bcl->stats.recv_bundled += msg_msgcnt(msg);
			spin_unlock_bh(&bc_lock);
			tipc_node_unlock(node);
			tipc_link_recv_bundle(buf);
		} else if (msg_user(msg) == MSG_FRAGMENTER) {
			bcl->stats.recv_fragments++;
			if (tipc_link_recv_fragment(&mcl->defragm,
						    &buf, &msg)) {
				bcl->stats.recv_fragmented++;
				msg_set_destnode_cache(msg, tipc_own_addr);
			}
			spin_unlock_bh(&bc_lock);
			tipc_node_unlock(node);
			tipc_net_route_msg(buf);
		} else if (msg_user(msg) == NAME_DISTRIBUTOR) {
			spin_unlock_bh(&bc_lock);
			tipc_node_unlock(node);
			tipc_named_recv(buf);
		} else if (msg_user(msg) == ROUTE_DISTRIBUTOR) {
			spin_unlock_bh(&bc_lock);
			tipc_node_unlock(node);
			tipc_route_recv(buf);
		} else {
			spin_unlock_bh(&bc_lock);
			tipc_node_unlock(node);
			tipc_net_route_msg(buf);
		}

		buf = NULL;

		/* Determine new synchronization state */

		tipc_node_lock(node);
		if (unlikely(!tipc_node_is_up(node)))
			goto unlock;

		if (mcl->last_in == mcl->last_sent)
			goto unlock;

		if (!mcl->deferred_head) {
			mcl->oos_state = 1;
            mcl->deferred_size = 0;
			goto unlock;
		}

		msg = buf_msg(mcl->deferred_head);
		seqno = msg_seqno(msg);
		next_in = mod(next_in + 1);
		if (seqno != next_in)
			goto unlock;

		/* Take in-sequence message from deferred queue & deliver it */

		buf = mcl->deferred_head;
		mcl->deferred_head = buf->next;
		mcl->deferred_size--;
		goto receive;
	}

	/* Handle out-of-sequence broadcast message */

	if (less(next_in, seqno)) {
		deferred = tipc_link_defer_pkt(&mcl->deferred_head,
					       &mcl->deferred_tail,
					       buf, seqno);
		mcl->deferred_size += deferred;
		buf = NULL;
		bclink_update_last_sent(mcl, seqno);

        if (deferred && bclink_nack_allowed(seqno, node, mcl))
            bclink_send_nack(node, mcl);
	} else
		deferred = 0;

	spin_lock_bh(&bc_lock);
	if (deferred) {
		bcl->stats.deferred_recv++;
		mcl->deferes++;
	} else {
		bcl->stats.duplicates++;
		mcl->duplicates++;
	}
	spin_unlock_bh(&bc_lock);

unlock:
	tipc_node_unlock(node);
exit:
	buf_discard(buf);
}

u32 tipc_bclink_acks_missing(struct tipc_node *n_ptr)
{
	struct mclink *mcl = NULL;
	int timout = 0, miss = 0;
	if (!n_ptr->bclink.supported)
		return 0;
	
	list_for_each_entry(mcl, &n_ptr->mclinks, mclist) {
        if (!mcl->supported)
            continue;
		/* 检查组播状态是否长时间不一致，框冲突可能遗留影响 */
		if (unlikely(WORKING_WORKING != mcl->state)) {
			if (mcl->oos_state++ > 20) {
				timout = 1;
				warn("Reset node %x for mcl %d state %u timeout\n",
					n_ptr->elm.addr, mcl->mcgid, mcl->state);
			}
		}

        /* 第一个判断表示对端还有未向本端确认的报文
         * 第二个判断表示本端还有未向对端确认的报文
         */
		if (mcl->acked != tipc_bclink_get_last_sent(mcl->mcgl) ||
            mcl->last_in != mcl->last_in_chk ||
            WORKING_WORKING != mcl->state) {
			miss = 1;
		}
	}

	if (unlikely(timout)) {
		tipc_k_signal((Handler)link_reset_all, (unsigned long)n_ptr->elm.addr);
	}

	return miss;	
}



/**
 * tipc_nmap_include - 
 * @nm_a: input node map A
 * @nm_b: input node map B
 *
 * Returns 1 if nm_b is subset of nm_a
 */
static int tipc_nmap_include(struct tipc_node_map *nm_a,
				  struct tipc_node_map *nm_b)
{
	int start = (nm_b->start) / WSIZE;
	int stop = (nm_b->stop + WSIZE-1) / WSIZE;
	int w;

	for (w = start; w < stop; w++) {
		if ((nm_a->map[w] & nm_b->map[w]) != nm_b->map[w]) {
			return 0;
		}
	}

	return 1;
}


/**
 * tipc_bcbearer_send - send a packet through the broadcast pseudo-bearer
 *
 * Send through as many bearers as necessary to reach all nodes
 * that support TIPC multicasting.
 *
 * Returns 0 if packet sent successfully, non-zero if not
 */

static int tipc_bcbearer_send(struct sk_buff *buf,
			      struct tipc_bearer *unused1,
			      struct tipc_media_addr *unused2)
{
	int bp_index;

	struct tipc_media_addr *dest = NULL;
	struct mcglink *mcgl = tipc_bclink_find_mcglink(msg_nametype2mcgid(buf_msg(buf)));
	if (unlikely(NULL == mcgl)) {
		return 0;
	}
	dest = &mcgl->link.media_addr;
	/*
	 * Prepare broadcast link message for reliable transmission,
	 * if first time trying to send it
	 *
	 * Note: Preparation is skipped for broadcast link protocol messages
	 * since they are sent in an unreliable manner and don't need it
	 */

	if (likely(!msg_non_seq(buf_msg(buf)))) {
		struct tipc_msg *msg;

		dbg_assert(mcgl->mcast_nodes.count != 0);
		bcbuf_set_acks(buf, mcgl->mcast_nodes.count);
		msg = buf_msg(buf);
		msg_set_non_seq(msg, 1);
		msg_set_mc_netid(msg, tipc_net_id);
		/* 走到这里的报文都是入了outqueue的 */
		dbg_assert(mcgl->ccack_count != 0);
		bcbuf_set_ccacks(buf, mcgl->ccack_count);
		if (!mcgl->first_pack) {
			/* possibel mcgl->link.out_queue_size > 1 */
			mcgl->first_pack = mcgl->last_pack = buf;
			mcgl->pack_queue_size = 1;
		} else {
			/* 这里覆盖link_add_to_outqueue()中的链表关系
			 * 这个是必须的,否则可能出现如下断链的情况
			 * first_p-xx--l_p->null]  [f_o-xx->l_o->null]
			 * 覆盖之后的变为
			 * first_p-xx->l_p==first_o-xx->l_o-->null
			 */

			mcgl->last_pack->next = buf;
			mcgl->last_pack = buf;

			mcgl->pack_queue_size++;
		}
	}else {
		dbg("tipc_bcbearer_send: non seq:%u\n", buf_seqno(buf));
	}
	
	BCLINK_CHECK_QUEUE(mcgl);

	/* Send buffer over bearers until all targets reached */
#ifndef BCLINK_SEND_NOUSE_NMAP
	bcbearer->remains = mcgl->mcast_nodes;
#endif
	for (bp_index = 0; bp_index < TIPC_MAX_BEARERS; bp_index++) {
		struct bearer *p = bcbearer->bpairs[bp_index].primary;
		struct bearer *s = bcbearer->bpairs[bp_index].secondary;

		if (!p)
			break;	/* no more bearers to try */

#ifdef BCLINK_SEND_NOUSE_NMAP
		/* 从所有的bearer发送，并且使用dest组播地址。*/
		if (p->publ.blocked ||
		    p->media->send_msg(buf, &p->publ, dest)) {
			/* unable to send on primary bearer */
			if (!s || s->publ.blocked ||
			    s->media->send_msg(buf, &s->publ, dest)) {
				/* unable to send on either bearer */
				continue;
			}
		}

		if (s) {
			bcbearer->bpairs[bp_index].primary = s;
			bcbearer->bpairs[bp_index].secondary = p;
		}

		/* 可能的重传报文从所有bear发送，以免多次重传 */
		if (mod(msg_seqno(buf_msg(buf)) - mcgl->link.last_retransmitted) <= TIPC_MIN_LINK_WIN) {
			if (s && !s->publ.blocked) 
				s->media->send_msg(buf, &s->publ, dest);
			continue;
		}
		
		/* p reach all nodes of mcgl */
		if (tipc_nmap_include(&p->nodes, &mcgl->mcast_nodes))
            return 0;
#else
		tipc_nmap_diff(&bcbearer->remains, &p->nodes, &bcbearer->remains_new);
		if (bcbearer->remains_new.count == bcbearer->remains.count)
			continue;	/* bearer pair doesn't add anything */

		if (p->publ.blocked ||
		    p->media->send_msg(buf, &p->publ, &p->media->bcast_addr)) {
			/* unable to send on primary bearer */
			if (!s || s->publ.blocked ||
			    s->media->send_msg(buf, &s->publ,
					       &s->media->bcast_addr)) {
				/* unable to send on either bearer */
				continue;
			}
		}

		if (s) {
			bcbearer->bpairs[bp_index].primary = s;
			bcbearer->bpairs[bp_index].secondary = p;
		}

		if (bcbearer->remains_new.count == 0)
			return 0;

		bcbearer->remains = bcbearer->remains_new;
#endif		
	}
	
	/* 
	 * Unable to reach all targets (indicate success, since currently 
	 * there isn't code in place to properly block & unblock the
	 * pseudo-bearer used by the broadcast link)
	 */
	
	return 0;
}

/**
 * tipc_bcbearer_sort - create sets of bearer pairs used by broadcast bearer
 */

void tipc_bcbearer_sort(void)
{
	struct bcbearer_pair *bp_temp = bcbearer->bpairs_temp;
	struct bcbearer_pair *bp_curr;
	int b_index;
	int pri;

	spin_lock_bh(&bc_lock);

	/* Group bearers by priority (can assume max of two per priority) */

	memset(bp_temp, 0, sizeof(bcbearer->bpairs_temp));

	for (b_index = 0; b_index < TIPC_MAX_BEARERS; b_index++) {
		struct bearer *b = &tipc_bearers[b_index];

		if (!b->active || !b->nodes.count)
			continue;

		if (!bp_temp[b->priority].primary)
			bp_temp[b->priority].primary = b;
		else
			bp_temp[b->priority].secondary = b;
	}

	/* Create array of bearer pairs for broadcasting */

	bp_curr = bcbearer->bpairs;
	memset(bcbearer->bpairs, 0, sizeof(bcbearer->bpairs));

	for (pri = TIPC_MAX_LINK_PRI; pri >= 0; pri--) {

		if (!bp_temp[pri].primary)
			continue;

		bp_curr->primary = bp_temp[pri].primary;

		if (bp_temp[pri].secondary) {
			if (tipc_nmap_equal(&bp_temp[pri].primary->nodes,
					    &bp_temp[pri].secondary->nodes)) {
				bp_curr->secondary = bp_temp[pri].secondary;
			} else {
				bp_curr++;
				bp_curr->primary = bp_temp[pri].secondary;
			}
		}

		bp_curr++;
	}

	spin_unlock_bh(&bc_lock);
}

/**
 * tipc_bcbearer_push - resolve bearer congestion
 *
 * Forces bclink to push out any unsent packets, until all packets are gone
 * or congestion reoccurs.
 * No locks set when function called
 */

void tipc_bcbearer_push(void)
{
	struct bearer *b_ptr;

	spin_lock_bh(&bc_lock);
	b_ptr = &bcbearer->bearer;
	if (b_ptr->publ.blocked) {
		b_ptr->publ.blocked = 0;
		tipc_bearer_lock_push(b_ptr);
	}
	spin_unlock_bh(&bc_lock);
}


#ifdef CONFIG_TIPC_CONFIG_SERVICE

int tipc_bclink_stats(char *buf, const u32 buf_size, const char *bclname)
{
	struct print_buf pb;
	struct link *bcl = NULL;
	u32 i;

	struct mcglink *mcgl = NULL;

	if (!bcbearer)
		return 0;

	tipc_printbuf_init(&pb, buf, buf_size);

	spin_lock_bh(&bc_lock);
	
	for (i=0; i<CONFIG_TIPC_MCASTGID_MAX; i++) {
		mcgl = bcbearer->mcgls[i];
		if (!mcgl) 
			continue;

		bcl = &mcgl->link;
		if (bclname && strcmp(bcl->name, bclname))
			continue;

		
		tipc_printf(&pb, "Link <%s>  ----  ", bcl->name);
		
		tipc_media_addr_printf(&pb, &bcl->media_addr);
		tipc_printf(&pb, "\n");
		
		tipc_printf(&pb, "  Window:%u packets  Flag:%x\n",
			    bcl->queue_limit[0], mcgl->flag);

		tipc_printf(&pb, "  RX packets:%u fragments:%u/%u bundles:%u/%u\n", 
			    bcl->stats.recv_info,
			    bcl->stats.recv_fragments,
			    bcl->stats.recv_fragmented,
			    bcl->stats.recv_bundles,
			    bcl->stats.recv_bundled);
		tipc_printf(&pb, "  TX packets:%u fragments:%u/%u bundles:%u/%u\n", 
			    bcl->next_out_no - bcl->stats.sent_info,
			    bcl->stats.sent_fragments,
			    bcl->stats.sent_fragmented, 
			    bcl->stats.sent_bundles,
			    bcl->stats.sent_bundled);

		tipc_printf(&pb, "  Next-ou-no:%u outque-cnt:%u packque-cnt:%u re-tx-no:%u re-tx-cnt:%u\n",
			    tipc_bclink_get_last_sent(mcgl),
			    bcl->out_queue_size,
			    mcgl->pack_queue_size,
			    bcl->retransm_queue_head,
			    bcl->retransm_queue_size);			
		tipc_printf(&pb, "  RX naks:%u defs:%u dups:%u\n", 
			    bcl->stats.recv_nacks,
			    bcl->stats.deferred_recv, 
			    bcl->stats.duplicates);
		tipc_printf(&pb, "  TX naks:%u acks:%u dups:%u\n", 
			    bcl->stats.sent_nacks, 
			    bcl->stats.sent_acks, 
			    bcl->stats.retransmitted);
		tipc_printf(&pb, "  Congestion bearer:%u link:%u  Send/Pack queue max:%u/%u avg:%u\n",
			    bcl->stats.bearer_congs,
			    bcl->stats.link_congs,
			    bcl->stats.max_queue_sz, mcgl->pack_queue_max,
			    bcl->stats.queue_sz_counts
			    ? (bcl->stats.accu_queue_sz / bcl->stats.queue_sz_counts)
			    : 0);
		tipc_printf(&pb, "  Reset:%u  Checkcnt:%u failed:%u  Retx:%u\n",
				mcgl->reset_count, 0, 0, bcl->retx_count);

		bclink_mcgl_stat(mcgl, &pb);		
	}

	spin_unlock_bh(&bc_lock);
	
	return tipc_printbuf_validate(&pb);
}

int tipc_bclink_reset_stats(const char *bclname)
{
	struct link *bcl = NULL;
	u32 i;
	struct mcglink *mcgl = NULL;

	if (!bcbearer)
		return -ENOPROTOOPT;

	spin_lock_bh(&bc_lock);
	
	for (i=0; i<CONFIG_TIPC_MCASTGID_MAX; i++) {
		mcgl = bcbearer->mcgls[i];
		if (!mcgl) 
			continue;

		bcl = &mcgl->link;
		if (bclname && strcmp(bcl->name, bclname))
			continue;
		
		memset(&bcl->stats, 0, sizeof(bcl->stats));
		bcl->stats.sent_info = bcl->next_out_no;
       
		mcgl->pack_queue_max = 0;
	}
	spin_unlock_bh(&bc_lock);
	return 0;
}

#endif

int tipc_bclink_set_queue_limits(u32 limit, const char *bclname)
{
	u32 i;
	struct mcglink *mcgl = NULL;
	
	if (!bcbearer)
		return -ENOPROTOOPT;
	if ((limit < TIPC_MIN_LINK_WIN) || (limit > TIPC_MAX_LINK_WIN))
		return -EINVAL;

	spin_lock_bh(&bc_lock);
	for (i=0; i<CONFIG_TIPC_MCASTGID_MAX; i++) {
		mcgl = bcbearer->mcgls[i];
		if (!mcgl) 
			continue;

		if (bclname && strcmp(mcgl->link.name, bclname))
			continue;
		
		tipc_link_set_queue_limits(&mcgl->link, limit);
	}
	spin_unlock_bh(&bc_lock);
	return 0;
}

int tipc_bclink_get_mcmap(u8 mcmap[], u32 bytes)
{
	memcpy(mcmap, bcbearer->mc_map, bytes);

	return 0;
}

u32 tipc_bclink_get_readable(struct mcglink *mcgl)
{
    return !(mcgl->flag & TIPC_MCGLINK_FLG_NO_READ);
}

static void bclink_reset(struct mcglink *mcgl)
{
    u32 mcgid = mcgl->mcgid;

    /* 超时重置多次仍然失效，是否要复位系统? */
    if (++mcgl->reset_count > 5) {
    	/* ??? */
    }

    /* 超时则重置组播链路，并通知远端 */
	warn("Reset %s %u times, outque %u, packque %u\n",
	        mcgl->link.name, mcgl->reset_count,
	        mcgl->link.out_queue_size, mcgl->pack_queue_size);

    /* 去使能该组播 */
	spin_lock_bh(&bc_lock);
    tipc_mcglink_reset(mcgl);
    clr_bytes_bit(bcbearer->mc_map, mcgid);
    spin_unlock_bh(&bc_lock);

    /* 本地的node mclink */
    tipc_nodes_disable_mclink(mcgid);    
    /* 对端的node mclink */
    tipc_bearers_send_disc();
    
    /* 再使能该组播 */
	spin_lock_bh(&bc_lock);
    tipc_mcglink_reset(mcgl);
    set_bytes_bit(bcbearer->mc_map, mcgid);
    spin_unlock_bh(&bc_lock);

    /* 本地的node mclink */
    tipc_nodes_enable_mclink(mcgid);    
    /* 对端的node mclink */
    tipc_bearers_send_disc();

    /* 再检查发送等待者 */
	if (!list_empty(&mcgl->link.waiting_ports)) {
		tipc_link_wakeup_ports(&mcgl->link, 0);
	}  

	mcgl->error = 0; /* 清除错误标记 */
	/* 0 非常关键，重新发布所有name */
	if (0 == mcgl->mcgid) {
		tipc_k_signal(tipc_named_node_up, addr_cluster(tipc_own_addr));
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static void bclink_timeout(struct timer_list *timer)
#else
static void bclink_timeout(struct mcglink *mcgl)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    struct link *bcl = container_of(timer, struct link, timer);
    struct mcglink *mcgl = container_of(bcl, struct mcglink, link);
#else
    struct link *bcl = &mcgl->link;
#endif
    int timout = 0;
    
    if (!read_trylock(&tipc_net_lock))
        return;
    
    if (bcbearer) {
        spin_lock_bh(&bc_lock);
        timout = tipc_link_check_waiting(bcl);

        mcgl->retrans_pps_max = 500; /* 2019-10-22 限制组播重传报文个数500，防止性能较差的网口被打死 */
        k_start_timer(&bcl->timer, bcl->tolerance);
        spin_unlock_bh(&bc_lock);

        if (timout || mcgl->error) {
            bclink_reset(mcgl);
        }
    }
    read_unlock(&tipc_net_lock);
}


int tipc_mcglink_create(u32 mcgid, u32 addrtag, u32 flag)
{
	struct link *link = NULL;
	struct mcglink *mcgl;

    mcgl = bcbearer->mcgls[mcgid];
    if (mcgl) {
        mcgl->flag = flag;
        return TIPC_OK;
    }
    
    mcgl = kzalloc(sizeof(*mcgl), GFP_ATOMIC);
	if (NULL == mcgl)
		return -ENOMEM;

	link = &mcgl->link;
	tipc_bearer_mc_add(mcgid, addrtag, &link->media_addr);
	
	INIT_LIST_HEAD(&link->waiting_ports);
	link->next_out_no = 1;
	link->stats.sent_info = link->next_out_no; /* 使mclink Tx与单播意义一致 */

	link->owner = &bcbearer->node;
	link->max_pkt = MAX_PKT_DEFAULT_MCAST;
	tipc_link_set_queue_limits(link, BCLINK_WIN_DEFAULT);
	link->b_ptr = &bcbearer->bearer;
	link->state = WORKING_WORKING;
	link->net_plane = mcgid;
	sprintf(link->name, "%s%u", tipc_bclink_name, mcgid);	

	if (BCLINK_LOG_BUF_SIZE) {
		char *pb = kmalloc(BCLINK_LOG_BUF_SIZE, GFP_ATOMIC);

		if (!pb)
			return -ENOMEM;
		tipc_printbuf_init(&link->print_buf, pb, BCLINK_LOG_BUF_SIZE);
	}
	mcgl->mcgid = mcgid;
	mcgl->min_rate = TIPC_MAX_LINK_PRI;
    mcgl->flag = flag;

	bcbearer->mcgls[mcgid] = mcgl;
	bcbearer->mcgl_count++;
	bcbearer->mcgls_ref[mcgid] = 1;

    link->abort_limit = (mcgid == 0) ? 50 : 15; /* 15则认为超时, 0需要高可靠 */
    link->tolerance = 1000; /* 1s检查一次 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	k_init_timer(&link->timer, (timer_handler)bclink_timeout);
#else
	k_init_timer(&link->timer, (Handler)bclink_timeout, (unsigned long)mcgl);
#endif
	k_start_timer(&link->timer, link->tolerance);

	return TIPC_OK;
}

void tipc_mcglink_reset(struct mcglink *mcgl)
{
	struct sk_buff *buf;
	struct sk_buff *next;

	buf = mcgl->first_pack;
	while (buf) {
		next = buf->next;
		if (mcgl->link.first_out == buf)
			break;
		
		buf_discard(buf);
		buf = next;
	}
    mcgl->first_pack = NULL;
    mcgl->last_pack = NULL;
    mcgl->pack_queue_size = 0;
    mcgl->pack_queue_max = 0;

	buf = mcgl->link.first_out;
	while (buf) {
		next = buf->next;
		buf_discard(buf);
		buf = next;
	}
    mcgl->link.first_out = NULL;
    mcgl->link.last_out = NULL;
    mcgl->link.next_out = NULL;
    mcgl->link.out_queue_size = 0;
    bclink_set_last_sent(mcgl); /* 也需要重置 */
    /* 其它信息不需要清除 */
}

int tipc_mc_start(u8 mcgids[], int count)
{
	int i, j;
    int k = 0; /* 业务组播mcgid开始位置，1表示控制组播与业务组播分开配置 */

	if (count > CONFIG_TIPC_MCASTGID_MAX) {
		warn("Multicast link creation failed, too many mcgids\n");
		return -EINVAL;
	}

	for (i=k; i<count; i++) {
		if (!mcgids[i] || mcgids[i] >= CONFIG_TIPC_MCASTGID_MAX) {
			warn("Multicast link creation failed, invalid mcgid [%d]\n", mcgids[i]);
			return -EINVAL;
		}
		for (j=k; j<i;j++) {
			if (mcgids[i] == mcgids[j]) {
				warn("Multicast link creation failed, duplicate mcgid [%d]\n", mcgids[i]);
				return -EINVAL;
			}
		}			
	}

	bcbearer = kzalloc(sizeof(*bcbearer), GFP_ATOMIC);
	if (NULL == bcbearer)
		goto nomem;
	
	INIT_LIST_HEAD(&bcbearer->bearer.cong_links);
	bcbearer->bearer.media = &bcbearer->media;
	/* becarefule! media's other members are null */
	bcbearer->media.send_msg = tipc_bcbearer_send;
	sprintf(bcbearer->media.name, "tipc-multicast");
	
	INIT_LIST_HEAD(&bcbearer->node.mclinks);	
	spin_lock_init(&bcbearer->node.elm.lock);
    bcbearer->node.elm.addr = addr_cluster(tipc_own_addr);

	bcbearer->type2mcgid_rshift = TYPE2MCG_RSHIFT_DEF;
	bcbearer->type2mcgid_mask = TYPE2MCG_MASK_DEF;

	/* mclink(0) */
	if (tipc_mcglink_create(0, count > 0 ? mcgids[0] : 0, 0))
        goto nomem;
    set_bytes_bit(bcbearer->mc_map, 0);
 	for (i=k; i<count; i++) {
		if (tipc_mcglink_create(mcgids[i], MC_TAG(mcgids[i]), 0))
			goto nomem;
        
    	set_bytes_bit(bcbearer->mc_map, mcgids[i]);
	}

	return TIPC_OK;
	
nomem:
 	warn("Multicast link creation failed, no memory\n");
	tipc_mc_stop();
	
	return -ENOMEM;			
	
}

void tipc_mc_stop(void)
{
	struct mcglink *mcgl;
	u32 i;

	spin_lock_bh(&bc_lock);

	if (bcbearer) {
		spin_lock_term(&bcbearer->node.elm.lock);
		for (i=0; i<CONFIG_TIPC_MCASTGID_MAX; i++) {
			mcgl = bcbearer->mcgls[i];
			if (!mcgl) 
				continue;

            tipc_mcglink_reset(mcgl);
            k_cancel_timer(&mcgl->link.timer);

			if (mcgl->link.print_buf.buf)
				kfree(mcgl->link.print_buf.buf);
			kfree(mcgl);
		}
		kfree(bcbearer);
		bcbearer = NULL;
	}
	spin_unlock_bh(&bc_lock);
}


int tipc_mc_mask(u32 mask)
{
    u32 i;
    u32 rshift = sizeof(u32)*BYTE_BITS;
    u32 rmask = 0;

    /* mask应该是连续个1，1之间不能有0 */
    for (i=0; i<sizeof(u32)*BYTE_BITS; i++) {
        if (mask & (1 << i)) {
            rmask = (rmask << 1) | 1;
            if (rshift == sizeof(u32)*BYTE_BITS)
                rshift = i;
        } else {
            if (rmask) {
                break; /* 遇到0停止 */
            }
        }
    }

    /* 如果还有1则是错误的mask */
    for (; i<sizeof(u32)*BYTE_BITS; i++) {
        if (mask & (1 << i)) {
    		warn("Set multicast mask failed, invalid mask [0x%x]\n", mask);
    		return -EINVAL;            
        }
    }

    /* (mcgid & rmask)取值应在[0,CONFIG_TIPC_MCASTGID_MAX) */
    if (rmask/2 >= CONFIG_TIPC_MCASTGID_MAX) {
		warn("Set multicast mask failed, invalid mask [0x%x]\n", mask);
		return -EINVAL;
    }

    if (!rmask) /* mask为0不需要shifit */
        rshift = 0;


    spin_lock_bh(&bc_lock);
    bcbearer->type2mcgid_rshift = rshift;
    bcbearer->type2mcgid_mask   = rmask;

    spin_unlock_bh(&bc_lock);


    return TIPC_OK;
}


int tipc_mc_enable(u32 mcgid, u32 flag)
{
    if (!mcgid || mcgid >= CONFIG_TIPC_MCASTGID_MAX) {
		warn("Multicast link enable failed, invalid mcgid [%d]\n", mcgid);
		return -EINVAL;
    }

   
    spin_lock_bh(&bc_lock);

    if (test_bytes_bit(bcbearer->mc_map, mcgid) &&
        bcbearer->mcgls[mcgid] &&
        ++bcbearer->mcgls_ref[mcgid] > 1) {
        spin_unlock_bh(&bc_lock);
        return TIPC_OK;
    }    

    if (tipc_mcglink_create(mcgid, MC_TAG(mcgid), flag)) {
        spin_unlock_bh(&bc_lock);
     	warn("Multicast link enable failed, no memory\n");

        return -ENOMEM;
    }

    
    set_bytes_bit(bcbearer->mc_map, mcgid);
    spin_unlock_bh(&bc_lock);

    /* 本地的node mclink */
    tipc_nodes_enable_mclink(mcgid);    
    /* 对端的node mclink */
    tipc_bearers_send_disc();

    return TIPC_OK;
}

int tipc_mc_disable(u32 mcgid, u32 flag)
{
    if (mcgid >= CONFIG_TIPC_MCASTGID_MAX) {
		warn("Multicast link disable failed, invalid mcgid [%d]\n", mcgid);
		return -EINVAL;
    }

    if (!mcgid) {
		warn("Multicast link 0 cannot dynamic changed\n");
		return -EINVAL;
    }

    spin_lock_bh(&bc_lock);
    if (!test_bytes_bit(bcbearer->mc_map, mcgid) ||
        !bcbearer->mcgls[mcgid]) {
        spin_unlock_bh(&bc_lock);
		warn("Multicast link disable mcgid [%d] not exist\n", mcgid);
		return -EINVAL;
    }

    if (bcbearer->mcgls_ref[mcgid] > 0 &&
        --bcbearer->mcgls_ref[mcgid] > 0) {
        spin_unlock_bh(&bc_lock);
        return TIPC_OK;
    }
    
    tipc_mcglink_reset(bcbearer->mcgls[mcgid]);

    clr_bytes_bit(bcbearer->mc_map, mcgid);
    spin_unlock_bh(&bc_lock);

    /* 本地的node mclink */
    tipc_nodes_disable_mclink(mcgid);    
    /* 对端的node mclink */
    tipc_bearers_send_disc();

    return TIPC_OK;
}

int tipc_bclink_init(void)
{
#if 0
	bcbearer = kzalloc(sizeof(*bcbearer), GFP_ATOMIC);
	bclink = kzalloc(sizeof(*bclink), GFP_ATOMIC);
	if (!bcbearer || !bclink) {
 nomem:
		warn("Broadcast link creation failed, no memory\n");
		kfree(bcbearer);
		bcbearer = NULL;
		kfree(bclink);
		bclink = NULL;
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&bcbearer->bearer.cong_links);
	bcbearer->bearer.media = &bcbearer->media;
	bcbearer->media.send_msg = tipc_bcbearer_send;
	sprintf(bcbearer->media.name, "tipc-broadcast");

	bcl = &bclink->link;
	INIT_LIST_HEAD(&bcl->waiting_ports);
	bcl->next_out_no = 1;
	spin_lock_init(&bclink->node.elm.lock);
	bcl->owner = &bclink->node;
	bcl->max_pkt = MAX_PKT_DEFAULT_MCAST;
	tipc_link_set_queue_limits(bcl, BCLINK_WIN_DEFAULT);
	bcl->b_ptr = &bcbearer->bearer;
	bcl->state = WORKING_WORKING;
	sprintf(bcl->name, tipc_bclink_name);

	if (BCLINK_LOG_BUF_SIZE) {
		char *pb = kmalloc(BCLINK_LOG_BUF_SIZE, GFP_ATOMIC);

		if (!pb)
			goto nomem;
		tipc_printbuf_init(&bcl->print_buf, pb, BCLINK_LOG_BUF_SIZE);
	}
#endif	
	if (!bcbearer) {
		return -ENOMEM;
	}
	return 0;
}

void tipc_bclink_stop(void)
{
#if 0
	spin_lock_bh(&bc_lock);
	if (bcbearer) {
		tipc_link_stop(bcl);
		if (BCLINK_LOG_BUF_SIZE)
			kfree(bcl->print_buf.buf);
		bcl = NULL;
		spin_lock_term(&bclink->node.elm.lock);
		kfree(bclink);
		bclink = NULL;
		kfree(bcbearer);
		bcbearer = NULL;
	}
	spin_unlock_bh(&bc_lock);
#endif
	tipc_mc_stop();
}

/**
 * tipc_nmap_add - add a node to a node map
 */

void tipc_nmap_add(struct tipc_node_map *nm_ptr, u32 node)
{
	int n = tipc_node(node);
	int w = n / WSIZE;
	u32 mask = (1 << (n % WSIZE));

	if ((nm_ptr->map[w] & mask) == 0) {
		nm_ptr->count++;
		nm_ptr->map[w] |= mask;

		if (nm_ptr->count == 1) {
			nm_ptr->start = n;
			nm_ptr->stop = n;
			return;
		}

		if (nm_ptr->start > n)
			nm_ptr->start = n;
		if (nm_ptr->stop < n)
			nm_ptr->stop = n;
	}
}

/** 
 * tipc_nmap_remove - remove a node from a node map
 */

void tipc_nmap_remove(struct tipc_node_map *nm_ptr, u32 node)
{
	int n = tipc_node(node);
	int w = n / WSIZE;
	u32 mask = (1 << (n % WSIZE));

	if ((nm_ptr->map[w] & mask) != 0) {
		nm_ptr->map[w] &= ~mask;
		nm_ptr->count--;

		if (!nm_ptr->count) {
			nm_ptr->start = MAX_NODES;
			nm_ptr->stop = 0;
			return;
		}

		/* 小概率，检查所有节点 */
		if (nm_ptr->start == n) {
			for (n=0; n<MAX_NODES; n++) {
				w = n / WSIZE;
				mask = (1 << (n % WSIZE));
				if (nm_ptr->map[w] & mask)
					break;
			}
			nm_ptr->start = n;
		}
		if (nm_ptr->stop == n) {
			for (n=MAX_NODES-1; n>0; n--) {
				w = n / WSIZE;
				mask = (1 << (n % WSIZE));
				if (nm_ptr->map[w] & mask)
					break;
			}
			nm_ptr->stop = n;
		}
	}
}

/**
 * tipc_nmap_diff - find differences between node maps
 * @nm_a: input node map A
 * @nm_b: input node map B
 * @nm_diff: output node map A-B (i.e. nodes of A that are not in B)
 */

void tipc_nmap_diff(struct tipc_node_map *nm_a, struct tipc_node_map *nm_b,
		    struct tipc_node_map *nm_diff)
{
	int stop = sizeof(nm_a->map) / sizeof(u32);
	int w;
	int b;
	u32 map;

	memset(nm_diff, 0, sizeof(*nm_diff));
	for (w = 0; w < stop; w++) {
		map = nm_a->map[w] ^ (nm_a->map[w] & nm_b->map[w]);
		nm_diff->map[w] = map;
		if (map != 0) {
			for (b = 0 ; b < WSIZE; b++) {
				if (map & (1 << b))
					nm_diff->count++;
			}
		}
	}
}

/**
 * tipc_port_list_add - add a port to a port list, ensuring no duplicates
 */

void tipc_port_list_add(struct port_list *pl_ptr, u32 port)
{
	struct port_list *item = pl_ptr;
	int i;
	int item_sz = PLSIZE;
	int cnt = pl_ptr->count;

	for (; ; cnt -= item_sz, item = item->next) {
		if (cnt < PLSIZE)
			item_sz = cnt;
		for (i = 0; i < item_sz; i++)
			if (item->ports[i] == port)
				return;
		if (i < PLSIZE) {
			item->ports[i] = port;
			pl_ptr->count++;
			return;
		}
		if (!item->next) {
			item->next = kmalloc(sizeof(*item), GFP_ATOMIC);
			if (!item->next) {
				warn("Incomplete multicast delivery, no memory\n");
				return;
			}
			item->next->next = NULL;
		}
	}
}

/**
 * tipc_port_list_free - free dynamically created entries in port_list chain
 * 
 * Note: First item is on stack, so it doesn't need to be released
 */

void tipc_port_list_free(struct port_list *pl_ptr)
{
	struct port_list *item;
	struct port_list *next;

	for (item = pl_ptr->next; item; item = next) {
		next = item->next;
		kfree(item);
	}
}

