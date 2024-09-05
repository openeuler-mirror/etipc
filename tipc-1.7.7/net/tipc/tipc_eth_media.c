/*
 * net/tipc/tipc_eth_media.c: Ethernet bearer support for TIPC
 *
 * Copyright (c) 2001-2007, Ericsson AB
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

#include <net/tipc/tipc.h>
#include <net/tipc/tipc_plugin_if.h>
#include <net/tipc/tipc_plugin_msg.h>
#include <linux/netdevice.h>
#include <linux/workqueue.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#include <net/net_namespace.h>
#endif
#include <linux/if_vlan.h> /* */
#include "tipc_core.h"
#include "tipc_dbg.h"
#include "tipc_bearer.h"

#define MAX_ETH_BEARERS		TIPC_MAX_BEARERS
#define ETH_LINK_PRIORITY	TIPC_DEF_LINK_PRI
#define ETH_LINK_TOLERANCE	(TIPC_DEF_LINK_TOL * 2) /* */

extern unsigned int g_tipc_dbg_switch;

#ifndef ETH_P_TIPC
#define ETH_P_TIPC 0x88CA
#endif

/**
 * struct eth_bearer - Ethernet bearer data structure
 * @bearer: ptr to associated "generic" bearer structure
 * @dev: ptr to associated Ethernet network device
 * @tipc_packet_type: used in binding TIPC to Ethernet driver
 * @cleanup: work item used when disabling bearer
 */


static struct tipc_media eth_media_info;
static struct eth_bearer eth_bearers[MAX_ETH_BEARERS];
static int eth_started = 0;

static struct notifier_block notifier;
static struct work_struct reg_notifier;

static u8 g_auc_mcgid[CONFIG_TIPC_MCASTGID_MAX];
static u32 g_cnt_mcgid;

#ifdef CONFIG_SMP
DEFINE_RWLOCK(eth_recv_lock); /* 确保多核中tipc_recv_msg()保序 */
#define RECV_LOCK_BH()   write_lock_bh(&eth_recv_lock)
#define RECV_UNLOCK_BH() write_unlock_bh(&eth_recv_lock)
#else
#define RECV_LOCK_BH() 
#define RECV_UNLOCK_BH()
#endif
/**
 * eth_media_addr_init - initialize Ethernet media address structure
 * 
 * Structure's "value" field stores address info in the following format:
 * - Ethernet media type identifier [4 bytes, in network byte order]
 * - MAC address [6 bytes]
 * - unused [10 bytes of zeroes]
 * 
 * Note: This is the same format as the TIPC neighbour discovery message uses
 * to designate an Ethernet address, which simplies the job of getting the
 * media address into/out of the message header.
 */

static void eth_media_addr_init(struct tipc_media_addr *a, char *mac)
{
	memset(a->value, 0, sizeof(a->value));
	a->value[3] = TIPC_MEDIA_ID_ETH;
	memcpy(&a->value[4], mac, ETH_ALEN);

	a->media_id = TIPC_MEDIA_ID_ETH;
        a->broadcast = !memcmp(mac, &eth_media_info.bcast_addr.value[4], ETH_ALEN);
}

void tipc_add_checksum(struct sk_buff *skb, struct eth_bearer *eth_ptr, 
	struct buf_ck_data* ck, void *data, u32 len)
{
	ck->type = 0; /* 先标记无ck，计算后再设置 */
	ck->flag = 0;
	if (tipc_checkable() && ++eth_ptr->chk_msg_cnt >= tipc_check_rate) {
		eth_ptr->chk_msg_cnt = 0;
		ck->sum = csum16((void *)data, len);
		ck->type = CK_TYP_CKSUM;
	}
	skb_put(skb, sizeof(*ck)); /* 尾部添加ck */
}

/**
 * send_msg - send a TIPC message out over an Ethernet interface
 */

static int send_msg(struct sk_buff *buf, struct tipc_bearer *tb_ptr,
						struct tipc_media_addr *dest)
{
	struct sk_buff *clone;
	struct net_device *dev;
	int delta;
	struct ethhdr   *ehdr;
	struct vlan_hdr *vhdr;
	u16 vlan_TCI = 0;
	struct buf_ck_data* ck;
	u32 msg_sz = msg_size(buf_msg(buf)); /* data必是tipc_msg */
	struct eth_bearer *eth_ptr = (struct eth_bearer *)(tb_ptr->usr_handle);
	u32 eth_hdr_sz = ETH_HLEN + (eth_ptr->vlan_no ? VLAN_HLEN : 0);


	/* tipc_priority 2012-9-12 使用同一个优先级，否则报文可能cos乱序*/
	buf->priority = TIPC_PRI_MANAGE;
	/* cloned表示buf还在上一次发送ing，需skb_copy后更改；正常情况skb_clone */
	if (!skb_cloned(buf))
		clone = skb_clone(buf, GFP_ATOMIC);
	else
		clone = skb_copy(buf, GFP_ATOMIC); /* 此处与pskb_copy等效 */
	if (!clone)
		return 0;
	
	dev = ((struct eth_bearer *)(tb_ptr->usr_handle))->dev;

	if (eth_ptr->vlan_no) {
		delta = ETH_HLEN + VLAN_HLEN - skb_headroom(buf);
	} else {
		delta = dev->hard_header_len - skb_headroom(buf);
	}

	if ((delta > 0 || skb_tailroom(buf) < CK_SIZE) && 
		pskb_expand_head(clone, SKB_DATA_ALIGN(delta), CK_SIZE, GFP_ATOMIC)) {
		kfree_skb(clone);
		return 0;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	skb_reset_network_header(clone);
#else
	clone->nh.raw = clone->data;
#endif
	clone->dev = dev;
	if (eth_ptr->vlan_no) {
		ck = (struct buf_ck_data *)(clone->data + msg_sz);/* 报文尾部ck空间 */
		/* encapsulate tipc over ether + vlan header */
		ehdr = (struct ethhdr   *)skb_push(clone, eth_hdr_sz);
		memcpy(ehdr->h_dest, &dest->value[4], ETH_ALEN);
		memcpy(ehdr->h_source, dev->dev_addr, ETH_ALEN);

		ehdr->h_proto = 0; /* vlan will be removed in recv end */

		vhdr = (struct vlan_hdr *)(ehdr + 1);
		/* build the four bytes that make this a VLAN header. */

		/* Now, construct the second two bytes. This field looks something
		 * like:
		 * usr_priority: 3 bits	 (high bits)
		 * CFI		 1 bit, 0
		 * VLAN ID	 12 bits (low bits), 1
		 *
		 */
		vhdr->h_vlan_TCI = 0; /* vlan will be removed in recv end */
		vhdr->h_vlan_encapsulated_proto = htons(ETH_P_TIPC);
		
		/* checksum 功能 */
		tipc_add_checksum(clone, eth_ptr, ck, ehdr, (eth_hdr_sz + msg_sz));
		buf_emulate_bad(clone, 10); /* 此处模拟源mac地址改写错误 */
		ehdr->h_proto = htons(ETH_P_8021Q);
		vlan_TCI = ((buf->priority & 0x7) << 13) | 1;
		vhdr->h_vlan_TCI = htons(vlan_TCI);
	} else {
		ck = (struct buf_ck_data *)(clone->data + msg_sz); /* 报文尾部ck空间 注意顺序不要放到skb_push后面 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
		dev_hard_header(clone, dev, ETH_P_TIPC, &dest->value[4],
				dev->dev_addr, clone->len);
#else
		dev->hard_header(clone, dev, ETH_P_TIPC, &dest->value[4],
				 dev->dev_addr, clone->len);
#endif
		/* checksum 功能 dev_hard_header 里面执行skb_push操作，skb->data 对应着ehdr，而不是tipc hdr */
		tipc_add_checksum(clone, eth_ptr, ck, clone->data, (eth_hdr_sz + msg_sz)); 
	}

	dev_queue_xmit(clone);
	return 0;
}

static int dump_dev(struct net_device *dev)
{
	/* 简单记数及常见错误 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    struct rtnl_link_stats64 stats64;
    struct rtnl_link_stats64 *stats;
#else    
	const struct net_device_stats *stats = NULL;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    stats = dev_get_stats(dev, &stats64);    
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	stats = dev_get_stats(dev);
#else
	if (!dev->get_stats) /* 其实不可能为空 */
		return 0;
	stats = dev->get_stats(dev);
#endif	
	if (!stats)
		return 0;

	info("RX:%lu errors:%lu dropped:%lu crc:%lu\n", stats->rx_packets,
		stats->rx_errors, stats->rx_dropped, stats->rx_crc_errors);
	info("TX:%lu errors:%lu dropped:%lu fifo:%lu\n", stats->tx_packets,
		stats->tx_errors, stats->tx_dropped, stats->tx_fifo_errors);

	return 0;
}

int recv_msg_check(struct sk_buff *buf, struct eth_bearer *eb_ptr)
{
	/* 紧邻eth_hdr，含校验数据的报文，CK_TYP_CKSUM类型.
	   校验失败返回0; 校验通过，没有校验或新校验方式，返回1 */
	struct ethhdr * ehdr;
	u32 msg_sz; /* data必是tipc_msg */
	struct buf_ck_data* ck;

	/* 因hi161x系列驱动收包buffer小于256，超过256的报文使用分片方式保存，需要线性化处理。*/
	if (unlikely(buf_linearize(buf))) {
		if (tipc_ratelimit(++eb_ptr->err_msg_cnt, 1)) {
			info("Recv invalid pkt count %u(linearize error), bearer %s\n",
				eb_ptr->err_msg_cnt, eb_ptr->bearer? eb_ptr->bearer->name : "NULL");
			tipc_dump_buf(buf);
		}
		return 0;
	}

    ehdr = eth_hdr(buf);
	msg_sz = msg_size(buf_msg(buf)); /* data必是tipc_msg */
	ck = (struct buf_ck_data*)(buf->data + msg_sz);
	
	/*目的mac地址(非广播组播)与bearer的不匹配，当作检验错误*/

	if (eb_ptr->bearer == NULL)	{
		if (tipc_ratelimit(++eb_ptr->err_msg_cnt, 1)) {
			info("Recv invalid pkt count %u(bearer NULL)\n", eb_ptr->err_msg_cnt);
			tipc_dump_buf(buf);
		}
		return 0; /*返回错误，bearer为NULL说明接口已经down掉*/
	}

    if ((ehdr->h_dest[0] & 0x1) == 0 && memcmp(ehdr->h_dest, &eb_ptr->bearer->addr.value[4], ETH_ALEN)) {
        if (tipc_ratelimit(++eb_ptr->mac_fail_cnt, 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_ETH_MEDIA)) {
            info("%s recv msg check dest mac failed count %u, mac %02x-%02x-%02x-%02x-%02x-%02x\n",
                eb_ptr->dev->name, eb_ptr->mac_fail_cnt, ehdr->h_dest[0], ehdr->h_dest[1], 
                ehdr->h_dest[2], ehdr->h_dest[3], ehdr->h_dest[4], ehdr->h_dest[5]);
            tipc_dump_buf(buf);
        }
    
        return 0; /*返回错误，不接收目的mac不一致的报文*/
    }

	if ((void *)(ehdr + 1) == buf->data &&
		buf->len >= msg_sz + sizeof(*ck) &&
		CK_TYP_CKSUM == ck->type) {
		/* 报文没有vlan头 */
		__sum16 sum = csum16((void *)ehdr, ETH_HLEN+msg_sz);
		if (sum != ck->sum) {
			if (tipc_ratelimit(++eb_ptr->chk_fail_cnt, 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_ETH_MEDIA)) {
				info("%s recv msg check failed count %u, csum %x neq %x %p\n",
					eb_ptr->dev->name, eb_ptr->chk_fail_cnt, sum, ck->sum, ck);
				dump_dev(eb_ptr->dev);
				tipc_dump_buf(buf);
			}

			return 0; /* 校验失败 */
		}

		return 1; /* 校验成功 */
	}
	if (tipc_ratelimit(++eb_ptr->nochk_cnt, 1)  || tipc_dbg_is_on(TIPC_DBG_SWITCH_ETH_MEDIA)) {
		info("%s recv msg nocheck count %u\n", eb_ptr->dev->name, eb_ptr->nochk_cnt);
		tipc_dump_buf(buf);
	}
	return 1; /* 没有校验或新校验。1 for compatible, issu upgrade */
}

/**
 * recv_msg - handle incoming TIPC message from an Ethernet interface
 *
 * Accept only packets explicitly sent to this node, or broadcast packets;
 * ignores packets sent using Ethernet multicast, and traffic sent to other
 * nodes (which can happen if interface is running in promiscuous mode).
 */

static int recv_msg(struct sk_buff *buf, struct net_device *dev,
		    struct packet_type *pt, struct net_device *orig_dev)
{
	struct eth_bearer *eb_ptr = (struct eth_bearer *)pt->af_packet_priv;
	int cksum_ok = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	if (!net_eq(dev_net(dev), &init_net)) {
		kfree_skb(buf);
		return 0;
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	if (dev_net(dev) != &init_net) {
		kfree_skb(buf);
		return 0;
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	if (dev->nd_net != &init_net) {
		kfree_skb(buf);
		return 0;
	}
#endif

	buf_emulate_bad(buf, 30); /* 此处模拟收包改写错误 */
	if (likely(eb_ptr->bearer)) {
		cksum_ok = recv_msg_check(buf, eb_ptr);
		/* change to multicast. 增加reboot后需要增加NET检查 */
		if (likely(buf->pkt_type <= PACKET_MULTICAST) &&
            TIPC_NET_MODE == tipc_mode && cksum_ok) {
			buf->next = NULL;
			RECV_LOCK_BH();
			tipc_recv_msg(buf, eb_ptr->bearer);
			RECV_UNLOCK_BH();
			return 0;
		}
	}

	/* 校验不成功都已经记录日志 */
	if (cksum_ok && tipc_ratelimit(++eb_ptr->err_msg_cnt, 1)) {
		info("Recv invalid pkt count %u, type %d and bearer %s\n",
			 eb_ptr->err_msg_cnt, buf->pkt_type,
			 eb_ptr->bearer? eb_ptr->bearer->name : "NULL");
	}

	kfree_skb(buf);
	return 0;
}

/**
 * enable_bearer - attach TIPC bearer to an Ethernet interface
 */

static int enable_bearer(struct tipc_bearer *tb_ptr)
{
	struct net_device *dev = NULL;
	struct net_device *pdev;
	struct eth_bearer *eb_ptr = &eth_bearers[0];
	struct eth_bearer *stop = &eth_bearers[MAX_ETH_BEARERS];
	char *driver_name = strchr((const char *)tb_ptr->name, ':') + 1;
	int pending_dev = 0;
	u32 i; /* */
	
	/* NE8000 ATN M2H M2K  PTN990  PTN910e 发送不加VLAN */
#ifdef CONFIG_TIPC_SEND_VLAN
	eb_ptr->vlan_no = 1;
	info("enable_bearer: vlan %u\n", eb_ptr->vlan_no);
#else
	eb_ptr->vlan_no = 0;
	info("enable_bearer: vlan %u\n", eb_ptr->vlan_no);
#endif
	/* Find unused Ethernet bearer structure */
	while (eb_ptr->dev) {
		if (!eb_ptr->bearer)
			pending_dev++;
		if (++eb_ptr == stop)
			return pending_dev ? -EAGAIN : -EDQUOT;
	}

	/* Find device with specified name */

	read_lock(&dev_base_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	for_each_netdev(&init_net, pdev)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	for_each_netdev(pdev)
#else
	for (pdev = dev_base; pdev; pdev = pdev->next)
#endif
	{
		if (!strncmp(pdev->name, driver_name, IFNAMSIZ)) {
			dev = pdev;
			dev_hold(dev);
			break;
		}
	}
	read_unlock(&dev_base_lock);
	if (!dev)
		return -ENODEV;

	/* Create Ethernet bearer for device */
	if (strncmp(dev->name, "peth", 4) == 0) {
		eb_ptr->vlan_no = 0;
	}

	eb_ptr->dev = dev;
	eb_ptr->tipc_packet_type.type = htons(ETH_P_TIPC);
	eb_ptr->tipc_packet_type.dev = dev; 

	eb_ptr->tipc_packet_type.func = recv_msg;
	eb_ptr->tipc_packet_type.af_packet_priv = eb_ptr;
	INIT_LIST_HEAD(&(eb_ptr->tipc_packet_type.list));
	/* 内核切换RTOS 4.4后与2.6处理流程变化极大，记录下
	1. VSUF依靠bond_handle_frame将TIPC报文转给子接口 
	2. 其他单板物理口, bonging不处理，
	依靠__netif_receive_skb_core 兜底流程
	bong0不处理转给物理dev协议栈处理
	此处仍然保留注册dev级别的ptype处理 */
	dev_add_pack(&eb_ptr->tipc_packet_type);

	eb_ptr->chk_msg_cnt = eb_ptr->chk_fail_cnt = eb_ptr->nochk_cnt = eb_ptr->mac_fail_cnt = 0;
	/* Associate TIPC bearer with Ethernet bearer */

	eb_ptr->bearer = tb_ptr;
	tb_ptr->usr_handle = (void *)eb_ptr;
	tb_ptr->mtu = dev->mtu;
	tb_ptr->blocked = (dev->flags & IFF_UP) ? 0 : 1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
	eth_media_addr_init(&tb_ptr->addr, (char *)dev->dev_addr);
#else
	eth_media_addr_init(&tb_ptr->addr, (char *)&dev->dev_addr);
#endif
	/* mc_add */
	for (i=1; i<CONFIG_TIPC_MCASTGID_MAX; i++) {
		u8 mcaddr[ETH_ALEN] = TIPC_MCAST_ADDR_DEF;
		mcaddr[4] = g_auc_mcgid[i];

		if (mcaddr[4] && dev)
			#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 34)
			dev_mc_add(dev, mcaddr);
			#else
			dev_mc_add(dev, mcaddr, ETH_ALEN, 0);
			#endif
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
    rcu_assign_pointer(dev->tipc_ptr, tb_ptr);
#endif

	return 0;
}

/**
 * cleanup_bearer - break association between Ethernet bearer and interface 
 * 
 * This routine must be invoked from a work queue because it can sleep. 
 */

static void cleanup_bearer(struct work_struct *work)
{
	struct eth_bearer *eb_ptr =
		container_of(work, struct eth_bearer, cleanup);

	dev_remove_pack(&eb_ptr->tipc_packet_type);
	dev_put(eb_ptr->dev);
	eb_ptr->dev = NULL;
}

/**
 * disable_bearer - detach TIPC bearer from an Ethernet interface
 *
 * Mark Ethernet bearer as inactive so that incoming buffers are thrown away,
 * then get worker thread to complete bearer cleanup.  (Can't do cleanup
 * here because cleanup code needs to sleep and caller holds spinlocks.)
 */

static void disable_bearer(struct tipc_bearer *tb_ptr)
{
	struct eth_bearer *eb_ptr = (struct eth_bearer *)tb_ptr->usr_handle;
	u32 i;
	
	/* mc_add */
	for (i=1; i<CONFIG_TIPC_MCASTGID_MAX; i++) {
		u8 mcaddr[ETH_ALEN] = TIPC_MCAST_ADDR_DEF;
		mcaddr[4] = g_auc_mcgid[i];

		if (mcaddr[4] && eb_ptr->dev)
			#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 34)
			dev_mc_del(eb_ptr->dev, mcaddr);
			#else
			dev_mc_delete(eb_ptr->dev, mcaddr, ETH_ALEN, 0);
			#endif
	}
	
	eb_ptr->bearer = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
	INIT_WORK(&eb_ptr->cleanup, cleanup_bearer);
#else
	INIT_WORK(&eb_ptr->cleanup, (void (*)(void *))cleanup_bearer,
		  &eb_ptr->cleanup);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
    RCU_INIT_POINTER(eb_ptr->dev->tipc_ptr, NULL);
#endif

	schedule_work(&eb_ptr->cleanup);
}

/**
 * recv_notification - handle device updates from OS
 *
 * Change the state of the Ethernet bearer (if any) associated with the
 * specified device.
 */

static int recv_notification(struct notifier_block *nb, unsigned long evt,
			     void *dv)
{
	struct net_device *dev;
	struct eth_bearer *eb_ptr __attribute__((unused)) = &eth_bearers[0];
	struct eth_bearer *stop __attribute__((unused)) = &eth_bearers[MAX_ETH_BEARERS];
    struct tipc_bearer *b_ptr;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
    dev = netdev_notifier_info_to_dev(dv);
#else
    dev = (struct net_device *)dv;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
    b_ptr = rtnl_dereference(dev->tipc_ptr);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	if (dev_net(dev) != &init_net)
		return NOTIFY_DONE;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	if (dev->nd_net != &init_net)
		return NOTIFY_DONE;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
    if (!b_ptr)
		return NOTIFY_DONE;
#else
	while ((eb_ptr->dev != dev)) {
		if (++eb_ptr == stop)
			return NOTIFY_DONE;	/* couldn't find device */
	}
	if (!eb_ptr->bearer)
		return NOTIFY_DONE;		/* bearer had been disabled */

	b_ptr = eb_ptr->bearer;
#endif

    b_ptr->mtu = dev->mtu;
    
	switch (evt) {
	case NETDEV_CHANGE:
		if (netif_carrier_ok(dev))
			tipc_continue(b_ptr);
#if 0 /* ignore for 83xx! 使用fast_standby快切，仍关闭避免不稳定reset */
		else {
            if (g_auc_mcgid[0] != 3)
			    tipc_block_bearer(eb_ptr->bearer->name);
		}
#endif		
		break;
	case NETDEV_UP:
		tipc_continue(b_ptr);
		break;
	case NETDEV_DOWN:
		tipc_block_bearer(b_ptr->name);
		break;
	case NETDEV_CHANGEMTU:
	case NETDEV_CHANGEADDR:
		tipc_block_bearer(b_ptr->name);
		tipc_continue(b_ptr);
		break;
	case NETDEV_UNREGISTER:
	case NETDEV_CHANGENAME:
		tipc_disable_bearer(b_ptr->name);
		break;
	}
	return NOTIFY_OK;
}

static int eth_msg2addr(struct tipc_media_addr *a, u32 *msg_area)
{
	if (msg_area[0] != htonl(TIPC_MEDIA_ID_ETH))
		return 1;

	eth_media_addr_init(a, (char *)&msg_area[1]);
	return 0;
}

static int eth_addr2msg(struct tipc_media_addr *a, u32 *msg_area)
{
	if (a->media_id != TIPC_MEDIA_ID_ETH)
		return 1;

	memcpy(msg_area, a->value, sizeof(a->value));
	return 0;
}

/**
 * eth_addr2str - convert Ethernet address to string
 */

static int eth_addr2str(struct tipc_media_addr *a, char *str_buf, int str_size)
{                       
	unsigned char *mac;

	if ((a->media_id != TIPC_MEDIA_ID_ETH) || (str_size < 18))
		return 1;
		
	mac = (unsigned char *)&a->value[4];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	sprintf(str_buf, "%pM", mac);
#else
	sprintf(str_buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
#endif
	return 0;
}


/**
 * eth_str2addr - convert string to Ethernet address
 */

static int eth_str2addr(struct tipc_media_addr *a, char *str_buf)
{                     
	char mac[6];

        if (ETH_ALEN != sscanf(str_buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                               (u32 *)&mac[0], (u32 *)&mac[1], (u32 *)&mac[2],
                               (u32 *)&mac[3], (u32 *)&mac[4], (u32 *)&mac[5]))
            return 1;

	eth_media_addr_init(a, mac);
        return 0;
}

/*
 * Ethernet media registration info required by TIPC
 */

static struct tipc_media eth_media_info = {
	TIPC_MEDIA_ID_ETH,
	"eth",
	ETH_LINK_PRIORITY,
	ETH_LINK_TOLERANCE,
	TIPC_DEF_LINK_WIN,
	send_msg,
	enable_bearer,
	disable_bearer,
	eth_addr2str,
	eth_str2addr,
        eth_msg2addr,
        eth_addr2msg,
	{{0, 0, 0, TIPC_MEDIA_ID_ETH, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	TIPC_MEDIA_ID_ETH, 1}
};

/**
 * do_registration - register TIPC to receive device notifications
 * 
 * This routine must be invoked from a work queue because it can sleep. 
 */

static void do_registration(struct work_struct *dummy)
{
	notifier.notifier_call = &recv_notification;
	notifier.priority = 0;
	register_netdevice_notifier(&notifier);
}

/**
 * tipc_eth_media_start - activate Ethernet bearer support
 *
 * Register Ethernet media type with TIPC bearer code.
 * Also register with OS for notifications about device state changes.
 */

int tipc_eth_media_start(void)
{                       
	int res;

	if (eth_started == 1)
		return -EINVAL;

	memset(eth_bearers, 0, sizeof(eth_bearers));

	res = tipc_register_media(&eth_media_info);
	if (res)
		return res;

    if (!eth_started) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
	INIT_WORK(&reg_notifier, do_registration);
#else
	INIT_WORK(&reg_notifier, (void (*)(void *))do_registration, NULL);
#endif
	schedule_work(&reg_notifier);
    }
	eth_started = 1;
	return res;
}

/**
 * tipc_eth_media_stop - deactivate Ethernet bearer support
 */

void tipc_eth_media_shutdown(int stop)
{
	if (!eth_started)
		return;
	if (stop) {
		flush_scheduled_work();
	    unregister_netdevice_notifier(&notifier);
	}
	memset(g_auc_mcgid, 0, sizeof(g_auc_mcgid));
	g_cnt_mcgid = 0;
	eth_started = stop ? 0 : 2;
}

void tipc_eth_media_stop(void)
{
	tipc_eth_media_shutdown(1);
}

/* */
/**
 * tipc_bearer_mc_add - add mc to eth media 
 * @mcgid: multicast group ID
 * @addrtag: mcaddr[4]
 * @media_addr: output, return medira addr
 *  
 */

void tipc_bearer_mc_add(u32 mcgid, u32 addrtag, struct tipc_media_addr *media_addr)
{
	u8 mcaddr[ETH_ALEN] = TIPC_MCAST_ADDR_DEF;
	if (addrtag) {
#ifndef CONFIG_TIPC_DUMMY_MULTICAST
		mcaddr[4] = addrtag;
#else
		memset(mcaddr, 0xff, ETH_ALEN);
#endif
		g_cnt_mcgid++;
		g_auc_mcgid[mcgid] = addrtag;
		
		if (mcgid == 0)
			memcpy(&eth_media_info.bcast_addr.value[4],
				mcaddr, ETH_ALEN);
	}
	else
		memset(mcaddr, 0xff, ETH_ALEN);

	
	media_addr->media_id = TIPC_MEDIA_ID_ETH;
	media_addr->value[3] = TIPC_MEDIA_ID_ETH;
	memcpy(&media_addr->value[4], mcaddr, ETH_ALEN);	
	media_addr->broadcast = 1;
}


/* !0: same
 * 0: diff
 */
int tipc_bearer_eq_addr(struct tipc_media_addr *addr1, struct tipc_media_addr *addr2)
{
	return !memcmp(addr1, addr2, sizeof(*addr1));			
}

int tipc_bearer_eq_skb_addr(struct sk_buff *buf, struct tipc_bearer *tb_ptr, struct tipc_media_addr *addr)
{
	struct net_device *dev;

	if (unlikely(tb_ptr->addr.media_id != TIPC_MEDIA_ID_ETH)) 
		return 0;

	
	dev = ((struct eth_bearer *)(tb_ptr->usr_handle))->dev;
	
	if (likely(skb_headroom(buf) >= dev->hard_header_len && 
	    		dev->hard_header_len >= ETH_HLEN)) {
		/* mpu dev->hard_header_len错误，暂时用ETH_HLEN代替 */
		return !memcmp(buf->data - ETH_HLEN + dev->addr_len,
					&addr->value[4], dev->addr_len) ||
			   !memcmp(buf->data - dev->hard_header_len + dev->addr_len,
					&addr->value[4], dev->addr_len);
	}
	
	return 0;
}

int tipc_media_rate(struct tipc_media *media)
{
    /* 主控板(组播1)的速率高 */
    return media->priority + (media->bcast_addr.value[4+4] == 1 ? 5 : 0);
}

void tipc_media_fill_mac(struct sk_buff *skb, char *src_mac, char *dst_mac)
{
    if(NULL != dst_mac)
        memcpy(skb->data, dst_mac, ETH_ALEN);

    if(NULL != src_mac)
        memcpy(skb->data + ETH_ALEN, src_mac, ETH_ALEN);
}
int tipc_media_check_mtu(struct bearer *pbearer, size_t len)
{
    struct eth_bearer *eth_ptr = (struct eth_bearer *)(pbearer->publ.usr_handle);
    struct net_device *dev;
    int res = 0;
    dev = eth_ptr->dev;
    if (len > dev->mtu + dev->hard_header_len)
        res = -EMSGSIZE;
    return res;
}
struct net_device * tipc_media_get_dev(struct bearer *pbearer)
{
    return ((struct eth_bearer *)(pbearer->publ.usr_handle))->dev;
}
