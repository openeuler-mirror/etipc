/*
 * net/tipc/tipc_cfgsrv.c: TIPC configuration service code
 *
 * Copyright (c) 2002-2006, Ericsson AB
 * Copyright (c) 2004-2007, 2010, Wind River Systems
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
#include "tipc_bearer.h"
#include "tipc_port.h"
#include "tipc_link.h"
#include "tipc_net.h"
#include "tipc_addr.h"
#include "tipc_name_table.h"
#include "tipc_node.h"
#include "tipc_cfgsrv.h"
#include "tipc_discover.h"

#ifdef CONFIG_TIPC_CONFIG_SERVICE

struct manager {
	u32 user_ref;
	u32 port_ref;
};

static struct manager mng = { 0 };

static DEFINE_SPINLOCK(config_lock);

static const void *req_tlv_area;	/* request message TLV area */
static int req_tlv_space;		/* request message TLV area size */
static int rep_headroom;		/* reply message headroom to use */

extern void tipc_eth_media_shutdown(int stop);
extern struct sk_buff *tipc_set_portmsg_stats(const void *req_tlv_area, int req_tlv_space,
                                                  u16 cmd_type);
extern struct sk_buff *tipc_get_portmsg_stats(const void *req_tlv_area, int req_tlv_space,
                                                  u16 cmd_type);
extern struct sk_buff *tipc_debug_log_switch(const void *req_tlv_area, int req_tlv_space);

struct sk_buff *tipc_cfg_reply_alloc(int payload_size)
{
	struct sk_buff *buf;

	buf = alloc_skb(rep_headroom + payload_size, GFP_ATOMIC);
	if (buf)
		skb_reserve(buf, rep_headroom);
	return buf;
}

int tipc_cfg_append_tlv(struct sk_buff *buf, int tlv_type,
			void *tlv_data, int tlv_data_size)
{
	struct tlv_desc *tlv = (struct tlv_desc *)skb_tail_pointer(buf);
	int new_tlv_space = TLV_SPACE(tlv_data_size);

	if (skb_tailroom(buf) < new_tlv_space) {
		err("Can't append TLV to configuration message\n");
		return 0;
	}
	skb_put(buf, new_tlv_space);
	tlv->tlv_type = htons(tlv_type);
	tlv->tlv_len  = htons(TLV_LENGTH(tlv_data_size));
	if (tlv_data_size && tlv_data)
		memcpy(TLV_DATA(tlv), tlv_data, tlv_data_size);
	return 1;
}

struct sk_buff *tipc_cfg_reply_unsigned_type(u16 tlv_type, u32 value)
{
	struct sk_buff *buf;
	__be32 value_net;

	buf = tipc_cfg_reply_alloc(TLV_SPACE(sizeof(value)));
	if (buf) {
		value_net = htonl(value);
		tipc_cfg_append_tlv(buf, tlv_type, &value_net,
				    sizeof(value_net));
	}
	return buf;
}

struct sk_buff *tipc_cfg_reply_string_type(u16 tlv_type, char *string)
{
	struct sk_buff *buf;
	int string_len = strlen(string) + 1;

	buf = tipc_cfg_reply_alloc(TLV_SPACE(string_len));
	if (buf)
		tipc_cfg_append_tlv(buf, tlv_type, string, string_len);
	return buf;
}


#if 0

/* Now obsolete code for handling commands not yet implemented the new way */

/*
 * Some of this code assumed that the manager structure contains two added
 * fields:
 *	u32 link_subscriptions;
 *	struct list_head link_subscribers;
 * which are currently not present.  These fields may need to be re-introduced
 * if and when support for link subscriptions is added.
 */

struct subscr_data {
	char usr_handle[8];
	u32 domain;
	u32 port_ref;
	struct list_head subd_list;
};


void tipc_cfg_link_event(u32 addr, char *name, int up)
{
	/* TIPC DOESN'T HANDLE LINK EVENT SUBSCRIPTIONS AT THE MOMENT */
}

int tipc_cfg_cmd(const struct tipc_cmd_msg * msg,
		 char *data,
		 u32 sz,
		 u32 *ret_size,
		 struct tipc_portid *orig)
{
	int rv = -EINVAL;
	u32 cmd = msg->cmd;

	*ret_size = 0;
	switch (cmd) {
	case TIPC_REMOVE_LINK:
	case TIPC_CMD_BLOCK_LINK:
	case TIPC_CMD_UNBLOCK_LINK:
		if (!cfg_check_connection(orig))
			rv = link_control(msg->argv.link_name, msg->cmd, 0);
		break;
	case TIPC_ESTABLISH:
		{
			int connected;

			tipc_isconnected(mng.conn_port_ref, &connected);
			if (connected || !orig) {
				rv = TIPC_FAILURE;
				break;
			}
			rv = tipc_connect2port(mng.conn_port_ref, orig);
			if (rv == TIPC_OK)
				orig = 0;
			break;
		}
	case TIPC_GET_PEER_ADDRESS:
		*ret_size = link_peer_addr(msg->argv.link_name, data, sz);
		break;
	default: {}
	}
	if (*ret_size)
		rv = TIPC_OK;
	return rv;
}

static void cfg_cmd_event(struct tipc_cmd_msg *msg,
			  char *data,
			  u32 sz,
			  struct tipc_portid const *orig)
{
	int rv = -EINVAL;
	struct tipc_cmd_result_msg rmsg;
	struct iovec msg_sect[2];
	int *arg;

	msg->cmd = ntohl(msg->cmd);

	cfg_prepare_res_msg(msg->cmd, msg->usr_handle, rv, &rmsg, msg_sect,
			    data, 0);
	if (ntohl(msg->magic) != TIPC_MAGIC)
		goto exit;

	switch (msg->cmd) {
	case TIPC_CREATE_LINK:
		if (!cfg_check_connection(orig))
			rv = disc_create_link(&msg->argv.create_link);
		break;
	case TIPC_LINK_SUBSCRIBE:
		{
			struct subscr_data *sub;

			if (mng.link_subscriptions > 64)
				break;
			sub = (struct subscr_data *)kmalloc(sizeof(*sub),
							    GFP_ATOMIC);
			if (sub == NULL) {
				warn("Memory squeeze; dropped remote link subscription\n");
				break;
			}
			INIT_LIST_HEAD(&sub->subd_list);
			tipc_createport(mng.user_ref,
					(void *)sub,
					TIPC_HIGH_IMPORTANCE,
					0,
					0,
					(tipc_conn_shutdown_event)cfg_linksubscr_cancel,
					0,
					0,
					(tipc_conn_msg_event)cfg_linksubscr_cancel,
					0,
					&sub->port_ref);
			if (!sub->port_ref) {
				kfree(sub);
				break;
			}
			memcpy(sub->usr_handle,msg->usr_handle,
			       sizeof(sub->usr_handle));
			sub->domain = msg->argv.domain;
			list_add_tail(&sub->subd_list, &mng.link_subscribers);
			tipc_connect2port(sub->port_ref, orig);
			rmsg.retval = TIPC_OK;
			tipc_send(sub->port_ref, 2u, msg_sect);
			mng.link_subscriptions++;
			return;
		}
	default:
		rv = tipc_cfg_cmd(msg, data, sz, (u32 *)&msg_sect[1].iov_len, orig);
	}
exit:
	rmsg.result_len = htonl(msg_sect[1].iov_len);
	rmsg.retval = htonl(rv);
	tipc_cfg_respond(msg_sect, 2u, orig);
}

#endif

#define MAX_STATS_INFO 2000

/* 将tipc_config -s的打印单独列为一个函数，方便打tipc.ko示例补丁，并与之前版本保持一致 */
void tipc_show_stats_printf(struct print_buf *pb)
{
    tipc_printf(pb, "TIPC version " TIPC_MOD_VER "\n");
    printk("TIPC version " TIPC_MOD_VER "\n");
    return;
}

static struct sk_buff *tipc_show_stats(void)
{
	struct sk_buff *buf;
	struct tlv_desc *rep_tlv;
	struct print_buf pb;
	int str_len;
	u32 value;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_UNSIGNED))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	value = ntohl(*(u32 *)TLV_DATA(req_tlv_area));
	if (value != 0)
		return tipc_cfg_reply_error_string("unsupported argument");

	buf = tipc_cfg_reply_alloc(TLV_SPACE(MAX_STATS_INFO));
	if (buf == NULL)
		return NULL;

	rep_tlv = (struct tlv_desc *)buf->data;
	tipc_printbuf_init(&pb, (char *)TLV_DATA(rep_tlv), MAX_STATS_INFO);

	tipc_show_stats_printf(&pb);

	/* Use additional tipc_printf()'s to return more info ... */

	str_len = tipc_printbuf_validate(&pb);
	skb_put(buf, TLV_SPACE(str_len));
	TLV_SET(rep_tlv, TIPC_TLV_ULTRA_STRING, NULL, str_len);

	return buf;
}

static struct sk_buff *cfg_enable_bearer(void)
{
	struct tipc_bearer_config *args;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_BEARER_CONFIG))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	args = (struct tipc_bearer_config *)TLV_DATA(req_tlv_area);
	if (tipc_enable_bearer(args->name,
			       ntohl(args->disc_domain),
			       ntohl(args->priority)))
		return tipc_cfg_reply_error_string("unable to enable bearer");

	return tipc_cfg_reply_none();
}

static struct sk_buff *cfg_disable_bearer(void)
{
	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_BEARER_NAME))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	if (tipc_disable_bearer((char *)TLV_DATA(req_tlv_area)))
		return tipc_cfg_reply_error_string("unable to disable bearer");

	return tipc_cfg_reply_none();
}

/*BEGIN***********************************************************************
 函 数 名  : cfg_shutdown_tipc
 功能描述  : 停止tipc core net
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 

*************************************************************************END*/
static struct sk_buff *cfg_shutdown_tipc(void)
{
	tipc_cfg_stop();
	tipc_subscr_stop();
	tipc_net_stop();
	tipc_own_addr = 0;

	tipc_eth_media_shutdown(0);
	return tipc_cfg_reply_ultra_string("TIPC: Shutdown!\n");
}

static struct sk_buff *cfg_set_own_addr(void)
{
	u32 addr;

	struct tlv_desc *tlv = (struct tlv_desc *)req_tlv_area;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_NET_ADDR))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	addr = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
	if (addr == tipc_own_addr)
		return tipc_cfg_reply_none();
	if (!tipc_addr_node_valid(addr))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (node address)");
	if (tipc_mode == TIPC_NET_MODE)
		return tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
						   " (cannot change node address once assigned)");

#ifdef CONFIG_TIPC_MCASTGID_MAX
	if (tipc_mc_start(TLV_DATA(tlv) + sizeof(u32), 
			ntohs(tlv->tlv_len) - TLV_LENGTH(sizeof(u32))))
		return tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
						   " (multicast link creation failed)");
#endif

	tipc_core_start_net(addr);

	return tipc_cfg_reply_none();
}

static struct sk_buff *cfg_get_checksum(void)
{
    struct sk_buff *buf;
    u32 check_len = tipc_check_len;
    u32 check_rate = tipc_check_rate;

    buf = tipc_cfg_reply_alloc(2*TLV_SPACE(sizeof(u32)));
    if (!buf)
    	return NULL;

    check_len = htonl(check_len);
    tipc_cfg_append_tlv(buf, TIPC_TLV_UNSIGNED,
        &check_len, sizeof(check_len));
    check_rate = htonl(check_rate);
    tipc_cfg_append_tlv(buf, TIPC_TLV_UNSIGNED,
        &check_rate, sizeof(check_rate));
    
	return buf;
}

static struct sk_buff *cfg_set_checksum(void)
{
	u32 check_len = 0;
    u32 check_rate = 0;
    const void *tlv = req_tlv_area;
    int len = req_tlv_space;

	if (!TLV_CHECK(tlv, len, TIPC_TLV_UNSIGNED))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	check_len = ntohl(*(__be32 *)TLV_DATA(tlv));

    tlv += TLV_SPACE(sizeof(__be32));
    len -= TLV_SPACE(sizeof(__be32));

	if (len > 0 && TLV_CHECK(tlv, len, TIPC_TLV_UNSIGNED))
    	check_rate = ntohl(*(__be32 *)TLV_DATA(tlv));

#define MAX_USHORT_VALUE ((u16)(~0U))

    if (check_len > MAX_USHORT_VALUE) {
        check_len = MAX_USHORT_VALUE;
    }
    if (check_len && check_len < MAX_H_SIZE) { /* 0表示disable. */
        check_len = MAX_H_SIZE;
    }
    if (check_rate > MAX_USHORT_VALUE) {
        check_rate = MAX_USHORT_VALUE;
    }

    tipc_check_len = (u16)check_len;
    tipc_check_rate = (u16)check_rate;

    if (tipc_mode == TIPC_NET_MODE) {
        tipc_bearers_send_disc();
    }

	return tipc_cfg_reply_none();
}


static struct sk_buff *cfg_mask_mc(void)
{
	u32 mask;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_UNSIGNED))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	mask = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));

	if (tipc_mode != TIPC_NET_MODE)
		return tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
						   " (not supported in standalone mode)");

	if (tipc_mc_mask(mask))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (set multicast mask failed)");

	return tipc_cfg_reply_none();
}

static struct sk_buff *cfg_enable_mc(void)
{
	u32 mcgid;
    u32 flag = 0;
    const void *tlv = req_tlv_area;
    int tlv_len = req_tlv_space;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_UNSIGNED))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	mcgid = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));

    tlv += TLV_SPACE(sizeof(u32));
    tlv_len -= TLV_SPACE(sizeof(u32));
    if (tlv_len > 0 && TLV_CHECK(tlv, tlv_len, TIPC_TLV_UNSIGNED)) {
        flag = ntohl(*(__be32 *)TLV_DATA(tlv));
    }
    flag |= mcgid & 0xFFFF0000; /* mcgid 高16位表示Flag */
    mcgid &= 0xFF;              /* mcgid 低8位表示硬件组播id */
    
	if (tipc_mode != TIPC_NET_MODE)
		return tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
						   " (not supported in standalone mode)");

	if (tipc_mc_enable(mcgid, flag))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (multicast link enable failed)");

	return tipc_cfg_reply_none();
}

static struct sk_buff *cfg_disable_mc(void)
{
	u32 mcgid;
    u32 flag = 0;
    const void *tlv = req_tlv_area;
    int tlv_len = req_tlv_space;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_UNSIGNED))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	mcgid = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));

    tlv += TLV_SPACE(sizeof(u32));
    tlv_len -= TLV_SPACE(sizeof(u32));
    if (tlv_len > 0 && TLV_CHECK(tlv, tlv_len, TIPC_TLV_UNSIGNED)) {
        flag = ntohl(*(__be32 *)TLV_DATA(tlv));
    }
    flag |= mcgid & 0xFFFF0000; /* mcgid 高16位表示Flag */
    mcgid &= 0xFF;              /* mcgid 低8位表示硬件组播id */

	if (tipc_mode != TIPC_NET_MODE)
		return tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
						   " (not supported in standalone mode)");

	if (tipc_mc_disable(mcgid, flag))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (multicast link disable failed)");

	return tipc_cfg_reply_none();
}

static struct sk_buff *cfg_set_remote_mng(void)
{
	u32 value;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_UNSIGNED))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	value = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
	tipc_remote_management = (value != 0);
	return tipc_cfg_reply_none();
}

static struct sk_buff *cfg_set_max_publications(void)
{
	u32 value;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_UNSIGNED))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	value = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
	if (value != delimit(value, 1, 65535))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (max publications must be 1-65535)");
	tipc_max_publications = value;
	return tipc_cfg_reply_none();
}

static struct sk_buff *cfg_set_max_subscriptions(void)
{
	u32 value;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_UNSIGNED))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	value = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
	if (value != delimit(value, 1, 65535))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (max subscriptions must be 1-65535");
	tipc_max_subscriptions = value;
	return tipc_cfg_reply_none();
}

static struct sk_buff *cfg_set_max_ports(void)
{
	u32 value;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_UNSIGNED))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);
	value = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
	if (value == tipc_max_ports)
		return tipc_cfg_reply_none();
	if (value != delimit(value, 127, 65535))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (max ports must be 127-65535)");
	if (tipc_mode != TIPC_NOT_RUNNING)
		return tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
			" (cannot change max ports while TIPC is active)");
	tipc_max_ports = value;
	return tipc_cfg_reply_none();
}

static struct sk_buff *cfg_set_max_zones(void)
{
	u32 value;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_UNSIGNED))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);
	value = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
	if (value == tipc_max_zones)
		return tipc_cfg_reply_none();
	if (value != delimit(value, 1, 255))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (max zones must be 1-255)");
	if (tipc_mode == TIPC_NET_MODE)
		return tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
			" (cannot change max zones once TIPC has joined a network)");
	tipc_max_zones = value;
	return tipc_cfg_reply_none();
}

static struct sk_buff *cfg_set_max_clusters(void)
{
	u32 value;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_UNSIGNED))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);
	value = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
	if (value == tipc_max_clusters)
		return tipc_cfg_reply_none();
	if (value != delimit(value, 1, 4095))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (max clusters must be 1-4095)");
	if (tipc_mode == TIPC_NET_MODE)
		return tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
			" (cannot change max clusters once TIPC has joined a network)");
	tipc_max_clusters = value;
	return tipc_cfg_reply_none();
}

static struct sk_buff *cfg_set_max_nodes(void)
{
	u32 value;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_UNSIGNED))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);
	value = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
	if (value == tipc_max_nodes)
		return tipc_cfg_reply_none();
	if (value != delimit(value, 8, 4095))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (max nodes must be 8-4095)");
	if (tipc_mode == TIPC_NET_MODE)
		return tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
			" (cannot change max nodes once TIPC has joined a network)");
	tipc_max_nodes = value;
	return tipc_cfg_reply_none();
}

static struct sk_buff *cfg_set_max_remotes(void)
{
	u32 value;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_UNSIGNED))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);
	value = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
	if (value == tipc_max_remotes)
		return tipc_cfg_reply_none();
	if (value != delimit(value, 0, 255))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (max remotes must be 0-255)");
	if (tipc_mode == TIPC_NET_MODE)
		return tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
			" (cannot change max remotes once TIPC has joined a network)");
	tipc_max_remotes = value;
	return tipc_cfg_reply_none();
}

static struct sk_buff *cfg_set_netid(void)
{
	u32 value;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_UNSIGNED))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);
	value = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
	if (value == tipc_net_id)
		return tipc_cfg_reply_none();
	if (value != delimit(value, 1, 9999))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (network id must be 1-9999)");
	if (tipc_mode == TIPC_NET_MODE)
		return tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
			" (cannot change network id once TIPC has joined a network)");
	tipc_net_id = value;
	return tipc_cfg_reply_none();
}

static struct sk_buff *cfg_ping(void)
{
	return NULL; /* NULL will reply with the incoming buf */
}

struct sk_buff *tipc_cfg_do_cmd(u32 orig_node, u16 cmd, const void *request_area,
				int request_space, int reply_headroom)
{
	struct sk_buff *rep_tlv_buf;

	spin_lock_bh(&config_lock);

	/* Save request and reply details in a well-known location */

	req_tlv_area = request_area;
	req_tlv_space = request_space;
	rep_headroom = reply_headroom;

	/* Check command authorization */

	if (likely(orig_node == tipc_own_addr)) {
		/* command is permitted */
	} else if (cmd >= 0x8000) {
		rep_tlv_buf = tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
							  " (cannot be done remotely)");
		goto exit;
	} else if (!tipc_remote_management) {
		rep_tlv_buf = tipc_cfg_reply_error_string(TIPC_CFG_NO_REMOTE);
		goto exit;
	}
	else if (cmd >= 0x4000) {
		u32 domain = 0;

		if ((tipc_nametbl_translate(TIPC_ZM_SRV, 0, &domain) == 0) ||
		    (domain != orig_node)) {
			rep_tlv_buf = tipc_cfg_reply_error_string(TIPC_CFG_NOT_ZONE_MSTR);
			goto exit;
		}
	}

	/* Call appropriate processing routine */

	switch (cmd) {
	case TIPC_CMD_NOOP:
		rep_tlv_buf = tipc_cfg_reply_none();
		break;
	case TIPC_CMD_GET_NODES:
		rep_tlv_buf = tipc_node_get_nodes(req_tlv_area, req_tlv_space);
		break;
	case TIPC_CMD_GET_ROUTES:
		rep_tlv_buf = tipc_nametbl_get_routes(req_tlv_area, req_tlv_space);
		break;
	case TIPC_CMD_GET_LINKS:
		rep_tlv_buf = tipc_node_get_links(req_tlv_area, req_tlv_space);
		break;
	case TIPC_CMD_SHOW_LINK_STATS:
		rep_tlv_buf = tipc_link_cmd_show_stats(req_tlv_area, req_tlv_space);
		break;
#if 1
    case TIPC_CMD_GET_LINK_STATES_BY_NODE: 
        rep_tlv_buf = tipc_get_links_states(req_tlv_area, req_tlv_space);
        break;
    case TIPC_CMD_SUBSCRIB_LINK_STATE: 
        rep_tlv_buf = tipc_node_link_state_issuance(req_tlv_area, req_tlv_space);
        break;
#endif
	case TIPC_CMD_RESET_LINK_STATS:
		rep_tlv_buf = tipc_link_cmd_reset_stats(req_tlv_area, req_tlv_space);
		break;
	case TIPC_CMD_SHOW_NAME_TABLE:
		rep_tlv_buf = tipc_nametbl_get(req_tlv_area, req_tlv_space);
		break;
	case TIPC_CMD_GET_BEARER_NAMES:
		rep_tlv_buf = tipc_bearer_get_names();
		break;
#if 1
    case TIPC_CMD_UPDATE_DISC_FORCE:
        rep_tlv_buf = tipc_bearers_update_disc();
        break;
#endif
	case TIPC_CMD_GET_MEDIA_NAMES:
		rep_tlv_buf = tipc_media_get_names();
		break;
	case TIPC_CMD_SHOW_PORTS:
		rep_tlv_buf = tipc_port_get_ports();
		break;
#if 1
	case TIPC_CMD_SHOW_PORT_STATS:
		rep_tlv_buf = port_show_stats(req_tlv_area, req_tlv_space);
		break;
	case TIPC_CMD_RESET_PORT_STATS:
#if 0	
		rep_tlv_buf = tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED);
#else
		rep_tlv_buf = port_reset_stats(req_tlv_area, req_tlv_space);
#endif
		break;
#endif
	case TIPC_CMD_DOUBT_NODE:
		rep_tlv_buf = tipc_link_cmd_doubt_node(req_tlv_area, req_tlv_space);
		break;
	case TIPC_CMD_SET_LOG_SIZE:
		rep_tlv_buf = tipc_log_resize_cmd(req_tlv_area, req_tlv_space);
		break;
	case TIPC_CMD_DUMP_LOG:
		rep_tlv_buf = tipc_log_dump();
		break;
	case TIPC_CMD_SHOW_STATS:
		rep_tlv_buf = tipc_show_stats();
		break;
	case TIPC_CMD_SET_LINK_TOL:
	case TIPC_CMD_SET_LINK_PRI:
	case TIPC_CMD_SET_LINK_WINDOW:
		rep_tlv_buf = tipc_link_cmd_config(req_tlv_area, req_tlv_space, cmd);
		break;
#ifdef PROTO_MULTI_DISCOVERY_OBJECT
	case TIPC_CMD_CREATE_LINK:
		rep_tlv_buf = tipc_disc_cmd_create_link(req_tlv_area, req_tlv_space);
		break;
	case TIPC_CMD_DELETE_LINK:
		rep_tlv_buf = tipc_link_cmd_delete(req_tlv_area, req_tlv_space);
		break;
#endif
	case TIPC_CMD_ENABLE_BEARER:
		rep_tlv_buf = cfg_enable_bearer();
		break;
	case TIPC_CMD_DISABLE_BEARER:
		rep_tlv_buf = cfg_disable_bearer();
		break;
	case TIPC_CMD_SET_NODE_ADDR:
		rep_tlv_buf = cfg_set_own_addr();
		break;
	case TIPC_CMD_SET_REMOTE_MNG:
		rep_tlv_buf = cfg_set_remote_mng();
		break;
	case TIPC_CMD_SET_MAX_PORTS:
		rep_tlv_buf = cfg_set_max_ports();
		break;
	case TIPC_CMD_SET_MAX_PUBL:
		rep_tlv_buf = cfg_set_max_publications();
		break;
	case TIPC_CMD_SET_MAX_SUBSCR:
		rep_tlv_buf = cfg_set_max_subscriptions();
		break;
	case TIPC_CMD_SET_MAX_ZONES:
		rep_tlv_buf = cfg_set_max_zones();
		break;
	case TIPC_CMD_SET_MAX_CLUSTERS:
		rep_tlv_buf = cfg_set_max_clusters();
		break;
	case TIPC_CMD_SET_MAX_NODES:
		rep_tlv_buf = cfg_set_max_nodes();
		break;
	case TIPC_CMD_SET_MAX_REMOTES:
		rep_tlv_buf = cfg_set_max_remotes();
		break;
	case TIPC_CMD_SET_NETID:
		rep_tlv_buf = cfg_set_netid();
		break;
	case TIPC_CMD_GET_REMOTE_MNG:
		rep_tlv_buf = tipc_cfg_reply_unsigned(tipc_remote_management);
		break;
	case TIPC_CMD_GET_MAX_PORTS:
		rep_tlv_buf = tipc_cfg_reply_unsigned(tipc_max_ports);
		break;
	case TIPC_CMD_GET_MAX_ZONES:
		rep_tlv_buf = tipc_cfg_reply_unsigned(tipc_max_zones);
		break;
	case TIPC_CMD_GET_MAX_CLUSTERS:
		rep_tlv_buf = tipc_cfg_reply_unsigned(tipc_max_clusters);
		break;
	case TIPC_CMD_GET_MAX_NODES:
		rep_tlv_buf = tipc_cfg_reply_unsigned(tipc_max_nodes);
		break;
	case TIPC_CMD_GET_MAX_REMOTES:
		rep_tlv_buf = tipc_cfg_reply_unsigned(tipc_max_remotes);
		break;
	case TIPC_CMD_GET_MAX_PUBL:
		rep_tlv_buf = tipc_cfg_reply_unsigned(tipc_max_publications);
		break;
	case TIPC_CMD_GET_MAX_SUBSCR:
		rep_tlv_buf = tipc_cfg_reply_unsigned(tipc_max_subscriptions);
		break;
	case TIPC_CMD_GET_NETID:
		rep_tlv_buf = tipc_cfg_reply_unsigned(tipc_net_id);
		break;
	case TIPC_CMD_SHUTDOWN_TIPC:
		rep_tlv_buf = cfg_shutdown_tipc();
		break;
	case TIPC_CMD_GET_CHECKSUM:
		rep_tlv_buf = cfg_get_checksum();
		break;
	case TIPC_CMD_SET_CHECKSUM:
		rep_tlv_buf = cfg_set_checksum();
		break;
	case TIPC_CMD_MASK_MCLINK:
		rep_tlv_buf = cfg_mask_mc();
		break;
	case TIPC_CMD_ENABLE_MCLINK:
		rep_tlv_buf = cfg_enable_mc();
		break;
	case TIPC_CMD_DISABLE_MCLINK:
		rep_tlv_buf = cfg_disable_mc();
		break;
	case TIPC_CMD_PING:
		rep_tlv_buf = cfg_ping();
		break;
	case TIPC_CMD_NOT_NET_ADMIN:
		rep_tlv_buf = tipc_cfg_reply_error_string(TIPC_CFG_NOT_NET_ADMIN);
		break;
    case TIPC_CMD_SET_RCVMSG_STATS:
    case TIPC_CMD_SET_SNDMSG_STATS:
        rep_tlv_buf = tipc_set_portmsg_stats(req_tlv_area, req_tlv_space, cmd);
        break;
    case TIPC_CMD_GET_RCVMSG_STATS:
    case TIPC_CMD_GET_SNDMSG_STATS:
        rep_tlv_buf = tipc_get_portmsg_stats(req_tlv_area, req_tlv_space, cmd);
        break;
    case TIPC_CMD_DEBUG_LOG_SWITCH:
        rep_tlv_buf = tipc_debug_log_switch(req_tlv_area, req_tlv_space);
        break;
	case TIPC_CMD_SHOW_BEARER_STATS:
        rep_tlv_buf = tipc_bearer_get_stats();
        break;
	default:
		rep_tlv_buf = tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
							  " (unknown command)");
		break;
	}

	/* Return reply buffer */
exit:
	spin_unlock_bh(&config_lock);
	return rep_tlv_buf;
}

static void cfg_named_msg_event(void *userdata,
				u32 port_ref,
				struct sk_buff **buf,
				const unchar *msg,
				u32 size,
				u32 importance,
				struct tipc_portid const *orig,
				struct tipc_name_seq const *dest)
{
	struct tipc_cfg_msg_hdr *req_hdr;
	struct tipc_cfg_msg_hdr *rep_hdr;
	struct sk_buff *rep_buf;

	/* Validate configuration message header (ignore invalid message) */

	req_hdr = (struct tipc_cfg_msg_hdr *)msg;
	if ((size < sizeof(*req_hdr)) ||
	    (size != TCM_ALIGN(ntohl(req_hdr->tcm_len))) ||
	    (ntohs(req_hdr->tcm_flags) != TCM_F_REQUEST)) {
		warn("Invalid configuration message discarded\n");
		return;
	}

	/* Generate reply for request (if can't, return request) */

	rep_buf = tipc_cfg_do_cmd(orig->node,
				  ntohs(req_hdr->tcm_type),
				  msg + sizeof(*req_hdr),
				  size - sizeof(*req_hdr),
				  BUF_HEADROOM + MAX_H_SIZE + sizeof(*rep_hdr));
	if (rep_buf) {
		skb_push(rep_buf, sizeof(*rep_hdr));
		rep_hdr = (struct tipc_cfg_msg_hdr *)rep_buf->data;
		memcpy(rep_hdr, req_hdr, sizeof(*rep_hdr));
		rep_hdr->tcm_len = htonl(rep_buf->len);
		rep_hdr->tcm_flags &= htons(~TCM_F_REQUEST);
	} else {
		rep_buf = *buf;
		*buf = NULL;
	}

	/* NEED TO ADD CODE TO HANDLE FAILED SEND (SUCH AS CONGESTION) */
	tipc_send_buf2port(port_ref, orig, rep_buf, rep_buf->len);
}

int tipc_cfg_init(void)
{
	struct tipc_name_seq seq;
	int res;

	res = tipc_attach(&mng.user_ref, NULL, NULL);
	if (res)
		goto failed;

	res = tipc_createport(mng.user_ref, NULL, TIPC_CRITICAL_IMPORTANCE,
			      NULL, NULL, NULL, NULL, cfg_named_msg_event, 
			      NULL, NULL, &mng.port_ref);
	if (res)
		goto failed;

	seq.type = TIPC_CFG_SRV;
	seq.lower = seq.upper = tipc_own_addr;
	res = tipc_publish_rsv(mng.port_ref, TIPC_CLUSTER_SCOPE, &seq);
	if (res)
		goto failed;

	return 0;

failed:
	err("Unable to create configuration service\n");
	tipc_detach(mng.user_ref);
	mng.user_ref = 0;
	return res;
}

void tipc_cfg_stop(void)
{
	if (mng.user_ref) {
		tipc_detach(mng.user_ref);
		mng.user_ref = 0;
	}
}

#else

static struct publication *mng_publ = NULL;

int tipc_cfg_init(void)
{
	mng_publ = tipc_nametbl_publish_rsv(TIPC_CFG_SRV, tipc_own_addr,
					    tipc_own_addr, TIPC_CLUSTER_SCOPE,
					    0, tipc_random);
	if (mng_publ == NULL)
		err("Unable to create configuration service identifier\n");
	return !mng_publ;
}

void tipc_cfg_stop(void)
{
	if (mng_publ) {
		tipc_nametbl_withdraw(TIPC_CFG_SRV, tipc_own_addr, 0, tipc_random);
		mng_publ = NULL;
	}
}

#endif
