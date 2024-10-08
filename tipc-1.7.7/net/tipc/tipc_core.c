/*
 * net/tipc/tipc_core.c: TIPC module code
 *
 * Copyright (c) 2003-2006, Ericsson AB
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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/reboot.h> /* for reboot notify */

#include "tipc_core.h"
#include "tipc_dbg.h"
#include "tipc_ref.h"
#include "tipc_net.h"
#include "tipc_user_reg.h"
#include "tipc_name_table.h"
#include "tipc_topsrv.h"
#include "tipc_cfgsrv.h"
#include "tipc_raw_socket.h"

/* configurable TIPC parameters */

#ifndef CONFIG_TIPC_ADVANCED
#define CONFIG_TIPC_NETID	4711
#define CONFIG_TIPC_REMOTE_MNG	1
#define CONFIG_TIPC_PORTS	8191
#define CONFIG_TIPC_NODES	255
#define CONFIG_TIPC_CLUSTERS	8
#define CONFIG_TIPC_ZONES	4
#define CONFIG_TIPC_REMOTES	8
#define CONFIG_TIPC_PUBL	10000
#define CONFIG_TIPC_SUBSCR	2000
#define CONFIG_TIPC_LOG		0
#else
#ifndef CONFIG_TIPC_REMOTE_MNG
#define CONFIG_TIPC_REMOTE_MNG	0
#endif
#endif

u32 tipc_own_addr;
int tipc_net_id;
int tipc_remote_management;
int tipc_max_nodes;
int tipc_max_clusters;
int tipc_max_zones;
int tipc_max_remotes;
int tipc_max_ports;
int tipc_max_publications;
int tipc_max_subscriptions;
u16 tipc_check_len = 10000; /* effective length MTU   */
u16 tipc_check_rate = 1;  /* check 1 time per <rate> packets */

/* global variables used by multiple sub-systems within TIPC */

int tipc_mode = TIPC_NOT_RUNNING;
int tipc_random;
atomic_t tipc_user_count = ATOMIC_INIT(0);

static struct notifier_block reboot_notifier;


const char tipc_alphabet[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.";

int g_tipc_reg_ptype_flag = TIPC_REG_DEV_PTYPE;
int tipc_get_reg_ptype_flag(void)
{
    return g_tipc_reg_ptype_flag;
}

#ifdef TIPC_SUPPORT_LS
int g_mcid_map_start = 0;
int g_mcid_map_tag = 0;

int tipc_get_mc_tag(int mcid)
{
    if (g_mcid_map_start > 0 && mcid >= g_mcid_map_start) {
        return g_mcid_map_tag + mcid - g_mcid_map_start;
    } else {
        return mcid;
    }
}

#endif

int tipc_get_mode(void)
{
	return tipc_mode;
}

/**
 * buf_acquire - creates a TIPC message buffer
 * @size: message size (including TIPC header)
 *
 * Returns a new buffer with data pointers set to the specified size.
 * 
 * NOTE: Headroom is reserved to allow prepending of a data link header.
 *       There may also be unrequested tailroom present at the buffer's end.
 */

struct sk_buff *buf_acquire(u32 size)
{
	struct sk_buff *skb;
	unsigned int buf_size = (BUF_HEADROOM + size + CK_SIZE + 3) & ~3u;

	skb = alloc_skb_fclone(buf_size, GFP_ATOMIC);
	if (skb) {
		skb_reserve(skb, BUF_HEADROOM);
		skb_put(skb, size);
		skb->next = NULL;
	}
	dbg_assert(skb != NULL);
	return skb;
}

/**
 * tipc_core_stop_net - shut down TIPC networking sub-systems
 */

void tipc_core_stop_net(void)
{
	tipc_net_stop();
	tipc_eth_media_stop();
}

/**
 * tipc_core_start_net - start TIPC networking sub-systems
 */

int tipc_core_start_net(unsigned long addr)
{
	int res;

	if ((res = tipc_net_start(addr)) ||
	    (res = tipc_eth_media_start())) {
		tipc_core_stop_net();
	}
	return res;
}

/**
 * tipc_core_stop - switch TIPC from SINGLE NODE to NOT RUNNING mode
 */

void tipc_core_stop(void)
{
	if (tipc_mode != TIPC_NODE_MODE)
		return;

	tipc_mode = TIPC_NOT_RUNNING;

	tipc_socket_stop();
	tipc_netlink_stop();
	tipc_cfg_stop();
	tipc_subscr_stop();
	tipc_nametbl_stop();
	tipc_routetbl_stop();
	tipc_reg_stop();
	tipc_ref_table_stop();
	tipc_handler_stop();
}

/**
 * tipc_core_start - switch TIPC from NOT RUNNING to SINGLE NODE mode
 */

int tipc_core_start(void)
{
	int res;

	if (tipc_mode != TIPC_NOT_RUNNING)
		return -ENOPROTOOPT;

	get_random_bytes(&tipc_random, sizeof(tipc_random));
	tipc_mode = TIPC_NODE_MODE;

	if ((res = tipc_handler_start())
	    || (res = tipc_ref_table_init(tipc_max_ports, tipc_random))
	    || (res = tipc_reg_start())
	    || (res = tipc_routetbl_init())
	    || (res = tipc_nametbl_init())
            || (res = tipc_k_signal((Handler)tipc_subscr_start, 0))
	    || (res = tipc_k_signal((Handler)tipc_cfg_init, 0))
	    || (res = tipc_netlink_start())
	    || (res = tipc_socket_init())
	    ) {
		tipc_core_stop();
	}
	return res;
}

/**
 * reboot_notification - handle reboot from OS
 *
 */

static int reboot_notification(struct notifier_block *nb, unsigned long evt,
			     void *dv)
{
#ifdef CONFIG_TIPC_CONFIG_SERVICE
    TIPC_OUTPUT->echo = 0; /* 关闭复位时TIPC的打印 */
#endif

    tipc_handler_set(0);
    tipc_net_stop();

	return NOTIFY_DONE;
}

static int __init tipc_init(void)
{
	int res;

	tipc_log_resize(CONFIG_TIPC_LOG);
	dbg("Activated (version " TIPC_MOD_VER
	     " compiled " __DATE__ " " __TIME__ ")\n");

	tipc_own_addr = 0;
	tipc_net_id = delimit(CONFIG_TIPC_NETID, 1, 9999);
	tipc_remote_management = CONFIG_TIPC_REMOTE_MNG;
	tipc_max_ports = delimit(CONFIG_TIPC_PORTS, 127, 65536);
	tipc_max_nodes = delimit(CONFIG_TIPC_NODES, 8, 4095);
	tipc_max_clusters = delimit(CONFIG_TIPC_CLUSTERS, 1, 4095);
	tipc_max_zones = delimit(CONFIG_TIPC_ZONES, 1, 255);
	tipc_max_remotes = delimit(CONFIG_TIPC_REMOTES, 0, 255);
	tipc_max_publications = delimit(CONFIG_TIPC_PUBL, 1, 65535);
	tipc_max_subscriptions = delimit(CONFIG_TIPC_SUBSCR, 1, 65535);

	if ((res = tipc_core_start()))
		err("Unable to start in single node mode\n");
	else {
		info("Started in single node mode\n");

		reboot_notifier.notifier_call = reboot_notification;
		register_reboot_notifier(&reboot_notifier);
	}
	return res;
}

static void __exit tipc_exit(void)
{
	unregister_reboot_notifier(&reboot_notifier);
    
	tipc_handler_set(0);
	tipc_core_stop_net();
	tipc_core_stop();
	info("Deactivated\n");
	tipc_log_resize(0);
}

module_init(tipc_init);
module_exit(tipc_exit);
#ifdef TIPC_SUPPORT_LS
module_param_named(mcid_map, g_mcid_map_start, int, S_IRUGO);
module_param_named(mcid_tag, g_mcid_map_tag, int, S_IRUGO);
#endif
module_param_named(ptype_flag, g_tipc_reg_ptype_flag, int, S_IRUGO);


MODULE_DESCRIPTION("TIPC: Transparent Inter Process Communication");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(TIPC_MOD_VER);

/* Native TIPC API for kernel-space applications (see tipc.h) */

EXPORT_SYMBOL(tipc_attach);
EXPORT_SYMBOL(tipc_detach);
EXPORT_SYMBOL(tipc_get_addr);
EXPORT_SYMBOL(tipc_get_mode);
EXPORT_SYMBOL(tipc_createport);
EXPORT_SYMBOL(tipc_deleteport);
EXPORT_SYMBOL(tipc_ownidentity);
EXPORT_SYMBOL(tipc_portimportance);
EXPORT_SYMBOL(tipc_set_portimportance);
EXPORT_SYMBOL(tipc_portunreliable);
EXPORT_SYMBOL(tipc_set_portunreliable);
EXPORT_SYMBOL(tipc_portunreturnable);
EXPORT_SYMBOL(tipc_set_portunreturnable);
EXPORT_SYMBOL(tipc_publish);
EXPORT_SYMBOL(tipc_withdraw);
EXPORT_SYMBOL(tipc_connect2port);
EXPORT_SYMBOL(tipc_disconnect);
EXPORT_SYMBOL(tipc_shutdown);
EXPORT_SYMBOL(tipc_isconnected);
EXPORT_SYMBOL(tipc_peer);
EXPORT_SYMBOL(tipc_ref_valid);
EXPORT_SYMBOL(tipc_send);
EXPORT_SYMBOL(tipc_send_buf);
EXPORT_SYMBOL(tipc_send2name);
EXPORT_SYMBOL(tipc_forward2name);
EXPORT_SYMBOL(tipc_send_buf2name);
EXPORT_SYMBOL(tipc_forward_buf2name);
EXPORT_SYMBOL(tipc_send2port);
EXPORT_SYMBOL(tipc_forward2port);
EXPORT_SYMBOL(tipc_send_buf2port);
EXPORT_SYMBOL(tipc_forward_buf2port);
EXPORT_SYMBOL(tipc_multicast);
/* EXPORT_SYMBOL(tipc_multicast_buf); not available yet */
EXPORT_SYMBOL(tipc_ispublished);
EXPORT_SYMBOL(tipc_available_nodes);

/* TIPC API for external bearers (see tipc_bearer.h) */

EXPORT_SYMBOL(tipc_block_bearer);
EXPORT_SYMBOL(tipc_continue);
EXPORT_SYMBOL(tipc_disable_bearer);
EXPORT_SYMBOL(tipc_enable_bearer);
EXPORT_SYMBOL(tipc_recv_msg);
EXPORT_SYMBOL(tipc_register_media);

/* TIPC API for external APIs (see tipc_port.h) */

EXPORT_SYMBOL(tipc_createport_raw);
EXPORT_SYMBOL(tipc_reject_msg);
EXPORT_SYMBOL(tipc_send_buf_fast);
EXPORT_SYMBOL(tipc_acknowledge);
EXPORT_SYMBOL(tipc_get_port);
EXPORT_SYMBOL(tipc_get_handle);

