/*
 * net/tipc/tipc_netlink.c: TIPC configuration handling
 *
 * Copyright (c) 2005-2006, Ericsson AB
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

#include "tipc_core.h"
#include "tipc_cfgsrv.h"
#include <net/genetlink.h>

#ifdef CONFIG_TIPC_CONFIG_SERVICE

static int handle_cmd(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *rep_buf;
	struct nlmsghdr *rep_nlh;
	struct nlmsghdr *req_nlh = info->nlhdr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	struct tipc_genlmsghdr *req_userhdr = genl_info_userhdr(info);
#else
	struct tipc_genlmsghdr *req_userhdr = info->userhdr;
#endif
	int hdr_space = NLMSG_SPACE(GENL_HDRLEN + TIPC_GENL_HDRLEN);
	u16 cmd;

	if ((req_userhdr->cmd & 0xC000) && (!capable(CAP_NET_ADMIN)))
		cmd = TIPC_CMD_NOT_NET_ADMIN;
	else
		cmd = req_userhdr->cmd;

	rep_buf = tipc_cfg_do_cmd(req_userhdr->dest, cmd,
			NLMSG_DATA(req_nlh) + GENL_HDRLEN + TIPC_GENL_HDRLEN,
			NLMSG_PAYLOAD(req_nlh, GENL_HDRLEN + TIPC_GENL_HDRLEN),
			hdr_space);

	if (rep_buf) {
		skb_push(rep_buf, hdr_space);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
		rep_nlh = nlmsg_hdr(rep_buf);
#else
		rep_nlh = (struct nlmsghdr *)rep_buf->data;
#endif
		memcpy(rep_nlh, req_nlh, hdr_space);
		rep_nlh->nlmsg_len = rep_buf->len;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        genlmsg_unicast(&init_net, rep_buf, NETLINK_CB(skb).portid);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
		genlmsg_unicast(&init_net, rep_buf, NETLINK_CB(skb).pid);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 22)
		genlmsg_unicast(rep_buf, NETLINK_CB(skb).pid);
#else
		genlmsg_unicast(rep_buf, req_nlh->nlmsg_pid);
#endif
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
static const struct genl_ops tipc_genl_v2_ops[] = {
	{
		.cmd	= TIPC_GENL_CMD,
		.doit	= handle_cmd,
	}
};
#else
static struct genl_ops tipc_genl_ops = {
	.cmd		= TIPC_GENL_CMD,
	.doit		= handle_cmd,
};
#endif

static int tipc_genl_family_registered;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
struct genl_family tipc_genl_family = {
	.name		= TIPC_GENL_NAME,
	.version	= TIPC_GENL_VERSION,
	.hdrsize	= TIPC_GENL_HDRLEN,
	.maxattr	= 0,
	.ops		= tipc_genl_v2_ops,
	.n_ops      = ARRAY_SIZE(tipc_genl_v2_ops),
};
#else
struct genl_family tipc_genl_family = {
	.id		= GENL_ID_GENERATE,
	.name		= TIPC_GENL_NAME,
	.version	= TIPC_GENL_VERSION,
	.hdrsize	= TIPC_GENL_HDRLEN,
	.maxattr	= 0,
};
#endif

int tipc_netlink_start(void)
{
	int res;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    res = genl_register_family(&tipc_genl_family);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
    res = genl_register_family_with_ops(&tipc_genl_family,
					    tipc_genl_v2_ops);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
	res = genl_register_family_with_ops(&tipc_genl_family,
					    &tipc_genl_ops, 1);
#else
	res = genl_register_family(&tipc_genl_family);
	if (!res)
		res = genl_register_ops(&tipc_genl_family, &tipc_genl_ops);
#endif

	if (res) {
		err("Failed to register netlink interface\n");
		return res;
	}

	tipc_genl_family_registered = 1;
	return 0;
}

void tipc_netlink_stop(void)
{
	if (!tipc_genl_family_registered)
		return;
	genl_unregister_family(&tipc_genl_family);
	tipc_genl_family_registered = 0;
}

#else

/*
 * Dummy routines used when configuration service is not included
 */

int tipc_netlink_start(void)
{
	return 0;

}

void tipc_netlink_stop(void)
{
	/* do nothing */
}

#endif
