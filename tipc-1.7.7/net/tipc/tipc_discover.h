/*
 * net/tipc/tipc_discover.h: Include file for TIPC neighbor discovery code
 *
 * Copyright (c) 2003-2006, Ericsson AB
 * Copyright (c) 2005-2007, 2010, Wind River Systems
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

#ifndef _TIPC_DISCOVER_H
#define _TIPC_DISCOVER_H

#include "tipc_core.h"

/**
 * struct discoverer - information about an ongoing link setup request
 * @bearer: bearer used for discovery messages
 * @disc_list: adjacent discoverers belonging to the same bearer
 * @dest: destination address for discovery messages
 * @domain: network domain of node(s) which should respond to discovery message
 * @num_nodes: number of nodes currently discovered
 * @buf: discovery message to be (repeatedly) sent
 * @timer: timer governing period between discovery messages
 * @timer_intv: current interval between requests (in ms)
 */
 
struct discoverer {
	struct bearer *bearer;
	struct list_head disc_list;
	struct tipc_media_addr dest;
        u32 domain;
	int num_nodes;
	struct sk_buff *buf;
	struct timer_list timer;
	unsigned int timer_intv;
	unsigned int chk_dup;
};

int tipc_disc_create(struct bearer *b_ptr, struct tipc_media_addr *dest,
		     u32 domain);
void tipc_disc_update(struct discoverer *d_ptr);
void tipc_disc_delete(struct discoverer *d_ptr);
void tipc_disc_deactivate(struct discoverer *d_ptr);
void tipc_disc_recv_msg(struct sk_buff *buf, struct bearer *b_ptr);
void tipc_disc_send_msg(struct discoverer *d_ptr);
struct sk_buff *tipc_disc_cmd_create_link(const void *disc_tlv_area, 
					  int disc_tlv_space);
void tipc_disc_send_doubt_msg(struct discoverer *d_ptr, u32 doubt); /* */

#endif
