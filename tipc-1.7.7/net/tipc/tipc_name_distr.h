/*
 * net/tipc/tipc_name_distr.h: Include file for TIPC name distribution code
 * 
 * Copyright (c) 2000-2006, Ericsson AB
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

#ifndef _TIPC_NAME_DISTR_H
#define _TIPC_NAME_DISTR_H

#include "tipc_name_table.h"

/* Publication/route distribution masks */

#define TIPC_DIST_TO_CLUSTER	0x01
#define TIPC_DIST_TO_ZONE	0x02
#define TIPC_DIST_TO_NETWORK	0x04

void tipc_named_insert_publ(struct publication *publ);
void tipc_named_remove_publ(struct publication *publ);
void tipc_named_distribute(struct publication *publ, int msg_type,
			   int dist_mask);
void tipc_named_node_up(unsigned long node);
void tipc_named_node_up_uni(unsigned long node);
void tipc_named_request(unsigned long node); /* */
void tipc_named_recv(struct sk_buff *buf);
void tipc_named_reinit(void);

void tipc_route_insert_publ(struct publication *publ);
void tipc_route_remove_publ(struct publication *publ);
void tipc_route_distribute(struct publication *publ, int msg_type,
			   int dist_mask);
void tipc_route_node_up(unsigned long node);
void tipc_route_recv(struct sk_buff *buf);

#endif
