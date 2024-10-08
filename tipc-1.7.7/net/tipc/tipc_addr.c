/*
 * net/tipc/tipc_addr.c: TIPC address utility routines
 *
 * Copyright (c) 2000-2006, Ericsson AB
 * Copyright (c) 2004-2007, Wind River Systems
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
#include "tipc_addr.h"
#include "tipc_net.h"

u32 tipc_get_addr(void)
{
	return tipc_own_addr;
}

/**
 * tipc_addr_domain_valid - validates a network domain address
 *
 * Accepts <Z.C.N>, <Z.C.0>, <Z.0.0>, and <0.0.0>, where Z, C, & N are non-zero.
 * 
 * Returns 1 if domain address is valid, otherwise 0
 */

int tipc_addr_domain_valid(u32 addr)
{
	u32 n = tipc_node(addr);
	u32 c = tipc_cluster(addr);
	u32 z = tipc_zone(addr);

	if (n && (!z || !c))
		return 0;
	if (c && !z)
		return 0;
	return 1;
}

/**
 * tipc_addr_node_valid - validates a proposed network address for this node
 *
 * Accepts <Z.C.N>, where Z, C, and N are non-zero.
 * 
 * Returns 1 if address can be used, otherwise 0
 */

int tipc_addr_node_valid(u32 addr)
{
	return (tipc_addr_domain_valid(addr) && tipc_node(addr));
}

/**
 * tipc_in_scope - determines if network address lies within specified domain
 */

int tipc_in_scope(u32 domain, u32 addr)
{
        if (likely(domain == addr))
                return 1;
	if (domain == 0)
		return 1;
	if (domain == addr_cluster(addr)) /* domain <Z.C.0> */
		return 1;
	if (domain == addr_zone(addr)) /* domain <Z.0.0> */
		return 1;
	return 0;
}

char *tipc_addr_string_fill(char *string, u32 addr)
{
	snprintf(string, 16, "<%u.%u.%u>",
		 tipc_zone(addr), tipc_cluster(addr), tipc_node(addr));
	return string;
}

