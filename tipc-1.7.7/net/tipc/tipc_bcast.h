/*
 * net/tipc/tipc_bcast.h: Include file for TIPC broadcast code
 *
 * Copyright (c) 2003-2006, Ericsson AB
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

#ifndef _TIPC_BCAST_H
#define _TIPC_BCAST_H

#define MAX_NODES 4096
#define WSIZE 32

/**
 * struct tipc_node_map - set of node identifiers
 * @count: # of nodes in set
 * @map: bitmap of node identifiers that are in the set
 */

struct tipc_node_map {
	u32 count;
	u32 start;
	u32 stop;
	u32 map[MAX_NODES / WSIZE];
};


#define PLSIZE 32

/**
 * struct port_list - set of node local destination ports
 * @count: # of ports in set (only valid for first entry in list)
 * @next: pointer to next entry in list
 * @ports: array of port references
 */

struct port_list {
	int count;
	struct port_list *next;
	u32 ports[PLSIZE];
};


struct tipc_node;
/* 本文件改动较大 */
struct mcglink;
struct mclink;
extern char tipc_bclink_name[];

void tipc_nmap_add(struct tipc_node_map *nm_ptr, u32 node);
void tipc_nmap_remove(struct tipc_node_map *nm_ptr, u32 node);
void tipc_nmap_diff(struct tipc_node_map *nm_a, struct tipc_node_map *nm_b,
		    struct tipc_node_map *nm_diff);

static inline int tipc_nmap_equal(struct tipc_node_map *nm_a,
				  struct tipc_node_map *nm_b)
{
	return !memcmp(nm_a, nm_b, sizeof(*nm_a));
}

void tipc_port_list_add(struct port_list *pl_ptr, u32 port);
void tipc_port_list_free(struct port_list *pl_ptr);

int  tipc_bclink_init(void);
void tipc_bclink_stop(void);

void tipc_bclink_add_node(struct tipc_node *n_ptr, struct mclink *mcl);
void tipc_bclink_remove_node(struct tipc_node *n_ptr, struct mclink *mcl);
void tipc_bclink_acknowledge(struct tipc_node *n_ptr, u32 acked, struct mclink *mcl);
int  tipc_bclink_send_msg(struct sk_buff *buf);
void tipc_bclink_recv_pkt(struct sk_buff *buf);

u32  tipc_bclink_get_last_sent(struct mcglink *mcgl);
u32  tipc_bclink_acks_missing(struct tipc_node *n_ptr);
void tipc_bclink_update_link_state(struct tipc_node *n_ptr, u32 last_sent, struct mclink *mcl);
int  tipc_bclink_stats(char *stats_buf, const u32 buf_size, const char *bclname);
int  tipc_bclink_reset_stats(const char *bclname);
int  tipc_bclink_set_queue_limits(u32 limit, const char *bclname);
int tipc_bclink_get_bclinks(struct sk_buff *buf);
void tipc_bcbearer_sort(void);
void tipc_bcbearer_push(void);

int tipc_mc_start(u8 mcgids[], int count);
void tipc_mc_stop(void);

int tipc_bclink_get_mcmap(u8 mcmap[], u32 bytes);
u32 tipc_bclink_mcg_count(void);
struct mcglink *tipc_bclink_find_mcglink(u32 mcgid);
int tipc_mc_mask(u32 mask);
int tipc_mc_enable(u32 mcgid, u32 flag);
int tipc_mc_disable(u32 mcgid, u32 flag);
u32  tipc_bclink_get_readable(struct mcglink *mcgl);

#endif
