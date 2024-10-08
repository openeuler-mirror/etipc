/*
 * net/tipc/tipc_bearer.h: Include file for TIPC bearer code
 * 
 * Copyright (c) 1996-2006, Ericsson AB
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

#ifndef _TIPC_BEARER_H
#define _TIPC_BEARER_H

#include "tipc_core.h"
#include "tipc_bcast.h"


/**
 * struct bearer - TIPC bearer information
 * @publ: bearer information available to privileged users
 * @media: ptr to media structure associated with bearer
 * @priority: default link priority for bearer
 * @window: default window size for bearer
 * @tolerance: default link tolerance for bearer
 * @identity: array index of this bearer within TIPC bearer array
 * @disc_list: list of neighbor discovery objects
 * @links: list of non-congested links associated with bearer
 * @cong_links: list of congested links associated with bearer
 * @continue_count: # of times bearer has resumed after congestion or blocking
 * @in_use: if zero, bearer entry is unassigned (fully disabled)
 * @active: if non-zero, bearer entry is bound to an interface (fully enabled)
 * @net_plane: network plane ('A' through 'H') currently associated with bearer
 * @nodes: indicates which nodes in cluster can be reached through bearer
 */
 
struct bearer {
	struct tipc_bearer publ;
	struct tipc_media *media;
	u32 priority;
	u32 window;
	u32 tolerance;
	u32 identity;
	struct list_head disc_list;
	struct list_head links;
	struct list_head cong_links;
	u32 continue_count;
	int in_use;
	int active;
	char net_plane;
	struct tipc_node_map nodes;
};

struct bearer_name {
	char media_name[TIPC_MAX_MEDIA_NAME];
	char if_name[TIPC_MAX_IF_NAME];
};

struct link;

extern struct bearer *tipc_bearers;

int tipc_media_set_priority(const char *name, u32 new_value);
int tipc_media_set_window(const char *name, u32 new_value);
void tipc_media_addr_printf(struct print_buf *pb, struct tipc_media_addr *a);
struct sk_buff *tipc_media_get_names(void);

struct sk_buff *tipc_bearer_get_names(void);

struct sk_buff *tipc_bearers_update_disc(void);

void tipc_bearer_add_dest(struct bearer *b_ptr, u32 dest,
			  struct tipc_media_addr *maddr);
void tipc_bearer_remove_dest(struct bearer *b_ptr, u32 dest,
			     struct tipc_media_addr *maddr);
void tipc_bearer_remove_discoverer(struct bearer *b_ptr, u32 dest);
void tipc_bearer_schedule(struct bearer *b_ptr, struct link *l_ptr);
struct bearer *tipc_bearer_find(const char *name);
struct tipc_media *tipc_media_find_name(const char *name);
int tipc_bearer_resolve_congestion(struct bearer *b_ptr, struct link *l_ptr);
int tipc_bearer_congested(struct bearer *b_ptr, struct link *l_ptr);
int tipc_bearer_init(void);
void tipc_bearer_stop(void);
void tipc_bearer_lock_push(struct bearer *b_ptr);
void tipc_bearer_send_discover(struct bearer *b_ptr, u32 dest);

void tipc_bearers_send_disc(void);
void tipc_bearers_send_doubt(u32 doubt_node);
void tipc_bearer_mc_add(u32 mcgid, u32 addrtag, struct tipc_media_addr *media_addr);
int tipc_bearer_eq_addr(struct tipc_media_addr *addr1, struct tipc_media_addr *addr2);
int tipc_bearer_eq_skb_addr(struct sk_buff *buf, struct tipc_bearer *tb_ptr, struct tipc_media_addr *addr);
int tipc_media_rate(struct tipc_media *media);
struct sk_buff *tipc_bearer_get_stats(void);

/**
 * tipc_bearer_send- sends buffer to destination over bearer
 *
 * Returns true (1) if successful, or false (0) if unable to send
 *
 * IMPORTANT:
 * The media send routine must not alter the buffer being passed in
 * as it may be needed for later retransmission!
 *
 * If the media send routine returns a non-zero value (indicating that
 * it was unable to send the buffer), it must:
 *   1) mark the bearer as blocked,
 *   2) call tipc_continue() once the bearer is able to send again.
 * Media types that are unable to meet these two critera must ensure their
 * send routine always returns success -- even if the buffer was not sent --
 * and let TIPC's link code deal with the undelivered message.
 */

static inline int tipc_bearer_send(struct bearer *b_ptr, struct sk_buff *buf,
				   struct tipc_media_addr *dest)
{
    b_ptr->publ.send_count++;
	return !b_ptr->media->send_msg(buf, &b_ptr->publ, dest);
}

#endif
