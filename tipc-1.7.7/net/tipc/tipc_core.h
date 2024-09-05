/*
 * net/tipc/tipc_core.h: Include file for TIPC global declarations
 *
 * Copyright (c) 2005-2006, Ericsson AB
 * Copyright (c) 2005-2008, 2010-2011, Wind River Systems
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

#ifndef _TIPC_CORE_H
#define _TIPC_CORE_H

#include <linux/tipc.h>
#include <linux/tipc_config.h>
#include <net/tipc/tipc_plugin_msg.h>
#include <net/tipc/tipc_plugin_port.h>
#include <net/tipc/tipc_plugin_if.h>
#include <net/tipc/tipc.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <asm/uaccess.h>
#include <linux/interrupt.h>
#include <asm/atomic.h>
#include <asm/hardirq.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/vmalloc.h>


#define TIPC_MOD_VER "1.7.7"

/*
 * Spinlock wrappers (lets TIPC common files run unchanged on other OS's)
 */
 
#define DECLARE_SPINLOCK(x) extern spinlock_t x
#define DECLARE_RWLOCK(x)   extern rwlock_t x

static inline void spin_lock_term(spinlock_t *lock) { }

/*
 * Sanity test macros
 */

#define assert(i)  BUG_ON(!(i))

#ifdef CONFIG_TIPC_DEBUG
#define dbg_assert(i) BUG_ON(!(i))
#else
#define dbg_assert(i) do {} while (0)
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#define tipc_hlist_for_each_entry(tpos, pos, head, member) (void)(pos);hlist_for_each_entry(tpos, head, member)
#define tipc_hlist_for_each_entry_safe(tpos, pos, n, head, member) (void)(pos);hlist_for_each_entry_safe(tpos, n, head, member)

#else
#define tipc_hlist_for_each_entry(tpos, pos, head, member) hlist_for_each_entry(tpos, pos, head, member)
#define tipc_hlist_for_each_entry_safe(tpos, pos, n, head, member) hlist_for_each_entry_safe(tpos, pos, n, head, member)
#endif


/*
 * TIPC system monitoring code
 */

/*
 * TIPC's print buffer subsystem supports the following print buffers:
 *
 * TIPC_NULL : null buffer (i.e. print nowhere)
 * TIPC_CONS : system console
 * TIPC_LOG  : TIPC log buffer
 * &buf	     : user-defined buffer (struct print_buf *)
 *
 * Note: TIPC_LOG is configured to echo its output to the system console;
 *       user-defined buffers can be configured to do the same thing.
 */

extern struct print_buf *const TIPC_NULL;
extern struct print_buf *const TIPC_CONS;
extern struct print_buf *const TIPC_LOG;
extern struct print_buf *TIPC_DEBUG;

void tipc_printf(struct print_buf *, const char *fmt, ...);

/*
 * TIPC_OUTPUT is the destination print buffer for system messages.
 */

#ifndef TIPC_OUTPUT
#define TIPC_OUTPUT TIPC_LOG
#endif

/*
 * TIPC can be configured to send system messages to TIPC_OUTPUT, the system
 * console only, or to suppress them entirely.
 */

#ifdef CONFIG_TIPC_SYSTEM_MSGS

#ifdef CONFIG_TIPC_CONFIG_SERVICE

#define err(fmt, arg...)  tipc_printf(TIPC_OUTPUT, KERN_WARNING "TIPC: " fmt, ## arg)
#define warn(fmt, arg...) tipc_printf(TIPC_OUTPUT, KERN_WARNING "TIPC: " fmt, ## arg)
#define info(fmt, arg...) tipc_printf(TIPC_OUTPUT, KERN_NOTICE "TIPC: " fmt, ## arg)
#else

#define err(fmt, arg...)  printk(KERN_ERR "TIPC: " fmt , ## arg)
#define info(fmt, arg...) printk(KERN_INFO "TIPC: " fmt , ## arg)
#define warn(fmt, arg...) printk(KERN_WARNING "TIPC: " fmt , ## arg)

#endif

#else

#define err(fmt, arg...)  do {} while (0)
#define info(fmt, arg...) do {} while (0)
#define warn(fmt, arg...) do {} while (0)

#endif

/*
 * DBG_OUTPUT is the destination print buffer for debug messages.
 * It defaults to the the null print buffer, but can be redefined
 * (typically in the individual .c files being debugged) to allow
 * selected debug messages to be generated where needed.
 */

#ifndef DBG_OUTPUT
#define DBG_OUTPUT TIPC_DEBUG
#endif

/*
 * TIPC can be configured to send debug messages to the specified print buffer
 * (typically DBG_OUTPUT) or to suppress them entirely.
 */

#ifdef CONFIG_TIPC_DEBUG

#define dbg_printf(pb, fmt, arg...) \
	do {if (pb != TIPC_NULL) tipc_printf(pb, fmt, ## arg);} while (0)
#define dbg_msg(pb, msg, txt) \
	do {if (pb != TIPC_NULL) tipc_msg_dbg(pb, msg, txt);} while (0)
#define dbg_dump(pb, fmt, arg...) \
	do {if (pb != TIPC_NULL) tipc_dump_dbg(pb, fmt, ##arg);} while (0)

#define dbg(fmt, arg...)	dbg_printf(DBG_OUTPUT, fmt, ##arg)
#define msg_dbg(msg, txt)	dbg_msg(DBG_OUTPUT, msg, txt)
#define dump_dbg(fmt, arg...)	dbg_dump(DBG_OUTPUT, fmt, ##arg)

void tipc_msg_dbg(struct print_buf *, struct tipc_msg *, const char *);
void tipc_dump_dbg(struct print_buf *, const char *fmt, ...);

#else

#define dbg_printf(pb, fmt, arg...)	do {} while (0)
#define dbg_msg(pb, msg, txt)		do {} while (0)
#define dbg_dump(pb, fmt, arg...)	do {} while (0)

#define dbg(fmt, arg...)	do {} while (0)
#define msg_dbg(msg, txt)	do {} while (0)
#define dump_dbg(fmt, arg...)	do {} while (0)

#define tipc_msg_dbg(...)	do {} while (0)
#define tipc_dump_dbg(...)	do {} while (0)

#endif


/*
 * TIPC-specific error codes
 */

#define ELINKCONG EAGAIN	/* link congestion <=> resource unavailable */

/*
 * Global configuration variables
 */

extern u32 tipc_own_addr;
extern int tipc_max_nodes;
extern int tipc_max_clusters;
extern int tipc_max_zones;
extern int tipc_max_remotes;
extern int tipc_max_ports;
extern int tipc_max_subscriptions;
extern int tipc_max_publications;
extern int tipc_net_id;
extern int tipc_remote_management;
extern u16 tipc_check_len;
extern u16 tipc_check_rate;

/*
 * Other global variables
 */

extern int tipc_mode;
extern int tipc_random;
extern const char tipc_alphabet[];
extern atomic_t tipc_user_count;


/*
 * Routines available to privileged subsystems
 */

extern int  tipc_core_start(void);
extern void tipc_core_stop(void);
extern int  tipc_core_start_net(unsigned long addr);
extern void tipc_core_stop_net(void);
extern int  tipc_handler_start(void);
extern void tipc_handler_stop(void);
extern int  tipc_netlink_start(void);
extern void tipc_netlink_stop(void);
extern int  tipc_socket_init(void);
extern void tipc_socket_stop(void);

static inline int delimit(int val, int min, int max)
{
	if (val > max)
		return max;
	if (val < min)
		return min;
	return val;
}


/*
 * TIPC timer and signal code
 */

typedef void (*Handler) (unsigned long);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
typedef void (*timer_handler) (struct timer_list *);
#endif
void tipc_handler_set(int enable);
u32 tipc_k_signal(Handler routine, unsigned long argument);

/**
 * k_init_timer - initialize a timer
 * @timer: pointer to timer structure
 * @routine: pointer to routine to invoke when timer expires
 * @argument: value to pass to routine when timer expires
 *
 * Timer must be initialized before use (and terminated when no longer needed).
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static inline void k_init_timer(struct timer_list *timer, timer_handler routine)
#else
static inline void k_init_timer(struct timer_list *timer, Handler routine,
				unsigned long argument)
#endif
{
	dbg("initializing timer %p\n", timer);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	timer_setup(timer, routine, 0);
#else
	setup_timer(timer, routine, argument);
#endif
}

/**
 * k_start_timer - start a timer
 * @timer: pointer to timer structure
 * @msec: time to delay (in ms)
 *
 * Schedules a previously initialized timer for later execution.
 * If timer is already running, the new timeout overrides the previous request.
 *
 * To ensure the timer doesn't expire before the specified delay elapses,
 * the amount of delay is rounded up when converting to the jiffies
 * then an additional jiffy is added to account for the fact that
 * the starting time may be in the middle of the current jiffy.
 */

static inline void k_start_timer(struct timer_list *timer, unsigned long msec)
{
    unsigned delta = msecs_to_jiffies(msec);
    delta = delta ? delta : 1;
	dbg("starting timer %p for %u\n", timer, msec);
	mod_timer(timer, jiffies + delta);
}

/**
 * k_cancel_timer - cancel a timer
 * @timer: pointer to timer structure
 *
 * Cancels a previously initialized timer.
 * Can be called safely even if the timer is already inactive.
 *
 * WARNING: Must not be called when holding locks required by the timer's
 *          timeout routine, otherwise deadlock can occur on SMP systems!
 */

static inline void k_cancel_timer(struct timer_list *timer)
{
	dbg("cancelling timer %p\n", timer);
	del_timer_sync(timer);
}

/**
 * k_term_timer - terminate a timer
 * @timer: pointer to timer structure
 *
 * Prevents further use of a previously initialized timer.
 *
 * WARNING: Caller must ensure timer isn't currently running.
 *
 * (Do not "enhance" this routine to automatically cancel an active timer,
 * otherwise deadlock can arise when a timeout routine calls k_term_timer.)
 */

static inline void k_term_timer(struct timer_list *timer)
{
	dbg("terminating timer %p\n", timer);
}


/*
 * TIPC message buffer code
 *
 * TIPC message buffer headroom reserves space for the worst-case
 * link-level device header (in case the message is sent off-node).
 *
 * Note: Headroom should be a multiple of 4 to ensure the TIPC header fields
 *       are word aligned for quicker access
 */

#define BUF_HEADROOM LL_MAX_HEADER

struct tipc_skb_cb {
	void *handle;
	void *priv;
};

#define TIPC_SKB_CB(__skb) ((struct tipc_skb_cb *)&((__skb)->cb[0]))

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
static inline unsigned char *skb_tail_pointer(const struct sk_buff *skb)
{
	return skb->tail;
}

static inline void skb_copy_to_linear_data(struct sk_buff *skb,
					   const void *from,
					   const unsigned int len)
{
	memcpy(skb->data, from, len);
}

static inline void skb_copy_to_linear_data_offset(struct sk_buff *skb,
						  const int offset,
						  const void *from,
						  const unsigned int len)
{
	memcpy(skb->data + offset, from, len);
}
#endif


static inline struct tipc_msg *buf_msg(struct sk_buff *skb)
{
	return (struct tipc_msg *)skb->data;
}

static inline void *buf_handle(struct sk_buff *skb)
{
	return TIPC_SKB_CB(skb)->handle;
}

static inline void buf_set_handle(struct sk_buff *skb, void *value)
{
	TIPC_SKB_CB(skb)->handle = value;
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

struct sk_buff *buf_acquire(u32 size);

/**
 * buf_discard - frees a TIPC message buffer
 * @skb: message buffer
 *
 * Frees a message buffer.  If passed NULL, just returns.
 */

static inline void buf_discard(struct sk_buff *skb)
{
    if (skb) {
        /* 怀疑cache不一致，暂规避。 */
        if (unlikely(skb_shinfo(skb)->nr_frags)) {
            err("skb %p nrfrags %u datap %p\n",
                skb, skb_shinfo(skb)->nr_frags, skb->data);

            
            skb_shinfo(skb)->nr_frags = 0;
        }

        /* 怀疑cache不一致，写一些数据可以避免收到错误数据。 */
        if (atomic_read(&(skb_shinfo(skb)->dataref)) == 1 && skb->len >= 0x20)
            memset(skb->data, 0, 0x20);
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17)
	kfree_skb(skb);
#else
	if (likely(skb != NULL))
		kfree_skb(skb);
#endif
}

/**
 * buf_linearize - convert a TIPC message buffer into a single contiguous piece
 * @skb: message buffer
 *
 * Returns 0 on success.
 */

static inline int buf_linearize(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
	return skb_linearize(skb);
#else
	return skb_linearize(skb, GFP_ATOMIC);
#endif
}

static inline int tipc_checkable(void)
{
    return tipc_check_len ? 1 : 0;
}

/**  
  * for cnt [0 .. 0xffffffff]
  * 24575 times return 1 if +5
  * 32767 times retrun 1 if +4
  * 49151 times retrun 1 if +3
  * 65535 times retrun 1 if +2
  *
  * +4: return 1 if cnt is 1,0x11,0x21,0x41,0x61,0x81,0xc1,0x101,0x141,...,0xfff80001,0xfffc0001
  */
static inline int tipc_ratelimit(unsigned int cnt, unsigned int rem)
{
	int f = ((fls(cnt) + 4)/2);
	
	if (cnt % (1 << f) != rem)
		return 0;
	else
		return 1;
}

/* 2012-5: 报文尾部增加4字节以便可以校验mac地址，替代之前的校验方式:
   加在尾部可忽略，不再支持协商；
   按网口校验，链路丢包通过请求重传计数用于告警显示；
   后续改变校验方式可更改type实现兼容处理*/
#define CK_TYP_CKSUM 0xc1
struct buf_ck_data {
	u8 type;
	u8 flag; /* reserved */
	__sum16 sum; /* eth_hdr + tipc_msg_data */
};

#define CK_SIZE sizeof(struct buf_ck_data)

#define csum16(data, len) csum_fold(csum_partial(data,len,0))

int buf_emulate_bad(struct sk_buff *buf, u32 pos); /* patch for testing */

#ifdef TIPC_SUPPORT_LS
int tipc_get_mc_tag(int mcid);
#define MC_TAG(mcid) (tipc_get_mc_tag(mcid))
#else
#define MC_TAG(mcid) (mcid)
#endif

#define TIPC_REG_DEV_PTYPE     0
#define TIPC_REG_GLOBAL_PTYPE  1
int tipc_get_reg_ptype_flag(void);

#endif
