/*
 * net/tipc/tipc_socket.c: TIPC socket API
 *
 * Copyright (c) 2001-2007, Ericsson AB
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

#include <linux/module.h>
#include <linux/types.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/fcntl.h>
#include <asm/string.h>
#include <asm/atomic.h>
#include <net/sock.h>

#include <linux/tipc.h>
#include <linux/tipc_config.h>
#include <net/tipc/tipc_plugin_msg.h>
#include <net/tipc/tipc_plugin_port.h>

#include "tipc_core.h"
#include "tipc_dbg.h"
#include "tipc_raw_socket.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
#include <net/net_namespace.h>
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 34)
#define SK_SLEEP(sk) sk_sleep(sk)
#else
#define SK_SLEEP(sk) sk->sk_sleep
#endif
#ifdef CONFIG_TIPC_SOCKET_API

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23)
#ifndef SHUT_RDWR
#define SHUT_RDWR 2	/* this is undefined in kernel space for some reason */
#endif
#endif

#define SS_LISTENING	-1	/* socket is listening */
#define SS_READY	-2	/* socket is connectionless */

#define OVERLOAD_LIMIT_BASE	20000 /* about 14 x socks(1536) */
#define CONN_TIMEOUT_DEFAULT	8000	/* default connect timeout = 8s */

extern unsigned int g_tipc_dbg_switch;

#define RETURN_OVERLOAD(tp, quelen) do {\
	if (tipc_ratelimit(++over_load_count, 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_SOCKET)) \
		warn("Overload 0x%x, total queue %u, Sock port %u queue %u, last read at %u\n",\
		over_load_count, (u32)atomic_read(&tipc_queue_size),\
		(tp)->ref, (quelen), (tp)->last_read_tim);\
    if (waitqueue_active( SK_SLEEP(sk))) /*如在wait,增加尝试唤醒下 */ \
        wake_up_interruptible( SK_SLEEP(sk)); \
	return TIPC_ERR_OVERLOAD;\
} while (0)

/* rdm flow-control */
/* should be: OVERLOAD_LIMIT_BASE > PAUSE_LIMIT > TIPC_FLOW_CONTROL_WIN*4 */
#define PAUSE_QUE_LIMIT       (TIPC_FLOW_CONTROL_WIN * 10)
#define PAUSE_SK_QUE_LIMIT    (TIPC_FLOW_CONTROL_WIN * 2)  /* 单个10% 开始反压*/

#define SIZE_WEIGHT(sz)  ((sz) < 0x800 ? 0 : (sz) / 0x800)


/* 报文从特别多降下来的时候检查 */
#define NEED_UNPAUSE(q_sz)   \
	((q_sz) == PAUSE_SK_QUE_LIMIT/2 && \
	 atomic_read(&tipc_queue_size) < PAUSE_QUE_LIMIT/2)


struct tipc_sock {
	struct sock sk;
	struct tipc_port *p;
	struct tipc_portid peer_name;
	long conn_timeout;
};

#define tipc_sk(sk) ((struct tipc_sock *)(sk))
#define tipc_sk_port(sk) ((struct tipc_port *)(tipc_sk(sk)->p))

static int backlog_rcv(struct sock *sk, struct sk_buff *skb);
static u32 dispatch(struct tipc_port *tport, struct sk_buff *buf);
static void wakeupdispatch(struct tipc_port *tport);

static const struct proto_ops packet_ops;
static const struct proto_ops stream_ops;
static const struct proto_ops msg_ops;

static struct proto tipc_proto;

static int sockets_enabled = 0;
static int over_load_count = 0;

static atomic_t tipc_queue_size = ATOMIC_INIT(0);

/*
 * Revised TIPC socket locking policy:
 *
 * Most socket operations take the standard socket lock when they start
 * and hold it until they finish (or until they need to sleep).  Acquiring
 * this lock grants the owner exclusive access to the fields of the socket
 * data structures, with the exception of the backlog queue.  A few socket
 * operations can be done without taking the socket lock because they only
 * read socket information that never changes during the life of the socket.
 *
 * Socket operations may acquire the lock for the associated TIPC port if they
 * need to perform an operation on the port.  If any routine needs to acquire
 * both the socket lock and the port lock it must take the socket lock first
 * to avoid the risk of deadlock.
 *
 * The dispatcher handling incoming messages cannot grab the socket lock in
 * the standard fashion, since invoked it runs at the BH level and cannot block.
 * Instead, it checks to see if the socket lock is currently owned by someone,
 * and either handles the message itself or adds it to the socket's backlog
 * queue; in the latter case the queued message is processed once the process
 * owning the socket lock releases it.
 *
 * NOTE: Releasing the socket lock while an operation is sleeping overcomes
 * the problem of a blocked socket operation preventing any other operations
 * from occurring.  However, applications must be careful if they have
 * multiple threads trying to send (or receive) on the same socket, as these
 * operations might interfere with each other.  For example, doing a connect
 * and a receive at the same time might allow the receive to consume the
 * ACK message meant for the connect.  While additional work could be done
 * to try and overcome this, it doesn't seem to be worthwhile at the present.
 *
 * NOTE: Releasing the socket lock while an operation is sleeping also ensures
 * that another operation that must be performed in a non-blocking manner is
 * not delayed for very long because the lock has already been taken.
 *
 * NOTE: This code assumes that certain fields of a port/socket pair are
 * constant over its lifetime; such fields can be examined without taking
 * the socket lock and/or port lock, and do not need to be re-read even
 * after resuming processing after waiting.  These fields include:
 *   - socket type
 *   - pointer to socket sk structure (aka tipc_sock structure)
 *   - pointer to port structure
 *   - port reference
 */

/**
 * advance_rx_queue - discard first buffer in socket receive queue
 *
 * Caller must hold socket lock
 */

static void advance_rx_queue(struct sock *sk)
{
	struct tipc_port *tport = tipc_sk_port(sk);
	buf_discard(__skb_dequeue(&sk->sk_receive_queue));
	atomic_dec(&tipc_queue_size);
	tport->sk_que_sz = skb_queue_len(&sk->sk_receive_queue);
	tport->sk_bk_sz = 0;
}

/**
 * discard_rx_queue - discard all buffers in socket receive queue
 *
 * Caller must hold socket lock
 */

static void discard_rx_queue(struct sock *sk)
{
	struct sk_buff *buf;

	while ((buf = __skb_dequeue(&sk->sk_receive_queue))) {
		atomic_dec(&tipc_queue_size);
		buf_discard(buf);
	}
}

/**
 * reject_rx_queue - reject all buffers in socket receive queue
 *
 * Caller must hold socket lock
 */

static void reject_rx_queue(struct sock *sk)
{
	struct sk_buff *buf;
	struct tipc_port *tport = tipc_sk_port(sk);

	while ((buf = __skb_dequeue(&sk->sk_receive_queue))) {
		tipc_reject_msg(buf, TIPC_ERR_NO_PORT);
		atomic_dec(&tipc_queue_size);
	}
	tport->sk_que_sz = 0;
}

/**
 * tipc_create - create a TIPC socket
 * @net: network namespace (must be default network) -- only for 2.6.24+
 * @sock: pre-allocated socket structure
 * @protocol: protocol indicator (must be 0)
 * @kern: caused by kernel or by userspace? (unused) -- only for 2.6.33+
 *
 * This routine creates additional data structures used by the TIPC socket,
 * initializes them, and links them together.
 *
 * Returns 0 on success, errno otherwise
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
static int tipc_create(struct net *net, struct socket *sock, int protocol,
		       int kern)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
static int tipc_create(struct net *net, struct socket *sock, int protocol)
#else
static int tipc_create(struct socket *sock, int protocol)
#endif
{
	const struct proto_ops *ops;
	socket_state state;
	struct sock *sk;
	struct tipc_port *tp_ptr;

	/* Validate arguments */
#if 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
	if (!net_eq(net, &init_net))
		return -EAFNOSUPPORT;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	if (net != &init_net)
		return -EAFNOSUPPORT;
#endif
#else
    net = &init_net;
#endif

	if (unlikely((protocol != 0) && (SOCK_RAW != sock->type)))
		return -EPROTONOSUPPORT;

	switch (sock->type) {
	case SOCK_STREAM:
		ops = &stream_ops;
		state = SS_UNCONNECTED;
		break;
	case SOCK_SEQPACKET:
		ops = &packet_ops;
		state = SS_UNCONNECTED;
		break;
	case SOCK_DGRAM:
	case SOCK_RDM:
		ops = &msg_ops;
		state = SS_READY;
		break;
	case SOCK_RAW:
        info("for SOCK_RAW enter\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	    return tipc_raw_create(net, sock, protocol, 0);
#else
	    return tipc_raw_create(net, sock, protocol);
#endif

	default:
		return -EPROTOTYPE;
	}

	/* Allocate socket's protocol area */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 1)
	sk = sk_alloc(net, AF_TIPC, GFP_KERNEL, &tipc_proto, kern);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	sk = sk_alloc(net, AF_TIPC, GFP_KERNEL, &tipc_proto);
#else
	sk = sk_alloc(AF_TIPC, GFP_KERNEL, &tipc_proto, 1);
#endif

	if (sk == NULL)
		return -ENOMEM;

	/* Allocate TIPC port for socket to use */

	tp_ptr = tipc_createport_raw(sk, &dispatch, &wakeupdispatch,
				     TIPC_LOW_IMPORTANCE);
	if (unlikely(!tp_ptr)) {
		sk_free(sk);
		return -ENOMEM;
	}

	/* Finish initializing socket data structures */

	sock->ops = ops;
	sock->state = state;

	sock_init_data(sock, sk);
    sk->sk_rcvbuf =	max(0x1000000, sk->sk_rcvbuf); /* 避免缺省值太小 */
	sk->sk_backlog_rcv = backlog_rcv;
	tipc_sk(sk)->p = tp_ptr;
	tipc_sk(sk)->conn_timeout = msecs_to_jiffies(CONN_TIMEOUT_DEFAULT);

	spin_unlock_bh(tp_ptr->lock);

	if (sock->state == SS_READY) {
		tipc_set_portunreturnable(tp_ptr->ref, 1);
		if (sock->type == SOCK_DGRAM)
			tipc_set_portunreliable(tp_ptr->ref, 1);
	}

	atomic_inc(&tipc_user_count);
	return 0;
}

/**
 * release - destroy a TIPC socket
 * @sock: socket to destroy
 *
 * This routine cleans up any messages that are still queued on the socket.
 * For DGRAM and RDM socket types, all queued messages are rejected.
 * For SEQPACKET and STREAM socket types, the first message is rejected
 * and any others are discarded.  (If the first message on a STREAM socket
 * is partially-read, it is discarded and the next one is rejected instead.)
 *
 * NOTE: Rejected messages are not necessarily returned to the sender!  They
 * are returned or discarded according to the "destination droppable" setting
 * specified for the message by the sender.
 *
 * Returns 0 on success, errno otherwise
 */

static int release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport;
	struct sk_buff *buf;
	int res;

	/*
	 * Exit if socket isn't fully initialized (occurs when a failed accept()
	 * releases a pre-allocated child socket that was never used)
	 */

	if (sk == NULL)
		return 0;

	tport = tipc_sk_port(sk);
	lock_sock(sk);

	/*
	 * Reject all unreceived messages, except on an active connection
	 * (which disconnects locally & sends a 'FIN+' to peer)
	 */

	while (sock->state != SS_DISCONNECTING) {
		buf = __skb_dequeue(&sk->sk_receive_queue);
		if (buf == NULL)
			break;
		atomic_dec(&tipc_queue_size);
		if (buf_handle(buf) != msg_data(buf_msg(buf)))
			buf_discard(buf);
		else {
			if ((sock->state == SS_CONNECTING) ||
			    (sock->state == SS_CONNECTED)) {
				sock->state = SS_DISCONNECTING;
				tipc_disconnect(tport->ref);
			}
			tipc_reject_msg(buf, TIPC_ERR_NO_PORT);
		}
	}

	/*
	 * Delete TIPC port; this ensures no more messages are queued
	 * (also disconnects an active connection & sends a 'FIN-' to peer)
	 */

	res = tipc_deleteport(tport->ref);

	/* Discard any remaining (connection-based) messages in receive queue */

	discard_rx_queue(sk);

	/* Reject any messages that accumulated in backlog queue */

	sock->state = SS_DISCONNECTING;
	release_sock(sk);

	sock_put(sk);
	sock->sk = NULL;

	atomic_dec(&tipc_user_count);
	return res;
}

/**
 * bind - associate or disassocate TIPC name(s) with a socket
 * @sock: socket structure
 * @uaddr: socket address describing name(s) and desired operation
 * @uaddr_len: size of socket address data structure
 *
 * Name and name sequence binding is indicated using a positive scope value;
 * a negative scope value unbinds the specified name.  Specifying no name
 * (i.e. a socket address length of 0) unbinds all names from the socket.
 *
 * Returns 0 on success, errno otherwise
 *
 * NOTE: This routine doesn't need to take the socket lock since it doesn't
 *       access any non-constant socket information.
 */

static int bind(struct socket *sock, struct sockaddr *uaddr, int uaddr_len)
{
	struct sockaddr_tipc *addr = (struct sockaddr_tipc *)uaddr;
	u32 portref = tipc_sk_port(sock->sk)->ref;

	if (unlikely(!uaddr_len))
		return tipc_withdraw(portref, 0, NULL);

	if (uaddr_len < sizeof(struct sockaddr_tipc))
		return -EINVAL;
	if (addr->family != AF_TIPC)
		return -EAFNOSUPPORT;

	if (addr->addrtype == TIPC_ADDR_NAME)
		addr->addr.nameseq.upper = addr->addr.nameseq.lower;
	else if (addr->addrtype != TIPC_ADDR_NAMESEQ)
		return -EAFNOSUPPORT;

	return (addr->scope > 0) ?
		tipc_publish(portref, addr->scope, &addr->addr.nameseq) :
		tipc_withdraw(portref, -addr->scope, &addr->addr.nameseq);
}

/**
 * get_name - get port ID of socket or peer socket
 * @sock: socket structure
 * @uaddr: area for returned socket address
 * @uaddr_len: area for returned length of socket address
 * @peer: 0 = own ID, 1 = current peer ID, 2 = current/former peer ID
 *
 * Returns 0 on success, errno otherwise
 *
 * NOTE: This routine doesn't need to take the socket lock since it only
 *       accesses socket information that is unchanging (or which changes in
 * 	 a completely predictable manner).
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static int get_name(struct socket *sock, struct sockaddr *uaddr, int peer)
#else
static int get_name(struct socket *sock, struct sockaddr *uaddr,
		    int *uaddr_len, int peer)
#endif
{
	struct sockaddr_tipc *addr = (struct sockaddr_tipc *)uaddr;
	struct tipc_sock *tsock = tipc_sk(sock->sk);
	memset(addr, 0, sizeof(*addr));
	if (peer) {
		if ((sock->state != SS_CONNECTED) &&
			((peer != 2) || (sock->state != SS_DISCONNECTING)))
			return -ENOTCONN;
		addr->addr.id.ref = tsock->peer_name.ref;
		addr->addr.id.node = tsock->peer_name.node;
	} else {
		tipc_ownidentity(tsock->p->ref, &addr->addr.id);
	}
	addr->addrtype = TIPC_ADDR_ID;
	addr->family = AF_TIPC;
	addr->scope = 0;
	addr->addr.name.domain = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	*uaddr_len = sizeof(*addr);
	return 0;
#else
	return sizeof(*addr);
#endif
}

/**
 * poll - read and possibly block on pollmask
 * @file: file structure associated with the socket
 * @sock: socket for which to calculate the poll bits
 * @wait: ???
 *
 * Returns pollmask value
 *
 * COMMENTARY:
 * It appears that the usual socket locking mechanisms are not useful here
 * since the pollmask info is potentially out-of-date the moment this routine
 * exits.  TCP and other protocols seem to rely on higher level poll routines
 * to handle any preventable race conditions, so TIPC will do the same ...
 *
 * TIPC sets the returned events as follows:
 *
 * socket state		flags set
 * ------------ 	---------
 * unconnected		no read flags
 *			no write flags
 *
 * connecting		POLLIN/POLLRDNORM if ACK/NACK in rx queue
 *			no write flags
 *
 * connected		POLLIN/POLLRDNORM if data in rx queue
 *			POLLOUT if port is not congested
 *
 * disconnecting	POLLIN/POLLRDNORM/POLLHUP
 *			no write flags
 *
 * listening		POLLIN if SYN in rx queue
 *			no write flags
 *
 * ready		POLLIN/POLLRDNORM if data in rx queue
 * [connectionless]	POLLOUT (since port cannot be congested)
 *
 * IMPORTANT: The fact that a read or write operation is indicated does NOT
 * imply that the operation will succeed, merely that it should be performed
 * and will not block.
 */

static unsigned int poll(struct file *file, struct socket *sock,
			 poll_table *wait)
{
	struct sock *sk = sock->sk;
	u32 mask = 0;

	poll_wait(file,  SK_SLEEP(sk), wait);

	switch ((int)sock->state) {
	case SS_READY:
	case SS_CONNECTED:
		if (!tipc_sk_port(sk)->congested && !tipc_sk_port(sk)->stopped)
			mask |= POLLOUT;
		/* fallthrough */
	case SS_CONNECTING:
	case SS_LISTENING:
		if (!skb_queue_empty(&sk->sk_receive_queue))
			mask |= (POLLIN | POLLRDNORM);
		break;
	case SS_DISCONNECTING:
		mask = (POLLIN | POLLRDNORM | POLLHUP);
		break;
	}

	return mask;
}

/**
 * dest_name_check - verify user is permitted to send to specified port name
 * @dest: destination address
 * @m: descriptor for message to be sent
 *
 * Prevents restricted configuration commands from being issued by
 * unauthorized users.
 *
 * Returns 0 if permission is granted, otherwise errno
 */

static int dest_name_check(struct sockaddr_tipc *dest, struct msghdr *m)
{
	struct tipc_cfg_msg_hdr hdr;

	if (likely(dest->addr.name.name.type >= TIPC_RESERVED_TYPES))
		return 0;
	if (likely(dest->addr.name.name.type == TIPC_TOP_SRV))
		return 0;
	if (likely(dest->addr.name.name.type != TIPC_CFG_SRV))
		return -EACCES;

	if (copy_from_user(&hdr, get_msgiov(m)[0].iov_base, sizeof(hdr)))
		return -EFAULT;
	if ((ntohs(hdr.tcm_type) & 0xC000) && (!capable(CAP_NET_ADMIN)))
		return -EACCES;

	return 0;
}

/**
 * send_msg - send message in connectionless manner
 * @iocb: if NULL, indicates that socket lock is already held
 * @sock: socket structure
 * @m: message to send
 * @total_len: length of message
 *
 * Message must have an destination specified explicitly.
 * Used for SOCK_RDM and SOCK_DGRAM messages,
 * and for 'SYN' messages on SOCK_SEQPACKET and SOCK_STREAM connections.
 * (Note: 'SYN+' is prohibited on SOCK_STREAM.)
 *
 * Returns the number of bytes sent on success, or errno otherwise
 */

static int __send_msg(struct socket *sock,
		    struct msghdr *m, size_t total_len)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport = tipc_sk_port(sk);
	struct sockaddr_tipc *dest = (struct sockaddr_tipc *)m->msg_name;
	int needs_conn;
	int res = -EINVAL;

	if (unlikely(!dest))
		return -EDESTADDRREQ;
	if (unlikely((m->msg_namelen < sizeof(*dest)) ||
		     (dest->family != AF_TIPC)))
		return -EINVAL;

	needs_conn = (sock->state != SS_READY);
	if (unlikely(needs_conn)) {
		if (sock->state == SS_LISTENING) {
			res = -EPIPE;
			goto exit;
		}
		if (sock->state != SS_UNCONNECTED) {
			res = -EISCONN;
			goto exit;
		}
		if ((tport->published) ||
		    ((sock->type == SOCK_STREAM) && (total_len != 0))) {
			res = -EOPNOTSUPP;
			goto exit;
		}
		if (dest->addrtype == TIPC_ADDR_NAME) {
			tport->conn_type = dest->addr.name.name.type;
			tport->conn_instance = dest->addr.name.name.instance;
		}

		/* Abort any pending connection attempts (very unlikely) */

		reject_rx_queue(sk);
	}

	tport->msg_flags = m->msg_flags & MSG_DONTROUTE;
	do {
		if (dest->addrtype == TIPC_ADDR_NAME) {
			if ((res = dest_name_check(dest, m)))
				break;
			res = tipc_send2name(tport->ref,
					     &dest->addr.name.name,
					     dest->addr.name.domain,
					     get_msgiovlen(m),
					     get_msgiov(m));
		}
		else if (dest->addrtype == TIPC_ADDR_ID) {
			res = tipc_send2port(tport->ref,
					     &dest->addr.id,
					     get_msgiovlen(m),
					     get_msgiov(m));
		}
		else if (dest->addrtype == TIPC_ADDR_MCAST) {
			if (needs_conn) {
				res = -EOPNOTSUPP;
				break;
			}
			if ((res = dest_name_check(dest, m)))
				break;
			res = tipc_multicast(tport->ref,
					     &dest->addr.nameseq,
					     0,
					     get_msgiovlen(m),
					     get_msgiov(m));
		}
		if (likely(res != -ELINKCONG)) {
			if (unlikely(res < 0)) /* 失败不包括-ELINKCONG */
				tport->sent_failed++;
			if (needs_conn && (res >= 0)) {
				sock->state = SS_CONNECTING;
			}
			break;
		}
		if (m->msg_flags & MSG_DONTWAIT) {
			tport->nowait++; /* */
			res = -EWOULDBLOCK;
			break;
		}
		tport->wait++; /* */
		release_sock(sk);
		/* rdm flow-control */
		res = wait_event_interruptible(* SK_SLEEP(sk),
				!tport->congested && !tport->stopped);
		lock_sock(sk);
		if (res)
				break;
	} while (1);
	tport->msg_flags = 0; /* MSG_DONTROUTE */

exit:

	return res;
}

static int send_msg(TIPC_KIOCB struct socket *sock,
			struct msghdr *m, size_t total_len)
{
	struct sock *sk = sock->sk;
	int ret;

	if (IOCB_LK)
		lock_sock(sk);
		
	ret = __send_msg(sock, m, total_len);

	if (IOCB_LK)
	    release_sock(sk);

	return ret;
}		    

		    
/**
 * send_packet - send a connection-oriented message
 * @iocb: if NULL, indicates that socket lock is already held
 * @sock: socket structure
 * @m: message to send
 * @total_len: length of message
 *
 * Used for SOCK_SEQPACKET messages and SOCK_STREAM data.
 *
 * Returns the number of bytes sent on success, or errno otherwise
 */

static int __send_packet(struct socket *sock,
		       struct msghdr *m, size_t total_len)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport = tipc_sk_port(sk);
	struct sockaddr_tipc *dest = (struct sockaddr_tipc *)m->msg_name;
	int res;

	/* Handle implied connection establishment */
	if (unlikely(dest))
		return __send_msg(sock, m, total_len);

	do {
		if (unlikely(sock->state != SS_CONNECTED)) {
			if (sock->state == SS_DISCONNECTING)
				res = -EPIPE;
			else
				res = -ENOTCONN;
			break;
		}

		res = tipc_send(tport->ref, get_msgiovlen(m), get_msgiov(m));
		if (likely(res != -ELINKCONG)) {
			if (unlikely(res < 0)) /* */
				tport->sent_failed++;
			break;
		}
		if (m->msg_flags & MSG_DONTWAIT) {
			res = -EWOULDBLOCK;
			tport->nowait++; /* */
			break;
		}
		tport->wait++; /* */
		release_sock(sk);
		res = wait_event_interruptible(* SK_SLEEP(sk),
			((!tport->congested  && !tport->stopped) || !tport->connected));
		lock_sock(sk);
		if (res)
			break;
	} while (1);

	return res;
}

static int send_packet(TIPC_KIOCB struct socket *sock,
		       struct msghdr *m, size_t total_len)
{
	struct sock *sk = sock->sk;
	int ret;

	if (IOCB_LK)
		lock_sock(sk);

	ret = __send_packet(sock, m, total_len);

	if (IOCB_LK)
		release_sock(sk);
		
	return ret;
}
		       
/**
 * send_stream - send stream-oriented data
 * @iocb: (unused)
 * @sock: socket structure
 * @m: data to send
 * @total_len: total length of data to be sent
 *
 * Used for SOCK_STREAM data.
 *
 * Returns the number of bytes sent on success (or partial success),
 * or errno if no data sent
 */

static int send_stream(TIPC_KIOCB struct socket *sock,
		       struct msghdr *m, size_t total_len)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport = tipc_sk_port(sk);
	struct msghdr my_msg;
	struct iovec my_iov;
	const struct iovec *curr_iov;
	int curr_iovlen;
	char __user *curr_start;
	u32 hdr_size;
	int curr_left;
	int bytes_to_send;
	int bytes_sent;
	int res;

	lock_sock(sk);

	/* Handle special cases where there is no connection */

	if (unlikely(sock->state != SS_CONNECTED)) {
		if (sock->state == SS_UNCONNECTED) {
			res = __send_packet(sock, m, total_len);
			goto exit;
		} else if (sock->state == SS_DISCONNECTING) {
			res = -EPIPE;
			goto exit;
		} else {
			res = -ENOTCONN;
			goto exit;
		}
	}

	if (unlikely(m->msg_name)) {
		res = -EISCONN;
		goto exit;
	}

	/*
	 * Send each iovec entry using one or more messages
	 *
	 * Note: This algorithm is good for the most likely case
	 * (i.e. one large iovec entry), but could be improved to pass sets
	 * of small iovec entries into send_packet().
	 */

	curr_iov = get_msgiov(m);
	curr_iovlen = get_msgiovlen(m);
#if LINUX_VERSION_CODE > KERNEL_VERSION(6, 0, 0)
	// my_msg type is ITER_IOVEC=0, so the iter_iov is iter->__iov
	my_msg.msg_iter.__iov = &my_iov;
#else
	get_msgiov(&my_msg) = &my_iov;
#endif
	get_msgiovlen(&my_msg) = 1;
	my_msg.msg_flags = m->msg_flags;
	my_msg.msg_name = NULL;
	bytes_sent = 0;

	hdr_size = msg_hdr_sz(&tport->phdr);

	while (curr_iovlen--) {
		curr_start = curr_iov->iov_base;
		curr_left = curr_iov->iov_len;

		while (curr_left) {
			bytes_to_send = tport->max_pkt - hdr_size;
			if (bytes_to_send > TIPC_MAX_USER_MSG_SIZE)
				bytes_to_send = TIPC_MAX_USER_MSG_SIZE;
			if (curr_left < bytes_to_send)
				bytes_to_send = curr_left;
			my_iov.iov_base = curr_start;
			my_iov.iov_len = bytes_to_send;
			if ((res = __send_packet(sock, &my_msg, 0)) < 0) {
				if (bytes_sent)
					res = bytes_sent;
				goto exit;
			}
			curr_left -= bytes_to_send;
			curr_start += bytes_to_send;
			bytes_sent += bytes_to_send;
		}

		curr_iov++;
	}
	res = bytes_sent;
exit:
	release_sock(sk);
	return res;
}

/**
 * auto_connect - complete connection setup to a remote port
 * @sock: socket structure
 * @msg: peer's response message
 *
 * Returns 0 on success, errno otherwise
 */

static int auto_connect(struct socket *sock, struct tipc_msg *msg)
{
	struct tipc_sock *tsock = tipc_sk(sock->sk);

	if (msg_errcode(msg)) {
		sock->state = SS_DISCONNECTING;
		return -ECONNREFUSED;
	}

	tsock->peer_name.ref = msg_origport(msg);
	tsock->peer_name.node = msg_orignode(msg);
	tipc_connect2port(tsock->p->ref, &tsock->peer_name);
	tipc_set_portimportance(tsock->p->ref, msg_importance(msg));
	sock->state = SS_CONNECTED;
	return 0;
}

/**
 * set_orig_addr - capture sender's address for received message
 * @m: descriptor for message info
 * @msg: received message header
 *
 * Note: Address is not captured if not requested by receiver.
 */

static void set_orig_addr(struct msghdr *m, struct tipc_msg *msg)
{
	struct sockaddr_tipc *addr = (struct sockaddr_tipc *)m->msg_name;

	if (addr) {
		addr->family = AF_TIPC;
		addr->addrtype = TIPC_ADDR_ID;
		memset(&addr->addr, 0, sizeof(addr->addr));
		addr->addr.id.ref = msg_origport(msg);
		addr->addr.id.node = msg_orignode(msg);
		addr->addr.name.domain = 0;   	/* could leave uninitialized */
		addr->scope = 0;   		/* could leave uninitialized */
		m->msg_namelen = sizeof(struct sockaddr_tipc);
	}
}

/**
 * anc_data_recv - optionally capture ancillary data for received message
 * @m: descriptor for message info
 * @msg: received message header
 * @tport: TIPC port associated with message
 *
 * Note: Ancillary data is not captured if not requested by receiver.
 *
 * Returns 0 if successful, otherwise errno
 */

static int anc_data_recv(struct msghdr *m, struct tipc_msg *msg,
				struct tipc_port *tport)
{
	u32 anc_data[3];
	u32 err;
	u32 dest_type;
	int has_name;
	int res;

	if (likely(m->msg_controllen == 0))
		return 0;

	/* Optionally capture errored message object(s) */

	err = msg ? msg_errcode(msg) : 0;
	if (unlikely(err)) {
		anc_data[0] = err;
		anc_data[1] = msg_data_sz(msg);
		if ((res = put_cmsg(m, SOL_TIPC, TIPC_ERRINFO, 8, anc_data)))
			return res;
		if (anc_data[1] &&
		    (res = put_cmsg(m, SOL_TIPC, TIPC_RETDATA, anc_data[1],
				    msg_data(msg))))
			return res;
	}

	/* Optionally capture message destination object */

	dest_type = msg ? msg_type(msg) : TIPC_DIRECT_MSG;
	switch (dest_type) {
	case TIPC_NAMED_MSG:
		has_name = 1;
		anc_data[0] = msg_nametype(msg);
		anc_data[1] = msg_namelower(msg);
		anc_data[2] = msg_namelower(msg);
		break;
	case TIPC_MCAST_MSG:
		has_name = 1;
		anc_data[0] = msg_nametype(msg);
		anc_data[1] = msg_namelower(msg);
		anc_data[2] = msg_nameupper(msg);
		break;
	case TIPC_CONN_MSG:
		has_name = (tport->conn_type != 0);
		anc_data[0] = tport->conn_type;
		anc_data[1] = tport->conn_instance;
		anc_data[2] = tport->conn_instance;
		break;
	default:
		has_name = 0;
	}
	if (has_name &&
	    (res = put_cmsg(m, SOL_TIPC, TIPC_DESTNAME, 12, anc_data)))
		return res;

	return 0;
}

/**
 * recv_msg - receive packet-oriented message
 * @iocb: (unused)
 * @m: descriptor for message info
 * @buf_len: total size of user buffer area
 * @flags: receive flags
 *
 * Used for SOCK_DGRAM, SOCK_RDM, and SOCK_SEQPACKET messages.
 * If the complete message doesn't fit in user area, truncate it.
 *
 * Returns size of returned message data, errno otherwise
 */

static int recv_msg(TIPC_KIOCB struct socket *sock,
		    struct msghdr *m, size_t buf_len, int flags)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport = tipc_sk_port(sk);
	struct sk_buff *buf;
	struct tipc_msg *msg;
	long timeout_val;
	unsigned int sz;
	u32 err;
	int res;

	/* Catch invalid receive requests */

	if (get_msgiovlen(m) != 1)
		return -EOPNOTSUPP;   /* Don't do multiple iovec entries yet */

	if (unlikely(!buf_len))
		return -EINVAL;

	lock_sock(sk);

	if (unlikely(sock->state == SS_UNCONNECTED)) {
		res = -ENOTCONN;
		goto exit;
	}
	
	/* will be updtaed in set_orig_addr() if needed */
	m->msg_namelen = 0;
	
	timeout_val = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
restart:

	/* Look for a message in receive queue; wait if necessary */

	while (skb_queue_empty(&sk->sk_receive_queue)) {
		if (sock->state == SS_DISCONNECTING) {
			res = -ENOTCONN;
			goto exit;
		}
		if (timeout_val <= 0L) {
			res = timeout_val ? timeout_val : -EWOULDBLOCK;
			goto exit;
		}
		release_sock(sk);
		timeout_val = wait_event_interruptible_timeout(* SK_SLEEP(sk),
				(!skb_queue_empty(&sk->sk_receive_queue) ||
				 (sock->state == SS_DISCONNECTING)),
				timeout_val);
		lock_sock(sk);
	}

	/* Look at first message in receive queue */

	buf = skb_peek(&sk->sk_receive_queue);
	msg = buf_msg(buf);
	sz = msg_data_sz(msg);
	err = msg_errcode(msg);

	/* Complete connection setup for an implied connect */

	if (unlikely(sock->state == SS_CONNECTING)) {
		res = auto_connect(sock, msg);
		if (res)
			goto exit;
	}

	/* Discard an empty non-errored message & try again */

	if ((!sz) && (!err)) {
		advance_rx_queue(sk);
		goto restart;
	}

	/* Capture sender's address (optional) */

	set_orig_addr(m, msg);

	/* Capture ancillary data (optional) */

	res = anc_data_recv(m, msg, tport);
	if (res)
		goto exit;

	/* Capture message data (if valid) & compute return value (always) */

	if (!err) {
		if (unlikely(buf_len < sz)) {
			sz = buf_len;
			m->msg_flags |= MSG_TRUNC;
		}
		/* support iov recv, m->msg_iov会被改变 */
		if (unlikely(tipc_memcpy_to_msg(m, msg_data(msg),
					  sz))) {
			res = -EFAULT;
			goto exit;
		}
		res = sz;
	} else {
		if ((sock->state == SS_READY) ||
		    ((err == TIPC_CONN_SHUTDOWN) || m->msg_control))
			res = 0;
		else
			res = -ECONNRESET;
	}

	/* Consume received message (optional) */

	if (likely(!(flags & MSG_PEEK))) {
		if ((sock->state != SS_READY) &&
		    (++tport->conn_unacked >= TIPC_FLOW_CONTROL_WIN))
			tipc_acknowledge(tport->ref, tport->conn_unacked);

        /* rdm-flow control, send unpause */
        /* 如果有拥塞，尽量通过超时解除。
         这里不再处理，否则锁的使用不一致，修改太复杂
		if (unlikely(NEED_UNPAUSE(skb_queue_len(&sk->sk_receive_queue)))) {
			struct port_msg_stat *ps;
			u32 oport = msg_origport(msg);
			u32 onode = msg_orignode(msg);
			u32 mc = msg_mcast(msg);
			
			ps = tipc_find_ps_recv(tport, onode, oport);
			if (ps && ps->pause_msec) {
				ps->pause_msec = 0;
				ps->stat.sent_pause[1]++;
			
				tipc_pause(tport, onode, oport, mc, 0);
			}
		} */
		
		advance_rx_queue(sk);
	}
exit:
	tport->last_read_tim = jiffies;
	release_sock(sk);
	return res;
}

/**
 * recv_stream - receive stream-oriented data
 * @iocb: (unused)
 * @m: descriptor for message info
 * @buf_len: total size of user buffer area
 * @flags: receive flags
 *
 * Used for SOCK_STREAM messages only.  If not enough data is available
 * will optionally wait for more; never truncates data.
 *
 * Returns size of returned message data, errno otherwise
 */

static int recv_stream(TIPC_KIOCB struct socket *sock,
		       struct msghdr *m, size_t buf_len, int flags)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport = tipc_sk_port(sk);
	struct sk_buff *buf;
	struct tipc_msg *msg;
	long timeout_val;
	unsigned int sz;
	int sz_to_copy, target, needed;
	int sz_copied = 0;
	char __user *crs = get_msgiov(m)->iov_base;
	unsigned char *buf_crs;
	u32 err;
	int res = 0;

	/* Catch invalid receive attempts */

	if (get_msgiovlen(m) != 1)
		return -EOPNOTSUPP;   /* Don't do multiple iovec entries yet */

	if (unlikely(!buf_len))
		return -EINVAL;

	lock_sock(sk);

	if (unlikely((sock->state == SS_UNCONNECTED) ||
		     (sock->state == SS_CONNECTING))) {
		res = -ENOTCONN;
		goto exit;
	}
			 
	/* will be updtaed in set_orig_addr() if needed */
	m->msg_namelen = 0;

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, buf_len);
	timeout_val = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
restart:

	/* Look for a message in receive queue; wait if necessary */

	while (skb_queue_empty(&sk->sk_receive_queue)) {
		if (sock->state == SS_DISCONNECTING) {
			res = -ENOTCONN;
			goto exit;
		}
		if (timeout_val <= 0L) {
			res = timeout_val ? timeout_val : -EWOULDBLOCK;
			goto exit;
		}
		release_sock(sk);
		timeout_val = wait_event_interruptible_timeout(* SK_SLEEP(sk),
				(!skb_queue_empty(&sk->sk_receive_queue) ||
				 (sock->state == SS_DISCONNECTING)),
				timeout_val);
		lock_sock(sk);
	}

	/* Look at first message in receive queue */

	buf = skb_peek(&sk->sk_receive_queue);
	msg = buf_msg(buf);
	sz = msg_data_sz(msg);
	err = msg_errcode(msg);

	/* Discard an empty non-errored message & try again */

	if ((!sz) && (!err)) {
		advance_rx_queue(sk);
		goto restart;
	}

	/* Optionally capture sender's address & ancillary data of first msg */

	if (sz_copied == 0) {
		set_orig_addr(m, msg);
		res = anc_data_recv(m, msg, tport);
		if (res)
			goto exit;
	}

	/* Capture message data (if valid) & compute return value (always) */

	if (!err) {
		buf_crs = (unsigned char *)(buf_handle(buf));
		sz = (unsigned char *)msg + msg_size(msg) - buf_crs;

		needed = (buf_len - sz_copied);
		sz_to_copy = (sz <= needed) ? sz : needed;
		if (unlikely(copy_to_user(crs, buf_crs, sz_to_copy))) {
			res = -EFAULT;
			goto exit;
		}
		sz_copied += sz_to_copy;

		if (sz_to_copy < sz) {
			if (!(flags & MSG_PEEK))
				buf_set_handle(buf, buf_crs + sz_to_copy);
			goto exit;
		}

		crs += sz_to_copy;
	} else {
		if (sz_copied != 0)
			goto exit; /* can't add error msg to valid data */

		if ((err == TIPC_CONN_SHUTDOWN) || m->msg_control)
			res = 0;
		else
			res = -ECONNRESET;
	}

	/* Consume received message (optional) */

	if (likely(!(flags & MSG_PEEK))) {
		if (unlikely(++tport->conn_unacked >= TIPC_FLOW_CONTROL_WIN))
			tipc_acknowledge(tport->ref, tport->conn_unacked);
		advance_rx_queue(sk);
	}

	/* Loop around if more data is required */

	if ((sz_copied < buf_len)    /* didn't get all requested data */
	    && (!skb_queue_empty(&sk->sk_receive_queue) ||
		(sz_copied < target))
				     /* ... and more is ready or required */
	    && (!(flags & MSG_PEEK)) /* ... and aren't just peeking at data */
	    && (!err)                /* ... and haven't reached a FIN */
	    )
		goto restart;

exit:
	release_sock(sk);
	return sz_copied ? sz_copied : res;
}

/**
 * rx_queue_full - determine if receive queue can accept another message
 * @msg: message to be added to queue
 * @queue_size: current size of queue
 * @base: nominal maximum size of queue
 *
 * Returns 1 if queue is unable to accept message, 0 otherwise
 */

static int rx_queue_full(struct tipc_msg *msg, u32 queue_size, u32 base)
{
	u32 threshold;
	u32 imp = msg_importance(msg);

	if (imp == TIPC_LOW_IMPORTANCE)
		threshold = base;
	else if (imp == TIPC_MEDIUM_IMPORTANCE)
		threshold = base * 9/8; /* 2 -> 9/8 */
	else if (imp == TIPC_HIGH_IMPORTANCE)
		threshold = base * 10/8; /* 10 -> 10/8 */
	else
		return 0;

	if (msg_connected(msg))
		threshold *= 4;

	return (queue_size >= threshold);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
/**
 * rcvbuf_limit - get proper overload limit of socket receive queue
 * @sk: socket
 * @buf: message
 *
 * For all connection oriented messages, irrespective of importance,
 * the default overload value (i.e. 67MB) is set as limit.
 *
 * For all connectionless messages, by default new queue limits are
 * as belows:
 *
 * TIPC_LOW_IMPORTANCE       (4 MB)
 * TIPC_MEDIUM_IMPORTANCE    (8 MB)
 * TIPC_HIGH_IMPORTANCE      (16 MB)
 * TIPC_CRITICAL_IMPORTANCE  (32 MB)
 *
 * Returns overload limit according to corresponding message importance
 */
static unsigned int rcvbuf_limit(struct sock *sk, struct sk_buff *buf)
{
	struct tipc_msg *msg = buf_msg(buf);
	unsigned int limit; /* 16M, 20, 24, 28 */

	if (msg_connected(msg))
		limit = sk->sk_rcvbuf;
	else
		limit = sk->sk_rcvbuf / 4 * (4 + msg_importance(msg));
	return limit;
}
#endif

/**
 * filter_rcv - validate incoming message
 * @sk: socket
 * @buf: message
 *
 * Enqueues message on receive queue if acceptable; optionally handles
 * disconnect indication for a connected socket.
 *
 * Called with socket lock already taken; port lock may also be taken.
 *
 * Returns TIPC error status code (TIPC_OK if message is not to be rejected)
 */

static u32 filter_rcv(struct sock *sk, struct sk_buff *buf)
{
	struct socket *sock = sk->sk_socket;
	struct tipc_msg *msg = buf_msg(buf);
	u32 recv_q_len;

	/* Reject message if it is wrong sort of message for socket */

	/*
	 * WOULD IT BE BETTER TO JUST DISCARD THESE MESSAGES INSTEAD?
	 * "NO PORT" ISN'T REALLY THE RIGHT ERROR CODE, AND THERE MAY
	 * BE SECURITY IMPLICATIONS INHERENT IN REJECTING INVALID TRAFFIC
	 */

	if (sock->state == SS_READY) {
		if (msg_connected(msg)) {
			msg_dbg(msg, "dispatch filter 1\n");
			return TIPC_ERR_NO_PORT;
		}
	} else {
		if (msg_mcast(msg)) {
			msg_dbg(msg, "dispatch filter 2\n");
			return TIPC_ERR_NO_PORT;
		}
		if (sock->state == SS_CONNECTED) {
			if (!msg_connected(msg)) {
				msg_dbg(msg, "dispatch filter 3\n");
				return TIPC_ERR_NO_PORT;
			}
		}
		else if (sock->state == SS_CONNECTING) {
			if (!msg_connected(msg) && (msg_errcode(msg) == 0)) {
				msg_dbg(msg, "dispatch filter 4\n");
				return TIPC_ERR_NO_PORT;
			}
		}
		else if (sock->state == SS_LISTENING) {
			if (msg_connected(msg) || msg_errcode(msg)) {
				msg_dbg(msg, "dispatch filter 5\n");
				return TIPC_ERR_NO_PORT;
			}
		}
		else if (sock->state == SS_DISCONNECTING) {
			msg_dbg(msg, "dispatch filter 6\n");
			return TIPC_ERR_NO_PORT;
		}
		else /* (sock->state == SS_UNCONNECTED) */ {
			if (msg_connected(msg) || msg_errcode(msg)) {
				msg_dbg(msg, "dispatch filter 7\n");
				return TIPC_ERR_NO_PORT;
			}
		}
	}

	/* Reject message if there isn't room to queue it */

	recv_q_len = (u32)atomic_read(&tipc_queue_size);
	if (unlikely(recv_q_len >= OVERLOAD_LIMIT_BASE && 
				skb_queue_len(&sk->sk_receive_queue) > PAUSE_SK_QUE_LIMIT)) {
		if (rx_queue_full(msg, recv_q_len, OVERLOAD_LIMIT_BASE)) {
			RETURN_OVERLOAD(tipc_sk_port(sk), skb_queue_len(&sk->sk_receive_queue));
		}
	}
	recv_q_len = skb_queue_len(&sk->sk_receive_queue);
	if (unlikely(recv_q_len >= (OVERLOAD_LIMIT_BASE / 3))) {
		if (rx_queue_full(msg, recv_q_len, OVERLOAD_LIMIT_BASE / 2) ||
		    (SIZE_WEIGHT(msg_size(msg)) * recv_q_len > (OVERLOAD_LIMIT_BASE))) {
			RETURN_OVERLOAD(tipc_sk_port(sk), skb_queue_len(&sk->sk_receive_queue));
		}
	}

	/* Enqueue message (finally!) */

	msg_dbg(msg, "<DISP<: ");
	buf_set_handle(buf, msg_data(msg));
	atomic_inc(&tipc_queue_size);
	__skb_queue_tail(&sk->sk_receive_queue, buf);

	/* Initiate connection termination for an incoming 'FIN' */

	if (unlikely(msg_errcode(msg) && (sock->state == SS_CONNECTED))) {
		sock->state = SS_DISCONNECTING;
		tipc_disconnect_port(tipc_sk_port(sk));
	}

	if (waitqueue_active( SK_SLEEP(sk)))
		wake_up_interruptible( SK_SLEEP(sk));
	return TIPC_OK;
}

/**
 * backlog_rcv - handle incoming message from backlog queue
 * @sk: socket
 * @buf: message
 *
 * Caller must hold socket lock, but not port lock.
 *
 * Returns 0
 */

static int backlog_rcv(struct sock *sk, struct sk_buff *buf)
{
	u32 res;
	struct tipc_port *tport = tipc_sk_port(sk);

	/* tport->sk_bk_sz--; 这里没有spin_lock(sk_lock.slock)，在dispatch置0 */
	res = filter_rcv(sk, buf);
	if (res) {
		if (res != TIPC_ERR_NO_PORT)
			tport->recv_reject_backlog++; /* flow-control */
		tipc_reject_msg(buf, res);
	}
	return 0;
}

static inline __must_check int SK_ADD_BACKLOG(struct sock *sk, struct sk_buff *buf)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    return sk_add_backlog(sk, buf, rcvbuf_limit(sk, buf));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
    return sk_add_backlog(sk, buf);
#else
    sk_add_backlog(sk, buf);
    return 0;
#endif
}

/**
 * dispatch - handle incoming message
 * @tport: TIPC port that received message
 * @buf: message
 *
 * Called with port lock already taken.
 *
 * Returns TIPC error status code (TIPC_OK if message is not to be rejected)
 */

static u32 dispatch(struct tipc_port *tport, struct sk_buff *buf)
{
	struct sock *sk = (struct sock *)tport->usr_handle;
	u32 res;
	u32 send_pause = 0; /* */
	struct tipc_msg *msg = buf_msg(buf);
	u32 snode = msg_orignode(msg);
	u32 sport = msg_origport(msg);
	u32 mc = msg_mcast(msg);
	struct port_msg_stat *ps = NULL;
	u32 tipc_que_sz = atomic_read(&tipc_queue_size);
    u32 sk_que_len = 0;


	/*
	 * Process message if socket is unlocked; otherwise add to backlog queue
	 *
	 * This code is based on sk_receive_skb(), but must be distinct from it
	 * since a TIPC-specific filter/reject mechanism is utilized
	 */

	bh_lock_sock(sk);
	/* 
	 * rdm flow-control
	 * check pause before reject, inc tipc_queue_size !
	 * send pause message to notify sender pause 10 msec 
	 * if there isn't enough room 
	 */
	/* single and total queue */
    sk_que_len = skb_queue_len(&sk->sk_receive_queue) + tport->sk_bk_sz;
	if (unlikely(tipc_que_sz >= PAUSE_QUE_LIMIT ||
		 sk_que_len >= PAUSE_SK_QUE_LIMIT ||
		 SIZE_WEIGHT(msg_size(msg)) * sk_que_len > PAUSE_SK_QUE_LIMIT*3)) {

		/*
		 * 因为报文有延迟,所以每若干个发一次pause，sock报文少时不发送pause
		 * 当接近临界值时,加快发送pause，且pause时间应增大
		 */
		if (sk_que_len % (TIPC_MIN_LINK_WIN) == 0 && 
            sk_que_len > PAUSE_SK_QUE_LIMIT/4) {
    		send_pause = TIPC_PAUSE_MS_DEF * (sk_que_len/TIPC_FLOW_CONTROL_WIN*2 + 1);
		} else {
			/* 防止缓存大报文占用大量内存 */
		    if (sk_que_len > PAUSE_SK_QUE_LIMIT * 3/2 || 
				(sk_que_len % (TIPC_MIN_LINK_WIN/4) == 1 &&
				 SIZE_WEIGHT(msg_size(msg)) * sk_que_len > PAUSE_SK_QUE_LIMIT*3))
		  		send_pause = TIPC_PAUSE_MS_DEF * (sk_que_len/TIPC_FLOW_CONTROL_WIN*2 + 2);
		}
	}

	
	if (!sock_owned_by_user(sk)) {
		res = filter_rcv(sk, buf);
		tport->sk_bk_sz = 0; /* see release_sock()，此时backlog必为空 */
	} else {
		if (SK_ADD_BACKLOG(sk, buf))
			res = TIPC_ERR_OVERLOAD;
		else {
			res = TIPC_OK;
			tport->sk_bk_sz++;
		}
	}


	if (likely(!res)) {
		tport->sk_que_sz = sk_que_len + 1;
		if (unlikely(tport->sk_que_max < tport->sk_que_sz))
			tport->sk_que_max = tport->sk_que_sz;
	}

	bh_unlock_sock(sk);

	/* flow-control, increase pause-time */
	ps = tipc_find_ps_recv(tport, snode, sport);
	if (ps) {
		ps->stat.recv++;
		if (unlikely(res)) {
			ps->stat.recv_reject++;
		}
        if (mc) {
            ps->stat.recv_mcast++;
        }
        
		if (unlikely(send_pause)) {
			if (tipc_ratelimit(++ps->stat.sent_pause[0], 1) || tipc_dbg_is_on(TIPC_DBG_SWITCH_SOCKET))
                info("Port %u queue %u send pause to %x:%u  0x%x\n", tport->ref, tport->sk_que_sz, snode, sport, ps->stat.sent_pause[0]);
			ps->pause_msec = send_pause;
			tipc_pause(tport, snode, sport, mc, ps->pause_msec);
		}
	} else {
		/* 单向通信的也要反压，不能接除反压，所以减半处理 */
		if (unlikely(send_pause)) {
			tipc_pause(tport, snode, sport, mc, send_pause/2);
		}		
	}
	
	return res;
}

/**
 * wakeupdispatch - wake up port after congestion
 * @tport: port to wakeup
 *
 * Called with port lock already taken.
 */

static void wakeupdispatch(struct tipc_port *tport)
{
	struct sock *sk = (struct sock *)tport->usr_handle;

	if (waitqueue_active( SK_SLEEP(sk)))
		wake_up_interruptible_all( SK_SLEEP(sk));
}

/**
 * connect - establish a connection to another TIPC port
 * @sock: socket structure
 * @dest: socket address for destination port
 * @destlen: size of socket address data structure
 * @flags: file-related flags associated with socket
 *
 * Returns 0 on success, errno otherwise
 */

static int connect(struct socket *sock, struct sockaddr *dest, int destlen,
		   int flags)
{
	struct sock *sk = sock->sk;
	struct sockaddr_tipc *dst = (struct sockaddr_tipc *)dest;
	struct msghdr m = {NULL,};
	struct sk_buff *buf;
	struct tipc_msg *msg;
	long timeout;
	int res;

	lock_sock(sk);

	/* For now, TIPC does not allow use of connect() with DGRAM/RDM types */

	if (sock->state == SS_READY) {
		res = -EOPNOTSUPP;
		goto exit;
	}

	/* For now, TIPC does not support the non-blocking form of connect() */

	if (flags & O_NONBLOCK) {
		res = -EOPNOTSUPP;
		goto exit;
	}

	/* Issue Posix-compliant error code if socket is in the wrong state */

	if (sock->state == SS_LISTENING) {
		res = -EOPNOTSUPP;
		goto exit;
	}
	if (sock->state == SS_CONNECTING) {
		res = -EALREADY;
		goto exit;
	}
	if (sock->state != SS_UNCONNECTED) {
		res = -EISCONN;
		goto exit;
	}

	/*
	 * Reject connection attempt using multicast address
	 *
	 * Note: send_msg() validates the rest of the address fields,
	 *       so there's no need to do it here
	 */

	if (dst->addrtype == TIPC_ADDR_MCAST) {
		res = -EINVAL;
		goto exit;
	}

	/* Reject any messages already in receive queue (very unlikely) */

	reject_rx_queue(sk);

	/* Send a 'SYN-' to destination */

	m.msg_name = dest;
	m.msg_namelen = destlen;
	res = __send_msg(sock, &m, 0);
	if (res < 0) {
		goto exit;
	}

	/* Wait until an 'ACK' or 'RST' arrives, or a timeout occurs */

	timeout = tipc_sk(sk)->conn_timeout;
	release_sock(sk);
	res = wait_event_interruptible_timeout(* SK_SLEEP(sk),
			(!skb_queue_empty(&sk->sk_receive_queue) ||
			(sock->state != SS_CONNECTING)),
			timeout ? timeout : MAX_SCHEDULE_TIMEOUT);
	lock_sock(sk);

	if (res > 0) {
		buf = skb_peek(&sk->sk_receive_queue);
		if (buf != NULL) {
			msg = buf_msg(buf);
			res = auto_connect(sock, msg);
			if (!res) {
				if (!msg_data_sz(msg))
					advance_rx_queue(sk);
			}
		} else {
			if (sock->state == SS_CONNECTED) {
				res = -EISCONN;
			} else {
				res = -ECONNREFUSED;
			}
		}
	} else {
		if (res == 0)
			res = -ETIMEDOUT;
		else
			; /* leave "res" unchanged */
		sock->state = SS_DISCONNECTING;
	}

exit:
	release_sock(sk);
	return res;
}

/**
 * listen - allow socket to listen for incoming connections
 * @sock: socket structure
 * @len: (unused)
 *
 * Returns 0 on success, errno otherwise
 */

static int listen(struct socket *sock, int len)
{
	struct sock *sk = sock->sk;
	int res;

	lock_sock(sk);

	if (sock->state == SS_READY)
		res = -EOPNOTSUPP;
	else if (sock->state != SS_UNCONNECTED)
		res = -EINVAL;
	else {
		sock->state = SS_LISTENING;
		res = 0;
	}

	release_sock(sk);
	return res;
}

/**
 * accept - wait for connection request
 * @sock: listening socket
 * @newsock: new socket that is to be connected
 * @flags: file-related flags associated with socket
 *
 * Returns 0 on success, errno otherwise
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static int accept(struct socket *sock, struct socket *new_sock, int flags, bool kern)
#else
static int accept(struct socket *sock, struct socket *new_sock, int flags)
#endif
{
	struct sock *sk = sock->sk;
	struct sk_buff *buf;
	int res;

	lock_sock(sk);

	if (sock->state == SS_READY) {
		res = -EOPNOTSUPP;
		goto exit;
	}
	if (sock->state != SS_LISTENING) {
		res = -EINVAL;
		goto exit;
	}

	while (skb_queue_empty(&sk->sk_receive_queue)) {
		if (flags & O_NONBLOCK) {
			res = -EWOULDBLOCK;
			goto exit;
		}
		release_sock(sk);
		res = wait_event_interruptible(* SK_SLEEP(sk),
				(!skb_queue_empty(&sk->sk_receive_queue)));
		lock_sock(sk);
		if (res)
			goto exit;
	}

	buf = skb_peek(&sk->sk_receive_queue);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	res = tipc_create(sock_net(sock->sk), new_sock, 0, 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
	res = tipc_create(sock_net(sock->sk), new_sock, 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	res = tipc_create(sock->sk->sk_net, new_sock, 0);
#else
	res = tipc_create(new_sock, 0);
#endif
	if (!res) {
		struct sock *new_sk = new_sock->sk;
		struct tipc_sock *new_tsock = tipc_sk(new_sk);
		struct tipc_port *new_tport = new_tsock->p;
		u32 new_ref = new_tport->ref;
		struct tipc_msg *msg = buf_msg(buf);

		lock_sock(new_sk);

		/*
		 * Reject any stray messages received by new socket
		 * before the socket lock was taken (very, very unlikely)
		 */

		reject_rx_queue(new_sk);

		/* Connect new socket to it's peer */

		new_tsock->peer_name.ref = msg_origport(msg);
		new_tsock->peer_name.node = msg_orignode(msg);
		tipc_connect2port(new_ref, &new_tsock->peer_name);
		new_sock->state = SS_CONNECTED;

		tipc_set_portimportance(new_ref, msg_importance(msg));
		if (msg_named(msg)) {
			new_tport->conn_type = msg_nametype(msg);
			new_tport->conn_instance = msg_nameinst(msg);
		}

		/*
		 * Respond to 'SYN-' by discarding it & returning 'ACK'-.
		 * Respond to 'SYN+' by queuing it on new socket.
		 */

		msg_dbg(msg,"<ACC<: ");
		if (!msg_data_sz(msg)) {
			struct msghdr m = {NULL,};

			advance_rx_queue(sk);
            __send_packet(new_sock, &m, 0);
		} else {
			__skb_dequeue(&sk->sk_receive_queue);
			__skb_queue_head(&new_sk->sk_receive_queue, buf);
		}
		release_sock(new_sk);
	}
exit:
	release_sock(sk);
	return res;
}

/**
 * shutdown - shutdown socket connection
 * @sock: socket structure
 * @how: direction to close (must be SHUT_RDWR)
 *
 * Terminates connection (if necessary), then purges socket's receive queue.
 *
 * Returns 0 on success, errno otherwise
 */

static int shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport = tipc_sk_port(sk);
	struct sk_buff *buf;
	int res;

	if (how != SHUT_RDWR)
		return -EINVAL;

	lock_sock(sk);

	switch (sock->state) {
	case SS_CONNECTING:
	case SS_CONNECTED:

		/* Disconnect and send a 'FIN+' or 'FIN-' message to peer */
restart:
		buf = __skb_dequeue(&sk->sk_receive_queue);
		if (buf) {
			atomic_dec(&tipc_queue_size);
			if (buf_handle(buf) != msg_data(buf_msg(buf))) {
				buf_discard(buf);
				goto restart;
			}
			tipc_disconnect(tport->ref);
			tipc_reject_msg(buf, TIPC_CONN_SHUTDOWN);
		} else {
			tipc_shutdown(tport->ref);
		}

		sock->state = SS_DISCONNECTING;

		/* fall through */

	case SS_DISCONNECTING:

		/* Discard any unreceived messages; wake up sleeping tasks */

		discard_rx_queue(sk);
		if (waitqueue_active( SK_SLEEP(sk)))
			wake_up_interruptible( SK_SLEEP(sk));
		res = 0;
		break;

	default:
		res = -ENOTCONN;
	}

	release_sock(sk);
	return res;
}

/**
 * setsockopt - set socket option
 * @sock: socket structure
 * @lvl: option level
 * @opt: option identifier
 * @ov: pointer to new option value
 * @ol: length of option value
 *
 * For stream sockets only, accepts and ignores all IPPROTO_TCP options
 * (to ease compatibility).
 *
 * Returns 0 on success, errno otherwise
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static int setsockopt(struct socket *sock, int lvl, int opt,
			   sockptr_t ov, unsigned int ol)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
static int setsockopt(struct socket *sock,
		      int lvl, int opt, char __user *ov, unsigned int ol)
#else
static int setsockopt(struct socket *sock,
		      int lvl, int opt, char __user *ov, int ol)
#endif
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport = tipc_sk_port(sk);
	u32 value;
	int res;

	if ((lvl == IPPROTO_TCP) && (sock->type == SOCK_STREAM))
		return 0;
	if (lvl != SOL_TIPC)
		return -ENOPROTOOPT;
	if (ol < sizeof(value))
		return -EINVAL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	if ((res = copy_from_sockptr(&value, ov, sizeof(u32))))
#else
	if ((res = get_user(value, (u32 __user *)ov)))
#endif
		return res;

	lock_sock(sk);

	switch (opt) {
	case TIPC_IMPORTANCE:
		res = tipc_set_portimportance(tport->ref, value);
        tport->sk_priority = value + TIPC_PRI_DATA_PIPE;
        if (tport->sk_priority > TIPC_PRI_DATA_SSP)
            tport->sk_priority = TIPC_PRI_DATA_SSP;
		break;
	case TIPC_SRC_DROPPABLE:
		if (sock->type != SOCK_STREAM)
			res = tipc_set_portunreliable(tport->ref, value);
		else
			res = -ENOPROTOOPT;
		break;
	case TIPC_DEST_DROPPABLE:
		res = tipc_set_portunreturnable(tport->ref, value);
		break;
	case TIPC_CONN_TIMEOUT:
		tipc_sk(sk)->conn_timeout = msecs_to_jiffies(value);
		/* no need to set "res", since already 0 at this point */
		break;
	/* tipc_priority */
	case TIPC_PRIORITY:
		if (value <= TIPC_PRI_DATA_SSP &&
			value >= TIPC_PRI_DATA_PIPE) {
			tport->sk_priority = value;
			break;
		}
		res = -EINVAL;
		break;
	default:
		res = -EINVAL;
	}

	release_sock(sk);

	return res;
}

/**
 * getsockopt - get socket option
 * @sock: socket structure
 * @lvl: option level
 * @opt: option identifier
 * @ov: receptacle for option value
 * @ol: receptacle for length of option value
 *
 * For stream sockets only, returns 0 length result for all IPPROTO_TCP options
 * (to ease compatibility).
 *
 * Returns 0 on success, errno otherwise
 */

static int getsockopt(struct socket *sock,
		      int lvl, int opt, char __user *ov, int __user *ol)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport = tipc_sk_port(sk);
	int len;
	u32 value;
	int res;

	if ((lvl == IPPROTO_TCP) && (sock->type == SOCK_STREAM))
		return put_user(0, ol);
	if (lvl != SOL_TIPC)
		return -ENOPROTOOPT;
	if ((res = get_user(len, ol)))
		return res;

	lock_sock(sk);

	switch (opt) {
	case TIPC_IMPORTANCE:
		res = tipc_portimportance(tport->ref, &value);
		break;
	case TIPC_SRC_DROPPABLE:
		res = tipc_portunreliable(tport->ref, &value);
		break;
	case TIPC_DEST_DROPPABLE:
		res = tipc_portunreturnable(tport->ref, &value);
		break;
	case TIPC_CONN_TIMEOUT:
		value = jiffies_to_msecs(tipc_sk(sk)->conn_timeout);
		/* no need to set "res", since already 0 at this point */
		break;
	case TIPC_NODE_RECVQ_DEPTH:
		value = (u32)atomic_read(&tipc_queue_size);
		break;
	case TIPC_SOCK_RECVQ_DEPTH:
		value = skb_queue_len(&sk->sk_receive_queue);
		break;
	/* tipc_priority */
	case TIPC_PRIORITY:
		value = tport->sk_priority;
		break;
	default:
		res = -EINVAL;
	}

	release_sock(sk);

	if (res) {
		/* "get" failed */
	}
	else if (len < sizeof(value)) {
		res = -EINVAL;
	}
	else if (copy_to_user(ov, &value, sizeof(value))) {
		res = -EFAULT;
	}
	else {
		res = put_user(sizeof(value), ol);
	}

	return res;
}

/**
 * Protocol switches for the various types of TIPC sockets
 */

static const struct proto_ops msg_ops = {
	.owner 		= THIS_MODULE,
	.family		= AF_TIPC,
	.release	= release,
	.bind		= bind,
	.connect	= connect,
	.socketpair	= sock_no_socketpair,
	.accept		= accept,
	.getname	= get_name,
	.poll		= poll,
	.ioctl		= sock_no_ioctl,
	.listen		= listen,
	.shutdown	= shutdown,
	.setsockopt	= setsockopt,
	.getsockopt	= getsockopt,
	.sendmsg	= send_msg,
	.recvmsg	= recv_msg,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 11, 0)
	.sendpage	= sock_no_sendpage,
#endif
	.mmap		= sock_no_mmap
};

static const struct proto_ops packet_ops = {
	.owner 		= THIS_MODULE,
	.family		= AF_TIPC,
	.release	= release,
	.bind		= bind,
	.connect	= connect,
	.socketpair	= sock_no_socketpair,
	.accept		= accept,
	.getname	= get_name,
	.poll		= poll,
	.ioctl		= sock_no_ioctl,
	.listen		= listen,
	.shutdown	= shutdown,
	.setsockopt	= setsockopt,
	.getsockopt	= getsockopt,
	.sendmsg	= send_packet,
	.recvmsg	= recv_msg,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 11, 0)
	.sendpage	= sock_no_sendpage,
#endif
	.mmap		= sock_no_mmap
};

static const struct proto_ops stream_ops = {
	.owner 		= THIS_MODULE,
	.family		= AF_TIPC,
	.release	= release,
	.bind		= bind,
	.connect	= connect,
	.socketpair	= sock_no_socketpair,
	.accept		= accept,
	.getname	= get_name,
	.poll		= poll,
	.ioctl		= sock_no_ioctl,
	.listen		= listen,
	.shutdown	= shutdown,
	.setsockopt	= setsockopt,
	.getsockopt	= getsockopt,
	.sendmsg	= send_stream,
	.recvmsg	= recv_stream,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 11, 0)
	.sendpage	= sock_no_sendpage,
#endif
	.mmap		= sock_no_mmap
};

static struct net_proto_family tipc_family_ops = {
	.owner 		= THIS_MODULE,
	.family		= AF_TIPC,
	.create		= tipc_create
};

static struct proto tipc_proto = {
	.name		= "TIPC",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct tipc_sock)
};

/**
 * tipc_socket_init - initialize TIPC socket interface
 *
 * Returns 0 on success, errno otherwise
 */
int tipc_socket_init(void)
{
	int res;

	res = proto_register(&tipc_proto, 1);
	if (res) {
		err("Failed to register TIPC protocol type\n");
		goto out;
	}

	res = sock_register(&tipc_family_ops);
	if (res) {
		err("Failed to register TIPC socket type\n");
		proto_unregister(&tipc_proto);
		goto out;
	}

	sockets_enabled = 1;
 out:
	return res;
}

/**
 * tipc_socket_stop - stop TIPC socket interface
 */

void tipc_socket_stop(void)
{
	if (!sockets_enabled)
		return;

	sockets_enabled = 0;
	sock_unregister(tipc_family_ops.family);
	proto_unregister(&tipc_proto);
}

#else

/*
 * Dummy routines used when socket API is not included
 */

int tipc_socket_init(void)
{
	return 0;
}

void tipc_socket_stop(void)
{
	/* do nothing */
}

#endif
