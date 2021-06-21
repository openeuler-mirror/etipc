// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET        An implementation of the TCP/IP protocol suite for the LINUX
 *        operating system.  INET is implemented using the  BSD Socket
 *        interface as the means of communication with the user level.
 *
 *        PACKET - implements raw packet sockets.
 *
 * Authors:    Ross Biro
 *        Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *        Alan Cox, <gw4pts@gw4pts.ampr.org>
 *
 * Fixes:
 *        Alan Cox    :    verify_area() now used correctly
 *        Alan Cox    :    new skbuff lists, look ma no backlogs!
 *        Alan Cox    :    tidied skbuff lists.
 *        Alan Cox    :    Now uses generic datagram routines I
 *                    added. Also fixed the peek/read crash
 *                    from all old Linux datagram code.
 *        Alan Cox    :    Uses the improved datagram code.
 *        Alan Cox    :    Added NULL's for socket options.
 *        Alan Cox    :    Re-commented the code.
 *        Alan Cox    :    Use new kernel side addressing
 *        Rob Janssen    :    Correct MTU usage.
 *        Dave Platt    :    Counter leaks caused by incorrect
 *                    interrupt locking and some slightly
 *                    dubious gcc output. Can you read
 *                    compiler: it said _VOLATILE_
 *    Richard Kooijman    :    Timestamp fixes.
 *        Alan Cox    :    New buffers. Use sk->mac.raw.
 *        Alan Cox    :    sendmsg/recvmsg support.
 *        Alan Cox    :    Protocol setting support
 *    Alexey Kuznetsov    :    Untied from IPv4 stack.
 *    Cyrus Durgin        :    Fixed kerneld for kmod.
 *    Michal Ostrowski        :       Module initialization cleanup.
 *         Ulises Alonso        :       Frame number limit removal and
 *                                      packet_set_ring memory leak.
 *        Eric Biederman    :    Allow for > 8 byte hardware addresses.
 *                    The convention is that longer addresses
 *                    will simply extend the hardware address
 *                    byte arrays at the end of sockaddr_ll
 *                    and packet_mreq.
 *        Johann Baudy    :    Added TX RING.
 *
 *        This program is free software; you can redistribute it and/or
 *        modify it under the terms of the GNU General Public License
 *        as published by the Free Software Foundation; either version
 *        2 of the License, or (at your option) any later version.
 *
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/io.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/poll.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/if_vlan.h>
#include <linux/virtio_net.h>
#include <linux/net.h>

#ifdef CONFIG_INET
#include <net/inet_common.h>
#endif

#include "net/tipc/tipc_plugin_msg.h"
#include "linux/tipc_config.h"
#include "linux/tipc.h"
#include "tipc_link.h"
#include "tipc_node.h"
#include "tipc_name_table.h"
#include "tipc_bearer.h"
#include "tipc_raw_socket.h"
/*
   Assumptions:
   - if device has no dev->hard_header routine, it adds and removes ll header
     inside itself. In this case ll header is invisible outside of device,
     but higher levels still should reserve dev->hard_header_len.
     Some devices are enough clever to reallocate skb, when header
     will not fit to reserved space (tunnel), another ones are silly
     (PPP).
   - packet socket receives packets with pulled ll header,
     so that SOCK_RAW should push it back.

On receive:
-----------

Incoming, dev->hard_header!=NULL
   mac_header -> ll header
   data       -> data

Outgoing, dev->hard_header!=NULL
   mac_header -> ll header
   data       -> ll header

Incoming, dev->hard_header==NULL
   mac_header -> UNKNOWN position. It is very likely, that it points to ll
         header.  PPP makes it, that is wrong, because introduce
         assymetry between rx and tx paths.
   data       -> data

Outgoing, dev->hard_header==NULL
   mac_header -> data. ll header is still not built!
   data       -> data

Resume
  If dev->hard_header==NULL we are unlikely to restore sensible ll header.


On transmit:
------------

dev->hard_header != NULL
   mac_header -> ll header
   data       -> ll header

dev->hard_header == NULL (ll header is added by device, we cannot control it)
   mac_header -> data
   data       -> data

   We should set nh.raw on output to correct posistion,
   packet classifier depends on it.
 */

/* Private packet socket structures. */

struct packet_mclist {
    struct packet_mclist    *next;
    int            ifindex;
    int            count;
    unsigned short        type;
    unsigned short        alen;
    unsigned char        addr[MAX_ADDR_LEN];
};
/* identical to struct packet_mreq except it has
 * a longer address field.
 */
struct packet_mreq_max {
    int        mr_ifindex;
    unsigned short    mr_type;
    unsigned short    mr_alen;
    unsigned char    mr_address[MAX_ADDR_LEN];
};

static int packet_set_ring(struct sock *sk, struct tpacket_req *req,
        int closing, int tx_ring);

struct packet_ring_buffer {
    char            **pg_vec;
    unsigned int        head;
    unsigned int        frames_per_block;
    unsigned int        frame_size;
    unsigned int        frame_max;

    unsigned int        pg_vec_order;
    unsigned int        pg_vec_pages;
    unsigned int        pg_vec_len;

    atomic_t        pending;
};

static void packet_flush_mclist(struct sock *sk);

struct packet_sock {
    /* struct sock has to be the first member of packet_sock */
    struct sock        sk;
    struct tpacket_stats    stats;
    struct packet_ring_buffer    rx_ring;
    struct packet_ring_buffer    tx_ring;
    int                 copy_thresh;
    spinlock_t          bind_lock;
    struct mutex        pg_vec_lock;
    unsigned int        running:1,    /* prot_hook is attached*/
                        auxdata:1,
                        origdev:1,
                        has_vnet_hdr:1;
    int                 ifindex;      /* bound device        */
    __be16              num;
    struct packet_mclist    *mclist;
    atomic_t                 mapped;
    enum tpacket_versions    tp_version;
    unsigned int             tp_hdrlen;
    unsigned int             tp_reserve;
    unsigned int             tp_loss:1;
    struct packet_type       prot_hook ____cacheline_aligned_in_smp;
    struct packet_type       prot_hook_ext[TIPC_MAX_BEARERS] ____cacheline_aligned_in_smp;
};



struct packet_skb_cb {
    unsigned int origlen;
    union {
        struct sockaddr_pkt pkt;
        struct sockaddr_ll ll;
    } sa;
};

#define PACKET_SKB_CB(__skb)    ((struct packet_skb_cb *)((__skb)->cb))
static void __packet_set_status(struct packet_sock *po, void *frame, int status)
{
    union {
        struct tpacket_hdr *h1;
        struct tpacket2_hdr *h2;
        void *raw;
    } h;

    h.raw = frame;
    switch (po->tp_version) {
    case TPACKET_V1:
        h.h1->tp_status = status;
        flush_dcache_page(virt_to_page(&h.h1->tp_status));
        break;
    case TPACKET_V2:
        h.h2->tp_status = status;
        flush_dcache_page(virt_to_page(&h.h2->tp_status));
        break;
    default:
        pr_err("TPACKET version not supported\n");
        BUG();
    }

    smp_wmb();
}

static int __packet_get_status(struct packet_sock *po, void *frame)
{
    union {
        struct tpacket_hdr *h1;
        struct tpacket2_hdr *h2;
        void *raw;
    } h;

    smp_rmb();

    h.raw = frame;
    switch (po->tp_version) {
    case TPACKET_V1:
        flush_dcache_page(virt_to_page(&h.h1->tp_status));
        return h.h1->tp_status;
    case TPACKET_V2:
        flush_dcache_page(virt_to_page(&h.h2->tp_status));
        return h.h2->tp_status;
    default:
        pr_err("TPACKET version not supported\n");
        BUG();
        return 0;
    }
}

static void *packet_lookup_frame(struct packet_sock *po,
        struct packet_ring_buffer *rb,
        unsigned int position,
        int status)
{
    unsigned int pg_vec_pos, frame_offset;
    union {
        struct tpacket_hdr *h1;
        struct tpacket2_hdr *h2;
        void *raw;
    } h;

    pg_vec_pos = position / rb->frames_per_block;
    frame_offset = position % rb->frames_per_block;

    h.raw = rb->pg_vec[pg_vec_pos] + (frame_offset * rb->frame_size);

    if (status != __packet_get_status(po, h.raw))
        return NULL;

    return h.raw;
}

static inline void *packet_current_frame(struct packet_sock *po,
        struct packet_ring_buffer *rb,
        int status)
{
    return packet_lookup_frame(po, rb, rb->head, status);
}

static inline void *packet_previous_frame(struct packet_sock *po,
        struct packet_ring_buffer *rb,
        int status)
{
    unsigned int previous = rb->head ? rb->head - 1 : rb->frame_max;
    return packet_lookup_frame(po, rb, previous, status);
}

static inline void packet_increment_head(struct packet_ring_buffer *buff)
{
    buff->head = buff->head != buff->frame_max ? buff->head+1 : 0;
}

static inline struct packet_sock *pkt_sk(struct sock *sk)
{
    return (struct packet_sock *)sk;
}

static void packet_sock_destruct(struct sock *sk)
{
    WARN_ON(atomic_read(&sk->sk_rmem_alloc));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    WARN_ON(refcount_read(&sk->sk_wmem_alloc));
#else
    WARN_ON(atomic_read(&sk->sk_wmem_alloc));
#endif

    if (!sock_flag(sk, SOCK_DEAD)) {
        pr_err("Attempt to release alive packet socket: %p\n", sk);
        return;
    }

    sk_refcnt_debug_dec(sk);
}


static const struct proto_ops raw_packet_ops;

static const struct proto_ops raw_packet_ops_spkt;

/*
 *    Output a raw packet to a device layer. This bypasses all the other
 *    protocol layers and you must therefore supply it with a complete frame
 */
static int packet_sendmsg_spkt(TIPC_KIOCB struct socket *sock,
                   struct msghdr *msg, size_t len)
{
    struct sock *sk = sock->sk;
    struct sockaddr_pkt *saddr = (struct sockaddr_pkt *)msg->msg_name;
    struct sk_buff *skb = NULL;
    struct net_device *dev;
    __be16 proto = 0;
    int err;

    /*
     *    Get and verify the address.
     */

    if (saddr) {
        if (msg->msg_namelen < sizeof(struct sockaddr))
            return -EINVAL;
        if (msg->msg_namelen == sizeof(struct sockaddr_pkt))
            proto = saddr->spkt_protocol;
    } else
        return -ENOTCONN;    /* SOCK_PACKET must be sent giving an address */

    /*
     *    Find the device first to size check it
     */

    saddr->spkt_device[13] = 0;
retry:
    rcu_read_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)	
    dev = dev_get_by_name_rcu(sock_net(sk), saddr->spkt_device);
#else
    dev = dev_get_by_name(sock_net(sk), saddr->spkt_device);
#endif
    err = -ENODEV;
    if (dev == NULL)
        goto out_unlock;

    err = -ENETDOWN;
    if (!(dev->flags & IFF_UP))
        goto out_unlock;

    /*
     * You may not queue a frame bigger than the mtu. This is the lowest level
     * raw protocol and you must do your own fragmentation at this level.
     */

    err = -EMSGSIZE;
    if (len > dev->mtu + dev->hard_header_len)
        goto out_unlock;

    if (!skb) {
        size_t reserved = LL_RESERVED_SPACE(dev);
        unsigned int hhlen = dev->header_ops ? dev->hard_header_len : 0;

        rcu_read_unlock();
        skb = sock_wmalloc(sk, len + reserved, 0, GFP_KERNEL);
        if (skb == NULL)
            return -ENOBUFS;
        /* FIXME: Save some space for broken drivers that write a hard
         * header at transmission time by themselves. PPP is the notable
         * one here. This should really be fixed at the driver level.
         */
        skb_reserve(skb, reserved);
        skb_reset_network_header(skb);

        /* Try to align data part correctly */
        if (hhlen) {
            skb->data -= hhlen;
            skb->tail -= hhlen;
            if (len < hhlen)
                skb_reset_network_header(skb);
        }
        err = tipc_memcpy_from_msg(skb_put(skb, len), msg, len);
        if (err)
            goto out_free;
        goto retry;
    }


    skb->protocol = proto;
    skb->dev = dev;
    skb->priority = sk->sk_priority;
    skb->mark = sk->sk_mark;

    dev_queue_xmit(skb);
    rcu_read_unlock();
    return len;

out_unlock:
    rcu_read_unlock();
out_free:
    kfree_skb(skb);
    return err;
}

static inline unsigned int run_filter(struct sk_buff *skb, struct sock *sk,
                      unsigned int res)
{
    struct sk_filter *filter;

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
	rcu_read_lock();
	filter = rcu_dereference(sk->sk_filter);
	if (filter != NULL)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 1)
        res = bpf_prog_run_save_cb(filter->prog, skb);
#else
        res = SK_RUN_FILTER(filter, skb);
#endif
	rcu_read_unlock();
#else
    rcu_read_lock_bh();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)	
    filter = rcu_dereference_bh(sk->sk_filter);
#else
    filter = rcu_dereference(sk->sk_filter);
#endif
    if (filter != NULL)
        res = sk_run_filter(skb, filter->insns, filter->len);
    rcu_read_unlock_bh();
#endif


    return res;
}

/*
   This function makes lazy skb cloning in hope that most of packets
   are discarded by BPF.

   Note tricky part: we DO mangle shared skb! skb->data, skb->len
   and skb->cb are mangled. It works because (and until) packets
   falling here are owned by current CPU. Output packets are cloned
   by dev_queue_xmit_nit(), input packets are processed by net_bh
   sequencially, so that if we return skb to original state on exit,
   we will not harm anyone.
 */

static int packet_rcv(struct sk_buff *skb, struct net_device *dev,
              struct packet_type *pt, struct net_device *orig_dev)
{
    struct sock *sk;
    struct sockaddr_ll *sll;
    struct packet_sock *po;
    u8 *skb_head = skb->data;
    int skb_len = skb->len;
    unsigned int snaplen, res;

    if (skb->pkt_type == PACKET_LOOPBACK)
        goto drop;

    sk = pt->af_packet_priv;
    po = pkt_sk(sk);

    if (!net_eq(dev_net(dev), sock_net(sk)))
        goto drop;

    skb->dev = dev;

    if (dev->header_ops) {
        /* The device has an explicit notion of ll header,
           exported to higher levels.

           Otherwise, the device hides datails of it frame
           structure, so that corresponding packet head
           never delivered to user.
         */
        if (sk->sk_type != SOCK_DGRAM)
            skb_push(skb, skb->data - skb_mac_header(skb));
        else if (skb->pkt_type == PACKET_OUTGOING) {
            /* Special case: outgoing packets have ll header at head */
            skb_pull(skb, skb_network_offset(skb));
        }
    }

    snaplen = skb->len;

    res = run_filter(skb, sk, snaplen);
    if (!res)
        goto drop_n_restore;
    if (snaplen > res)
        snaplen = res;

    if (atomic_read(&sk->sk_rmem_alloc) + skb->truesize >=
        (unsigned)sk->sk_rcvbuf)
        goto drop_n_acct;

    if (skb_shared(skb)) {
        struct sk_buff *nskb = skb_clone(skb, GFP_ATOMIC);
        if (nskb == NULL)
            goto drop_n_acct;

        if (skb_head != skb->data) {
            skb->data = skb_head;
            skb->len = skb_len;
        }
        kfree_skb(skb);
        skb = nskb;
    }

    BUILD_BUG_ON(sizeof(*PACKET_SKB_CB(skb)) + MAX_ADDR_LEN - 8 >
             sizeof(skb->cb));

    sll = &PACKET_SKB_CB(skb)->sa.ll;
    sll->sll_family = AF_PACKET;
    sll->sll_hatype = dev->type;
    sll->sll_protocol = skb->protocol;
    sll->sll_pkttype = skb->pkt_type;
    if (unlikely(po->origdev))
        sll->sll_ifindex = orig_dev->ifindex;
    else
        sll->sll_ifindex = dev->ifindex;

    sll->sll_halen = dev_parse_header(skb, sll->sll_addr);

    PACKET_SKB_CB(skb)->origlen = skb->len;

    if (pskb_trim(skb, snaplen))
        goto drop_n_acct;

    skb_set_owner_r(skb, sk);
    skb->dev = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)	
    skb_dst_drop(skb);
#else
	dst_release(skb->dst);
	skb->dst = NULL;
#endif
    /* drop conntrack reference */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    nf_reset_ct(skb);
#else
    nf_reset(skb);
#endif

    spin_lock(&sk->sk_receive_queue.lock);
    po->stats.tp_packets++;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
    sock_skb_set_dropcount(sk, skb);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
    skb->dropcount = atomic_read(&sk->sk_drops);
#endif
    __skb_queue_tail(&sk->sk_receive_queue, skb);
    spin_unlock(&sk->sk_receive_queue.lock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)    
    sk->sk_data_ready(sk);
#else
    sk->sk_data_ready(sk, skb->len);
#endif
    return 0;

drop_n_acct:
    po->stats.tp_drops = atomic_inc_return(&sk->sk_drops);

drop_n_restore:
    if (skb_head != skb->data && skb_shared(skb)) {
        skb->data = skb_head;
        skb->len = skb_len;
    }
drop:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)		
    consume_skb(skb);
#else	
	kfree_skb(skb);
#endif	
    return 0;
}

static int tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
               struct packet_type *pt, struct net_device *orig_dev)
{
    struct sock *sk;
    struct packet_sock *po;
    struct sockaddr_ll *sll;
    union {
        struct tpacket_hdr *h1;
        struct tpacket2_hdr *h2;
        void *raw;
    } h;
    u8 *skb_head = skb->data;
    int skb_len = skb->len;
    unsigned int snaplen, res;
    unsigned long status = TP_STATUS_LOSING|TP_STATUS_USER;
    unsigned short macoff, netoff, hdrlen;
    struct sk_buff *copy_skb = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    struct timespec64 tv;
    struct timespec64 ts;
#else
    struct timeval tv;
    struct timespec ts;
#endif

    if (skb->pkt_type == PACKET_LOOPBACK)
        goto drop;

    sk = pt->af_packet_priv;
    po = pkt_sk(sk);

    if (!net_eq(dev_net(dev), sock_net(sk)))
        goto drop;

    if (dev->header_ops) {
        if (sk->sk_type != SOCK_DGRAM)
            skb_push(skb, skb->data - skb_mac_header(skb));
        else if (skb->pkt_type == PACKET_OUTGOING) {
            /* Special case: outgoing packets have ll header at head */
            skb_pull(skb, skb_network_offset(skb));
        }
    }

    if (skb->ip_summed == CHECKSUM_PARTIAL)
        status |= TP_STATUS_CSUMNOTREADY;

    snaplen = skb->len;

    res = run_filter(skb, sk, snaplen);
    if (!res)
        goto drop_n_restore;
    if (snaplen > res)
        snaplen = res;

    if (sk->sk_type == SOCK_DGRAM) {
        macoff = netoff = TPACKET_ALIGN(po->tp_hdrlen) + 16 +
                  po->tp_reserve;
    } else {
        unsigned maclen = skb_network_offset(skb);
        netoff = TPACKET_ALIGN(po->tp_hdrlen +
                       (maclen < 16 ? 16 : maclen)) +
            po->tp_reserve;
        macoff = netoff - maclen;
    }

    if (macoff + snaplen > po->rx_ring.frame_size) {
        if (po->copy_thresh &&
            atomic_read(&sk->sk_rmem_alloc) + skb->truesize <
            (unsigned)sk->sk_rcvbuf) {
            if (skb_shared(skb)) {
                copy_skb = skb_clone(skb, GFP_ATOMIC);
            } else {
                copy_skb = skb_get(skb);
                skb_head = skb->data;
            }
            if (copy_skb)
                skb_set_owner_r(copy_skb, sk);
        }
        snaplen = po->rx_ring.frame_size - macoff;
        if ((int)snaplen < 0)
            snaplen = 0;
    }

    spin_lock(&sk->sk_receive_queue.lock);
    h.raw = packet_current_frame(po, &po->rx_ring, TP_STATUS_KERNEL);
    if (!h.raw)
        goto ring_is_full;
    packet_increment_head(&po->rx_ring);
    po->stats.tp_packets++;
    if (copy_skb) {
        status |= TP_STATUS_COPY;
        __skb_queue_tail(&sk->sk_receive_queue, copy_skb);
    }
    if (!po->stats.tp_drops)
        status &= ~TP_STATUS_LOSING;
    spin_unlock(&sk->sk_receive_queue.lock);

    skb_copy_bits(skb, 0, h.raw + macoff, snaplen);

    switch (po->tp_version) {
    case TPACKET_V1:
        h.h1->tp_len = skb->len;
        h.h1->tp_snaplen = snaplen;
        h.h1->tp_mac = macoff;
        h.h1->tp_net = netoff;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (skb->tstamp)
            tv = ktime_to_timespec64(skb->tstamp);
#else
        if (skb->tstamp.tv64)
            tv = ktime_to_timeval(skb->tstamp);
#endif
        else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
            do_gettimeofday_snapshot(&tv);
        h.h1->tp_sec = tv.tv_sec;
        h.h1->tp_usec = ts.tv_nsec / NSEC_PER_USEC;
#else
            do_gettimeofday(&tv);
        h.h1->tp_sec = tv.tv_sec;
        h.h1->tp_usec = tv.tv_usec;
#endif
        hdrlen = sizeof(*h.h1);
        break;
    case TPACKET_V2:
        h.h2->tp_len = skb->len;
        h.h2->tp_snaplen = snaplen;
        h.h2->tp_mac = macoff;
        h.h2->tp_net = netoff;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (skb->tstamp)
            ts = ktime_to_timespec64(skb->tstamp);
#else
        if (skb->tstamp.tv64)
            ts = ktime_to_timespec(skb->tstamp);
#endif
        else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
            ktime_get_ts64(&ts);
#else
            getnstimeofday(&ts);
#endif
        h.h2->tp_sec = ts.tv_sec;
        h.h2->tp_nsec = ts.tv_nsec;
        h.h2->tp_vlan_tci = tipc_vlan_tci(skb);
        hdrlen = sizeof(*h.h2);
        break;
    default:
        BUG();
    }

    sll = h.raw + TPACKET_ALIGN(hdrlen);
    sll->sll_halen = dev_parse_header(skb, sll->sll_addr);
    sll->sll_family = AF_PACKET;
    sll->sll_hatype = dev->type;
    sll->sll_protocol = skb->protocol;
    sll->sll_pkttype = skb->pkt_type;
    if (unlikely(po->origdev))
        sll->sll_ifindex = orig_dev->ifindex;
    else
        sll->sll_ifindex = dev->ifindex;

    __packet_set_status(po, h.raw, status);
    smp_mb();
    {
        struct page *p_start, *p_end;
        u8 *h_end = h.raw + macoff + snaplen - 1;

        p_start = virt_to_page(h.raw);
        p_end = virt_to_page(h_end);
        while (p_start <= p_end) {
            flush_dcache_page(p_start);
            p_start++;
        }
    }

    tipc_sk_data_ready(sk);

drop_n_restore:
    if (skb_head != skb->data && skb_shared(skb)) {
        skb->data = skb_head;
        skb->len = skb_len;
    }
drop:
    kfree_skb(skb);
    return 0;

ring_is_full:
    po->stats.tp_drops++;
    spin_unlock(&sk->sk_receive_queue.lock);
    tipc_sk_data_ready(sk);
    kfree_skb(copy_skb);
    goto drop_n_restore;
}


int tipc_raw_build_skb(struct sk_buff **skb,
                                struct msghdr *msg,
                                size_t len)
{
    struct sk_buff *sk_buff = NULL;
    struct iovec const *msg_sect = NULL;
    u32 num_sect;
    u32 pos, res, cnt;
    char *put_char;

    /* build_skb */
    sk_buff = buf_acquire(len);
    if(!sk_buff)
        return -ENOBUFS;

    msg_sect = get_msgiov(msg); 
    num_sect = get_msgiovlen(msg);
    
    /* 填充数据 */
	for (pos = 0, res = 1, cnt = 0; res && (cnt < num_sect); cnt++) 
    {
		res = !copy_from_user(sk_buff->data + pos, 
				      msg_sect[cnt].iov_base, 
				      msg_sect[cnt].iov_len);
        pos += msg_sect[cnt].iov_len;
	}

    put_char = (char *)sk_buff->data;
    *skb = sk_buff;
    
    return 0;   
}


int tipc_raw_send_skb( struct sk_buff *skb)
{
    u32 res = 0;
        
    /* send_skb */
    res = dev_queue_xmit(skb);
    if (res > 0 && (res = net_xmit_errno(res)) != 0)
    {
        err("send skb fail res = %d \n", res);
        return res;
    }
    
    /* 此处入队列后，就不需要释放 */
    return res;
}

int tipc_raw_send2name( struct msghdr *msg,
                                 struct sock *sk,
                                 size_t len)
{
    struct tipc_node *node    = NULL;
    struct tipc_name *name    = NULL;
    struct sk_buff *skb       = NULL;
    struct sk_buff *copy_skb  = NULL;
    struct bearer *b_ptr      = NULL;
    struct link *l_ptr        = NULL;
    struct net_device *dev    = NULL;
    struct packet_sock *po = pkt_sk(sk);
    
    u32 destnode = 0;
    u32 destport = 0;
    u32 res      = 0;
    u32 i        = 0;
    char src_mac[ETH_ALEN];
    char dst_mac[ETH_ALEN];
    
    name = &((struct sockaddr_tipc *)msg->msg_name)->addr.name.name;

    /* find the dest node by name */
    destport = tipc_nametbl_translate(name->type, name->instance, &destnode);
    
    if ( (!destport) || (!destnode) || (destnode == tipc_own_addr) )
    {
        info("destnode find err destport = %d, destnode = %d, tipc_own_addr = %d\n",
            destport, destnode, tipc_own_addr);
        goto out;
    }

    /* build skb 之前本函数tipc_raw_build_skb在tipc_node_lock 之后 由于MIPS和POWERPC的 
    copy_from_user实现不一致 MIPS会放权(关闭中断获取锁之后不允许放权) 
    将tipc_raw_build_skb提前 预防一些死锁等问题 */
    res = tipc_raw_build_skb(&skb, msg, len);
    if (0 != res)
    {
        err("tipc_raw_send_skb failed res = %d\n", res);
        goto out;
    }

    read_lock_bh(&tipc_net_lock); 
    
    node = tipc_net_select_node(destnode);
    if (NULL == node) 
    {
        read_unlock_bh(&tipc_net_lock); 
        goto out;
    }
    
    tipc_node_lock(node); 

        
    for (i=0; i < 2; ++i)
    {
        if ( node->active_links[i] == NULL)
            break;
        
        if ((1 == i) && ((node->active_links[0]) == (node->active_links[1])))
            break;
    
        memset(src_mac, 0, ETH_ALEN);
        memset(dst_mac, 0, ETH_ALEN);

        l_ptr = node->active_links[i];
        b_ptr = l_ptr->b_ptr;

    	copy_skb = skb_copy(skb, GFP_ATOMIC);
        if (NULL == copy_skb)
        {
            err("copy or clone skb failed...\n");
            continue;
        }

        memcpy(src_mac, &(l_ptr->b_ptr->publ.addr.value[4]), ETH_ALEN);
        memcpy(dst_mac, &(l_ptr->media_addr.value[4]), ETH_ALEN);
        
        tipc_media_fill_mac(copy_skb, src_mac, dst_mac);

        /* check mtu */
        res = tipc_media_check_mtu(b_ptr, len);
        if (0 != res)
        {
            err("tipc_media_check_mtu fail res = %d\n", res);
            buf_discard(copy_skb);
            continue;
        }
        
        dev = tipc_media_get_dev(l_ptr->b_ptr);
        if (!dev)
        {
            buf_discard(copy_skb);
            continue;
        }
        
        
        copy_skb->protocol = po->num;        
        copy_skb->dev = dev;
	    copy_skb->priority = sk->sk_priority;
	    copy_skb->mark = sk->sk_mark;
        copy_skb->sk   = sk;
        
        res = tipc_raw_send_skb(copy_skb);
        if (0 != res)
            err("tipc_raw_send_skb failed res = %d\n", res);
    }
    
    buf_discard(skb);
    
    res = (res == 0) ? len : res;    
    tipc_node_unlock(node);
    read_unlock_bh(&tipc_net_lock);    
    return res;
    
out:
    if(skb)
        buf_discard(skb);
    if (destnode == tipc_own_addr)
    {
        warn("tipc_raw_send2name failed, because tipc raw socket cannot send to itself\n");
        return -EINVAL;
    }
    return -ENOENT;
}

int tipc_raw_multicast(struct msghdr *msg,
                             struct sock *sk,
                             size_t len)
{
    u32 res      = 0;
    u32 i        = 0;    
    struct sk_buff *skb       = NULL;
    struct sk_buff *copy_skb  = NULL;
    struct net_device *dev    = NULL;
    struct packet_sock *po = pkt_sk(sk);
    
    char src_mac[ETH_ALEN] = {0};

    /* build skb */
    res = tipc_raw_build_skb(&skb, msg, len);
    if (0 != res)
    {
        err("tipc_raw_build_skb failed res = %d\n", res);
        return res;
    }
    if(!tipc_bearers)
        return -EINVAL;
    
    for (i = 0; i < TIPC_MAX_BEARERS; i++) 
    {
        if (!tipc_bearers[i].active)
            continue;
        
    	copy_skb = skb_copy(skb, GFP_ATOMIC);
        if (NULL == copy_skb)
        {
            err("copy or clone skb failed...\n");
            continue;
        }
        
        /* get src_mac  */
        memcpy(&src_mac, &(tipc_bearers[i].publ.addr.value[4]), ETH_ALEN);
        
        /* fill src mac */
        tipc_media_fill_mac(copy_skb, src_mac, NULL);

        /* check mtu */
        res = tipc_media_check_mtu(&tipc_bearers[i], len);
        if (0 != res)
        {
            err("tipc_media_chech_mtu fail res = %d\n", res);
            buf_discard(copy_skb); 
            continue;
        }

        dev = tipc_media_get_dev(&tipc_bearers[i]);
        if (!dev)
        {
            buf_discard(copy_skb);
            continue;
        }
        
        
        copy_skb->protocol = po->num;
        copy_skb->dev = dev;
	    copy_skb->priority = sk->sk_priority;
	    copy_skb->mark = sk->sk_mark;
        copy_skb->sk = sk;
	    
        /* send skb */
        res = tipc_raw_send_skb(copy_skb);
        if (0 != res)
            err("tipc_raw_multicast send copy_skb failed, tipc_bearer is %s\n", 
                tipc_bearers[i].publ.name);
        
    }

    buf_discard(skb);
    
    res = (res == 0) ? len : res;
    return res;
}

/**
 * tipc_raw_dest_name_check - verify user is permitted to send to specified port name
 * @dest: destination address
 * @m: descriptor for message to be sent
 *
 * Prevents restricted configuration commands from being issued by
 * unauthorized users.
 *
 * Returns 0 if permission is granted, otherwise errno
 */

static int tipc_raw_dest_name_check(struct sockaddr_tipc *dest, struct msghdr *m)
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

int tipc_raw_calc_msg_len(struct msghdr *msg)
{
    int len = 0;
    int i = 0;

    for(; i < get_msgiovlen(msg); ++i)
    {
        len += get_msgiov(msg)->iov_len;
    }
    
    return len;    
}

static int tipc_raw_sendmsg(TIPC_KIOCB 
                                    struct socket *sock,
                                    struct msghdr *msg, 
                                    size_t len)
{
    struct sockaddr_tipc *dest = (struct sockaddr_tipc *)msg->msg_name;
    struct sock *sk = sock->sk;
    int res = -EINVAL;
    
    if (unlikely(!dest))
        return -EDESTADDRREQ;
    if (unlikely((msg->msg_namelen < sizeof(*dest)) 
        || (dest->family != AF_TIPC)))
        return -EINVAL;
 
    if (IOCB_LK)
        lock_sock(sk); 

    if (dest->addrtype == TIPC_ADDR_NAME) 
    {        
        if ((res = tipc_raw_dest_name_check(dest, msg)))
            goto exit;
        
        res = tipc_raw_send2name(msg, sk, len);
        goto exit;
    }
    else if (dest->addrtype == TIPC_ADDR_MCAST) 
    {        
        res = tipc_raw_multicast(msg, sk, len);
        goto exit;
    }
    else
        res = -ESOCKTNOSUPPORT;
    
exit:
    if (IOCB_LK)
        release_sock(sk);
    return res;    
}

/*
 *    Close a PACKET socket. This is fairly simple. We immediately go
 *    to 'closed' state and remove our protocol entry in the device list.
 */

static int tipc_raw_release(struct socket *sock)
{
    struct sock *sk = sock->sk;
    struct packet_sock *po;
    struct net *net;
    struct tpacket_req req;
    struct packet_type *pt = NULL;
    int i = 0;

    if (!sk)
        return 0;

    net = sock_net(sk);
    po = pkt_sk(sk);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    mutex_lock(&net->packet.sklist_lock);
    sk_del_node_init_rcu(sk);
    mutex_unlock(&net->packet.sklist_lock);

    preempt_disable();	
    sock_prot_inuse_add(net, sk->sk_prot, -1);
    preempt_enable();
    
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)

	spin_lock_bh(&net->packet.sklist_lock);
    sk_del_node_init_rcu(sk);
    sock_prot_inuse_add(net, sk->sk_prot, -1);
    spin_unlock_bh(&net->packet.sklist_lock);
	
#else

	write_lock_bh(&net->packet.sklist_lock);
	sk_del_node_init(sk);
	write_unlock_bh(&net->packet.sklist_lock);
	
#endif	

    spin_lock(&po->bind_lock);
    
    if (po->running) 
    {
        /*
         * Remove from protocol table
         */
        po->running = 0;
        po->num = 0;
        
        __sock_put(sk);
        
        for(i = 0; i < TIPC_MAX_BEARERS; i++)
        {
            pt = &po->prot_hook_ext[i];
            if (pt->type)
                __dev_remove_pack(pt);
        } 
    }
    
    spin_unlock(&po->bind_lock);

    
    packet_flush_mclist(sk);

    memset(&req, 0, sizeof(req));

    if (po->rx_ring.pg_vec)
        packet_set_ring(sk, &req, 1, 0);

    if (po->tx_ring.pg_vec)
        packet_set_ring(sk, &req, 1, 1);

    synchronize_net();
    /*
     *    Now the socket is dead. No more input will appear.
     */
    sock_orphan(sk);
    sock->sk = NULL;

    /* Purge queues */

    skb_queue_purge(&sk->sk_receive_queue);
    sk_refcnt_debug_release(sk);

    sock_put(sk);
    return 0;
}

void tipc_raw_unbind(struct sock *sk)
{
    int i = 0;
    struct packet_sock *po = pkt_sk(sk);
    struct packet_type *pt = NULL;
        
    for(i = 0; i < TIPC_MAX_BEARERS; i++)
    {
        pt = &po->prot_hook_ext[i];
        if (pt->type)
            dev_remove_pack(pt);
    }
}

void tipc_raw_do_bind(struct sock *sk, struct packet_type *pt, 
                                       struct net_device *dev, __be16 protocol)
{    
    pt->type = protocol;
    pt->dev  = dev;
    
    if (!dev || (dev->flags & IFF_UP)) 
    {
        dev_add_pack(pt);
    } 
    else 
    {
        err(" tipc_raw_do_bind net is down\n");
        sk->sk_err = ENETDOWN;
        if (!sock_flag(sk, SOCK_DEAD))
            sk->sk_error_report(sk);
    }
    return;
}

static int tipc_raw_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
    int i   = 0;
    int cnt = 0;
    struct sockaddr_ll *sll = (struct sockaddr_ll *)uaddr;
    struct bearer *b_ptr      = NULL; 
    struct net_device *dev    = NULL;
    struct sock *sk = sock->sk;
    
    extern struct bearer *tipc_bearers;

    struct packet_sock *po = pkt_sk(sk);
    struct packet_type *pt = NULL;
    
	if (addr_len < sizeof(struct sockaddr_ll))
		return -EINVAL;
	if (sll->sll_family != AF_PACKET)
		return -EINVAL;

    lock_sock(sk);
    /*coverity[lock]*/
    spin_lock(&po->bind_lock);
    
    
    /* unbind */
    if (!sll->sll_protocol)
    {
        info("tipc_raw_bind unbind..\n");
        if(!po->running)
            goto out_unlock;
        
        __sock_put(sk);
        po->running = 0;
        po->num = 0;
        spin_unlock(&po->bind_lock);

        for(i = 0; i < TIPC_MAX_BEARERS; i++)
        {
            pt = &po->prot_hook_ext[i];
            if (pt->type)
                dev_remove_pack(pt);
        } 
        /*coverity[double_lock]*/
        spin_lock(&po->bind_lock);
        goto out_unlock;
    }

    /* if running unbind first */
    if (po->running) 
    {       
        __sock_put(sk);
        po->running = 0;
        po->num = 0;
        spin_unlock(&po->bind_lock);
        
        for(i = 0; i < TIPC_MAX_BEARERS; i++)
        {
            pt = &po->prot_hook_ext[i];
            if (pt->type)
                dev_remove_pack(pt);
        }
        /*coverity[double_lock]*/
        spin_lock(&po->bind_lock);
    }
    
    po->num = sll->sll_protocol ? : pkt_sk(sk)->num;
    
    if(!po->num)
        goto out_unlock;
    
    for (i = 0; i < TIPC_MAX_BEARERS; ++i) 
    {
        if(!tipc_bearers)
            goto out_unlock;
        
        b_ptr = &tipc_bearers[i];
        if (!b_ptr->active)
            continue;

        dev = tipc_media_get_dev(b_ptr);
    	if (!dev)
    	    goto out_unlock;
        
        pt = &po->prot_hook_ext[cnt];

        /*
        与会人：
        PTN:   宋宏达、魏家道
        路由器：薛维、张健
        dopra： 汪飞
        背景： 快速感知的socket使用不标准，在tipc底层去转换了bind的协议类型，实际上根据协议要求，需要在上层转换。
        结论：ptn的代码已经被波分、ptn等多个产品线复用，如果改动，验证工作量巨大，而且容易出问题。所以针对快速感知
        的socket，在tipc底层做字节序转换，添加注释，防止后来人再继续用错。 后续创建socket，需要按照标准协议
        来搞。*/
        pt->type = htons(po->num);
        pt->dev  = dev;
        pt->func = packet_rcv;
        pt->af_packet_priv = sk;
        
        if (!dev || (dev->flags & IFF_UP)) 
            dev_add_pack(pt);
        else 
        {
            err(" tipc_raw_bind net is down\n");
            sk->sk_err = ENETDOWN;
            if (!sock_flag(sk, SOCK_DEAD))
                sk->sk_error_report(sk);
        }
        ++cnt;
    }

    sock_hold(sk);
    po->running = 1;

out_unlock: 
    spin_unlock(&po->bind_lock);
    release_sock(sk);
    return 0;
}

static struct proto packet_proto = {
    .name      = "PACKET",
    .owner      = THIS_MODULE,
    .obj_size = sizeof(struct packet_sock),
};

/*
 *    Create a packet of type SOCK_PACKET.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
int tipc_raw_create(struct net *net, struct socket *sock, int protocol, int kern)
#else
int tipc_raw_create(struct net *net, struct socket *sock, int protocol)
#endif
{
    struct sock *sk;
    struct packet_sock *po;
    __be16 proto = (__force __be16)protocol; /* weird, but documented */
    int res;

    info("tipc_raw_create enter..\n");

    /* 权限验证? */
    if (!capable(CAP_NET_RAW))
        return -EPERM;

    /* 协议簇验证 */
    if (sock->type != SOCK_RAW)
        return -ESOCKTNOSUPPORT;

    sock->state = SS_UNCONNECTED;
    
    /* 分配sk */    
    res = -ENOBUFS;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 1)
    sk = sk_alloc(net, PF_PACKET, GFP_KERNEL, &packet_proto, kern);
#else
    sk = sk_alloc(net, PF_PACKET, GFP_KERNEL, &packet_proto);
#endif

    if (sk == NULL)
        goto out;

    /* 设定sock的ops，即对应用户态的bind、connect诸如此类操作的动作 */
    sock->ops = &raw_packet_ops;

    /* 初始化sock结构(即sk)各成员，并设定与套接字socket(即sock)的关联 */
    sock_init_data(sock, sk);

    po = pkt_sk(sk);
    sk->sk_family = PF_PACKET;
    /*coverity[missing_lock]*/
    po->num = proto;

    /* 设定sk的destuct函数 */
    sk->sk_destruct = packet_sock_destruct;
    sk_refcnt_debug_inc(sk);

    /*
     *    Attach a protocol block
     */
     
    spin_lock_init(&po->bind_lock);
    mutex_init(&po->pg_vec_lock);
    
    #if 0  /* move to bind */
    po->prot_hook.func = packet_rcv;
    po->prot_hook.af_packet_priv = sk;

    if (proto)
    {
        po->prot_hook.type = proto;
        dev_add_pack(&po->prot_hook);
        sock_hold(sk);
        po->running = 1; /* when bind to set running = 1 */
    }
    #endif
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    mutex_lock(&net->packet.sklist_lock);
    sk_add_node_rcu(sk, &net->packet.sklist);
    mutex_unlock(&net->packet.sklist_lock);

    preempt_disable(); 
    sock_prot_inuse_add(net, &packet_proto, 1);
    preempt_enable();
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)

    spin_lock_bh(&net->packet.sklist_lock);
    sk_add_node_rcu(sk, &net->packet.sklist);
    sock_prot_inuse_add(net, &packet_proto, 1);
    spin_unlock_bh(&net->packet.sklist_lock);
#else

	write_lock_bh(&net->packet.sklist_lock);
	sk_add_node(sk, &net->packet.sklist);
	write_unlock_bh(&net->packet.sklist_lock);
	
#endif

    return 0;
out:
    err("tipc_raw_create leave res = %d..\n", res);
    return res;
}

/*
 *    Pull a packet from our receive queue and hand it to the user.
 *    If necessary we block.
 */

static int tipc_raw_recvmsg(TIPC_KIOCB struct socket *sock,
              struct msghdr *msg, size_t len, int flags)
{
    struct sock *sk = sock->sk;
    struct sk_buff *skb;
    int copied, err;
    struct sockaddr_ll *sll;
    int vnet_hdr_len = 0;
    
    err = -EINVAL;
    if (flags & ~(MSG_PEEK|MSG_DONTWAIT|MSG_TRUNC|MSG_CMSG_COMPAT))
        goto out;

#if 0
    /* What error should we return now? EUNATTACH? */
    if (pkt_sk(sk)->ifindex < 0)
        return -ENODEV;
#endif

    /*
     *    Call the generic datagram receiver. This handles all sorts
     *    of horrible races and re-entrancy so we can forget about it
     *    in the protocol layers.
     *
     *    Now it will return ENETDOWN, if device have just gone down,
     *    but then it will block.
     */

    skb = skb_recv_datagram(sk, flags, flags & MSG_DONTWAIT, &err);

    /*
     *    An error occurred so return it. Because skb_recv_datagram()
     *    handles the blocking we don't see and worry about blocking
     *    retries.
     */
    
    if (skb == NULL)
        goto out;

    if (pkt_sk(sk)->has_vnet_hdr) {
        struct virtio_net_hdr vnet_hdr = { 0 };
        err = -EINVAL;
        vnet_hdr_len = sizeof(vnet_hdr);
        /*coverity[unsigned_compare]*/
        if ((len < vnet_hdr_len))
            goto out_free;

        if (skb_is_gso(skb)) {
            struct skb_shared_info *sinfo = skb_shinfo(skb);
            /* This is a hint as to how much should be linear. */
            vnet_hdr.hdr_len = skb_headlen(skb);
            vnet_hdr.gso_size = sinfo->gso_size;
            if (sinfo->gso_type & SKB_GSO_TCPV4)
                vnet_hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
            else if (sinfo->gso_type & SKB_GSO_TCPV6)
                vnet_hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
            else if (sinfo->gso_type & SKB_GSO_UDP)
                vnet_hdr.gso_type = VIRTIO_NET_HDR_GSO_UDP;
			
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)			
            else if (sinfo->gso_type & SKB_GSO_FCOE)
                goto out_free;
#endif			
            else
                BUG();
            if (sinfo->gso_type & SKB_GSO_TCP_ECN)
                vnet_hdr.gso_type |= VIRTIO_NET_HDR_GSO_ECN;
        } else
            vnet_hdr.gso_type = VIRTIO_NET_HDR_GSO_NONE;
        if (skb->ip_summed == CHECKSUM_PARTIAL) {
            vnet_hdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
            vnet_hdr.csum_start = skb->csum_start -
                            skb_headroom(skb);
            vnet_hdr.csum_offset = skb->csum_offset;
        } /* else everything is zero */

        err = tipc_memcpy_to_msg(msg, (void *)&vnet_hdr, vnet_hdr_len);                     
        if (err < 0)
            goto out_free;
    }

    /*
     *    If the address length field is there to be filled in, we fill
     *    it in now.
     */

    sll = &PACKET_SKB_CB(skb)->sa.ll;
    if (sock->type == SOCK_PACKET)
        msg->msg_namelen = sizeof(struct sockaddr_pkt);
    else
        msg->msg_namelen = sll->sll_halen + offsetof(struct sockaddr_ll, sll_addr);

    /*
     *    You lose any data beyond the buffer you gave. If it worries a
     *    user program they can ask the device for its MTU anyway.
     */
    copied = skb->len;
    if (copied > len) {
        copied = len;
        msg->msg_flags |= MSG_TRUNC;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)	
    err = skb_copy_datagram_msg(skb, 0, msg, copied);
#else
    err = skb_copy_datagram_iovec(skb, 0, get_msgiov(msg), copied);
#endif

    if (err)
        goto out_free;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)	
    sock_recv_ts_and_drops(msg, sk, skb);
#else
    sock_recv_timestamp(msg, sk, skb);
#endif

    if (msg->msg_name)
        memcpy(msg->msg_name, &PACKET_SKB_CB(skb)->sa,
               msg->msg_namelen);

    if (pkt_sk(sk)->auxdata) {
        struct tpacket_auxdata aux;

        aux.tp_status = TP_STATUS_USER;
        if (skb->ip_summed == CHECKSUM_PARTIAL)
            aux.tp_status |= TP_STATUS_CSUMNOTREADY;
        aux.tp_len = PACKET_SKB_CB(skb)->origlen;
        aux.tp_snaplen = skb->len;
        aux.tp_mac = 0;
        aux.tp_net = skb_network_offset(skb);

        aux.tp_vlan_tci = tipc_vlan_tci(skb);
        put_cmsg(msg, SOL_PACKET, PACKET_AUXDATA, sizeof(aux), &aux);
    }

    /*
     *    Free or return the buffer as appropriate. Again this
     *    hides all the races and re-entrancy issues from us.
     */
    err = vnet_hdr_len + ((flags&MSG_TRUNC) ? skb->len : copied);

    if ((skb->data[12] == 0x37) && (skb->data[13] == 0x37))
    {
        info("skb->data_len = %d, skb->len = %d, err = %d\n", skb->data_len, skb->len, err);
    }
    
out_free:
    skb_free_datagram(sk, skb);
out:
    return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static int packet_getname_spkt(struct socket *sock, struct sockaddr *uaddr, int peer)
#else
static int packet_getname_spkt(struct socket *sock, struct sockaddr *uaddr,
                   int *uaddr_len, int peer)
#endif
{
    struct net_device *dev;
    struct sock *sk    = sock->sk;

    if (peer)
        return -EOPNOTSUPP;

    uaddr->sa_family = AF_PACKET;
    rcu_read_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)	
    dev = dev_get_by_index_rcu(sock_net(sk), pkt_sk(sk)->ifindex);
#else
    dev = dev_get_by_index(sock_net(sk), pkt_sk(sk)->ifindex);
#endif
    if (dev)
        /*coverity[buffer_size_warning]*/
        strncpy(uaddr->sa_data, dev->name, 14);
    else
        memset(uaddr->sa_data, 0, 14);
		
    rcu_read_unlock();
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    *uaddr_len = sizeof(*uaddr);
#endif

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static int packet_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
#else
static int packet_getname(struct socket *sock, struct sockaddr *uaddr,
              int *uaddr_len, int peer)
#endif
{
    struct net_device *dev;
    struct sock *sk = sock->sk;
    struct packet_sock *po = pkt_sk(sk);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)			
    DECLARE_SOCKADDR(struct sockaddr_ll *, sll, uaddr);
#else
	struct sockaddr_ll *sll = (struct sockaddr_ll*)uaddr;
#endif
    if (peer)
        return -EOPNOTSUPP;

    sll->sll_family = AF_PACKET;
    sll->sll_ifindex = po->ifindex;
    sll->sll_protocol = po->num;
    sll->sll_pkttype = 0;
    rcu_read_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)		
    dev = dev_get_by_index_rcu(sock_net(sk), po->ifindex);
#else
    dev = dev_get_by_index(sock_net(sk), po->ifindex);
#endif	
    if (dev) {
        sll->sll_hatype = dev->type;
        sll->sll_halen = dev->addr_len;
        memcpy(sll->sll_addr, dev->dev_addr, dev->addr_len);
    } else {
        sll->sll_hatype = 0;    /* Bad: we have no ARPHRD_UNSPEC */
        sll->sll_halen = 0;
    }
    rcu_read_unlock();

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    *uaddr_len = offsetof(struct sockaddr_ll, sll_addr) + sll->sll_halen;
#endif
    return 0;
}

static int packet_dev_mc(struct net_device *dev, struct packet_mclist *i,
             int what)
{
    switch (i->type) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
	case PACKET_MR_MULTICAST:
		if (i->alen != dev->addr_len)
			return -EINVAL;
		if (what > 0)
			return dev_mc_add(dev, i->addr);
		else
			return dev_mc_del(dev, i->addr);
		break;
	case PACKET_MR_PROMISC:
		return dev_set_promiscuity(dev, what);
		break;
	case PACKET_MR_ALLMULTI:
		return dev_set_allmulti(dev, what);
		break;
	case PACKET_MR_UNICAST:
		if (i->alen != dev->addr_len)
			return -EINVAL;
		if (what > 0)
			return dev_uc_add(dev, i->addr);
		else
			return dev_uc_del(dev, i->addr);
		break;
#else
    case PACKET_MR_MULTICAST:
        if (i->alen != dev->addr_len)
            return -EINVAL;
        if (what > 0)
            return dev_mc_add(dev, i->addr, i->alen, 0);
        else
            return dev_mc_delete(dev, i->addr, i->alen, 0);
        break;
    case PACKET_MR_PROMISC:
        return dev_set_promiscuity(dev, what);
        break;
    case PACKET_MR_ALLMULTI:
        return dev_set_allmulti(dev, what);
        break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)		
    case PACKET_MR_UNICAST:
        if (i->alen != dev->addr_len)
            return -EINVAL;
        if (what > 0)
            return dev_unicast_add(dev, i->addr);
        else
            return dev_unicast_delete(dev, i->addr);
        break;
#endif
#endif		
    default:
        break;
    }
    return 0;
}

static void packet_dev_mclist(struct net_device *dev, struct packet_mclist *i, int what)
{
    for ( ; i; i = i->next) {
        if (i->ifindex == dev->ifindex)
            packet_dev_mc(dev, i, what);
    }
}

static int packet_mc_add(struct sock *sk, struct packet_mreq_max *mreq)
{
    struct packet_sock *po = pkt_sk(sk);
    struct packet_mclist *ml, *i;
    struct net_device *dev;
    int err;

    rtnl_lock();

    err = -ENODEV;
    dev = __dev_get_by_index(sock_net(sk), mreq->mr_ifindex);
    if (!dev)
        goto done;

    err = -EINVAL;
    if (mreq->mr_alen > dev->addr_len)
        goto done;

    err = -ENOBUFS;
    i = kmalloc(sizeof(*i), GFP_KERNEL);
    if (i == NULL)
        goto done;

    err = 0;
    for (ml = po->mclist; ml; ml = ml->next) {
        if (ml->ifindex == mreq->mr_ifindex &&
            ml->type == mreq->mr_type &&
            ml->alen == mreq->mr_alen &&
            memcmp(ml->addr, mreq->mr_address, ml->alen) == 0) {
            ml->count++;
            /* Free the new element ... */
            kfree(i);
            goto done;
        }
    }

    i->type = mreq->mr_type;
    i->ifindex = mreq->mr_ifindex;
    i->alen = mreq->mr_alen;
    memcpy(i->addr, mreq->mr_address, i->alen);
    i->count = 1;
    i->next = po->mclist;
    po->mclist = i;
    err = packet_dev_mc(dev, i, 1);
    if (err) {
        po->mclist = i->next;
        kfree(i);
    }

done:
    rtnl_unlock();
    return err;
}

static int packet_mc_drop(struct sock *sk, struct packet_mreq_max *mreq)
{
    struct packet_mclist *ml, **mlp;

    rtnl_lock();

    for (mlp = &pkt_sk(sk)->mclist; (ml = *mlp) != NULL; mlp = &ml->next) {
        if (ml->ifindex == mreq->mr_ifindex &&
            ml->type == mreq->mr_type &&
            ml->alen == mreq->mr_alen &&
            memcmp(ml->addr, mreq->mr_address, ml->alen) == 0) {
            if (--ml->count == 0) {
                struct net_device *dev;
                *mlp = ml->next;
                dev = __dev_get_by_index(sock_net(sk), ml->ifindex);
                if (dev)
                    packet_dev_mc(dev, ml, -1);
                kfree(ml);
            }
            rtnl_unlock();
            return 0;
        }
    }
    rtnl_unlock();
    return -EADDRNOTAVAIL;
}

static void packet_flush_mclist(struct sock *sk)
{
    struct packet_sock *po = pkt_sk(sk);
    struct packet_mclist *ml;

    if (!po->mclist)
        return;

    rtnl_lock();
    while ((ml = po->mclist) != NULL) {
        struct net_device *dev;

        po->mclist = ml->next;
        dev = __dev_get_by_index(sock_net(sk), ml->ifindex);
        if (dev != NULL)
            packet_dev_mc(dev, ml, -1);
        kfree(ml);
    }
    rtnl_unlock();
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static int packet_setsockopt(struct socket *sock, int level, int optname, 
                             sockptr_t optval, unsigned int optlen)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
static int packet_setsockopt(struct socket *sock, int level, int optname, 
                             char __user *optval, unsigned int optlen)
#else
static int packet_setsockopt(struct socket *sock, int level, int optname, 
                             char __user *optval, int optlen)
#endif
{
    struct sock *sk = sock->sk;
    struct packet_sock *po = pkt_sk(sk);
    int ret;

    info("packet_setsockopt enter optname = %d, level = %d, optlen = %d\n", optname, level, optlen);
    if (level != SOL_PACKET)
        return -ENOPROTOOPT;

    switch (optname) {
    case PACKET_ADD_MEMBERSHIP:
    case PACKET_DROP_MEMBERSHIP:
    {
        struct packet_mreq_max mreq;
        int len = optlen;
        memset(&mreq, 0, sizeof(mreq));
        if (len < sizeof(struct packet_mreq))
            return -EINVAL;
        if (len > sizeof(mreq))
            len = sizeof(mreq);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (copy_from_sockptr(&mreq, optval, len))
#else
        if (copy_from_user(&mreq, optval, len))
#endif
            return -EFAULT;
        if (len < (mreq.mr_alen + offsetof(struct packet_mreq, mr_address)))
            return -EINVAL;
        if (optname == PACKET_ADD_MEMBERSHIP)
            ret = packet_mc_add(sk, &mreq);
        else
            ret = packet_mc_drop(sk, &mreq);
        return ret;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)

    case PACKET_RX_RING:
    case PACKET_TX_RING:
    {
        struct tpacket_req req;

        if (optlen < sizeof(req))
            return -EINVAL;
        if (pkt_sk(sk)->has_vnet_hdr)
            return -EINVAL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (copy_from_sockptr(&req, optval, sizeof(req)))
#else
        if (copy_from_user(&req, optval, sizeof(req)))
#endif
            return -EFAULT;
        return packet_set_ring(sk, &req, 0, optname == PACKET_TX_RING);
    }
	
#else

    case PACKET_RX_RING:
    {
    	struct tpacket_req req;
    
    	if (optlen<sizeof(req))
    		return -EINVAL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    	if (copy_from_sockptr(&req,optval,sizeof(req)))
#else
    	if (copy_from_user(&req,optval,sizeof(req)))
#endif
    		return -EFAULT;
    	return packet_set_ring(sk, &req, 0, 0);
    }

#endif	
    case PACKET_COPY_THRESH:
    {
        int val;

        if (optlen != sizeof(val))
            return -EINVAL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (copy_from_sockptr(&val, optval, sizeof(val)))
#else
        if (copy_from_user(&val, optval, sizeof(val)))
#endif
            return -EFAULT;

        pkt_sk(sk)->copy_thresh = val;
        return 0;
    }
    case PACKET_VERSION:
    {
        int val;

        if (optlen != sizeof(val))
            return -EINVAL;
        if (po->rx_ring.pg_vec || po->tx_ring.pg_vec)
            return -EBUSY;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (copy_from_sockptr(&val, optval, sizeof(val)))
#else
        if (copy_from_user(&val, optval, sizeof(val)))
#endif
            return -EFAULT;
        switch (val) {
        case TPACKET_V1:
        case TPACKET_V2:
            po->tp_version = val;
            return 0;
        default:
            return -EINVAL;
        }
    }
    case PACKET_RESERVE:
    {
        unsigned int val;

        if (optlen != sizeof(val))
            return -EINVAL;
        if (po->rx_ring.pg_vec || po->tx_ring.pg_vec)
            return -EBUSY;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (copy_from_sockptr(&val, optval, sizeof(val)))
#else
        if (copy_from_user(&val, optval, sizeof(val)))
#endif
            return -EFAULT;
        po->tp_reserve = val;
        return 0;
    }
    case PACKET_AUXDATA:
    {
        int val;

        if (optlen < sizeof(val))
            return -EINVAL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (copy_from_sockptr(&val, optval, sizeof(val)))
#else
        if (copy_from_user(&val, optval, sizeof(val)))
#endif
            return -EFAULT;

        po->auxdata = !!val;
        return 0;
    }
    case PACKET_ORIGDEV:
    {
        int val;

        if (optlen < sizeof(val))
            return -EINVAL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (copy_from_sockptr(&val, optval, sizeof(val)))
#else
        if (copy_from_user(&val, optval, sizeof(val)))
#endif
            return -EFAULT;

        po->origdev = !!val;
        return 0;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)	
    case PACKET_LOSS:
    {
        unsigned int val;

        if (optlen != sizeof(val))
            return -EINVAL;
        if (po->rx_ring.pg_vec || po->tx_ring.pg_vec)
            return -EBUSY;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (copy_from_sockptr(&val, optval, sizeof(val)))
#else
        if (copy_from_user(&val, optval, sizeof(val)))
#endif
            return -EFAULT;
        po->tp_loss = !!val;
        return 0;
    }	
    case PACKET_VNET_HDR:
    {
        int val;

        if (sock->type != SOCK_RAW)
            return -EINVAL;
        if (po->rx_ring.pg_vec || po->tx_ring.pg_vec)
            return -EBUSY;
        if (optlen < sizeof(val))
            return -EINVAL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (copy_from_sockptr(&val, optval, sizeof(val)))
#else
        if (copy_from_user(&val, optval, sizeof(val)))
#endif
            return -EFAULT;

        po->has_vnet_hdr = !!val;
        return 0;
    }
#endif
    default:
        return -ENOPROTOOPT;
    }
}

static int packet_getsockopt(struct socket *sock, int level, int optname,
                 char __user *optval, int __user *optlen)
{
    int len;
    int val;
    struct sock *sk = sock->sk;
    struct packet_sock *po = pkt_sk(sk);
    void *data;
    struct tpacket_stats st;

    if (level != SOL_PACKET)
        return -ENOPROTOOPT;

    if (get_user(len, optlen))
        return -EFAULT;

    if (len < 0)
        return -EINVAL;

    switch (optname) {
    case PACKET_STATISTICS:
        if (len > sizeof(struct tpacket_stats))
            len = sizeof(struct tpacket_stats);
        spin_lock_bh(&sk->sk_receive_queue.lock);
        st = po->stats;
        memset(&po->stats, 0, sizeof(st));
        spin_unlock_bh(&sk->sk_receive_queue.lock);
        st.tp_packets += st.tp_drops;

        data = &st;
        break;
    case PACKET_AUXDATA:
        if (len > sizeof(int))
            len = sizeof(int);
        val = po->auxdata;

        data = &val;
        break;
    case PACKET_ORIGDEV:
        if (len > sizeof(int))
            len = sizeof(int);
        val = po->origdev;

        data = &val;
        break;
    case PACKET_VERSION:
        if (len > sizeof(int))
            len = sizeof(int);
        val = po->tp_version;
        data = &val;
        break;
    case PACKET_HDRLEN:
        if (len > sizeof(int))
            len = sizeof(int);
        if (copy_from_user(&val, optval, len))
            return -EFAULT;
        switch (val) {
        case TPACKET_V1:
            val = sizeof(struct tpacket_hdr);
            break;
        case TPACKET_V2:
            val = sizeof(struct tpacket2_hdr);
            break;
        default:
            return -EINVAL;
        }
        data = &val;
        break;
    case PACKET_RESERVE:
        if (len > sizeof(unsigned int))
            len = sizeof(unsigned int);
        val = po->tp_reserve;
        data = &val;
        break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)		
    case PACKET_VNET_HDR:
        if (len > sizeof(int))
            len = sizeof(int);
        val = po->has_vnet_hdr;

        data = &val;
        break;		
    case PACKET_LOSS:
        if (len > sizeof(unsigned int))
            len = sizeof(unsigned int);
        val = po->tp_loss;
        data = &val;
        break;
#endif		
    default:
        return -ENOPROTOOPT;
    }

    if (put_user(len, optlen))
        return -EFAULT;
    if (copy_to_user(optval, data, len))
        return -EFAULT;
    return 0;
}


static int packet_notifier(struct notifier_block *this, unsigned long msg, void *data)
{
    struct sock *sk;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    struct hlist_node *node;
#endif		
    struct net_device *dev = data;
    struct net *net = dev_net(dev);
    int i = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    rcu_read_lock();
    sk_for_each_rcu(sk, &net->packet.sklist) {
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
    rcu_read_lock();
    sk_for_each_rcu(sk, node, &net->packet.sklist) {
#else		
	read_lock(&net->packet.sklist_lock);
	sk_for_each(sk, node, &net->packet.sklist) {
#endif		
        struct packet_sock *po = pkt_sk(sk);

        switch (msg) {
        case NETDEV_UNREGISTER:
            if (po->mclist)
                packet_dev_mclist(dev, po->mclist, -1);
            /* fallthrough */

        case NETDEV_DOWN:
            if (dev->ifindex == po->ifindex) {
                /*coverity[lock]*/
                /*coverity[double_lock]*/
                spin_lock(&po->bind_lock);
                if (po->running) {
                    //__dev_remove_pack(&po->prot_hook);
                    tipc_raw_unbind(sk);
                    __sock_put(sk);
                    po->running = 0;
                    sk->sk_err = ENETDOWN;
                    if (!sock_flag(sk, SOCK_DEAD))
                        sk->sk_error_report(sk);
                }
                if (msg == NETDEV_UNREGISTER) {
                    po->ifindex = -1;
                    po->prot_hook.dev = NULL;
                }
                spin_unlock(&po->bind_lock);
            }
            break;
        case NETDEV_UP:
            if (dev->ifindex == po->ifindex) {
                /*coverity[lock]*/
                /*coverity[double_lock]*/
                spin_lock(&po->bind_lock);
                if (po->num && !po->running) 
                {
                    /*coverity[unreachable]*/
                    for(i = 0; i < TIPC_MAX_BEARERS; ++i) 
                    {
                        if(!&po->prot_hook_ext[i].type)
                           dev_add_pack(&po->prot_hook_ext[i]); 
                        break;
                        
                    }
                    
                    sock_hold(sk);
                    po->running = 1;
                }
                spin_unlock(&po->bind_lock);
            }
            break;
        }
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)	
    rcu_read_unlock();
#else
    read_unlock(&net->packet.sklist_lock);
#endif	
    return NOTIFY_DONE;
}


static int packet_ioctl(struct socket *sock, unsigned int cmd,
            unsigned long arg)
{
    struct sock *sk = sock->sk;

    switch (cmd) {
    case SIOCOUTQ:
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        int amount = refcount_read(&sk->sk_wmem_alloc) - 1;
#else
        int amount = atomic_read(&sk->sk_wmem_alloc) - 1;
#endif

        return put_user(amount, (int __user *)arg);
    }
    case SIOCINQ:
    {
        struct sk_buff *skb;
        int amount = 0;

        spin_lock_bh(&sk->sk_receive_queue.lock);
        skb = skb_peek(&sk->sk_receive_queue);
        if (skb)
            amount = skb->len;
        spin_unlock_bh(&sk->sk_receive_queue.lock);
        return put_user(amount, (int __user *)arg);
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    case SIOCGSTAMP:
        return sock_get_timestamp(sk, (struct timeval __user *)arg);
    case SIOCGSTAMPNS:
        return sock_get_timestampns(sk, (struct timespec __user *)arg);
#endif

#ifdef CONFIG_INET
    case SIOCADDRT:
    case SIOCDELRT:
    case SIOCDARP:
    case SIOCGARP:
    case SIOCSARP:
    case SIOCGIFADDR:
    case SIOCSIFADDR:
    case SIOCGIFBRDADDR:
    case SIOCSIFBRDADDR:
    case SIOCGIFNETMASK:
    case SIOCSIFNETMASK:
    case SIOCGIFDSTADDR:
    case SIOCSIFDSTADDR:
    case SIOCSIFFLAGS:
        return inet_dgram_ops.ioctl(sock, cmd, arg);
#endif

    default:
        return -ENOIOCTLCMD;
    }
    return 0;
}

static unsigned int packet_poll(struct file *file, struct socket *sock,
                poll_table *wait)
{
    struct sock *sk = sock->sk;
    struct packet_sock *po = pkt_sk(sk);
    unsigned int mask = datagram_poll(file, sock, wait);

    spin_lock_bh(&sk->sk_receive_queue.lock);
    if (po->rx_ring.pg_vec) {
        if (!packet_previous_frame(po, &po->rx_ring, TP_STATUS_KERNEL))
            mask |= POLLIN | POLLRDNORM;
    }
    spin_unlock_bh(&sk->sk_receive_queue.lock);
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)	
    spin_lock_bh(&sk->sk_write_queue.lock);
    if (po->tx_ring.pg_vec) {
        if (packet_current_frame(po, &po->tx_ring, TP_STATUS_AVAILABLE))
            mask |= POLLOUT | POLLWRNORM;
    }
    spin_unlock_bh(&sk->sk_write_queue.lock);
#endif	

    return mask;
}


/* Dirty? Well, I still did not learn better way to account
 * for user mmaps.
 */

static void packet_mm_open(struct vm_area_struct *vma)
{
    struct file *file = vma->vm_file;
    struct socket *sock = file->private_data;
    struct sock *sk = sock->sk;

    if (sk)
        atomic_inc(&pkt_sk(sk)->mapped);
}

static void packet_mm_close(struct vm_area_struct *vma)
{
    struct file *file = vma->vm_file;
    struct socket *sock = file->private_data;
    struct sock *sk = sock->sk;

    if (sk)
        atomic_dec(&pkt_sk(sk)->mapped);
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)

static const struct vm_operations_struct packet_mmap_ops = {
    .open    =    packet_mm_open,
    .close    =    packet_mm_close,
};
#else
static struct vm_operations_struct packet_mmap_ops = {
	.open =	packet_mm_open,
	.close =packet_mm_close,
};
#endif

static void free_pg_vec(char **pg_vec, unsigned int order, unsigned int len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (likely(pg_vec[i]))
            free_pages((unsigned long) pg_vec[i], order);
    }
    kfree(pg_vec);
}

static inline char *alloc_one_pg_vec_page(unsigned long order)
{
    gfp_t gfp_flags = GFP_KERNEL | __GFP_COMP | __GFP_ZERO | __GFP_NOWARN;

    return (char *) __get_free_pages(gfp_flags, order);
}

static char **alloc_pg_vec(struct tpacket_req *req, int order)
{
    unsigned int block_nr = req->tp_block_nr;
    char **pg_vec;
    int i;

    pg_vec = kzalloc(block_nr * sizeof(char *), GFP_KERNEL);
    if (unlikely(!pg_vec))
        goto out;

    for (i = 0; i < block_nr; i++) {
        pg_vec[i] = alloc_one_pg_vec_page(order);
        if (unlikely(!pg_vec[i]))
            goto out_free_pgvec;
    }

out:
    return pg_vec;

out_free_pgvec:
    free_pg_vec(pg_vec, order, block_nr);
    pg_vec = NULL;
    goto out;
}

static int packet_set_ring(struct sock *sk, struct tpacket_req *req,
        int closing, int tx_ring)
{
    char **pg_vec = NULL;
    struct packet_sock *po = pkt_sk(sk);
    int was_running, order = 0;
    struct packet_ring_buffer *rb;
    struct sk_buff_head *rb_queue;
    __be16 num;
    int err, i;

    rb = tx_ring ? &po->tx_ring : &po->rx_ring;
    rb_queue = tx_ring ? &sk->sk_write_queue : &sk->sk_receive_queue;

    err = -EBUSY;
    if (!closing) {
        if (atomic_read(&po->mapped))
            goto out;
        if (atomic_read(&rb->pending))
            goto out;
    }

    if (req->tp_block_nr) {
        /* Sanity tests and some calculations */
        err = -EBUSY;
        if (unlikely(rb->pg_vec))
            goto out;

        switch (po->tp_version) {
        case TPACKET_V1:
            po->tp_hdrlen = TPACKET_HDRLEN;
            break;
        case TPACKET_V2:
            po->tp_hdrlen = TPACKET2_HDRLEN;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
            /* fallthrough */
        case TPACKET_V3:
            po->tp_hdrlen = TPACKET3_HDRLEN;
            break;
#endif
        }

        err = -EINVAL;
        if (unlikely((int)req->tp_block_size <= 0))
            goto out;
        if (unlikely(req->tp_block_size & (PAGE_SIZE - 1)))
            goto out;
        if (unlikely(req->tp_frame_size < po->tp_hdrlen +
                    po->tp_reserve))
            goto out;
        if (unlikely(req->tp_frame_size & (TPACKET_ALIGNMENT - 1)))
            goto out;

        rb->frames_per_block = req->tp_block_size/req->tp_frame_size;
        if (unlikely(rb->frames_per_block <= 0))
            goto out;
        if (unlikely((rb->frames_per_block * req->tp_block_nr) !=
                    req->tp_frame_nr))
            goto out;

        err = -ENOMEM;
        order = get_order(req->tp_block_size);
        pg_vec = alloc_pg_vec(req, order);
        if (unlikely(!pg_vec))
            goto out;
    }
    /* Done */
    else {
        err = -EINVAL;
        if (unlikely(req->tp_frame_nr))
            goto out;
    }

    lock_sock(sk);

    /* Detach socket from network */
    /*coverity[lock]*/
    spin_lock(&po->bind_lock);
    was_running = po->running;
    num = po->num;
    if (was_running) {
        tipc_raw_unbind(sk);
        //__dev_remove_pack(&po->prot_hook);
        po->num = 0;
        po->running = 0;
        __sock_put(sk);
    }
    spin_unlock(&po->bind_lock);

    synchronize_net();

    err = -EBUSY;
    mutex_lock(&po->pg_vec_lock);
    if (closing || atomic_read(&po->mapped) == 0) {
        err = 0;
#define XC(a, b) ({ __typeof__ ((a)) __t; __t = (a); (a) = (b); __t; })
        spin_lock_bh(&rb_queue->lock);
        pg_vec = XC(rb->pg_vec, pg_vec);
        rb->frame_max = (req->tp_frame_nr - 1);
        rb->head = 0;
        rb->frame_size = req->tp_frame_size;
        spin_unlock_bh(&rb_queue->lock);

        order = XC(rb->pg_vec_order, order);
        req->tp_block_nr = XC(rb->pg_vec_len, req->tp_block_nr);

        rb->pg_vec_pages = req->tp_block_size/PAGE_SIZE;
        for(i = 0; i < TIPC_MAX_BEARERS; ++i) 
        {
            if(&po->prot_hook_ext[i].type)
                po->prot_hook_ext[i].func = (po->rx_ring.pg_vec) ?
                        tpacket_rcv : packet_rcv;             
        }
        
        
        skb_queue_purge(rb_queue);
#undef XC
        if (atomic_read(&po->mapped))
            pr_err("packet_mmap: vma is busy: %d\n",
                   atomic_read(&po->mapped));
    }
    mutex_unlock(&po->pg_vec_lock);
    /*coverity[double_lock]*/
    spin_lock(&po->bind_lock);
    if (was_running && !po->running) {
        sock_hold(sk);
        po->running = 1;
        po->num = num;
        /*coverity[unreachable]*/
        for(i = 0; i < TIPC_MAX_BEARERS; ++i) 
        {
            if(!&po->prot_hook_ext[i].type)
               dev_add_pack(&po->prot_hook_ext[i]); 
            break;
            
        }
        
        //dev_add_pack(&po->prot_hook);
    }
    spin_unlock(&po->bind_lock);

    release_sock(sk);

    if (pg_vec)
        free_pg_vec(pg_vec, order, req->tp_block_nr);
out:
    return err;
}

static int packet_mmap(struct file *file, struct socket *sock,
        struct vm_area_struct *vma)
{
    struct sock *sk = sock->sk;
    struct packet_sock *po = pkt_sk(sk);
    unsigned long size, expected_size;
    struct packet_ring_buffer *rb;
    unsigned long start;
    int err = -EINVAL;
    int i;

    if (vma->vm_pgoff)
        return -EINVAL;

    mutex_lock(&po->pg_vec_lock);

    expected_size = 0;
    for (rb = &po->rx_ring; rb <= &po->tx_ring; rb++) {
        if (rb->pg_vec) {
            expected_size += rb->pg_vec_len
                        * rb->pg_vec_pages
                        * PAGE_SIZE;
        }
    }

    if (expected_size == 0)
        goto out;

    size = vma->vm_end - vma->vm_start;
    if (size != expected_size)
        goto out;

    start = vma->vm_start;
    for (rb = &po->rx_ring; rb <= &po->tx_ring; rb++) {
        if (rb->pg_vec == NULL)
            continue;

        for (i = 0; i < rb->pg_vec_len; i++) {
            struct page *page = virt_to_page(rb->pg_vec[i]);
            int pg_num;

            for (pg_num = 0; pg_num < rb->pg_vec_pages;
                    pg_num++, page++) {
                err = vm_insert_page(vma, start, page);
                if (unlikely(err))
                    goto out;
                start += PAGE_SIZE;
            }
        }
    }

    atomic_inc(&po->mapped);
    vma->vm_ops = &packet_mmap_ops;
    err = 0;

out:
    mutex_unlock(&po->pg_vec_lock);
    return err;
}

static const struct proto_ops raw_packet_ops_spkt = {
    .family     = PF_PACKET,
    .owner      = THIS_MODULE,
    .release    = tipc_raw_release,
    .bind       = tipc_raw_bind,
    .connect    = sock_no_connect,
    .socketpair = sock_no_socketpair,
    .accept     = sock_no_accept,
    .getname    = packet_getname_spkt,
    .poll       = datagram_poll,
    .ioctl      = packet_ioctl,
    .listen     = sock_no_listen,
    .shutdown   = sock_no_shutdown,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    .setsockopt = sock_no_setsockopt,
    .getsockopt = sock_no_getsockopt,
#endif
    .sendmsg    = packet_sendmsg_spkt,
    .recvmsg    = tipc_raw_recvmsg,
    .mmap       = sock_no_mmap,
    .sendpage   = sock_no_sendpage,
};

static const struct proto_ops raw_packet_ops = {
    .family     = PF_PACKET,
    .owner      = THIS_MODULE,
    .release    = tipc_raw_release,
    .bind       = tipc_raw_bind,
    .connect    = sock_no_connect,
    .socketpair = sock_no_socketpair,
    .accept     = sock_no_accept,
    .getname    = packet_getname,
    .poll       = packet_poll,
    .ioctl      = packet_ioctl,
    .listen     = sock_no_listen,
    .shutdown   = sock_no_shutdown,
    .setsockopt = packet_setsockopt,
    .getsockopt = packet_getsockopt,
    .sendmsg    = tipc_raw_sendmsg,
    .recvmsg    = tipc_raw_recvmsg,
    .mmap       = packet_mmap,
    .sendpage   = sock_no_sendpage,
};

static const struct net_proto_family packet_family_ops = {
    .family = PF_PACKET,
    .create = tipc_raw_create,
    .owner  = THIS_MODULE,
};

static struct notifier_block packet_netdev_notifier = {
    .notifier_call = packet_notifier,
};

#ifdef CONFIG_PROC_FS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
static void *packet_seq_start(struct seq_file *seq, loff_t *pos)
    __acquires(RCU)
{
    struct net *net = seq_file_net(seq);

    rcu_read_lock();
    return seq_hlist_start_head_rcu(&net->packet.sklist, *pos);
}

static void *packet_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
    struct net *net = seq_file_net(seq);
    return seq_hlist_next_rcu(v, &net->packet.sklist, pos);
}

static void packet_seq_stop(struct seq_file *seq, void *v)
    __releases(RCU)
{
    rcu_read_unlock();
}

static int packet_seq_show(struct seq_file *seq, void *v)
{
    if (v == SEQ_START_TOKEN)
        seq_puts(seq, "sk       RefCnt Type Proto  Iface R Rmem   User   Inode\n");
    else {
        struct sock *s = sk_entry(v);
        const struct packet_sock *po = pkt_sk(s);

        seq_printf(seq,
               "%p %-6d %-4d %04x   %-5d %1d %-6u %-6u %-6lu\n",
               s,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
               refcount_read(&s->sk_refcnt),
#else
               atomic_read(&s->sk_refcnt),
#endif
               s->sk_type,
               ntohs(po->num),
               po->ifindex,
               po->running,
               atomic_read(&s->sk_rmem_alloc),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
               from_kuid_munged(seq_user_ns(seq), sock_i_uid(s)),
#else
               sock_i_uid(s),
#endif
               sock_i_ino(s));
    }

    return 0;
}
#else
static inline struct sock *packet_seq_idx(struct net *net, loff_t off)
{
	struct sock *s;
	struct hlist_node *node;

	sk_for_each(s, node, &net->packet.sklist) {
		if (!off--)
			return s;
	}
	return NULL;
}

static void *packet_seq_start(struct seq_file *seq, loff_t *pos)
	__acquires(seq_file_net(seq)->packet.sklist_lock)
{
	struct net *net = seq_file_net(seq);
	read_lock(&net->packet.sklist_lock);
	return *pos ? packet_seq_idx(net, *pos - 1) : SEQ_START_TOKEN;
}

static void *packet_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct net *net = seq_file_net(seq);
	++*pos;
	return  (v == SEQ_START_TOKEN)
		? sk_head(&net->packet.sklist)
		: sk_next((struct sock*)v) ;
}

static void packet_seq_stop(struct seq_file *seq, void *v)
	__releases(seq_file_net(seq)->packet.sklist_lock)
{
	struct net *net = seq_file_net(seq);
	read_unlock(&net->packet.sklist_lock);
}

static int packet_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "sk       RefCnt Type Proto  Iface R Rmem   User   Inode\n");
	else {
		struct sock *s = v;
		const struct packet_sock *po = pkt_sk(s);

		seq_printf(seq,
			   "%p %-6d %-4d %04x   %-5d %1d %-6u %-6u %-6lu\n",
			   s,
			   atomic_read(&s->sk_refcnt),
			   s->sk_type,
			   ntohs(po->num),
			   po->ifindex,
			   po->running,
			   atomic_read(&s->sk_rmem_alloc),
			   sock_i_uid(s),
			   sock_i_ino(s) );
	}

	return 0;
}
#endif

static const struct seq_operations packet_seq_ops = {
    .start   = packet_seq_start,
    .next    = packet_seq_next,
    .stop    = packet_seq_stop,
    .show    = packet_seq_show,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
static int packet_seq_open(struct inode *inode, struct file *file)
{
    return seq_open_net(inode, file, &packet_seq_ops,
                sizeof(struct seq_net_private));
}

static const struct file_operations packet_seq_fops = {
    .owner      = THIS_MODULE,
    .open       = packet_seq_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = seq_release_net,
};
#endif

#endif

static int __net_init packet_net_init(struct net *net)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    mutex_init(&net->packet.sklist_lock);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
    spin_lock_init(&net->packet.sklist_lock);
#else
    rwlock_init(&net->packet.sklist_lock);
#endif	
    INIT_HLIST_HEAD(&net->packet.sklist);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    if (!proc_create_net("packet", 0, net->proc_net, &packet_seq_ops,
			sizeof(struct seq_net_private)))
		return -ENOMEM;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)

	if (!proc_create("packet", 0, net->proc_net, &packet_seq_fops))
		return -ENOMEM;
#else
    if (!proc_net_fops_create(net, "packet", 0, &packet_seq_fops))
        return -ENOMEM;
#endif	

    return 0;
}

static void __net_exit packet_net_exit(struct net *net)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)    
    remove_proc_entry("packet", net->proc_net);
#else
    proc_net_remove(net, "packet");
#endif
}

static struct pernet_operations packet_net_ops = {
    .init = packet_net_init,
    .exit = packet_net_exit,
};


void tipc_raw_socket_exit(void)
{
    unregister_netdevice_notifier(&packet_netdev_notifier);
    unregister_pernet_subsys(&packet_net_ops);
    sock_unregister(PF_PACKET);
    proto_unregister(&packet_proto);
}

int tipc_raw_socket_init(void)
{
    int rc = proto_register(&packet_proto, 0);

    if (rc != 0)
        goto out;

    sock_register(&packet_family_ops);
    register_pernet_subsys(&packet_net_ops);
    register_netdevice_notifier(&packet_netdev_notifier);
out:
    return rc;
}

