/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2024. All rights reserved.
 * Description: tipc_raw_sock.h
 */

#ifndef _TIPC_RAW_SOCKET_H__
#define _TIPC_RAW_SOCKET_H__

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
int tipc_raw_create(struct net *net, struct socket *sock, int protocol, int kern);
#else
int tipc_raw_create(struct net *net, struct socket *sock, int protocol);
#endif

int  tipc_raw_socket_init(void);
void tipc_raw_socket_exit(void);

struct bearer;
    
extern void tipc_media_fill_mac(struct sk_buff *skb, char *src_mac, char *dst_mac);
extern int  tipc_media_check_mtu(struct bearer *pbearer, size_t len);
extern struct net_device * tipc_media_get_dev(struct bearer *pbearer);


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
#define TIPC_KIOCB
#define IOCB_LK             1

#define get_msgiov(m)       (m)->msg_iter.iov
#define get_msgiovlen(m)    (m)->msg_iter.nr_segs

#define tipc_sk_data_ready(sk)                  \
            sk->sk_data_ready(sk)

#define tipc_vlan_tci(skb)                      \
            skb_vlan_tag_get(skb)

#define tipc_memcpy_to_msg(msg, data, len)      \
            memcpy_to_msg(msg, data, len)

#define tipc_memcpy_from_msg(data, msg, len)    \
            memcpy_from_msg(data, msg, len)


#else
#define TIPC_KIOCB          struct kiocb *iocb,
#define IOCB_LK             iocb


#define get_msgiov(m)       (m)->msg_iov
#define get_msgiovlen(m)    (m)->msg_iovlen

#define tipc_sk_data_ready(sk)                  \
            sk->sk_data_ready(sk, 0)

#define tipc_vlan_tci(skb)                      \
            vlan_tx_tag_get(skb)
            
#define tipc_memcpy_to_msg(msg, data, len)      \
            memcpy_toiovec(msg->msg_iov, data, len)

#define tipc_memcpy_from_msg(data, msg, len)    \
            memcpy_fromiovec(data, msg->msg_iov, len)            

#endif


#endif
