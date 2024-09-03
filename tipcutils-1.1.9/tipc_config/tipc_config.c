/*
 * tipc-config.c: TIPC configuration management tool
 * 
 * Copyright (c) 2004-2005, Ericsson Research Canada
 * Copyright (c) 2004-2006, Ericsson AB
 * Copyright (c) 2005-2008, Wind River Systems
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/tipc.h>
#include <linux/tipc_config.h>
#include <linux/genetlink.h>
#include <ctype.h>
#include <sys/time.h>

/* typedefs */

typedef void (*VOIDFUNCPTR) ();

/* constants */

#define MAX_COMMANDS 8
#define MAX_TLVS_SPACE (TIPC_MAX_TLV_SPACE+1000)		/* must be a multiple of 4 bytes */

/* local variables */

static int verbose = 0;
static int interactive = 0;
static __u32 dest = 0;
static __u32 tlv_area[MAX_TLVS_SPACE / sizeof(__u32)];
static __u32 tlv_list_area[MAX_TLVS_SPACE / sizeof(__u32)];

/* forward declarations */

static char usage[];

/* macros */

#define cprintf(fmt, arg...)	do { if (verbose) printf(fmt, ##arg); } while (0)

#define fatal(fmt, arg...)	do { printf(fmt, ##arg); exit(EXIT_FAILURE); } while (0)

#define confirm(fmt, arg...) do { \
		char c; \
		if (interactive) { \
			printf(fmt, ##arg); \
			if(scanf(" %c", &c) == 0){/*do nothing*/} /* leading blank skips whitespace */ \
			if ((c != '\n') && (c != 'Y') && (c != 'y')) { \
				printf("Exiting...\n"); \
				exit(EXIT_SUCCESS); \
			} \
		} \
	} while (0)

/* local variables */

static char *err_string[] = {
	"incorrect message format",
	"must be network administrator to perform operation",
	"must be zone master to perform operation",
	"remote management not enabled on destination node",
	"operation not supported",
	"invalid argument"
};

/******************************************************************************
 *
 * Utility routines used in executing command options
 *
 */

static inline int delimit(int val, int min, int max)
{
	if (val > max)
		return max;
	if (val < min)
		return min;
	return val;
}

static __u32 own_node(void)
{
	struct sockaddr_tipc addr;
	socklen_t sz = sizeof(addr);
	int sd;

	sd = socket(AF_TIPC, SOCK_RDM, 0);
	if (sd < 0)
		fatal("TIPC module not installed\n");
	if (getsockname(sd, (struct sockaddr *)&addr, &sz) < 0)
		fatal("failed to get TIPC socket address\n");
	close(sd);
	return addr.addr.id.node;
}

static const char *addr2str(__u32 addr)
{
	static char addr_area[4][16];	/* allow up to 4 uses in one printf() */
	static int addr_crs = 0;

	addr_crs = (addr_crs + 1) & 3;
	sprintf(&addr_area[addr_crs][0], "<%u.%u.%u>",
		tipc_zone(addr), tipc_cluster(addr), tipc_node(addr));
	return &addr_area[addr_crs][0];
}

static const char *for_dest(void)
{
	static char addr_area[30];

	if (dest == own_node())
		return "";
	snprintf(addr_area, sizeof(addr_area) - 1, " for node %s", addr2str(dest));
	return addr_area;
}

static const char *for_domain(const char *string, __u32 domain)
{
	static char addr_area[30];

	if (domain == 0)
		return "";
	snprintf(addr_area, sizeof(addr_area) - 1, "%s%s", string, addr2str(domain));
	return addr_area;
}

static void print_title(const char *main_title, const char *extra_title)
{
	printf(main_title, for_dest(), extra_title);
}

static void print_title_opt(const char *main_title, const char *extra_title)
{
	if ((dest == own_node()) && (extra_title[0] == '\0'))
		return;

	printf(main_title, for_dest(), extra_title);
}

char *get_arg(char **args)
{
	char *ret;
	char *comma;

	ret = *args;
	comma = strchr(ret, ',');
	if (comma) {
		*comma = '\0';
		*args = comma + 1;
	}
	else
		*args = NULL;
	return ret;
}

static __u32 str2addr(char *str)
{
	uint z, c, n;
	char dummy;

	if (sscanf(str, "%u.%u.%u%c", &z, &c, &n, &dummy) != 3)
		fatal("invalid network address, use syntax: Z.C.N\n");
	if ((z != delimit(z, 0, 255)) || 
	    (c != delimit(c, 0, 4095)) ||
	    (n != delimit(n, 0, 4095)))
		fatal("network address field value(s) too large\n");
	return tipc_addr(z, c, n);
}


/******************************************************************************
 *
 * Routines used to exchange messages over Netlink sockets
 *
 */

#define NLA_SIZE(type)	(NLA_HDRLEN + NLA_ALIGN(sizeof(type)))

#define nla_for_each_attr(pos, head, len, rem) \
	for (pos = head, rem = len; nla_ok(pos, rem); pos = nla_next(pos, &(rem)))

static inline void *nla_data(struct nlattr *nla)
{
	return ((char *)nla + NLA_HDRLEN);
}

static inline int nla_ok(const struct nlattr *nla, int remaining)
{
	return remaining >= sizeof(*nla) &&
		nla->nla_len >= sizeof(*nla) &&
		nla->nla_len <= remaining;
}

static inline struct nlattr *nla_next(struct nlattr *nla, int *remaining)
{
        int totlen = NLA_ALIGN(nla->nla_len);

        *remaining -= totlen;
        return (struct nlattr *)((char *)nla + totlen);
}

static inline int nla_put_string(struct nlattr *nla, int type, const char *str)
{
	int attrlen = strlen(str) + 1;

	nla->nla_len = NLA_HDRLEN + attrlen;
	nla->nla_type = type;
	memcpy(nla_data(nla), str, attrlen);

	return NLA_HDRLEN + NLA_ALIGN(attrlen);
}

static inline __u16 nla_get_u16(struct nlattr *nla)
{
	return *(__u16 *) nla_data(nla);
}

static int write_uninterrupted(int sk, const char *buf, int len)
{
	int c;

	while ((c = write(sk, buf, len)) < len) {
		if (c == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		buf += c;
		len -= c;
	}

	return 0;
}

static int genetlink_call(__u16 family_id, __u8 cmd, void *header, 
		size_t header_len, void *request, size_t request_len, 
		void *reply, size_t reply_len)
{
	struct msg {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char payload[0];
	};
	
	struct msg *request_msg;
	struct msg *reply_msg;
	int request_msg_size;
	int reply_msg_size;

	struct sockaddr_nl local;
	struct pollfd pfd;
	int sndbuf = MAX_TLVS_SPACE + 1000; /* 32k */
	int rcvbuf = MAX_TLVS_SPACE + 1000; /* 32k */
	int len;
	int sk;

	/*
	 * Prepare request/reply messages
	 */
	request_msg_size = NLMSG_LENGTH(GENL_HDRLEN + header_len + request_len);
	request_msg = malloc(request_msg_size);
	request_msg->n.nlmsg_len = request_msg_size;
	request_msg->n.nlmsg_type = family_id;
	request_msg->n.nlmsg_flags = NLM_F_REQUEST;
	request_msg->n.nlmsg_seq = 0;
	request_msg->n.nlmsg_pid = getpid();
	request_msg->g.cmd = cmd;
	request_msg->g.version = 0;
	if (header_len)
		memcpy(&request_msg->payload[0], header, header_len);
	if (request_len)
		memcpy(&request_msg->payload[header_len], request, request_len);

	reply_msg_size = NLMSG_LENGTH(GENL_HDRLEN + header_len + reply_len);
	reply_msg = malloc(reply_msg_size);

	/*
	 * Create socket
	 */
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;

	if ((sk = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC)) == -1)
		fatal("error creating Netlink socket\n");

	if ((bind(sk, (struct sockaddr*)&local, sizeof(local)) == -1) ||
	    (setsockopt(sk, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == -1) ||
	    (setsockopt(sk, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) == -1)) {
		fatal("error creating Netlink socket\n");
	}

	/*
	 * Send request
	 */
	if (write_uninterrupted(sk, (char*)request_msg, request_msg_size) < 0)
		fatal("error sending message via Netlink\n");

	/*
	 * Wait for reply
	 */
	pfd.fd = sk;
	pfd.events = ~POLLOUT;
	if ((poll(&pfd, 1, 3000) != 1) || !(pfd.revents & POLLIN))
		fatal("no reply detected from Netlink\n");

	/*
	 * Read reply
	 */
	len = recv(sk, (char*)reply_msg, reply_msg_size, 0);
	if (len < 0)
		fatal("error receiving reply message via Netlink\n");

	close(sk);

	/*
	 * Validate response
	 */
	if (!NLMSG_OK(&reply_msg->n, len))
		fatal("invalid reply message received via Netlink\n");

	if (reply_msg->n.nlmsg_type == NLMSG_ERROR) {
		len = -1;
		goto out;
	}

	if ((request_msg->n.nlmsg_type != reply_msg->n.nlmsg_type) ||
	    (request_msg->n.nlmsg_seq != reply_msg->n.nlmsg_seq))
		fatal("unexpected message received via Netlink\n");

	/*
	 * Copy reply header
	 */
	len -= NLMSG_LENGTH(GENL_HDRLEN);
	if (len < header_len)
		fatal("too small reply message received via Netlink\n");
	if (header_len > 0)
		memcpy(header, &reply_msg->payload[0], header_len);

	/*
	 * Copy reply payload
	 */
	len -= header_len;
	if (len > reply_len)
		fatal("reply message too large to copy\n");
	if (len > 0)
		memcpy(reply, &reply_msg->payload[header_len], len);

 out:
	free(request_msg);
	free(reply_msg);

	return len;
}

static int get_genl_family_id(const char* name)
{
	struct nlattr_family_name {
		char value[GENL_NAMSIZ];
	};

	struct nlattr_family_id {
		__u16 value;
	};

	/*
	 * Create request/reply buffers
	 *
	 * Note that the reply buffer is larger than necessary in case future
	 * versions of Netlink return additional protocol family attributes
	 */
	char request[NLA_SIZE(struct nlattr_family_name)];
	int request_len = nla_put_string((struct nlattr *)request, CTRL_ATTR_FAMILY_NAME, name);

	char reply[256];
	int reply_len = sizeof(reply);

	/*
	 * Call control service
	 */
	int len = genetlink_call(GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
				 0, 0,
				 request, request_len,
				 reply, reply_len);
	
	if (len == -1)
		return -1;

	/*
	 * Parse reply
	 */
        struct nlattr *head = (struct nlattr *) reply;
        struct nlattr *nla;
        int rem;

        nla_for_each_attr(nla, head, len, rem) {
                if (nla->nla_type == CTRL_ATTR_FAMILY_ID)
			return nla_get_u16(nla);
        }

        if (rem > 0)
                fatal("%d bytes leftover after parsing Netlink attributes\n", rem);

	return -1;
}

static int do_command_netlink(__u16 cmd, void *req_tlv, __u32 req_tlv_space,
			      void *rep_tlv, __u32 rep_tlv_space)
{
	struct tipc_genlmsghdr header;
	int family_id;
	int len;

	/*
	 * Request header
	 */
	header.dest = dest;
	header.cmd = cmd;

	/*
	 * Get TIPC family id
	 */
	if ((family_id = get_genl_family_id(TIPC_GENL_NAME)) == -1)
		fatal("no Netlink service registered for %s\n", TIPC_GENL_NAME);

	/*
	 * Call control service
	 */
	len = genetlink_call(family_id, TIPC_GENL_CMD,
			     &header, sizeof(header),
			     req_tlv, req_tlv_space,
			     rep_tlv, rep_tlv_space);

	return len;
}

/******************************************************************************
 *
 * Routines used to exchange messages over TIPC sockets
 *
 */

static int do_command_tipc(__u16 cmd, void *req_tlv, __u32 req_tlv_space,
			   void *rep_tlv, __u32 rep_tlv_space)
{
	struct {
		struct tipc_cfg_msg_hdr hdr;
		char buf[MAX_TLVS_SPACE];
	} req, ans;
	int msg_space;
	int tsd;
	struct sockaddr_tipc tipc_dest;
	int imp = TIPC_CRITICAL_IMPORTANCE;
	struct pollfd pfd;
	int pollres;

	if ((tsd = socket(AF_TIPC, SOCK_RDM, 0)) < 0)
		fatal("TIPC module not installed\n");

	msg_space = TCM_SET(&req.hdr, cmd, TCM_F_REQUEST, 
			    req_tlv, req_tlv_space);

	setsockopt(tsd, SOL_TIPC, TIPC_IMPORTANCE, &imp, sizeof(imp));

	tipc_dest.family = AF_TIPC;
	tipc_dest.addrtype = TIPC_ADDR_NAME;
	tipc_dest.addr.name.name.type = TIPC_CFG_SRV;
	tipc_dest.addr.name.name.instance = dest;
	tipc_dest.addr.name.domain = dest;

	if (sendto(tsd, &req, msg_space, 0,
		   (struct sockaddr *)&tipc_dest, sizeof(tipc_dest)) < 0)
		fatal("unable to send command to node %s\n", addr2str(dest));

	/* Wait for response message */

	pfd.events = 0xffff & ~POLLOUT;
	pfd.fd = tsd;
	pollres = poll(&pfd, 1, 3000);
	if ((pollres < 0) || !(pfd.revents & POLLIN))
		fatal("no reply detected from TIPC\n");
	msg_space = recv(tsd, &ans, sizeof(ans), 0);
	if (msg_space < 0)
		fatal("error receiving reply message via TIPC\n");

	/* Validate response message */

	if ((msg_space < TCM_SPACE(0)) || (ntohl(ans.hdr.tcm_len) > msg_space))
		fatal("invalid reply message received via TIPC\n");
	if ((ntohs(ans.hdr.tcm_type) != cmd) || 
	    (ntohs(ans.hdr.tcm_flags) != 0))
		fatal("unexpected message received via TIPC\n");

	msg_space = ntohl(ans.hdr.tcm_len) - TCM_SPACE(0);
	if (msg_space > rep_tlv_space)
		fatal("reply message too large to copy\n");
	memcpy(rep_tlv, ans.buf, msg_space);
	return msg_space;
}


/******************************************************************************
 *
 * Routines used to process commands requested by user
 *
 */

static __u32 do_command(__u16 cmd, void *req_tlv, __u32 req_tlv_space,
			void *rep_tlv, __u32 rep_tlv_space)
{
	int rep_len;

	if (dest == own_node())
		rep_len = do_command_netlink(cmd, req_tlv, req_tlv_space, 
					     rep_tlv, rep_tlv_space);
	else
		rep_len	= do_command_tipc(cmd, req_tlv, req_tlv_space, 
					  rep_tlv, rep_tlv_space);

	if (TLV_CHECK(rep_tlv, rep_len, TIPC_TLV_ERROR_STRING)) {
		char *c = (char *)TLV_DATA(rep_tlv);
		char code = *c;
		char max_code = sizeof(err_string)/sizeof(err_string[0]);

		if (code & 0x80) {
			code &= 0x7F;
			printf("%s", (code < max_code) 
			       ? err_string[(int)code] : "unknown error");
			c++;
		}
		fatal("%s\n", c);
	}

	return (__u32)rep_len;
}

static __u32 do_get_unsigned(__u16 cmd)
{
	int tlv_space;
	__u32 value;

	tlv_space = do_command(cmd, NULL, 0, tlv_area, sizeof(tlv_area));

	if (!TLV_CHECK(tlv_area, tlv_space, TIPC_TLV_UNSIGNED))
		fatal("corrupted reply message\n");

	value = *(__u32 *)TLV_DATA(tlv_area);
	return ntohl(value);
}

static void do_set_unsigned(char *args, __u16 cmd, char *attr_name, 
			    char *attr_warn)
{
	__u32 attr_val;
	__u32 attr_val_net;
	int tlv_space;
	char dummy;

	if (sscanf(args, "%u%c", &attr_val, &dummy) != 1)
		fatal("invalid numeric argument for %s\n", attr_name);

	confirm("set %s to %u%s?%s [Y/n]\n", attr_name, attr_val, 
		for_dest(), attr_warn);

	attr_val_net = htonl(attr_val);
	tlv_space = TLV_SET(tlv_area, TIPC_TLV_UNSIGNED, 
			    &attr_val_net, sizeof(attr_val_net));
	do_command(cmd, tlv_area, tlv_space, tlv_area, sizeof(tlv_area));

	cprintf("%s%s now set to %u\n", attr_name, for_dest(), attr_val);
}

static void set_node_addr(char *args)
{
	__u32 new_addr;
	__u32 new_addr_net;
	int tlv_space;
	char *s = NULL; /* w58537 */
	char *tmp = args;
	char dummy;
	struct {
		__u32 addr_net;
		__u8  mcgids[CONFIG_TIPC_MCASTGID_MAX];
	} ni;
	__u32  cnt = 0;
	__u32   mcgid = 0;

	if (!*args) {
		do_command(TIPC_CMD_NOOP, NULL, 0, tlv_area, sizeof(tlv_area));
		printf("node address: %s\n", addr2str(dest));
		return;
	}

	/* w58537 */
	if ((tmp = strchr(args, '/'))) {
		*tmp++ = '\0';
	}

	new_addr = str2addr(args);

	confirm("change node address%s to %s? "
		"(this will delete all links) [Y/n]\n", 
		for_dest(), addr2str(new_addr));

	ni.addr_net = new_addr_net = htonl(new_addr);

	while (tmp && cnt<CONFIG_TIPC_MCASTGID_MAX) {
		s = get_arg(&tmp);

		if (sscanf(s, "%u%c", &mcgid, &dummy) != 1)
			fatal("invalid mcgid\n");
		if (mcgid != delimit(mcgid, 1, 255))
			fatal("mcgid field value should be [1,255]\n");
		ni.mcgids[cnt++] = (__u8)mcgid;		
	}
	if (cnt >= CONFIG_TIPC_MCASTGID_MAX)
		fatal("mcgids more than %d\n", CONFIG_TIPC_MCASTGID_MAX);
	
	tlv_space = TLV_SET(tlv_area, TIPC_TLV_NET_ADDR, 
			    &ni, sizeof(ni.addr_net)+cnt);
	do_command(TIPC_CMD_SET_NODE_ADDR, tlv_area, tlv_space, 
		   tlv_area, sizeof(tlv_area));

	cprintf("node address%s now set to %s\n", 
		for_dest(), addr2str(new_addr));
	dest = new_addr;
}

static void get_check(char *args)
{
    struct tlv_desc *tlv;
    __u32 tlv_space;
    __u32 check_len;
    __u32 check_rate;
    
    tlv_space = do_command(TIPC_CMD_GET_CHECKSUM, NULL, 0,
        tlv_list_area, sizeof(tlv_list_area));

    tlv = (struct tlv_desc *)tlv_list_area;
    if (!TLV_CHECK(tlv, tlv_space, TIPC_TLV_UNSIGNED)){
        fatal("corrupted reply message\n");
    }
    check_len = ntohl(*(__u32 *)TLV_DATA(tlv));

    tlv = (struct tlv_desc *)((char *)tlv + TLV_SPACE(sizeof(__u32)));
    tlv_space -= TLV_SPACE(sizeof(__u32));
    if (!TLV_CHECK(tlv, tlv_space, TIPC_TLV_UNSIGNED)){
        fatal("corrupted reply message\n");
    }
    check_rate = ntohl(*(__u32 *)TLV_DATA(tlv));

    print_title("Checksum%s%s:\n", "");
    printf("check len:%d rate:1/%d\n", check_len, check_rate);
}

/* len=0 means disable checking, else enable checking 
   rate means checking per rate messages 
 */
static void set_check(char *args)
{
	__u32 len;
	__u32 rate;
	char dummy;
	int tlv_space;

	if (sscanf(args, "%u/%u%c", &len, &rate, &dummy) != 2)
		fatal("invalid len/rate\n");

	len = htonl(len);
    rate = htonl(rate);
	tlv_space = TLV_SET(tlv_area, TIPC_TLV_UNSIGNED, 
			    &len, sizeof(len));
    tlv_space += TLV_SET((char *)tlv_area+tlv_space, TIPC_TLV_UNSIGNED,
			    &rate, sizeof(rate));

	tlv_space = do_command(TIPC_CMD_SET_CHECKSUM, tlv_area, tlv_space,
			       tlv_area, sizeof(tlv_area));

	cprintf("Set check length %u, rate %u\n", ntohl(len), ntohl(rate));
}


static int do_ping_one(int tsd, void *send_buf, __u32 send_len,
	void *recv_buf, __u32 recv_len)
{
	int msg_space;
	struct sockaddr_tipc tipc_dest;
	struct pollfd pfd;
	int pollres;

	msg_space = TCM_SET(send_buf, TIPC_CMD_PING, TCM_F_REQUEST, 
			    send_buf, send_len);

	tipc_dest.family = AF_TIPC;
	tipc_dest.addrtype = TIPC_ADDR_NAME;
	tipc_dest.addr.name.name.type = TIPC_CFG_SRV;
	tipc_dest.addr.name.name.instance = dest;
	tipc_dest.addr.name.domain = dest;

	if (sendto(tsd, send_buf, msg_space, MSG_DONTROUTE,
		   (struct sockaddr *)&tipc_dest, sizeof(tipc_dest)) < 0) {
		printf("unable to send command to node %s\n", addr2str(dest));
		return -1;
	}


	/* Wait for response message */

	pfd.events = 0xffff & ~POLLOUT;
	pfd.fd = tsd;
	pollres = poll(&pfd, 1, 3000);
	if ((pollres < 0) || !(pfd.revents & POLLIN)) {
		printf("no reply detected from TIPC\n");
		return -1;
	}
	msg_space = recv(tsd, recv_buf, recv_len, 0);

	return msg_space - sizeof(struct tipc_cfg_msg_hdr);
}

static void do_ping_fill(void *buf, __u32 len, __u32 seq)
{
	__u32 i;
	__u8 *puc = buf;
	int afill[] = {0, 0x55, 0x5a, 0xa5, 0xaa, 0xff};
	i = seq % 7;
	if (i < sizeof(afill)/sizeof(afill[0])) {
		memset(buf, afill[i], len);
		return;
	}

	for (i=0; i<len; i++)
		puc[i] = (__u8)(i + seq);
	return;
}

static void do_ping(char *args)
{
	__u32 len = 1000;
	__u32 num = 4;
	char dummy;
	__u32 i = 0;;
	int rep_len;
	__u32 suc = 0;
	struct timeval tv, tv2;
	int usecs;
	int umin = 0, umax = 0, usum = 0;
	int tsd;
	int imp = TIPC_CRITICAL_IMPORTANCE;

	if (*args && sscanf(args, "%u/%u%c", &len, &num, &dummy) != 2)
		fatal("invalid len/num\n");

	if (len > TIPC_MAX_TLV_SPACE)
		len = TIPC_MAX_TLV_SPACE;

	if ((tsd = socket(AF_TIPC, SOCK_RDM, 0)) < 0)
		fatal("TIPC module not installed\n");
	
	setsockopt(tsd, SOL_TIPC, TIPC_IMPORTANCE, &imp, sizeof(imp));

	for (i=0; i<num; i++) {
		do_ping_fill(tlv_area, len, i);
		gettimeofday(&tv, NULL);
		rep_len = do_ping_one(tsd, tlv_area, len, tlv_area, sizeof(tlv_area));
		gettimeofday(&tv2, NULL);
		usecs = (tv2.tv_sec - tv.tv_sec) * 1000000u + tv2.tv_usec - tv.tv_usec;
		if (rep_len > 0) {
			suc++;
			usum += usecs;
			if (umin > usecs || !umin) umin = usecs;
			if (umax < usecs) umax = usecs;
			cprintf("%u bytes reply from %s: seq=%u time=%dus\n",
				rep_len, addr2str(dest), i, usecs);
		}
		
		/*usleep(1000);  sleep 1ms per packet */
	}

	close(tsd);
	printf("\n%u packets sent\n"
		"%u packets recv\n", num, suc);
	if (suc > 0)
		printf("round-trip min/avg/max = %u/%u/%u us\n", umin, usum/suc, umax);
	return;
}

static void print_link_state(struct tipc_node_links_state *pls_info)
{
    unsigned int i = 0;
    struct tipc_link_state *p_ls = NULL;

    for (i = 0; i < ntohl(pls_info->link_num); ++i) {
        p_ls = &pls_info->sz_linkstate[i];
        printf("%-9u%-9u%-8u%-8u%-8s%-8s%-3u%-4u%-7u", p_ls->self, p_ls->peer, p_ls->self_bid, p_ls->peer_bid,
               p_ls->self_dev, p_ls->peer_dev, p_ls->up, p_ls->active, ntohl(p_ls->error_count));
        printf("%02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x\n", p_ls->self_addr[4], p_ls->self_addr[5],
               p_ls->self_addr[6], p_ls->self_addr[7], p_ls->self_addr[8], p_ls->self_addr[9], p_ls->peer_addr[4],
               p_ls->peer_addr[5], p_ls->peer_addr[6], p_ls->peer_addr[7], p_ls->peer_addr[8], p_ls->peer_addr[9]);
    }
}

static void show_link_states_info(char *args)
{
    printf("Link statistics Info:\n");

    int tlv_space;
    int domain = 0;
    int dom_mask = 0;
    int node_addr = 0;

    __u32 domain_net;
    __u32 dom_mask_net;
    __u32 node_addr_net;

    struct tlv_list_desc tlv_list;
    struct tipc_node_links_state *pls_info = NULL;

    /* add domain to tlv */
    domain_net = htonl(domain);
    tlv_space = TLV_SET(tlv_list_area, TIPC_TLV_NET_ADDR, &domain_net, sizeof(domain_net));

    /* add dom_mask to tlv */
    dom_mask_net = htonl(dom_mask);
    tlv_space += TLV_SET((char *)(void *)tlv_list_area + tlv_space, TIPC_TLV_UNSIGNED, &dom_mask_net,
                         sizeof(dom_mask_net));

    /* add node_addr to tlv */
    node_addr_net = htonl(node_addr);
    tlv_space += TLV_SET((char *)(void *)tlv_list_area + tlv_space, TIPC_TLV_UNSIGNED, &node_addr_net,
                         sizeof(node_addr));

    tlv_space = (int)do_command(TIPC_CMD_GET_LINK_STATES_BY_NODE, tlv_list_area, tlv_space, tlv_list_area,
                                sizeof(tlv_list_area));

    printf("---------------------------------------------------------------------------------------------------\n");
    printf("Self     Peer     SelfBid PeerBid SelfDev PeerDev Up Act ErrCnt SelfAddr          PeerAddr         \n");
    printf("---------------------------------------------------------------------------------------------------\n");

    TLV_LIST_INIT(&tlv_list, tlv_list_area, tlv_space);

    while (!TLV_LIST_EMPTY(&tlv_list)) {
        if (TLV_LIST_CHECK(&tlv_list, TIPC_TLV_NODE_LINK_STATE)) {
            pls_info = (struct tipc_node_links_state *)TLV_LIST_DATA(&tlv_list);

            print_link_state(pls_info);
        } else {
            fatal("corrupted reply message\n");
        }
        TLV_LIST_STEP(&tlv_list);
    }
    return;
}

/* mask�е�1��Ҫ�������ģ���0x2F/0x34/0x10F���Ǵ���� */
static void mask_mc(char *args)
{
	__u32 mask;
	__u32 mask_net;
	char dummy;
	int tlv_space;

	if (sscanf(args, "0x%x%c", &mask, &dummy) != 1)
		fatal("invalid mask\n");

	mask_net = htonl(mask);
	tlv_space = TLV_SET(tlv_area, TIPC_TLV_UNSIGNED, 
			    &mask_net, sizeof(mask_net));
	tlv_space = do_command(TIPC_CMD_MASK_MCLINK, tlv_area, tlv_space,
			       tlv_area, sizeof(tlv_area));

	cprintf("Set multicast mask 0x%x\n", ntohl(mask));
}

static void enable_mc(char *args)
{
	__u32 mcgid;
	__u32 mcgid_net;
	char dummy;
	int tlv_space;
    __u32 flag = 0;

	if (*args != 0) {
        char *s_flag = NULL;

        s_flag = strchr(args, '/');
        if (s_flag) {
            *s_flag++ = '\0';
        }


    	if (sscanf(args, "%u%c", &mcgid, &dummy) != 1)
    		fatal("invalid mcgid\n");
		if (s_flag && strcmp(s_flag, "noread") == 0)
            flag = TIPC_MCGLINK_FLG_NO_READ;
		if (s_flag && strcmp(s_flag, "nowrite") == 0)
            flag = TIPC_MCGLINK_FLG_NO_WRITE;        
	}

	mcgid_net = htonl(mcgid);
	tlv_space = TLV_SET(tlv_area, TIPC_TLV_UNSIGNED, 
			    &mcgid_net, sizeof(mcgid_net));
    flag = htonl(flag);
	tlv_space += TLV_SET((char *)tlv_area + tlv_space, TIPC_TLV_UNSIGNED, 
			    &flag, sizeof(flag));

	tlv_space = do_command(TIPC_CMD_ENABLE_MCLINK, tlv_area, tlv_space,
			       tlv_area, sizeof(tlv_area));

	cprintf("Enable multicast %u\n", mcgid);
}

static void disable_mc(char *args)
{
	__u32 mcgid;
	__u32 mcgid_net;
	char dummy;
	int tlv_space;
    __u32 flag = 0;

	if (sscanf(args, "%u%c", &mcgid, &dummy) != 1)
		fatal("invalid mcgid\n");

	mcgid_net = htonl(mcgid);
	tlv_space = TLV_SET(tlv_area, TIPC_TLV_UNSIGNED, 
			    &mcgid_net, sizeof(mcgid_net));

    flag = htonl(flag);
	tlv_space += TLV_SET((char *)tlv_area + tlv_space, TIPC_TLV_UNSIGNED,
			    &flag, sizeof(flag));

	tlv_space = do_command(TIPC_CMD_DISABLE_MCLINK, tlv_area, tlv_space,
			       tlv_area, sizeof(tlv_area));

	cprintf("Disable multicast %u\n", mcgid);
}

static void set_remote_mng(char *args)
{
	__u32 attr_val;
	__u32 attr_val_net;
	int tlv_space;

	if (!*args) {
		printf("remote management%s: %s\n", for_dest(),
		       do_get_unsigned(TIPC_CMD_GET_REMOTE_MNG) ? 
		       "enabled" : "disabled");
		return;
	}

	if (!strcmp(args, "enable"))
		attr_val = 1;
	else if (!strcmp(args, "disable"))
		attr_val = 0;
	else
		fatal("invalid argument for remote management\n");

	confirm("%s remote management%s? [Y/n]\n", 
		attr_val ? "enable" : "disable", for_dest());

	attr_val_net = htonl(attr_val);
	tlv_space = TLV_SET(tlv_area, TIPC_TLV_UNSIGNED, 
			    &attr_val_net, sizeof(attr_val_net));
	do_command(TIPC_CMD_SET_REMOTE_MNG, tlv_area, tlv_space, 
		   tlv_area, sizeof(tlv_area));

	cprintf("remote management%s %s\n", for_dest(),
		attr_val ? "enabled" : "disabled");
}

static void set_max_ports(char *args)
{
	if (!*args)
		printf("maximum allowed ports%s: %u\n", for_dest(),
		       do_get_unsigned(TIPC_CMD_GET_MAX_PORTS));
	else
		do_set_unsigned(args, TIPC_CMD_SET_MAX_PORTS,
				"max ports", "");
}

static void set_max_publ(char *args)
{
	if (!*args)
		printf("maximum allowed publications%s: %u\n", for_dest(),
		       do_get_unsigned(TIPC_CMD_GET_MAX_PUBL));
	else
		do_set_unsigned(args, TIPC_CMD_SET_MAX_PUBL, 
				"max publications", "");
}

static void set_max_subscr(char *args)
{
	if (!*args)
		printf("maximum allowed subscriptions%s: %u\n", for_dest(),
		       do_get_unsigned(TIPC_CMD_GET_MAX_SUBSCR));
	else
		do_set_unsigned(args, TIPC_CMD_SET_MAX_SUBSCR, 
				"max subscriptions", "");
}

static void set_max_zones(char *args)
{
	if (!*args)
		printf("maximum allowed zones%s: %u\n", for_dest(),
		       do_get_unsigned(TIPC_CMD_GET_MAX_ZONES));
	else
		do_set_unsigned(args, TIPC_CMD_SET_MAX_ZONES,
				"max zones", "");
}

static void set_max_clusters(char *args)
{
	if (!*args)
		printf("maximum allowed clusters%s: %u\n", for_dest(),
		       do_get_unsigned(TIPC_CMD_GET_MAX_CLUSTERS));
	else
		do_set_unsigned(args, TIPC_CMD_SET_MAX_CLUSTERS,
				"max clusters", "");
}

static void set_max_nodes(char *args)
{
	if (!*args)
		printf("maximum allowed nodes%s: %u\n", for_dest(),
		       do_get_unsigned(TIPC_CMD_GET_MAX_NODES));
	else
		do_set_unsigned(args, TIPC_CMD_SET_MAX_NODES,
				"max nodes", "");
}

static void set_max_remotes(char *args)
{
	if (!*args)
		printf("maximum allowed remote nodes%s: %u\n", for_dest(),
		       do_get_unsigned(TIPC_CMD_GET_MAX_REMOTES));
	else
		do_set_unsigned(args, TIPC_CMD_SET_MAX_REMOTES,
				"max remote nodes", "");
}

static void set_netid(char *args)
{
	if (!*args)
		printf("current network id%s: %u\n", for_dest(),
		       do_get_unsigned(TIPC_CMD_GET_NETID));
	else
		do_set_unsigned(args, TIPC_CMD_SET_NETID,
				"network identity", "");
}

static void get_nodes(char *args)
{
	int tlv_space;
	__u32 domain = 0;
	__u32 domain_net;
	struct tlv_list_desc tlv_list;
	struct tipc_node_info *node_info;
	__u32 dom_mask = 0;

	if (*args != 0) {
        char *s_msk = NULL;

        s_msk = strchr(args, '/');
        if (s_msk) {
            *s_msk++ = '\0';
            dom_mask = str2addr(s_msk);
            dom_mask = htonl(dom_mask);
        }
    	domain = str2addr(args);
	}
	domain_net = htonl(domain);
	tlv_space = TLV_SET(tlv_area, TIPC_TLV_NET_ADDR,
			    &domain_net, sizeof(domain_net));
	tlv_space += TLV_SET((char *)tlv_area + tlv_space, TIPC_TLV_UNSIGNED, 
			    &dom_mask, sizeof(dom_mask));
	tlv_space = do_command(TIPC_CMD_GET_NODES, tlv_area, tlv_space,
			       tlv_area, sizeof(tlv_area));

	print_title("Neighbors%s%s:\n", for_domain(" within domain ", domain));
	if (!tlv_space) {
		printf("No nodes found\n");
		return;
	}

	TLV_LIST_INIT(&tlv_list, tlv_area, tlv_space);
	while (!TLV_LIST_EMPTY(&tlv_list)) {
		if (!TLV_LIST_CHECK(&tlv_list, TIPC_TLV_NODE_INFO))
			fatal("corrupted reply message\n");
		node_info = (struct tipc_node_info *)TLV_LIST_DATA(&tlv_list);
		printf("%s: %s\n", addr2str(ntohl(node_info->addr)),
		       ntohl(node_info->up) ? "up" : "down");
		TLV_LIST_STEP(&tlv_list);
	}
}

static void get_routes(char *args)
{
	int tlv_space;
	__u32 domain;
	__u32 domain_net;
	struct tlv_list_desc tlv_list;
	struct tipc_route_info *route_info;

	domain = (*args != 0) ? str2addr(args) : 0;
	domain_net = htonl(domain);
	tlv_space = TLV_SET(tlv_area, TIPC_TLV_NET_ADDR,
			    &domain_net, sizeof(domain_net));
	tlv_space = do_command(TIPC_CMD_GET_ROUTES, tlv_area, tlv_space,
			       tlv_area, sizeof(tlv_area));

	print_title_opt("Routes%s:\n", for_domain(" to ", domain));
	if (tlv_space == 0) {
		printf("No routes found\n");
		return;
	}

	printf("Region          Local router    Remote router\n");

	TLV_LIST_INIT(&tlv_list, tlv_area, tlv_space);
	while (!TLV_LIST_EMPTY(&tlv_list)) {
		if (!TLV_LIST_CHECK(&tlv_list, TIPC_TLV_ROUTE_INFO))
			fatal("corrupted reply message\n");
		route_info = (struct tipc_route_info *)TLV_LIST_DATA(&tlv_list);
		printf("%-15s %-15s %-15s\n", 
		       addr2str(ntohl(route_info->remote_addr)),
		       addr2str(ntohl(route_info->local_router)),
		       addr2str(ntohl(route_info->remote_router)));
		TLV_LIST_STEP(&tlv_list);
	}
}

static void get_nodelink(struct tipc_node_link_info *nl_info)
{
	int i = 0;
	struct tipc_nlink_info *nlink = NULL;
	__u32 self = dest;
	__u32 peer = ntohl(nl_info->dest);

	for (i=0; i<ntohl(nl_info->nlinks_cnt); i++) {
		nlink = &nl_info->nlinks[i];
		printf("%u.%u.%u:%s-%u.%u.%u:%s    %c-%c    %9u    %s\n",
			tipc_zone(self), tipc_cluster(self), tipc_node(self), nlink->self_dev, 
			tipc_zone(peer), tipc_cluster(peer), tipc_node(peer), nlink->peer_dev,
			nlink->self_bid, nlink->peer_bid, ntohl(nlink->error_count),
			ntohl(nlink->up) ? "up" : "down");
	}
}

/**
 * do_these_links - perform operation on specified set of links 
 * @funcToRun: operation to be performed on link
 * @domain: network domain of interest (0.0.0 if not used)
 * @str: link name pattern of interest (NULL if not used)
 * @vname: name of the parameter being set (optional arg to 'funcToRun')
 * @cmd: command to execute (optional arg to 'funcToRun')
 * @val: new value to be set (optional arg to 'funcToRun')
 *
 * This routine first retrieves the names of all links in the specified 
 * network domain, eliminates those that don't match the specified search
 * pattern, and then performs the requestion operation on each remaining link.
 */

static void do_these_links_ex(VOIDFUNCPTR funcToRun, __u32 domain, __u32 dom_mask, __u32 nodelink, const char *str,
			   const char *vname, int cmd, int val)
{
	int tlv_space;
	int numLinks = 0;
	__u32 domain_net;
	__u32 dom_mask_net;
	struct tlv_list_desc tlv_list;
	struct tipc_link_info *local_link_info;

	domain_net = htonl(domain);
	tlv_space = TLV_SET(tlv_list_area, TIPC_TLV_NET_ADDR,
			    &domain_net, sizeof(domain_net));
	dom_mask_net = htonl(dom_mask);
	tlv_space += TLV_SET((char *)tlv_list_area + tlv_space, TIPC_TLV_UNSIGNED,
			    &dom_mask_net, sizeof(dom_mask_net));
	if (dom_mask_net && nodelink) {
		nodelink = htonl(TIPC_TLV_NODE_LINK_INFO);
		tlv_space += TLV_SET((char *)tlv_list_area + tlv_space, TIPC_TLV_UNSIGNED,
					&nodelink, sizeof(nodelink));
	}
	tlv_space = do_command(TIPC_CMD_GET_LINKS, tlv_list_area, tlv_space,
			       tlv_list_area, sizeof(tlv_list_area));

	TLV_LIST_INIT(&tlv_list, tlv_list_area, tlv_space);

	while (!TLV_LIST_EMPTY(&tlv_list)) {
		if (TLV_LIST_CHECK(&tlv_list, TIPC_TLV_LINK_INFO)) {
			local_link_info = (struct tipc_link_info *)TLV_LIST_DATA(&tlv_list);
			if ((str == NULL) ||
			    (strstr(local_link_info->str, str) != NULL)) {
				funcToRun(local_link_info->str, local_link_info->up, 
					  vname, cmd, val);
				numLinks++;
			}
		} else if (TLV_LIST_CHECK(&tlv_list, TIPC_TLV_NODE_LINK_INFO)) {			
			struct tipc_node_link_info *nl_info = 
				(struct tipc_node_link_info *)TLV_LIST_DATA(&tlv_list);
			
			get_nodelink(nl_info);
			numLinks++;
		} else {
			fatal("corrupted reply message\n");
		}
		TLV_LIST_STEP(&tlv_list);
	}

	if (numLinks == 0) {
		if (str == NULL)
			printf("No links found\n");
		else
			printf("No links found matching pattern '%s'\n", str);
	}
}

static void do_these_links(VOIDFUNCPTR funcToRun, __u32 domain, const char *str,
			   const char *vname, int cmd, int val)
{
    do_these_links_ex(funcToRun, domain, 0, 0, str, vname, cmd, val);
}

static void get_link(char *linkName, __u32 up)
{
	printf("%s: %s\n", linkName, ntohl(up) ? "up" : "down");
}

static void get_linkset(char *args)
{
	char *strp = NULL;			/* list all links by default */
	__u32 domain = 0;
	__u32 dom_mask = 0;
	char *s = NULL;
	__u32 nodelink = 0;
	char dummy;

	if (*args != 0) {
		if (args[0] == '?')
			strp = args + 1;   	/* list links matching pattern */
		else {
            char *s_msk = NULL;
            s_msk = strchr(args, '/');
            if (s_msk) {
                *s_msk++ = '\0';
				s = strchr(s_msk, '/');
				if (s) {
					*s++ = '\0';
					if (sscanf(s, "%u%c", &nodelink, &dummy) != 1)
    					fatal("invalid args\n");
				}
				
                dom_mask = str2addr(s_msk);
            }

			domain = str2addr(args);/* list links in domain */
		}
	}

	print_title("Links%s%s:\n", for_domain(" within domain ", domain));

	do_these_links_ex(get_link, domain, dom_mask, nodelink, strp, "", 0, 0);
}

static void show_link_stats(char *linkName)
{
	int tlv_space;

	tlv_space = TLV_SET(tlv_area, TIPC_TLV_LINK_NAME, 
			    linkName, TIPC_MAX_LINK_NAME);
	tlv_space = do_command(TIPC_CMD_SHOW_LINK_STATS, tlv_area, tlv_space,
			       tlv_area, sizeof(tlv_area));

	if (!TLV_CHECK(tlv_area, tlv_space, TIPC_TLV_ULTRA_STRING))
		fatal("corrupted reply message\n");

	printf("%s\n", (char *)TLV_DATA(tlv_area));
}

static void show_linkset_stats(char *args)
{
	print_title("Link statistics%s:\n", NULL);

	if (*args == 0)			/* show for all links */
		do_these_links(show_link_stats, 0, NULL, NULL, 0, 0);
	else if (args[0] == '?') 	/* show for all links matching pattern */
		do_these_links(show_link_stats, 0, args+1, NULL, 0, 0);
	else	 			/* show for specified link */
		show_link_stats(args);
}

static void reset_link_stats(char *linkName)
{
	int tlv_space;

	tlv_space = TLV_SET(tlv_area, TIPC_TLV_LINK_NAME, 
			    linkName, TIPC_MAX_LINK_NAME);
	tlv_space = do_command(TIPC_CMD_RESET_LINK_STATS, tlv_area, tlv_space,
			       tlv_area, sizeof(tlv_area));

	cprintf("Link %s statistics reset\n", linkName);
}

static void reset_linkset_stats(char *args)
{
	if (args[0] == '?')
		do_these_links(reset_link_stats, 0, args+1, NULL, 0, 0);
	else
		reset_link_stats(args);
}


#if 0
static void create_link(char *args)
{
	char create_link_cmd[TIPC_MAX_BEARER_NAME + TIPC_MAX_MEDIA_ADDR + TIPC_MAX_ADDR + 1];
	int tlv_space;

	strncpy(create_link_cmd, args, TIPC_MAX_BEARER_NAME +  TIPC_MAX_ADDR + TIPC_MAX_MEDIA_ADDR);
	create_link_cmd[TIPC_MAX_BEARER_NAME + TIPC_MAX_MEDIA_ADDR] = '\0';

	tlv_space = TLV_SET(tlv_area, TIPC_TLV_CREATE_LINK, 
			    create_link_cmd, sizeof(create_link_cmd));
	tlv_space = do_command(TIPC_CMD_CREATE_LINK, tlv_area, tlv_space,
			       tlv_area, sizeof(tlv_area));
	cprintf("Created new link \n");

}

static void delete_link(char *args)
{
	char link_name[TIPC_MAX_LINK_NAME];
	int tlv_space;

	strncpy(link_name, args, TIPC_MAX_LINK_NAME - 1);
	link_name[TIPC_MAX_LINK_NAME - 1] = '\0';
	tlv_space = TLV_SET(tlv_area, TIPC_TLV_LINK_NAME, 
			    link_name, sizeof(link_name));
	tlv_space = do_command(TIPC_CMD_DELETE_LINK, tlv_area, tlv_space,
			       tlv_area, sizeof(tlv_area));

	cprintf("Deleted link %s\n", link_name);
}
#endif

static void show_name_table(char *args)
{
	int tlv_space;
	__u32 depth;
	__u32 type;
	__u32 lowbound;
	__u32 upbound;
	char dummy;
	struct tipc_name_table_query query_info;

	/* process (optional) depth argument */

	if (!*args)
		depth = 0;
	else if (args[0] == 'a')
		depth = 4;
	else if (args[0] == 'p')
	      depth = 3;
	else if (args[0] == 'n')
	      depth = 2;
	else if (args[0] == 't')
		depth = 1;
	else
		depth = 0;

	if (depth > 0) {
		args += strcspn(args, ",");
		if (*args)
			args++;   /* skip over comma */
	} else {
		depth = 4;
	}

	/* process (optional) type arguments */

	if (!*args) {
		depth |= TIPC_NTQ_ALLTYPES;
		type = lowbound = upbound = 0;
	} else if (sscanf(args, "%u,%u,%u%c", &type, &lowbound, &upbound,
			  &dummy) == 3) {
		/* do nothing more */
	} else if (sscanf(args, "%u,%u%c", &type, &lowbound, &dummy) == 2) {
		upbound = lowbound;
	} else if (sscanf(args, "%u%c", &type, &dummy) == 1) {
		lowbound = 0;
		upbound = ~0;
	} else
		fatal("%s", usage);

	/* issue query & process response */

	query_info.depth = htonl(depth);
	query_info.type = htonl(type);
	query_info.lowbound = htonl(lowbound);
	query_info.upbound = htonl(upbound);

	tlv_space = TLV_SET(tlv_area, TIPC_TLV_NAME_TBL_QUERY, 
			    &query_info, sizeof(query_info));
	tlv_space = do_command(TIPC_CMD_SHOW_NAME_TABLE, tlv_area, tlv_space,
			       tlv_area, sizeof(tlv_area));

	if (!TLV_CHECK(tlv_area, tlv_space, TIPC_TLV_ULTRA_STRING))
		fatal("corrupted reply message\n");

	print_title_opt("Names%s:\n", "");
	printf("%s", (char *)TLV_DATA(tlv_area));
}

static void get_media(char *dummy)
{
	int tlv_space;
	struct tlv_list_desc tlv_list;

	tlv_space = do_command(TIPC_CMD_GET_MEDIA_NAMES, NULL, 0,
			       tlv_area, sizeof(tlv_area));

	print_title("Media%s:\n", NULL);
	if (!tlv_space) {
		printf("No registered media\n");
		return;
	}

	TLV_LIST_INIT(&tlv_list, tlv_area, tlv_space);
	while (!TLV_LIST_EMPTY(&tlv_list)) {
		if (!TLV_LIST_CHECK(&tlv_list, TIPC_TLV_MEDIA_NAME))
			fatal("corrupted reply message\n");
		printf("%s\n", (char *)TLV_LIST_DATA(&tlv_list));
		TLV_LIST_STEP(&tlv_list);
	}
}

static void force_disc(char *dummy)
{
	(void)do_command(TIPC_CMD_UPDATE_DISC_FORCE, NULL, 0,
		tlv_area, sizeof(tlv_area));

	return;
}


/**
 * do_these_bearers - perform operation on specified set of bearers 
 * @funcToRun: operation to be performed on bearer
 * @str: bearer name pattern (if NULL, do operation on all bearers)
 */

static void do_these_bearers(VOIDFUNCPTR funcToRun, const char *str)
{
	int numBearers = 0;
	int tlv_space;
	struct tlv_list_desc tlv_list;
	char *bname;

	tlv_space = do_command(TIPC_CMD_GET_BEARER_NAMES, NULL, 0,
			       tlv_list_area, sizeof(tlv_list_area));

	TLV_LIST_INIT(&tlv_list, tlv_list_area, tlv_space);

	while (!TLV_LIST_EMPTY(&tlv_list)) {
		if (!TLV_LIST_CHECK(&tlv_list, TIPC_TLV_BEARER_NAME))
			fatal("corrupted reply message\n");
		bname = (char *)TLV_LIST_DATA(&tlv_list);
		if ((str == NULL) || (strstr(bname, str) != NULL)) {
			funcToRun(bname);
			numBearers++;
		}
		TLV_LIST_STEP(&tlv_list);
	}

	if (numBearers == 0) {
		if (str == NULL)
			printf("No active bearers\n");
		else
			printf("No bearers found matching pattern '%s'\n", str);
	}
}

static void get_bearer(char *bname)
{
	printf("%s\n", bname);
}

static void get_bearerset(char *args)
{
	print_title("Bearers%s:\n", NULL);

	if (*args == 0)
		do_these_bearers(get_bearer, NULL);	/* list all bearers */
	else if (args[0] == '?')
		do_these_bearers(get_bearer, args+1);	/* list matching ones */
	else
		fatal("Invalid argument '%s' \n", args);
}

static void show_bearer_stats(char *dummy)
{
	int tlv_space;

	tlv_space = do_command(TIPC_CMD_SHOW_BEARER_STATS, NULL, 0,
			       tlv_area, sizeof(tlv_area));

	if (!TLV_CHECK(tlv_area, tlv_space, TIPC_TLV_ULTRA_STRING))
		fatal("corrupted reply message\n");

	print_title("Bearers%s:\n", NULL);
	printf("%s", (char *)TLV_DATA(tlv_area));
}


static void show_ports(char *dummy)
{
	int tlv_space;

	tlv_space = do_command(TIPC_CMD_SHOW_PORTS, NULL, 0,
			       tlv_area, sizeof(tlv_area));

	if (!TLV_CHECK(tlv_area, tlv_space, TIPC_TLV_ULTRA_STRING))
		fatal("corrupted reply message\n");

	print_title("Ports%s:\n", NULL);
	printf("%s", (char *)TLV_DATA(tlv_area));
}

#if 1 /* w58537 */
static void show_port_stats(char *args)
{
	__u32 port_ref = 0; /* w58537 0 means show all port's stat*/
	__u32 port_ref_net;
	char dummy;
	int tlv_space;
	__u32 p_node = 0;
	__u32 p_ref  = 0;

	if (*args != 0) {
        char *s_peer = NULL;
        char *s_pref = NULL;
        s_peer = strchr(args, '-');
        if (s_peer) {
            *s_peer++ = '\0';
            s_pref = strchr(s_peer, ':');
            if (s_pref)
                *s_pref++ = '\0';
        }


		if (sscanf(args, "%u%c", &port_ref, &dummy) != 1)
			fatal("invalid port reference\n");
		if (s_peer)
            p_node = str2addr(s_peer);
		if (s_pref && sscanf(s_pref, "%u%c", &p_ref, &dummy) != 1)
			fatal("invalid port reference\n");
        
	}
    
	port_ref_net = htonl(port_ref);
	tlv_space = TLV_SET(tlv_area, TIPC_TLV_PORT_REF, 
			    &port_ref_net, sizeof(port_ref_net));
	p_node = htonl(p_node);
	tlv_space += TLV_SET((char *)tlv_area + tlv_space, TIPC_TLV_NET_ADDR, 
			    &p_node, sizeof(p_node));
	p_ref = htonl(p_ref);
	tlv_space += TLV_SET((char *)tlv_area + tlv_space, TIPC_TLV_PORT_REF, 
			    &p_ref, sizeof(p_ref));
    
	tlv_space = do_command(TIPC_CMD_SHOW_PORT_STATS, tlv_area, tlv_space,
			       tlv_area, sizeof(tlv_area));

	if (!TLV_CHECK(tlv_area, tlv_space, TIPC_TLV_ULTRA_STRING))
		fatal("corrupted reply message\n");

	printf("%s", (char *)TLV_DATA(tlv_area));
}

static void show_portset_stats(char *args)
{
	int tlv_space;
	char *digit;

	if (*args != 0) {
		show_port_stats(args);
		return;
	}

	tlv_space = do_command(TIPC_CMD_SHOW_PORTS, NULL, 0,
			       tlv_list_area, sizeof(tlv_list_area));

	if (!TLV_CHECK(tlv_list_area, tlv_space, TIPC_TLV_ULTRA_STRING))
		fatal("corrupted reply message\n");

	args = (char *)TLV_DATA(tlv_list_area);
    while (*args) {
        while (*args && !isdigit(*args))
            args++;
        digit = args;
        while (*args && isdigit(*args))
            args++;
		
		if (*args)
			*args++ = '\0';

        if (*digit)
			show_port_stats(digit);

        while (*args && (*args != '\n'))
            args++;
        args++;
    }
}

/*
 cmd
 0: eps_xxx=<portid>-off1,val1[,off2,val2]   ������һ��off/val����
 1: dps_xxx=<portid>[-off1,val1[,off2,val2]] ����û��off/val����
 */
static int get_msg_stats_info(char *args, int cmd, __u32* ptr_port,
                                  struct msg_filter_info* ptr_filter)
{
    __u32 off1, val1, off2, val2;
    char* ptr = NULL;
    int ret;

    if (*args == 0) {
        fatal("Invalid command line\n");
        return -1;
    }

    ptr = strchr(args, '-');
    if(ptr == NULL &&  cmd == 0) {
        fatal("Invalid command line\n");
        return -1;
    } else if (ptr == NULL && cmd == 1) { /* dps_xxx ֻ��port���� */
        ptr_filter->filter_cnts = 0;
        ret = sscanf(args, "%u", ptr_port);
        if (ret != 1) {
        fatal("Invalid port reference\n");
        return -1;
        }
        return 0;
    }
    
    *ptr++ = '\0';
    ret = sscanf(args, "%u", ptr_port);
    if (ret != 1) {
        fatal("Invalid port reference\n");
        return -1;
    }
    ret = sscanf(ptr, "%u,%u,%u,%u", &off1, &val1, &off2, &val2);
    if (ret == 2) {
        ptr_filter->filter_cnts = 1;
        ptr_filter->filter_list[0].offset = off1;
        ptr_filter->filter_list[0].value  = val1;
    } else if (ret == 4) {
        ptr_filter->filter_cnts = 2;
        ptr_filter->filter_list[1].offset = off2;
        ptr_filter->filter_list[1].value  = val2;
    } else {
        fatal("Invalid command line\n");
        return -1;
    }

    return 0;
}

static int set_msg_stats_tlv(__u32 portid, struct msg_filter_info* ptr_filter)
{
    __u32 port_ref, off, val;
    int tlv_space = 0;

    port_ref = htonl(portid);  
    tlv_space = TLV_SET((void *)tlv_area, TIPC_TLV_PORT_REF,
                                &port_ref, sizeof(port_ref));

    /* off1/val1 */
    if (ptr_filter->filter_cnts) {
        off = htonl(ptr_filter->filter_list[0].offset);
        val = htonl(ptr_filter->filter_list[0].value);
        tlv_space += TLV_SET((char *)tlv_area + tlv_space, TIPC_TLV_PORT_STATS_OFF1,
                                          &off, sizeof(off));
        tlv_space += TLV_SET((char *)tlv_area + tlv_space, TIPC_TLV_PORT_STATS_VAL1,
                                          &val, sizeof(val));
    }  
    /* off2/val2 */
    if (ptr_filter->filter_cnts == 2) {
        off = htonl(ptr_filter->filter_list[1].offset);
        val = htonl(ptr_filter->filter_list[1].value);
        tlv_space += TLV_SET((char *)tlv_area + tlv_space, TIPC_TLV_PORT_STATS_OFF2,
                                           &off, sizeof(off));
        tlv_space += TLV_SET((char *)tlv_area + tlv_space, TIPC_TLV_PORT_STATS_VAL2,
                                           &val, sizeof(val));
    }
    
    return tlv_space;
}

//tipc_config -eps_rcv=1234-55,66[,77,88]
static void set_rcvmsg_stats(char *args)
{
    __u32 port_ref = 0;
    struct msg_filter_info msg_filter;
    int tlv_space = 0;
    
	(void)memset((void *)&msg_filter, 0, sizeof(struct msg_filter_info));
    if (get_msg_stats_info(args, 0, &port_ref, &msg_filter))
        return;
    
    tlv_space = set_msg_stats_tlv(port_ref, &msg_filter);
    tlv_space = do_command(TIPC_CMD_SET_RCVMSG_STATS, tlv_area, tlv_space, 
                                               tlv_area, sizeof(tlv_area));
    if (!TLV_CHECK(tlv_area, tlv_space, TIPC_TLV_ULTRA_STRING)) {
        fatal("corrupted reply message\n");
    }

    printf("%s", (char *)TLV_DATA(tlv_area));
}

//tipc_config -eps_snd=1234-55,66[,77,88]
static void set_sndmsg_stats(char *args)
{
    __u32 port_ref = 0;
    struct msg_filter_info msg_filter;
    int tlv_space = 0;

    (void)memset((void *)&msg_filter, 0, sizeof(struct msg_filter_info));
    if (get_msg_stats_info(args, 0, &port_ref, &msg_filter))
        return;
    
    tlv_space = set_msg_stats_tlv(port_ref, &msg_filter);
    tlv_space = do_command(TIPC_CMD_SET_SNDMSG_STATS, tlv_area, tlv_space,
                                               tlv_area, sizeof(tlv_area));
    if (!TLV_CHECK(tlv_area, tlv_space, TIPC_TLV_ULTRA_STRING)) {
        fatal("corrupted reply message\n");
    }

    printf("%s", (char *)TLV_DATA(tlv_area));
}

//tipc_config -dps_rcv=1234[-55,66[,77,88]]
static void get_rcvmsg_stats(char *args)
{
    __u32 port_ref = 0;
    struct msg_filter_info msg_filter;
    int tlv_space = 0;
    
	(void)memset((void *)&msg_filter, 0, sizeof(struct msg_filter_info));
    if (get_msg_stats_info(args, 1, &port_ref, &msg_filter))
        return;
    
    tlv_space = set_msg_stats_tlv(port_ref, &msg_filter);
    tlv_space = do_command(TIPC_CMD_GET_RCVMSG_STATS, tlv_area, tlv_space,
                                               tlv_area, sizeof(tlv_area));
    if (!TLV_CHECK(tlv_area, tlv_space, TIPC_TLV_ULTRA_STRING)) {
        fatal("corrupted reply message\n");
    }

    printf("%s", (char *)TLV_DATA(tlv_area));
}

//tipc_config -dps_snd=1234[-55,66[,77,88]]
static void get_sndmsg_stats(char *args)
{
    __u32 port_ref = 0;
    struct msg_filter_info msg_filter;
    int tlv_space = 0;
    
	(void)memset((void *)&msg_filter, 0, sizeof(struct msg_filter_info));
    if (get_msg_stats_info(args, 1, &port_ref, &msg_filter))
        return;
    
    tlv_space = set_msg_stats_tlv(port_ref, &msg_filter);
    tlv_space = do_command(TIPC_CMD_GET_SNDMSG_STATS, tlv_area, tlv_space,
                                              tlv_area, sizeof(tlv_area));
    if (!TLV_CHECK(tlv_area, tlv_space, TIPC_TLV_ULTRA_STRING)) {
        fatal("corrupted reply message\n");
    }

    printf("%s", (char *)TLV_DATA(tlv_area));
}

static struct log_switch_info g_switch_info_list[6] =
{
    {TIPC_DBG_SWITCH_BCAST,      "bcast"},
    {TIPC_DBG_SWITCH_ETH_MEDIA,  "eth_media"},
    {TIPC_DBG_SWITCH_LINK,       "link"},
    {TIPC_DBG_SWITCH_PORT,       "port"},
    {TIPC_DBG_SWITCH_SOCKET,     "socket"},
    {TIPC_DBG_SWITCH_ALL,        "all"}
};

static int get_log_debug_info(char *args, __u32* ptr_type,
                                              __u32* ptr_stat)
{
    char* p = NULL;
    __u32 i;
    __u32 type = 0;
    __u32 stat = 0; /* on-1, off-0 */
    
    if (*args == 0) {
        fatal("Invalid command line\n");
        return -1;
    }

    p = strchr(args, '-');
    if(p == NULL) {
        fatal("Invalid command line\n");
        return -1;
    }

    *p++ = '\0';
    for (i = 0; i < 6; i++) {
        if (!strcasecmp(args, g_switch_info_list[i].switch_name)) {
            type = g_switch_info_list[i].switch_type;
            break;
        }
    }
    
    if (type == 0) {
        fatal("Invalid switch type\n");
        return -1;
    }

    if (!strcasecmp(p, "on")) {
        stat = 1;
    }
    else if (!strcasecmp(p, "off")) {
        stat = 0;
    }
    else {
        fatal("Invalid switch status\n");
        return -1;
    }

    *ptr_type = type;
    *ptr_stat = stat;
    return 0;
}


//tipc_config -dbg=bcast-on
static void debug_log_switch(char *args)
{
    __u32 type = 0;
    __u32 stat = 0;
    int tlv_space = 0;
    
    if (get_log_debug_info(args, &type, &stat))
        return;
 
    type = htonl(type);  
    tlv_space = TLV_SET((void *)tlv_area, TIPC_TLV_DEBUG_LOG_TYPE, 
                                &type, sizeof(type));
    stat = htonl(stat);
    tlv_space += TLV_SET((char *)tlv_area + tlv_space, TIPC_TLV_DEBUG_LOG_STAT,
                                &stat, sizeof(stat));

    tlv_space = do_command(TIPC_CMD_DEBUG_LOG_SWITCH, tlv_area, tlv_space,
                                              tlv_area, sizeof(tlv_area));
    if (!TLV_CHECK(tlv_area, tlv_space, TIPC_TLV_ULTRA_STRING)) {
        fatal("corrupted reply message\n");
    }
    
    printf("%s", (char *)TLV_DATA(tlv_area));   
}

static void reset_port_stats(char *args)
{
	__u32 port_ref;
	__u32 port_ref_net;
	char dummy;
	int tlv_space;

	if (sscanf(args, "%u%c", &port_ref, &dummy) != 1)
		fatal("invalid port reference\n");

	port_ref_net = htonl(port_ref);
	tlv_space = TLV_SET(tlv_area, TIPC_TLV_PORT_REF, 
			    &port_ref_net, sizeof(port_ref_net));
	tlv_space = do_command(TIPC_CMD_RESET_PORT_STATS, tlv_area, tlv_space,
			       tlv_area, sizeof(tlv_area));

	cprintf("Port %u statistics reset\n", port_ref);
}
#endif

static void set_log_size(char *args)
{
	int tlv_space;

	if (!*args) {
		tlv_space = do_command(TIPC_CMD_DUMP_LOG, NULL, 0,
				       tlv_area, sizeof(tlv_area));

		if (!TLV_CHECK(tlv_area, tlv_space, TIPC_TLV_ULTRA_STRING))
			fatal("corrupted reply message\n");

		printf("Log dump%s:\n%s", for_dest(), (char *)TLV_DATA(tlv_area));
	} else {
		do_set_unsigned(args, TIPC_CMD_SET_LOG_SIZE, "log size",
				" (this will discard current log contents)");
	}
}

/*BEGIN***********************************************************************
 �� �� ��  : stop_core_net
 ��������  : ֹͣtipc core net
 �������  : ��
 �������  : ��
 �� �� ֵ  : 

*************************************************************************END*/
static void shutdown_tipc(char *dummy)
{
        int tlv_space;
        char confirm = 0;
        int ret;
            
        printf("WARNING:This operation would cause tipc communication failed, are you sure to shutdown TIPC(y/n):");
        ret = scanf("%c", &confirm);
        if(ret == 0)
        {
            /*do nothing*/
        }
        if ('y' == confirm || 'Y' == confirm) 
        {
	    tlv_space = do_command(TIPC_CMD_SHUTDOWN_TIPC, NULL, 0,
			           tlv_area, sizeof(tlv_area));
	    if (!TLV_CHECK(tlv_area, tlv_space, TIPC_TLV_ULTRA_STRING))
	    {
		fatal("corrupted reply message\n");
	    }
	    printf("%s", (char *)TLV_DATA(tlv_area));
        }
        else
        {
            printf("TIPC is running!\n");
        }

}
static void show_stats(char *args)
{
	__u32 attr_val_net;
	int tlv_space;

	/*
	 * In future, may allow user to control what info is returned;
	 * for now, just hard code 0 as command argument to get default info
	 */

	attr_val_net = htonl(0);
	tlv_space = TLV_SET(tlv_area, TIPC_TLV_UNSIGNED, 
			    &attr_val_net, sizeof(attr_val_net));

	tlv_space = do_command(TIPC_CMD_SHOW_STATS, tlv_area, tlv_space,
			       tlv_area, sizeof(tlv_area));

	if (!TLV_CHECK(tlv_area, tlv_space, TIPC_TLV_ULTRA_STRING))
		fatal("corrupted reply message\n");

	print_title_opt("Status%s:\n", "");
	printf("%s", (char *)TLV_DATA(tlv_area));
}

static void set_link_value(char *linkName, __u32 dummy, const char *vname,
			   int cmd, int val)
{
	struct tipc_link_config req_tlv;
	int tlv_space;

	req_tlv.value = htonl(val);
	strcpy(req_tlv.name, linkName);
	req_tlv.name[TIPC_MAX_LINK_NAME - 1] = '\0';

	confirm("Change %s of link <%s>%s to %u? [Y/n]\n",
		vname, req_tlv.name, for_dest(), val);

	tlv_space = TLV_SET(tlv_area, TIPC_TLV_LINK_CONFIG,
			    &req_tlv, sizeof(req_tlv));
	tlv_space = do_command(cmd, tlv_area, tlv_space,
			       tlv_area, sizeof(tlv_area));

	cprintf("Link <%s>%s changed %s to %u\n", 
		req_tlv.name, for_dest(), vname, val);
}

static void set_linkset_value(char *args, const char *vname, int cmd)
{
	int  val;
	char dummy;
	char *s = strchr(args, '/');

	if (!s)
		fatal("Syntax: tipcConfig -l%c=<link-name>|<pattern>/<%s>\n",
		      vname[0], vname);

	*s++ = 0;

	if (sscanf(s, "%u%c", &val, &dummy) != 1)
		fatal("non-numeric link %s specified\n", vname);

	if (args[0] == '?')
		do_these_links(set_link_value, 0, args+1, vname, cmd, val);
	else
		set_link_value(args, 0, vname, cmd, val);
}

static void set_linkset_tolerance(char *args)
{
	set_linkset_value(args, "tolerance", TIPC_CMD_SET_LINK_TOL);
}

static void set_linkset_priority(char *args)
{
	set_linkset_value(args, "priority", TIPC_CMD_SET_LINK_PRI);
}

static void set_linkset_window(char *args)
{
	set_linkset_value(args, "window", TIPC_CMD_SET_LINK_WINDOW);
}


static void enable_bearer(char *args)
{
	struct tipc_bearer_config req_tlv;
	int tlv_space;
	char *a;
	char dummy;

	while (args) {
		__u32 domain = dest & 0xfffff000; /* defaults to own cluster */
		uint pri = TIPC_MEDIA_LINK_PRI; /* defaults to media priority */
		char *domain_str, *pri_str;

		a = get_arg(&args);
		if ((domain_str = strchr(a, '/'))) {
			*domain_str++ = 0;
			if ((pri_str = strchr(domain_str, '/'))) {
				*pri_str++ = 0;
				if ((*pri_str != 0) &&
				    sscanf(pri_str, "%u%c", &pri, &dummy) != 1)
					fatal("non-numeric bearer priority specified\n");
			}
			if (*domain_str != 0)
				domain = str2addr(domain_str);
		}

		confirm("Enable bearer <%s>%s with detection domain %s and "
			"priority %u? [Y/n]",
			a, for_dest(), addr2str(domain), pri);

		req_tlv.priority = htonl(pri);
		req_tlv.disc_domain = htonl(domain);
		strncpy(req_tlv.name, a, TIPC_MAX_BEARER_NAME - 1);
		req_tlv.name[TIPC_MAX_BEARER_NAME - 1] = '\0';

		tlv_space = TLV_SET(tlv_area, TIPC_TLV_BEARER_CONFIG, 
				    &req_tlv, sizeof(req_tlv));
		tlv_space = do_command(TIPC_CMD_ENABLE_BEARER, tlv_area, tlv_space,
				       tlv_area, sizeof(tlv_area));

		cprintf("Bearer <%s> enabled%s\n", a, for_dest());
	}
}

static void disable_bearer(char *bname)
{
	char bearer_name[TIPC_MAX_BEARER_NAME];
	int tlv_space;

	strncpy(bearer_name, bname, TIPC_MAX_BEARER_NAME - 1);
	bearer_name[TIPC_MAX_BEARER_NAME - 1] = '\0';

	confirm("Disable bearer <%s>%s ? [Y/n]", bearer_name, for_dest());

	tlv_space = TLV_SET(tlv_area, TIPC_TLV_BEARER_NAME, 
			    bearer_name, sizeof(bearer_name));
	tlv_space = do_command(TIPC_CMD_DISABLE_BEARER, tlv_area, tlv_space,
			       tlv_area, sizeof(tlv_area));

	cprintf("Bearer <%s> disabled%s\n", bearer_name, for_dest());
}

static void disable_bearerset(char *args)
{
	if (args[0] == '?')
		do_these_bearers(disable_bearer, args+1); /* name pattern */
	else {
		while (args) {				
			disable_bearer(get_arg(&args)); /* list of names */
		}
	}
}


#if 0

/* PROTOTYPE CODE FOR COMMANDS THAT AREN'T YET SUPPORTED */

const char *media_addr_string2(struct tipc_media_addr *a)
{
	static char addr_area[128];
	uint addr_type = unpack_msg(a->type);
	unsigned char *addr = (unsigned char *) & a->dev_addr;
	uint i, len;

	switch (addr_type) {
	case ETH_ADDR:
		{
			sprintf(addr_area,
				"ETH(%02x:%02x:%02x:%02x:%02x:%02x) ",
				addr[0], addr[1], addr[2], addr[3],
				addr[4], addr[5]);
			break;
		}
	case SOCKADDR_IPV4:
		{
			addr = (unsigned char *)&a->dev_addr.addr_in.sin_addr.s_addr;
			sprintf(addr_area, "SOCK_ADDR_IPV4(%u.%u.%u.%u:",
				addr[0], addr[1], addr[2], addr[3]);
			len = strlen(addr_area);
			sprintf(&addr_area[len], "%u)",
				a->dev_addr.addr_in.sin_port);
			break;
		}
	case SOCK_DESCR:
		{
			sprintf(addr_area, "SOCK_DESCR(%u)",
				ntohs(a->dev_addr.sock_descr));
			break;
		}
	default:
		{
			sprintf(addr_area, "UNKNOWN(%u):", addr_type);
			for (i = 0; i < (sizeof(*a) - sizeof(int)); i++) {
				sprintf(&addr_area[2 * i], "%02x ", addr[i]);
			}
		}
	}
	return addr_area;
}

static void get_peer_address(char *args)
{
	static struct tipc_cmd_result_msg *res_msg;
	static char addr_area[128];
	char link_name[TIPC_MAX_LINK_NAME];
	int i;

	if (*args) {
		strncpy(link_name, args, TIPC_MAX_LINK_NAME - 1);
		link_name[TIPC_MAX_LINK_NAME-1] = '\0';
	} else
		fatal(usage);
	res_msg = do_safe_operation(TIPC_GET_PEER_ADDRESS,
				    link_name, sizeof(link_name));
	if (res_msg) {
		printf("Peer Address of link <%s> is:\n", args);
		printf("   %s\n",
		       media_addr_string2(&res_msg->result.peer_address));
		free(res_msg);
	} else {
		printf("Error getting peer address");
	}
}

static void link_block(char *args)
{
	static struct tipc_cmd_result_msg *res_msg;
	char link_name[TIPC_MAX_LINK_NAME];

	strncpy(link_name, args, TIPC_MAX_LINK_NAME - 1);
	link_name[TIPC_MAX_LINK_NAME - 1] = '\0';
	confirm("Block link <%s> ? [Y/n]\n", link_name);
	res_msg = do_unsafe_operation(TIPC_CMD_BLOCK_LINK, link_name, sizeof(link_name));
	if (res_msg) {
		free(res_msg);
		cprintf("Link <%s> blocked\n", link_name);
	} else {
		printf("Error blocking link\n");
	}
}

static void link_unblock(char *args)
{
	static struct tipc_cmd_result_msg *res_msg;
	char link_name[TIPC_MAX_LINK_NAME];

	strncpy(link_name, args, TIPC_MAX_LINK_NAME - 1);
	link_name[TIPC_MAX_LINK_NAME - 1] = '\0';
	confirm("Unblock link <%s> ? [Y/n]\n", link_name);
	res_msg = do_unsafe_operation(TIPC_CMD_UNBLOCK_LINK, link_name, sizeof(link_name));
	if (res_msg) {
		free(res_msg);
		cprintf("Link <%s> unblocked\n", link_name);
	} else {
		printf("Error unblocking link\n");
	}
}

	#define MASTER_NAME 2
	#define DIE 345644567
	#define MAX_NODES 512

static __u32 me = 0;

static __u32 zone_master_node(void)
{
	struct tipc_subscr master_subscr = { {MASTER_NAME, 0, 0}, 0, 0,};
	struct tipc_event master_event;
	int topsd;
	struct sockaddr_tipc topsrv;

	memset(&topsrv, 0, sizeof(topsrv));
	topsrv.addrtype = TIPC_ADDR_NAME;
	topsrv.addr.name.name.type = TIPC_TOP_SRV;
	topsrv.addr.name.name.instance = TIPC_TOP_SRV;

	topsd = socket(AF_TIPC, SOCK_SEQPACKET, 0);
	if (topsd < 0) {
		perror("failed to create socket");
		exit(1);
	}
	if (connect(topsd, (struct sockaddr *) &topsrv, sizeof(topsrv)) < 0) {
		perror("failed to connect to topology server");
		close(topsd);
		exit(1);
	}
	if (send(topsd, &master_subscr, sizeof(master_subscr), 0) !=
	    sizeof(master_subscr)) {
		perror("failed to send master subscription");
		close(topsd);
		exit(1);
	}
	if (recv(topsd, &master_event, sizeof(master_event), 0) !=
	    sizeof(master_event)) {
		perror("failed to receive master subscription event");
		close(topsd);
		exit(1);
	}
	close(topsd);
	if (master_event.event != TIPC_PUBLISHED)
		return 0;
	return master_event.port.node;
}

static void get_zone_master(char *optarg)
{
	__u32 m = zone_master_node();
	if (m)
		printf("Zone Master is on %s\n", addr(m));
	else
		printf("No Zone Master Running\n");
}

static void start_zone_master(char *optarg)
{
	__u32 m = zone_master_node();
	if (m)
		fatal("Failed, Zone Master already on node %s\n",
		    addr(m));
	if (!fork()) {
		struct sockaddr_tipc maddr;
		int sd = socket(AF_TIPC, SOCK_RDM, 0);
		if (sd < 0)
			fatal("Failed to create zone master socket\n");
		maddr.family = AF_TIPC;
		maddr.addrtype = TIPC_ADDR_NAMESEQ;
		maddr.addr.nameseq.type = MASTER_NAME;
		maddr.addr.nameseq.lower = 0;
		maddr.addr.nameseq.upper = ~0;
		maddr.scope = TIPC_ZONE_SCOPE;
		if (bind(sd, (struct sockaddr *) &maddr, sizeof(maddr)))
			fatal("Failed to bind to zone master name\n");
		zone_master_main(sd);
	}
	exit(EXIT_SUCCESS);
}

static void kill_zone_master(char *optarg)
{
	static struct tipc_cmd_result_msg *res_msg;
	if (zone_master_node() == me) {
		res_msg = do_operation_tipc(MASTER_NAME, me, DIE, me, 0, 0);
		free(res_msg);
	} else
		fatal("Must be Zone Master to do this\n");
}

static void zone_master_main(int msd)
{
	struct tipc_cmd_msg cmd_msg;
	static struct tipc_cmd_result_msg *res_msg;
	struct tipc_subscr net_subscr = { {0, 0, -1}, -1, 0, 0,};
	struct tipc_event net_event;
	int topsd;
	struct sockaddr_tipc topsrv;
	struct pollfd pfd[2];
	int i;
	struct tipc_cmd_result_msg *rmsg =
	(struct tipc_cmd_result_msg *) malloc(TIPC_MAX_USER_MSG_SIZE);
	struct {
		int sd;
		__u32 addr;
	} nodes[MAX_NODES];

	memset(&nodes, 0, sizeof(nodes));

	/*
	 * Establish  connection to topology server and subscribe for
	 * network events
	 */
	memset(&topsrv, 0, sizeof(topsrv));
	topsrv.addrtype = TIPC_ADDR_NAME;
	topsrv.addr.name.name.type = TIPC_TOP_SRV;
	topsrv.addr.name.name.instance = TIPC_TOP_SRV;

	topsd = socket(AF_TIPC, SOCK_SEQPACKET, 0);
	if (topsd < 0) {
		perror("failed to create socket");
		exit(EXIT_FAILURE);
	}
	if (connect(topsd, (struct sockaddr *) &topsrv, sizeof(topsrv)) < 0) {
		perror("failed to connect to topology server");
		exit(EXIT_FAILURE);
	}
	if (send(topsd, &net_subscr, sizeof(net_subscr), 0) !=
	    sizeof(net_subscr)) {
		perror("failed to send master subscription");
		exit(EXIT_FAILURE);
	}
	pfd[0].fd = topsd;
	pfd[0].events = 0xffff & ~POLLOUT;

	cprintf("Zone Master daemeon started\n");

	pfd[1].fd = msd;
	pfd[1].events = 0xffff & ~POLLOUT;

	while (poll(pfd, 2, -1) > 0) {
		if (pfd[0].revents & POLLIN) {
			if (recv(topsd, &net_event, sizeof(net_event), 0)
			    != sizeof(net_event)) {
				perror
				("failed to receive network subscription event");
				exit(EXIT_FAILURE);
			}
			if (net_event.event == TIPC_PUBLISHED) {
				for (i = 0; nodes[i].sd; i++);
				nodes[i].addr = net_event.found_lower;
				nodes[i].sd =
				socket(AF_TIPC, SOCK_SEQPACKET, 0);
				if (nodes[i].sd < 0)
					err(1,
					    "Failed to create socket \n");
				res_msg = do_operation_tipc(0, nodes[i].addr,
							    TIPC_ESTABLISH, nodes[i].addr,
							    nodes[i].sd, 0, 0);
				free(res_msg);
				cprintf("Zone Master connected to %s\n",
					addr(nodes[i].addr));
			}
		}
		if (pfd[1].revents & POLLIN) {
			struct sockaddr_tipc tipc_orig, tipc_dest;
			socklen_t origlen = sizeof(tipc_orig);
			int sz =
			recvfrom(msd, &cmd_msg, sizeof(cmd_msg), 0,
				 (struct sockaddr *) &tipc_orig, &origlen);

			if (tipc_orig.addr.id.node != me)
				continue;

			/****
			 * MUST BE REPLACED BY SOMETHING ELSE
			 *
			ioctl(msd,TIPC_GET_DEST_ADDR,&tipc_dest);
			*/
			if ((pfd[1].revents & POLLERR) == 0) {
				uint dnode = 0x1001001;	//tipc_dest.addr.name.name.instance;
				uint rsz = sizeof(*rmsg);
				rmsg->retval = -EINVAL;
				if (unpack_msg(cmd_msg.cmd) == DIE) {
					rmsg->retval = TIPC_OK;
					sendto(msd, rmsg, sizeof(*rmsg), 0,
					       (struct sockaddr *) &tipc_orig,
					       sizeof(tipc_orig));
					cprintf
					("Zone Master terminating...\n");
					exit(EXIT_SUCCESS);
				}
				for (i = 0;
				    (nodes[i].addr != dnode)
				    && (i < MAX_NODES); i++);
				if (i < MAX_NODES) {
					if ((send(nodes[i].sd, &cmd_msg,
						  sizeof(cmd_msg), 0) <= 0)
					    || ((rsz = recv(nodes[i].sd, rmsg,
							    TIPC_MAX_USER_MSG_SIZE,
							    0)) <= 0)) {
						close(nodes[i].sd);
						nodes[i].sd = nodes[i].addr = 0;
					}
				}
				sendto(msd, rmsg, rsz, 0,
				       (struct sockaddr *) &tipc_orig, sizeof(tipc_orig));
			}
		}
	}
}

#endif


/******************************************************************************
 *
 * Basic data structures and routines associated with command/option processing
 *
 * Terminology note: The arguments passed to tipc-config are usually referred
 * to as "commands", since most of them are actually requests that are passed
 * on to TIPC rather than directives that are executed by tipc-config itself.
 * However, since tipc-config utilizes Linux's command line library to parse
 * the commands as if they were options, the latter term is also acceptable.
 *
 */

#define OPT_BASE '@'

struct command {
	void (*fcn) (char *args);
	char args[128];
};

/*
 * Help string generated by tipc-config application;
 * command entries are listed alphabetically
 */

static char usage[] =
"Usage: \n"
"       tipc-config command [command ...]\n"
"  \n"
"  valid commands:\n"
"  -addr [=<addr>]                            Get/set node address\n"
"  -b    [=<bearerpat>]                       Get bearers\n"
"  -bd    =<bearerpat>                        Disable bearer\n"
"  -be    =<bearer>[/<domain>[/<priority>]]]  Enable bearer\n"
"  -bs                                        Get bearer statistics\n"
"  -dest  =<addr>                             Command destination node\n"
"  -help                                      This usage list\n"
"  -i                                         Interactive set operations\n"
"  -l    [=<domain>|<linkpat>]                Get links to domain\n"
"  -log  [=<size>]                            Dump/resize log\n"
"  -lp    =<linkpat>|<bearer>|<media>/<value> Set link priority\n"
"  -ls   [=<linkpat>]                         Get link statistics\n"
"  -lsr   =<linkpat>                          Reset link statistics\n"
"  -lt    =<linkpat>|<bearer>|<media>/<value> Set link tolerance\n"
"  -lw    =<linkpat>|<bearer>|<media>/<value> Set link window\n"
"  -m                                         Get media\n"
"  -max_clusters [=<value>]                   Get/set max clusters in own zone\n"
"  -max_nodes    [=<value>]                   Get/set max nodes in own cluster\n"
"  -max_ports    [=<value>]                   Get/set max number of ports\n"
"  -max_publ     [=<value>]                   Get/set max publications\n"
"  -max_remotes  [=<value>]                   Get/set max non-cluster neighbors\n"
"  -max_subscr   [=<value>]                   Get/set max subscriptions\n"
"  -max_zones    [=<value>]                   Get/set max zones in own network\n"
"  -mng  [=enable|disable]                    Get/set remote management\n"
"  -n    [=<domain>]                          Get nodes in domain\n"
"  -netid[=<value>]                           Get/set network id\n"
"  -nt   [=[<depth>,]<type>[,<low>[,<up>]]]   Get name table\n"
"        where <depth> = types|names|ports|all\n"
"  -p                                         Get port info\n"
#if 1 /* w58537 */
"  -ps   [=<port>[-<dest>[:<port>]]]          Get port statistics\n"
"  -psr  =<port>                              Reset port statistics\n"
#endif
"  -r    [=<domain>]                          Get routes to domain\n"
"  -s                                         Get TIPC status info\n"
"  -shutdown                                  Shutdown TIPC (dangerous operation)\n"
"  -c                                         Get check message length and rate\n"
"  -ce  =<len>/<rate>                         Set check message length and rate\n"
"  -mm  =<mask>                               Set multicast mask(default 0xF000)\n"
"  -me  =<mcgid>[/noread|nowrite]             Enable multicast mcgid\n"
"  -md  =<mcgid>                              Disable multicast mcgid\n"
"  -ping=<len>/<num> -d=<dest>				  ping\n"
"  -v                                         Verbose output\n"
"  -V                                         Get tipc-config version info\n"
"  -eps_rcv=<portid>-off1,val1[,off2,val2]    Enable port recv msg statistics\n"
"  -eps_snd=<portid>-off1,val1[,off2,val2]    Enable port send msg statistics\n"
"  -dps_rcv=<portid>[-off1,val1[,off2,val2]]  Display port recv msg statistics\n"
"  -dps_snd=<portid>[-off1,val1[,off2,val2]]  Display port send msg statistics\n"
"  -dbg =<module_name>-<on/off>               TIPC module debug log switch\n"
"  -fd                                        Force send tipc links discover msg\n"
#if 0
/* commands proposed, but not yet implemented */
"  -la    =<linkpat>                          Get link peer address\n"
"  -lb    =<linkpat>                          Block link \n"
"  -lc    =<bearer>,<addr> | \n"
"                   <et:he:ra:dd:re:ss>       Create link\n"
"  -ld    =<bearer>,<addr> | <linkpat>        Delete link \n"
"  -lu    =<linkpat>                          Unblock link\n"
"  -p    [=all|bound|connected|<port>]        Get port info\n"
"  -ps    =<port>                             Get port statistics\n"
"  -psr   =<port>                             Reset port statistics\n"
"  -zm                                        Get zone master\n"
"        [=enable|disable ]                   Assume/relinquish zone\n"
#endif
; /* end of concatenated string literal */

/*
 * Option structure field usage in tipc-config application:
 *	1) option name
 *	2) argument count
 *		0 if argument is not allowed
 *		1 if argument is required
 *		2 if argument is optional
 *	3) always set to 0 
 *	4) value to return
 *
 * Note 1: Option name field must match the info in "usage" (above).
 * Note 2: Entries need not be stored alphabetically, but "value to return"
 *         field must reflect ordering used in "cmd_array" (below).  
 */

static struct option options[] = {
	{"help",         0, 0, '0'},
	{"v",            0, 0, '1'},
	{"i",            0, 0, '2'},
	{"dest",         1, 0, '3'},
	{"V",            0, 0, '4'},
	{"addr",         2, 0, OPT_BASE + 0},
	{"netid",        2, 0, OPT_BASE + 1},
	{"mng",          2, 0, OPT_BASE + 2},
	{"nt",           2, 0, OPT_BASE + 3},
	{"p",            0, 0, OPT_BASE + 4},
#if 1 /* w58537 */
	{"ps",           2, 0, OPT_BASE + 5},
	{"psr",          1, 0, OPT_BASE + 6},
#endif
	{"m",            0, 0, OPT_BASE + 7},
	{"b",            2, 0, OPT_BASE + 8},
	{"be",           1, 0, OPT_BASE + 9},
	{"bd",           1, 0, OPT_BASE + 10},
	{"n",            2, 0, OPT_BASE + 11},
	{"r",            2, 0, OPT_BASE + 12},
	{"l",            2, 0, OPT_BASE + 13},
	{"ls",           2, 0, OPT_BASE + 14},
	{"lsr",          1, 0, OPT_BASE + 15},
#if 0
	{"lc",           2, 0, OPT_BASE + 16},
	{"ld",           2, 0, OPT_BASE + 17},
	{"lb",           2, 0, OPT_BASE + 18},
	{"lu",           2, 0, OPT_BASE + 19},
#endif
	{"lp",           1, 0, OPT_BASE + 20},
	{"lw",           1, 0, OPT_BASE + 21},
	{"lt",           1, 0, OPT_BASE + 22},
#if 0
	{"la",           2, 0, OPT_BASE + 23},
	{"zm",           2, 0, OPT_BASE + 24},
#endif
	{"max_ports",    2, 0, OPT_BASE + 25},
	{"max_subscr",   2, 0, OPT_BASE + 26},
	{"max_publ",     2, 0, OPT_BASE + 27},
	{"max_zones",    2, 0, OPT_BASE + 28},
	{"max_clusters", 2, 0, OPT_BASE + 29},
	{"max_nodes",    2, 0, OPT_BASE + 30},
	{"max_remotes",  2, 0, OPT_BASE + 31},
	{"log",          2, 0, OPT_BASE + 32},
	{"s",            0, 0, OPT_BASE + 33},
	{"shutdown",     0, 0, OPT_BASE + 34},
	{"mm",           1, 0, OPT_BASE + 35},
	{"me",           1, 0, OPT_BASE + 36},
	{"md",           1, 0, OPT_BASE + 37},
	{"ce",           1, 0, OPT_BASE + 38},
	{"c",            0, 0, OPT_BASE + 39},
	{"ping",		 2, 0, OPT_BASE + 40},
	{"eps_rcv",      1, 0, OPT_BASE + 41},
	{"eps_snd",      1, 0, OPT_BASE + 42},
	{"dps_rcv",      1, 0, OPT_BASE + 43},
	{"dps_snd",      1, 0, OPT_BASE + 44},
	{"dbg",          1, 0, OPT_BASE + 45},
	{"bs",           0, 0, OPT_BASE + 47},
	{"fd",           0, 0, OPT_BASE + 48},
	{0, 0, 0, 0}
};

void (*cmd_array[])(char *args) = {
    set_node_addr,
    set_netid,
    set_remote_mng,
    show_name_table,
    show_ports,
    show_portset_stats,  /* show_port_stats, w58537*/
    reset_port_stats, /* reset_port_stats, w58537*/
    get_media,
    get_bearerset,
    enable_bearer,
    disable_bearerset,
    get_nodes,
    get_routes,
    get_linkset,
    show_linkset_stats,
    reset_linkset_stats,
    NULL, /* create_link */
    NULL, /* delete_link */
    NULL, /* link_block */
    NULL, /* link_unblock */
    set_linkset_priority,
    set_linkset_window,
    set_linkset_tolerance,
    NULL, /* get_peer_address */
    NULL, /* zone master */
    set_max_ports,
    set_max_subscr,
    set_max_publ,
    set_max_zones,
    set_max_clusters,
    set_max_nodes,
    set_max_remotes,
    set_log_size,
    show_stats,
    shutdown_tipc,
    mask_mc,
    enable_mc,
    disable_mc,
    set_check,
    get_check,
    do_ping,
    set_rcvmsg_stats,
    set_sndmsg_stats,
    get_rcvmsg_stats,
    get_sndmsg_stats,
    debug_log_switch,
    show_link_states_info,
	show_bearer_stats,
	force_disc,
    NULL
};

/*
 * Mainline parses option list and processes each command.  Most commands are
 * not actually executed until parsing is complete in case they are impacted
 * by commands that appear later in the list. 
 */

int main(int argc, char *argv[], char *dummy[])
{
	struct command commands[MAX_COMMANDS];
	int cno, cno2;
	int c;

	if (argc == 1)
		fatal("%s", usage);

	dest = own_node();

	cno = 0;
	while ((c = getopt_long_only(argc, argv, "", options, NULL)) != EOF) {

		if (c >= OPT_BASE) {
			if (cno >= MAX_COMMANDS)
				fatal("too many commands specified\n");

			commands[cno].fcn = cmd_array[c - OPT_BASE];
			if (optarg)
				strcpy(commands[cno].args, optarg);
			else
				commands[cno].args[0] = '\0';
			cno++;
		} else {
			switch (c) {
			case '0':
				fatal("%s", usage);
				break;
			case '1':
				verbose = 1;
				break;
			case '2':
				interactive = 1;
				break;
			case '3':
				dest = str2addr(optarg);
				break;
			case '4':
				printf("TIPC configuration tool version "
				       VERSION "\n");
				break;
			default:
				/* getopt_long_only() generates the error msg */
				exit(EXIT_FAILURE);
				break;
			}
		}

	}

	if (optind < argc) {
		/* detects arguments that don't start with a '-' sign */
		fatal("unexpected command argument '%s'\n", argv[optind]);
	}

	for (cno2 = 0; cno2 < cno; cno2++) {
		if (!commands[cno2].fcn)
			fatal("command table error\n");
		commands[cno2].fcn(commands[cno2].args);
	}

	return 0;
}
