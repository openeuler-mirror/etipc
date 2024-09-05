/*
 * net/tipc/tipc_dbg.c: TIPC print buffer routines
 *
 * Copyright (c) 1996-2006, Ericsson AB
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

#include "tipc_core.h"
#include "tipc_cfgsrv.h"
#include "tipc_dbg.h"
#include "tipc_port.h"

#if defined(CONFIG_TIPC_CONFIG_SERVICE) \
    || defined(CONFIG_TIPC_SYSTEM_MSGS) \
    || defined(CONFIG_TIPC_DEBUG)

/*
 * TIPC pre-defines the following print buffers:
 *
 * TIPC_NULL : null buffer (i.e. print nowhere)
 * TIPC_CONS : system console
 * TIPC_LOG  : TIPC log buffer
 *
 * Additional user-defined print buffers are also permitted.
 */
int *g_tipc_cons_printk = NULL;
static struct print_buf null_buf = { NULL, 0, NULL, 0 };
struct print_buf *const TIPC_NULL = &null_buf;

static struct print_buf cons_buf = { NULL, 0, NULL, 1 };
struct print_buf *const TIPC_CONS = &cons_buf;

static struct print_buf log_buf = { NULL, 0, NULL, 1 };
struct print_buf *const TIPC_LOG = &log_buf;

struct print_buf * TIPC_DEBUG = &null_buf;
/*
 * Locking policy when using print buffers.
 *
 * 1) tipc_printf() uses 'print_lock' to protect against concurrent access to
 * 'print_string' when writing to a print buffer. This also protects against
 * concurrent writes to the print buffer being written to.
 *
 * 2) tipc_dump_dbg() and tipc_log_XXX() leverage the aforementioned
 * use of 'print_lock' to protect against all types of concurrent operations
 * on their associated print buffer (not just write operations).
 *
 * Note: All routines of the form tipc_printbuf_XXX() are lock-free, and rely
 * on the caller to prevent simultaneous use of the print buffer(s) being
 * manipulated.
 */

static char print_string[TIPC_PB_MAX_STR];
static DEFINE_SPINLOCK(print_lock);


#define FORMAT(PTR,LEN,FMT) \
{\
       va_list args;\
       va_start(args, FMT);\
       LEN = vsprintf(PTR, FMT, args);\
       va_end(args);\
       *(PTR + LEN) = '\0';\
}

/**
 * tipc_printbuf_init - initialize print buffer to empty
 * @pb: pointer to print buffer structure
 * @raw: pointer to character array used by print buffer
 * @size: size of character array
 *
 * Note: If the character array is too small (or absent), the print buffer
 * becomes a null device that discards anything written to it.
 */

void tipc_printbuf_init(struct print_buf *pb, char *raw, u32 size)
{
	pb->buf = raw;
	pb->crs = raw;
	pb->size = size;
	pb->echo = 0;

	if (size < TIPC_PB_MIN_SIZE) {
		pb->buf = NULL;
	} else if (raw) {
		pb->buf[0] = 0;
		pb->buf[size - 1] = ~0;
	}
}

/**
 * tipc_printbuf_reset - reinitialize print buffer to empty state
 * @pb: pointer to print buffer structure
 */

void tipc_printbuf_reset(struct print_buf *pb)
{
	if (pb->buf) {
		pb->crs = pb->buf;
		pb->buf[0] = 0;
		pb->buf[pb->size - 1] = ~0;
	}
}

/**
 * tipc_printbuf_empty - test if print buffer is in empty state
 * @pb: pointer to print buffer structure
 *
 * Returns non-zero if print buffer is empty.
 */

int tipc_printbuf_empty(struct print_buf *pb)
{
	return (!pb->buf || (pb->crs == pb->buf));
}

/**
 * tipc_printbuf_validate - check for print buffer overflow
 * @pb: pointer to print buffer structure
 *
 * Verifies that a print buffer has captured all data written to it.
 * If data has been lost, linearize buffer and prepend an error message
 *
 * Returns length of print buffer data string (including trailing NUL)
 */

int tipc_printbuf_validate(struct print_buf *pb)
{
	char *err = "\n\n*** PRINT BUFFER OVERFLOW ***\n\n";
	char *cp_buf;
	struct print_buf cb;

	if (!pb->buf)
		return 0;

	if (pb->buf[pb->size - 1] == 0) {
		cp_buf = kmalloc(pb->size, GFP_ATOMIC);
		if (cp_buf) {
			tipc_printbuf_init(&cb, cp_buf, pb->size);
			tipc_printbuf_move(&cb, pb);
			tipc_printbuf_move(pb, &cb);
			kfree(cp_buf);
			memcpy(pb->buf, err, strlen(err));
		} else {
			tipc_printbuf_reset(pb);
			tipc_printf(pb, err);
		}
	}
	return (pb->crs - pb->buf + 1);
}

/**
 * tipc_printbuf_move - move print buffer contents to another print buffer
 * @pb_to: pointer to destination print buffer structure
 * @pb_from: pointer to source print buffer structure
 *
 * Current contents of destination print buffer (if any) are discarded.
 * Source print buffer becomes empty if a successful move occurs.
 */

void tipc_printbuf_move(struct print_buf *pb_to, struct print_buf *pb_from)
{
	int len;

	/* Handle the cases where contents can't be moved */

	if (!pb_to->buf)
		return;

	if (!pb_from->buf) {
		tipc_printbuf_reset(pb_to);
		return;
	}

	if (pb_to->size < pb_from->size) {
		strcpy(pb_to->buf, "*** PRINT BUFFER MOVE ERROR ***");
		pb_to->buf[pb_to->size - 1] = ~0;
		pb_to->crs = strchr(pb_to->buf, 0);
		return;
	}

	/* Copy data from char after cursor to end (if used) */

	len = pb_from->buf + pb_from->size - pb_from->crs - 2;
	if ((pb_from->buf[pb_from->size - 1] == 0) && (len > 0)) {
		strcpy(pb_to->buf, pb_from->crs + 1);
		pb_to->crs = pb_to->buf + len;
	} else
		pb_to->crs = pb_to->buf;

	/* Copy data from start to cursor (always) */

	len = pb_from->crs - pb_from->buf;
	strcpy(pb_to->crs, pb_from->buf);
	pb_to->crs += len;

	tipc_printbuf_reset(pb_from);
}

/**
 * tipc_printf - append formatted output to print buffer
 * @pb: pointer to print buffer
 * @fmt: formatted info to be printed
 */

void tipc_printf(struct print_buf *pb, const char *fmt, ...)
{
	int chars_to_add;
	int chars_left;
	char save_char;

	spin_lock_bh(&print_lock);

	FORMAT(print_string, chars_to_add, fmt);
	if (chars_to_add >= TIPC_PB_MAX_STR)
		strcpy(print_string, "*** PRINT BUFFER STRING TOO LONG ***");

	if (pb->buf) {
		chars_left = pb->buf + pb->size - pb->crs - 1;
		if (chars_to_add <= chars_left) {
			strcpy(pb->crs, print_string);
			pb->crs += chars_to_add;
		} else if (chars_to_add >= (pb->size - 1)) {
			strcpy(pb->buf, print_string + chars_to_add + 1
			       - pb->size);
			pb->crs = pb->buf + pb->size - 1;
		} else {
			strcpy(pb->buf, print_string + chars_left);
			save_char = print_string[chars_left];
			print_string[chars_left] = 0;
			strcpy(pb->crs, print_string);
			print_string[chars_left] = save_char;
			pb->crs = pb->buf + chars_to_add - chars_left;
		}
	}

	if (pb->echo) {
		/* ensure DO NOT print to console */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		int orig_log_level  = console_loglevel;
		console_loglevel = 0; /* KERN_EMERG	"<0>" */
		printk(print_string);
		console_loglevel = orig_log_level;
#else
		printk(KERN_INFO "%s", print_string);
#endif
	}
	
	spin_unlock_bh(&print_lock);
}
#endif

#ifdef CONFIG_TIPC_DEBUG

/**
 * print_to_console - write string of bytes to console in multiple chunks
 */

static void print_to_console(char *crs, int len)
{
	int rest = len;

	while (rest > 0) {
		int sz = rest < TIPC_PB_MAX_STR ? rest : TIPC_PB_MAX_STR;
		char c = crs[sz];

		crs[sz] = 0;
		printk((const char *)crs);
		crs[sz] = c;
		rest -= sz;
		crs += sz;
	}
}

/**
 * printbuf_dump - write print buffer contents to console
 */

static void printbuf_dump_dbg(struct print_buf *pb)
{
	int len;

	if (!pb->buf) {
		printk("*** PRINT BUFFER NOT ALLOCATED ***");
		return;
	}

	/* Dump print buffer from char after cursor to end (if used) */

	len = pb->buf + pb->size - pb->crs - 2;
	if ((pb->buf[pb->size - 1] == 0) && (len > 0))
		print_to_console(pb->crs + 1, len);

	/* Dump print buffer from start to cursor (always) */

	len = pb->crs - pb->buf;
	print_to_console(pb->buf, len);
}

/**
 * tipc_dump_dbg - dump (non-console) print buffer to console
 * @pb: pointer to print buffer
 */

void tipc_dump_dbg(struct print_buf *pb, const char *fmt, ...)
{
	int len;

	if (pb == TIPC_CONS)
		return;

	spin_lock_bh(&print_lock);

	FORMAT(print_string, len, fmt);
	printk(print_string);

	printk("\n---- Start of %s log dump ----\n\n",
	       (pb == TIPC_LOG) ? "global" : "local");
	printbuf_dump_dbg(pb);
	tipc_printbuf_reset(pb);
	printk("\n---- End of dump ----\n");

	spin_unlock_bh(&print_lock);
}

#endif


#ifdef CONFIG_TIPC_CONFIG_SERVICE

/**
 * tipc_log_resize - change the size of the TIPC log buffer
 * @log_size: print buffer size to use
 */

int tipc_log_resize(int log_size)
{
	int res = 0;

	spin_lock_bh(&print_lock);
	if (TIPC_LOG->buf) {
		kfree(TIPC_LOG->buf);
		TIPC_LOG->buf = NULL;
	}
	if (log_size) {
		if (log_size < TIPC_PB_MIN_SIZE)
			log_size = TIPC_PB_MIN_SIZE;
		res = TIPC_LOG->echo;
		tipc_printbuf_init(TIPC_LOG, kmalloc(log_size, GFP_ATOMIC),
				   log_size);
		TIPC_LOG->echo = res;
		res = !TIPC_LOG->buf;
	}
	TIPC_DEBUG = TIPC_LOG->buf ? TIPC_LOG : TIPC_NULL;
	spin_unlock_bh(&print_lock);

	return res;
}

/**
 * tipc_log_resize_cmd - reconfigure size of TIPC log buffer
 */

struct sk_buff *tipc_log_resize_cmd(const void *req_tlv_area, int req_tlv_space)
{
	u32 value;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_UNSIGNED))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	value = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
	if (value != delimit(value, 0, 32768))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (log size must be 0-32768)");
	if (tipc_log_resize(value))
		return tipc_cfg_reply_error_string(
			"unable to create specified log (log size is now 0)");
	return tipc_cfg_reply_none();
}

/**
 * tipc_log_dump - capture TIPC log buffer contents in configuration message
 */

struct sk_buff *tipc_log_dump(void)
{
	struct sk_buff *reply;

	spin_lock_bh(&print_lock);
	if (!TIPC_LOG->buf) {
		spin_unlock_bh(&print_lock);
		reply = tipc_cfg_reply_ultra_string("log not activated\n");
	} else if (tipc_printbuf_empty(TIPC_LOG)) {
		spin_unlock_bh(&print_lock);
		reply = tipc_cfg_reply_ultra_string("log is empty\n");
	}
	else {
		struct tlv_desc *rep_tlv;
		struct print_buf pb;
		int str_len;

		str_len = min(TIPC_LOG->size, 32768u);
		spin_unlock_bh(&print_lock);
		reply = tipc_cfg_reply_alloc(TLV_SPACE(str_len));
		if (reply) {
			rep_tlv = (struct tlv_desc *)reply->data;
			tipc_printbuf_init(&pb, TLV_DATA(rep_tlv), str_len);
			spin_lock_bh(&print_lock);
			tipc_printbuf_move(&pb, TIPC_LOG);
			spin_unlock_bh(&print_lock);
			str_len = strlen(TLV_DATA(rep_tlv)) + 1;
			skb_put(reply, TLV_SPACE(str_len));
			TLV_SET(rep_tlv, TIPC_TLV_ULTRA_STRING, NULL, str_len);
		}
	}
	return reply;
}

int tipc_dump_buf(struct sk_buff *buf)
{
	u32 i = (ETH_HLEN+buf->len+15)/16;
	u32 *p = (u32 *)eth_hdr(buf);

	for (i=min(i,10u);i>0; i--, p+=4) {
		info("%p: %08x %08x %08x %08x\n",
			p, ntohl(p[0]), ntohl(p[1]), ntohl(p[2]), ntohl(p[3]));
	}

	return 0;
}

void get_msg_stats_tlv(const void *req_tlv_area, int req_tlv_space,
                           u32* p_ref, struct msg_filter_info* pFilter)
{
    u32 port_id, off, val;
    const void *tlv = req_tlv_area;
    int tlv_len = req_tlv_space;
    pFilter->filter_cnts = 0;
    
    port_id = *(u32 *)TLV_DATA(req_tlv_area);
    *p_ref = ntohl(port_id);
    tlv += TLV_SPACE(sizeof(u32));
    tlv_len -= TLV_SPACE(sizeof(u32));
    if (tlv_len > 0 && TLV_CHECK(tlv, tlv_len, TIPC_TLV_PORT_STATS_OFF1)) {
        pFilter->filter_cnts = 1;
        off = *(u32 *)TLV_DATA(tlv);
        pFilter->filter_list[0].offset = ntohl(off);
        tlv += TLV_SPACE(sizeof(u32));
        tlv_len -= TLV_SPACE(sizeof(u32));
        TLV_CHECK(tlv, tlv_len, TIPC_TLV_PORT_STATS_VAL1);
        val = *(u32 *)TLV_DATA(tlv);
        pFilter->filter_list[0].value = ntohl(val);
        tlv += TLV_SPACE(sizeof(u32));
        tlv_len -= TLV_SPACE(sizeof(u32)); 
    }
    if (tlv_len > 0 && TLV_CHECK(tlv, tlv_len, TIPC_TLV_PORT_STATS_OFF2)) {
        pFilter->filter_cnts = 2;
        off = *(u32 *)TLV_DATA(tlv);
        pFilter->filter_list[1].offset = ntohl(off);
        tlv += TLV_SPACE(sizeof(u32));
        tlv_len -= TLV_SPACE(sizeof(u32));
        TLV_CHECK(tlv, tlv_len, TIPC_TLV_PORT_STATS_VAL2);
        val = *(u32 *)TLV_DATA(tlv);
        pFilter->filter_list[1].value = ntohl(val);
    }
}

struct sk_buff *tipc_set_portmsg_stats(const void *req_tlv_area,
                                                   int req_tlv_space,
                                                   u16 cmd_type)
{
    u32 port_ref = 0;
    struct msg_filter_info msg_filter = {0,{0}};
    struct filter_params* ptr_params = NULL;
    struct port *ptr_port;
    struct sk_buff *buf;
    struct tlv_desc *rep_tlv;
    struct print_buf pb;
    int str_len;

    if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_PORT_REF)) {   
        return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);
    }

    get_msg_stats_tlv(req_tlv_area, req_tlv_space, &port_ref, &msg_filter);
    ptr_port = tipc_port_lock(port_ref);
    if (ptr_port == NULL) {      
        return tipc_cfg_reply_error_string("port not found");
    }

    buf = tipc_cfg_reply_alloc(TLV_SPACE(TIPC_MAX_TLV_SPACE));
    if (!buf) {
        if (ptr_port) {      
            tipc_port_unlock(ptr_port);
        }
        return NULL;
    }
    
    rep_tlv = (struct tlv_desc *)buf->data;
    tipc_printbuf_init(&pb, TLV_DATA(rep_tlv), TIPC_MAX_TLV_SPACE);
    if (cmd_type == TIPC_CMD_SET_RCVMSG_STATS) {
        ptr_port->publ.msg_stats.rcvmsg_flag = 1;   /* rcv报文统计使能 */
        ptr_port->publ.msg_stats.rcvmsg_cnts = 0;   /* 计数清零 */
        ptr_params = ptr_port->publ.msg_stats.rcvmsg_filter.filter_list;
    } else {
        ptr_port->publ.msg_stats.sndmsg_flag = 1;
        ptr_port->publ.msg_stats.sndmsg_cnts = 0;
        ptr_params = ptr_port->publ.msg_stats.sndmsg_filter.filter_list;
    }
    /* 至少有一对off/val参数 */
    ptr_params[0].offset = msg_filter.filter_list[0].offset;
    ptr_params[0].value  = msg_filter.filter_list[0].value;
    if (msg_filter.filter_cnts == 2)
    {
        ptr_params[1].offset = msg_filter.filter_list[1].offset;
        ptr_params[1].value  = msg_filter.filter_list[1].value;
        tipc_printf(&pb, "Set portid:%u stats params:<off1:0x%x, val1:0x%x, off2:0x%x, val2:0x%x>\n",
                                     port_ref, msg_filter.filter_list[0].offset,
                                               msg_filter.filter_list[0].value, 
                                               msg_filter.filter_list[1].offset,
                                               msg_filter.filter_list[1].value);
    } else {
        tipc_printf(&pb, "Set portid:%u stats params:<off1:0x%x, val1:0x%x>\n",
                                     port_ref, msg_filter.filter_list[0].offset,
                                               msg_filter.filter_list[0].value);
    }
    tipc_port_unlock(ptr_port);
 
    str_len = tipc_printbuf_validate(&pb);
    skb_put(buf, TLV_SPACE(str_len));
    TLV_SET(rep_tlv, TIPC_TLV_ULTRA_STRING, NULL, str_len);
    
    return buf;
}

/* 校验off1/val off2/val2参数 */ 
int tipc_chk_msg_stats_params(u32 cmdtype, struct port *ptr_port,
                                        struct msg_filter_info* pFilter)
{
    u32 offset, value;
    struct msg_filter_info* ptr_filter;

    if (cmdtype == TIPC_CMD_GET_RCVMSG_STATS) {
        ptr_filter = &(ptr_port->publ.msg_stats.rcvmsg_filter);
    } else {
        ptr_filter = &(ptr_port->publ.msg_stats.sndmsg_filter);
    }
    /* tipc_config -dps_xxx=1234 没有off/val参数 */
    if (ptr_filter->filter_cnts == 0) {
        return 0;
    }
    offset = ptr_filter->filter_list[0].offset;
    value  = ptr_filter->filter_list[0].value;
    if ((offset != pFilter->filter_list[0].offset) 
        || (value != pFilter->filter_list[0].value)) {
        return -1;
    }
    
    if (ptr_filter->filter_cnts == 2) {
        offset = ptr_filter->filter_list[1].offset;
        value  = ptr_filter->filter_list[1].value;
        if ((offset != pFilter->filter_list[1].offset)
            || (value != pFilter->filter_list[1].value)) {
            return -1;
        }
    }
         
    return 0;
}

struct sk_buff *tipc_get_portmsg_stats(const void *req_tlv_area,
                                                  int req_tlv_space,
                                                       u16 cmd_type)
{
    u32 port_ref = 0;
    struct msg_filter_info msg_filter = {0, {0}};
    struct port *ptr_port;
    struct sk_buff *buf;
    struct tlv_desc *rep_tlv;
    struct print_buf pb;
    int str_len;
    int ret;

    if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_PORT_REF)) {   
        return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);
    }

    get_msg_stats_tlv(req_tlv_area, req_tlv_space, &port_ref, &msg_filter);
    ptr_port = tipc_port_lock(port_ref);
    if (ptr_port == NULL) {      
        return tipc_cfg_reply_error_string("port not found");
    }

    buf = tipc_cfg_reply_alloc(TLV_SPACE(TIPC_MAX_TLV_SPACE));
    if (!buf) {
        tipc_port_unlock(ptr_port);
        return NULL;
    }
    
    rep_tlv = (struct tlv_desc *)buf->data;
    tipc_printbuf_init(&pb, TLV_DATA(rep_tlv), TIPC_MAX_TLV_SPACE);
    /* 校验dps_rcv的输入和eps_rcv的输入是否一致 */
    ret = tipc_chk_msg_stats_params(cmd_type, ptr_port, &msg_filter);
    if (ret) {
        tipc_printf(&pb, "Check msg stats params fail!\n");
    } else {
        if (cmd_type == TIPC_CMD_GET_RCVMSG_STATS) {
            tipc_printf(&pb, "Rev msg match num: %d\n",
                        ptr_port->publ.msg_stats.rcvmsg_cnts);
            ptr_port->publ.msg_stats.rcvmsg_flag = 0; /* 打印完后重置使能标记 */
        } else {
            tipc_printf(&pb, "Snd msg match num: %d\n",
                        ptr_port->publ.msg_stats.sndmsg_cnts);
            ptr_port->publ.msg_stats.sndmsg_flag = 0;
        }
    }
    tipc_port_unlock(ptr_port);
 
    str_len = tipc_printbuf_validate(&pb);
    skb_put(buf, TLV_SPACE(str_len));
    TLV_SET(rep_tlv, TIPC_TLV_ULTRA_STRING, NULL, str_len);

    return buf;
}

/* 检查使能标记和offset1/2是否超了 */
int tipc_chk_msg_stats(struct sk_buff *buf, struct port *p_ptr,
                                       TIPC_PORT_MSG_TYPE_E msgtype)
{
    u32 stats_flag;
    struct tipc_msg *msg = buf_msg(buf);
    struct msg_filter_info msg_filter = {0, {0}};
    struct msg_stats_info* ptr_msg_stats;
    u32 data_size = msg_data_sz(msg); /* 去掉tipc头后的size */
    
    ptr_msg_stats = &(p_ptr->publ.msg_stats);
    if (msgtype == TIPC_PORT_RCVMSG) {
        stats_flag = ptr_msg_stats->rcvmsg_flag;
        /* 未使能 */
        if (stats_flag == 0) {
            return -1;
        }
        memcpy(&msg_filter, &(ptr_msg_stats->rcvmsg_filter), sizeof(struct msg_filter_info));
    } else {/* TIPC_PORT_SNDMSG */
        stats_flag = ptr_msg_stats->sndmsg_flag;
        if (stats_flag == 0) {
            return -1;
        }
        memcpy(&msg_filter, &(ptr_msg_stats->sndmsg_filter), sizeof(struct msg_filter_info));
    }
    /* 从offset处连续解析4个字节 */
    if (msg_filter.filter_list[0].offset + 4 > data_size) {
        return -1;
    }
    /* 继续比较off2 */
    if (msg_filter.filter_cnts == 2) {
        if (msg_filter.filter_list[1].offset + 4 > data_size) {
            return -1;
        }
    }

    return 0;
}
      
int tipc_filter_port_msg(struct sk_buff *buf, struct port *p_ptr,
                                    TIPC_PORT_MSG_TYPE_E msgtype)
{
    struct tipc_msg *msg = buf_msg(buf);
    struct msg_filter_info* ptr_msg_filter;
    struct msg_stats_info* ptr_msg_stats;
    unsigned char* ptr_data = (unsigned char*)buf->data;

    u32 hdr_sz = msg_hdr_sz(msg); /* tipc头长度 */
    u32 data_val, stats_val;
    
    ptr_msg_stats = &(p_ptr->publ.msg_stats);
    if (msgtype == TIPC_PORT_RCVMSG) {
        ptr_msg_filter = &(ptr_msg_stats->rcvmsg_filter);
    } else {/* TIPC_PORT_SNDMSG */
        ptr_msg_filter = &(ptr_msg_stats->sndmsg_filter);
    }

    data_val  = *(u32 *)(ptr_data + hdr_sz + ptr_msg_filter->filter_list[0].offset);
    data_val = ntohl(data_val);
    stats_val = ptr_msg_filter->filter_list[0].value;
    
    if (data_val != stats_val) {
        return -1;
    }
    if (ptr_msg_filter->filter_cnts == 2) {
        data_val  = *(u32 *)(ptr_data + hdr_sz + ptr_msg_filter->filter_list[1].offset);
        data_val = ntohl(data_val);
        stats_val = ptr_msg_filter->filter_list[1].value;
        if (data_val != stats_val) {
            return -1;
        }
    }
    
    /* 匹配到 计数加1 */
    if (msgtype == TIPC_PORT_RCVMSG) {
        ptr_msg_stats->rcvmsg_cnts++;
    } else {/* TIPC_PORT_SNDMSG */
        ptr_msg_stats->sndmsg_cnts++;
    }
    
    return 0;
}

void tipc_dump_port_msg(struct sk_buff *buf, struct port *p_ptr,
                                         TIPC_PORT_MSG_TYPE_E msgtype)
{
    struct tipc_msg *msg = buf_msg(buf);
    unsigned char dump_msg[DUMP_MSG_SIZE] = {0};
    unsigned char* ptr_data = (unsigned char*)buf->data;
    unsigned char chr;
    u32 hdr_sz = msg_hdr_sz(msg);     /* tipc头长度 */
    u32 data_sz = msg_data_sz(msg);   /* 去头后的长度 */
    u32 i, len = 0;
  
    for (i = 0; i < data_sz; i++) {
        if (len >= DUMP_MSG_SIZE) {
            *(dump_msg + DUMP_MSG_SIZE - 1) = '\0';
            break;
        }
        chr = *(ptr_data /*+ hdr_sz*/ + i); /* 注意起始地址 */
        if ((i % DUMP_MSG_LINE_ALIGN) == 0) {
            len += snprintf(dump_msg + len, DUMP_MSG_SIZE - len, "0x%04x:  ", i);
        }
        if ((i % DUMP_MSG_UNIT_ALIGN) == 0) {
            len += snprintf(dump_msg + len, DUMP_MSG_SIZE - len, "  %02x", chr);
        } else {
            len += snprintf(dump_msg + len, DUMP_MSG_SIZE - len, "%02x", chr);
        }
        if ((i & DUMP_MSG_LINE_ENTER) == DUMP_MSG_LINE_ENTER) {
            len += snprintf(dump_msg + len, DUMP_MSG_SIZE - len, "\n");
        }
    }
    /* 打印报文内容 */
    info("<%u.%u.%u:%u>-><%u.%u.%u:%u>. hdrsize %d bytes, msgsize %d bytes\n%s\n",
         tipc_zone(msg_orignode(msg)), tipc_cluster(msg_orignode(msg)), 
         tipc_node(msg_orignode(msg)), msg_origport(msg),
         tipc_zone(msg_destnode(msg)), tipc_cluster(msg_destnode(msg)),
         tipc_node(msg_destnode(msg)), msg_destport(msg),
         hdr_sz, msg_size(msg), dump_msg);
}

/* msgtype 0->revmsg 1->sndmsg  */
void tipc_port_msg_stats(struct sk_buff *buf, struct port *p_ptr,
                                    TIPC_PORT_MSG_TYPE_E msgtype)
{
    if (likely(tipc_chk_msg_stats(buf, p_ptr, msgtype))) {
        
    } else {
        /* 开始过滤报文 */
        if (likely(tipc_filter_port_msg(buf, p_ptr, msgtype))) {

        } else {
            tipc_dump_port_msg(buf, p_ptr, msgtype);
        }
    }
    return;
}

/* tipc模块日志开关 */
unsigned int g_tipc_dbg_switch = 0;

struct sk_buff *tipc_debug_log_switch(const void *req_tlv_area,
                                                  int req_tlv_space)
{
    const void *tlv = req_tlv_area;
    int tlv_len = req_tlv_space;
    struct sk_buff *buf;
    struct tlv_desc *rep_tlv;
    struct print_buf pb;
    int str_len;
    u32 type;
    u32 stat;

    /* 获取type/stat */
    if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_DEBUG_LOG_TYPE)) {   
        return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);
    }
    type = *(u32 *)TLV_DATA(req_tlv_area);
	type = ntohl(type);
    tlv += TLV_SPACE(sizeof(u32));
    tlv_len -= TLV_SPACE(sizeof(u32));
    
    if (!TLV_CHECK(tlv, tlv_len, TIPC_TLV_DEBUG_LOG_STAT)) {
        return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);
    }
    stat = *(u32 *)TLV_DATA(tlv);
	stat = ntohl(stat);
    tlv += TLV_SPACE(sizeof(u32));
    tlv_len -= TLV_SPACE(sizeof(u32));

    if (stat == 1) { /* on */
        g_tipc_dbg_switch |= type;
    }
    else { /* off */
        g_tipc_dbg_switch &= ~type;
    }

    buf = tipc_cfg_reply_alloc(TLV_SPACE(TIPC_MAX_TLV_SPACE));
    if (!buf) {
        return NULL;
    }
    
    rep_tlv = (struct tlv_desc *)buf->data;
    tipc_printbuf_init(&pb, TLV_DATA(rep_tlv), TIPC_MAX_TLV_SPACE);
    tipc_printf(&pb, "Debug switch info: 0x%x\n", g_tipc_dbg_switch & 0x1f);
    tipc_printf(&pb, "bcast: 0x1, eth_media: 0x2, link: 0x4\n");
    tipc_printf(&pb, "port:  0x8, socket:   0x10, all: 0x1f\n");
    
    str_len = tipc_printbuf_validate(&pb);
    skb_put(buf, TLV_SPACE(str_len));
    TLV_SET(rep_tlv, TIPC_TLV_ULTRA_STRING, NULL, str_len);

    return buf;
}

#endif
