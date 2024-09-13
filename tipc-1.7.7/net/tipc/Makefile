#
# Makefile for the Linux TIPC layer
#

##全局变量定义
RM = rm -f
INCLUDE =
DEFS =
OBJS =
CC=gcc

EXTRA_CFLAGS += -DVOS_OS_VER=4
###
EXTRA_CFLAGS += -DVOS_LITTLE_ENDIAN=1234
EXTRA_CFLAGS += -DVOS_BIG_ENDIAN=4321
ifeq ($(CPU_INSX),x86)
EXTRA_CFLAGS += -DVOS_BYTE_ORDER=VOS_LITTLE_ENDIAN
else ifeq ($(CPU_INSX),arm)
EXTRA_CFLAGS += -DVOS_BYTE_ORDER=VOS_LITTLE_ENDIAN
else ifeq ($(CPU_INSX),arm64)
EXTRA_CFLAGS += -DVOS_BYTE_ORDER=VOS_LITTLE_ENDIAN
else
EXTRA_CFLAGS += -DVOS_BYTE_ORDER=VOS_BIG_ENDIAN
endif

EXTRA_CFLAGS += -DIOF_KERNEL -g
EXTRA_CFLAGS += -Wno-missing-braces -Wno-array-bounds

# tipc-1.7.7/net/tipc/Makefile
#####################################################
# define module name                                #
#####################################################
MODULE = tipc

#####################################################
# define EXTRA_CFLAGS                               #
#####################################################

TIPC_FLAGS =
# TIPC_FLAGS += -DCONFIG_TIPC=m    # 该FLAG如果使能, 会导致内核模块编译出错
TIPC_FLAGS += -DCONFIG_TIPC_ADVANCED=1
TIPC_FLAGS += -DCONFIG_TIPC_NETID=4711
TIPC_FLAGS += -DCONFIG_TIPC_REMOTE_MNG=1
TIPC_FLAGS += -DCONFIG_TIPC_PORTS=8191
TIPC_FLAGS += -DCONFIG_TIPC_NODES=360
TIPC_FLAGS += -DCONFIG_TIPC_CLUSTERS=8
TIPC_FLAGS += -DCONFIG_TIPC_ZONES=4
TIPC_FLAGS += -DCONFIG_TIPC_REMOTES=8
TIPC_FLAGS += -DCONFIG_TIPC_PUBL=10000
TIPC_FLAGS += -DCONFIG_TIPC_SUBSCR=2000
TIPC_FLAGS += -DCONFIG_TIPC_LOG=0
TIPC_FLAGS += -DCONFIG_TIPC_UNICLUSTER_FRIENDLY=1
TIPC_FLAGS += -DCONFIG_TIPC_MULTIPLE_LINKS=1
TIPC_FLAGS += -DCONFIG_TIPC_CONFIG_SERVICE=1
TIPC_FLAGS += -DCONFIG_TIPC_SOCKET_API=1
TIPC_FLAGS += -DCONFIG_TIPC_SYSTEM_MSGS=1
TIPC_FLAGS += -DCONFIG_TIPC_PSHCNT_MAX=120000 # 韧性测试10业务量下超过80000

TIPC_FLAGS += -DCONFIG_TIPC_NODE_LINK_MAX=8
TIPC_FLAGS += -DCONFIG_TIPC_MCASTGID_MAX=32
#TIPC_FLAGS += -DCONFIG_TIPC_DUMMY_MULTICAST=0
TIPC_FLAGS += -DCONFIG_TIPC_LINK_TAG=1
TIPC_FLAGS += -DCONFIG_TIPC_SEND_VLAN=1

TIPC_FLAGS += -DTIPC_SUPPORT_LS

PWD := $(shell pwd)
INCLUDE=$(ETIPC_INCLUDE_PATH)
$(info INCLUDE_PATH=$(INCLUDE))

NOSTDINC_FLAGS := $(NOSTDINC_FLAGS) $(TIPC_FLAGS)
NOSTDINC_FLAGS += -I$(INCLUDE)
NOSTDINC_FLAGS += -D__nohcfi= -Ddo_gettimeofday_snapshot=ktime_get_real_ts64

EXTRA_CFLAGS += $(TIPC_FLAGS)
#####################################################
# define module obj                                 #
#####################################################

OBJS := tipc_addr.o tipc_bcast.o tipc_bearer.o tipc_cfgsrv.o  \
	   tipc_core.o tipc_handler.o tipc_link.o tipc_discover.o tipc_msg.o  \
	   tipc_name_distr.o tipc_topsrv.o tipc_name_table.o tipc_net.o  \
	   tipc_netlink.o tipc_node.o tipc_port.o tipc_ref.o  \
	   tipc_socket.o tipc_user_reg.o tipc_dbg.o tipc_eth_media.o tipc_raw_socket.o
#####################################################
# donn't modify                                     #
#####################################################
obj-m := $(MODULE).o
$(MODULE)-objs := $(OBJS)

### 内核头文件路径

KERNEL_DIR ?= /usr/src/kernels/$(shell uname -r)

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

# End of file

#####################################################
# make clean                                        #
#####################################################
clean:
	@$(RM) -rf $(shell find $(dir $(OBJS)) -name "*.o")
	@$(RM) -rf $(shell find $(dir $(OBJS)) -name "*.ko")
	@$(RM) -rf $(shell find $(dir $(OBJS)) -name "*.mod.c")
	@$(RM) -rf $(shell find $(dir $(OBJS)) -name "*.symvers")
	@$(RM) -rf $(shell find $(dir $(OBJS)) -name "*.order")
	@$(RM) -rf $(shell find $(dir $(OBJS)) -name ".*.cmd")