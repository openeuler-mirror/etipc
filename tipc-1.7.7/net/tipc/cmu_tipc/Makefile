#
# Makefile for the Linux TIPC layer
#
ifneq ($(KERNELRELEASE), )

obj-m += tipc.o

#####################################################
# define EXTRA_CFLAGS                               #
#####################################################
NE5000E_TIPC = 1
TIPC_FLAGS =

#TIPC_FLAGS += -DCONFIG_TIPC=m
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
TIPC_FLAGS += -DCONFIG_TIPC_PSHCNT_MAX=80000 # 韧性测试10业务量下超过60000

# NE5000E
ifeq ($(NE5000E_TIPC),1)

TIPC_FLAGS += -DCONFIG_TIPC_NODE_LINK_MAX=8
TIPC_FLAGS += -DCONFIG_TIPC_MCASTGID_MAX=32
#TIPC_FLAGS += -DCONFIG_TIPC_DUMMY_MULTICAST=0
TIPC_FLAGS += -DCONFIG_TIPC_LINK_TAG=1
TIPC_FLAGS += -DCONFIG_TIPC_SEND_VLAN=1

else
# atac

TIPC_FLAGS += -DCONFIG_TIPC_NODE_LINK_MAX=4
TIPC_FLAGS += -DCONFIG_TIPC_MCASTGID_MAX=32
TIPC_FLAGS += -DCONFIG_TIPC_DUMMY_MULTICAST=1
TIPC_FLAGS += -DCONFIG_TIPC_LINK_TAG=1
#TIPC_FLAGS += -DCONFIG_TIPC_SEND_VLAN=1

endif
TIPC_FLAGS += -DTIPC_SUPPORT_LS
TIPC_FLAGS += -DCMU_FLAG
MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
CUR_PATH := $(patsubst %/Makefile, %, $(MAKEFILE_PATH))
cur_offset_src=..

NOSTDINC_FLAGS := $(NOSTDINC_FLAGS) $(TIPC_FLAGS) -I$(CUR_PATH)/../../../include
               
EXTRA_CFLAGS +=

#####################################################
# define module obj                                 #
#####################################################

OBJS := $(cur_offset_src)/tipc_addr.o $(cur_offset_src)/tipc_bcast.o $(cur_offset_src)/tipc_bearer.o $(cur_offset_src)/tipc_cfgsrv.o  \
	$(cur_offset_src)/tipc_core.o $(cur_offset_src)/tipc_handler.o $(cur_offset_src)/tipc_link.o $(cur_offset_src)/tipc_discover.o \
	$(cur_offset_src)/tipc_msg.o $(cur_offset_src)/tipc_name_distr.o $(cur_offset_src)/tipc_topsrv.o \
	$(cur_offset_src)/tipc_name_table.o $(cur_offset_src)/tipc_net.o  \
	$(cur_offset_src)/tipc_netlink.o $(cur_offset_src)/tipc_node.o $(cur_offset_src)/tipc_port.o $(cur_offset_src)/tipc_ref.o  \
	$(cur_offset_src)/tipc_socket.o $(cur_offset_src)/tipc_user_reg.o $(cur_offset_src)/tipc_dbg.o \
	$(cur_offset_src)/tipc_eth_media.o $(cur_offset_src)/tipc_raw_socket.o

tipc-objs := $(OBJS)

else
default:
	$(MAKE) -C $(KERNELDIR) M=$(shell pwd) modules && aarch64-target-linux-gnu-strip -d tipc.ko

clean:
	$(MAKE) -C $(KERNELDIR) M=$(shell pwd) clean
	rm -f ../*.o ../.*.o.cmd

endif

