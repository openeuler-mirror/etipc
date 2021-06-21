#
# Makefile for the Linux TIPC layer
#


#####################################################
# include public define                             #
#####################################################
-include $(V8_ROOT)/build/main_build/def_ko.mak

#####################################################
# define module name                                #
#####################################################
MODULE = tipc

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
TIPC_FLAGS += -DCONFIG_TIPC_PSHCNT_MAX=120000 # 韧性测试10业务量下超过80000

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

S_DIR :=  $(if $(wildcard $(V8_ROOT)/$(src)),$(V8_ROOT)/$(src),$(src))

ifeq ($(NE5000E_TIPC),1)
#KBUILD_CPPFLAGS := -I$(S_DIR)/include  $(KBUILD_CPPFLAGS) $(TIPC_FLAGS)
NOSTDINC_FLAGS := $(NOSTDINC_FLAGS) -I$(S_DIR)/include $(TIPC_FLAGS)
else
CPPFLAGS := -I$(S_DIR)/include $(CPPFLAGS) $(TIPC_FLAGS)
endif


EXTRA_CFLAGS += 

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










# End of file
