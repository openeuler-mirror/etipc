#####################################################
# include public define file                        #
#####################################################
include $(V8_ROOT)/build/main_build/def_app.mak

#####################################################
# define variable                                   #
#####################################################
TARGET  = $(V8_RELEASE_APP_PATH)/tipc_config


SRC_FILES = tipc_config.c



#####################################################
# include module headfile                           #
#####################################################
INCLUDE +=	-I$(V8_ROOT)/open_source/tipc/src/include
			
ifndef VERSION
VERSION = UNKNOWN
endif

CFLAGS += -Wno-format-nonliteral

CFLAGS += -Wno-format-nonliteral -fPIE -D_FORTIFY_SOURCE=2 -O2
LDFLAGS += -fstack-protector-all -fPIE -pie
STRIP_FLAG += --strip-unneeded	       
DEFS += -DVERSION=\"${VERSION}\"
#####################################################
# include commfrv exec file                         #
#####################################################
include $(V8_ROOT)/build/main_build/exec_so.mak
