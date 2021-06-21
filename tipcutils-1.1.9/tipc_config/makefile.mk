include $(V8_ROOT)/build/main_build/ssp/ssp_pub.mak

ifndef VERSION
VERSION = UNKNOWN
endif

INCLUDE =  -I . -I ../tipc/include
DFLAGS = -D VERSION=\"${VERSION}\"
DEFS =
#ifeq ($(USELLT), 1)
#ifneq ($(CPU_INS), softfp)
#LIBS = -L$(HLLT_TOOLPATH) -lNCSCore$(CPU_INS)
#else
LIBS =
#endif
#endif
CFLAGS += $(DFLAGS)

SRC_FILES = $(wildcard *.c)

OBJ       = $(addprefix $(V8_RELEASE_OBJ_PATH)/, $(patsubst %.c, %.o, $(notdir $(SRC_FILES))))

TARGET    = $(V8_RELEASE_LIB_PATH)/tipc_config

PROJECT  := tipc_config
$(TARGET):$(OBJ)
#ifeq ($(USELLT),1)
#ifneq ($(CPU_INS), softfp)
#	lltld -projectname $(PROJECT) $(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LIBS)
#else
#	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LIBS)
#endif
#else
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LIBS)
#endif

include $(V8_ROOT)/build/main_build/ssp/exec.mak


