#####################################################
# include public define file                        #
#####################################################

##全局变量定义
INCLUDE :=
LIBS :=
DEFS :=
CFLAGS := -g
SRC_FILES :=
CC=gcc
VERSION = UNKNOWN

#####################################################
# define variable                                   #
#####################################################
TARGET  = tipc_config
SRCS = tipc_config.c

#####################################################
# include module headfile                           #
#####################################################

CFLAGS += -Wno-format-nonliteral -fPIE -D_FORTIFY_SOURCE=2 -O2
CFLAGS += -I$(ETIPC_INCLUDE_PATH)

CFLAGS += -DVERSION=\"${VERSION}\"

# The default target to build
all: $(TARGET)

# Rule to build the executable
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

# Clean up build files
clean:
	rm -f $(TARGET)