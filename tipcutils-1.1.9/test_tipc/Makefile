#
# Makefile for tipc-config
#

ifdef INCLUDE_PATH
# Specifies path to directory that resolves #include <linux/tipc.h>
IFLAGS = -I${INCLUDE_PATH}
endif

ifndef VERSION
VERSION = UNKNOWN
endif
CC = $(CROSS_COMPILE)gcc
OFLAGS = -Wall -O2 -s -D_FORTIFY_SOURCE=2 -g
DFLAGS = -D VERSION=\"${VERSION}\"
CFLAGS = ${IFLAGS} ${DFLAGS} ${OFLAGS} ${EXTRAS}

all: recv usend msend

recv : tipc_test_recv.o tipc_test_pub.o
	$(CC) $(CFLAGS) $^ -o $@

usend : tipc_test_send_unicast.o tipc_test_pub.o
	$(CC) $(CFLAGS) $^ -o $@

msend : tipc_test_send_mulcast.o tipc_test_pub.o
	$(CC) $(CFLAGS) $^ -o $@

clean:
	${RM} *.o recv msend usend

