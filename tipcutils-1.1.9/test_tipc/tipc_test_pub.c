#include <assert.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <linux/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include	<sys/queue.h>
#include <linux/tipc.h>
#include <unistd.h>
#include <pthread.h>
#include	<stdarg.h>

int tipc_create_port(int type, int instance)
{
	int fd;
	struct sockaddr_tipc sa;
	
	assert(type >=0 );
	assert(instance >= 0);

	fd = socket(AF_TIPC, SOCK_RDM, 0);
	assert(fd > 0);

	memset(&sa, 0, sizeof(struct sockaddr_tipc));
	sa.family = AF_TIPC;
	sa.addrtype = TIPC_ADDR_NAME;
	sa.addr.name.name.type = type;    
	sa.addr.name.name.instance = instance;
	sa.addr.name.domain = 0;
	sa.scope = TIPC_CLUSTER_SCOPE;

	if( bind( fd,(struct sockaddr *)&sa, sizeof(sa)) != 0)
		assert(0);
	
	return fd;	

}

unsigned int get_time_interval_info_us(void * start, void *end)
{
	struct timeval *start_time = NULL;
	struct timeval *end_time   = NULL;
	unsigned long  sec   = 0;
	unsigned long  usec  = 0;
	
	if (NULL == start || NULL == end)
	{
		return -1;
	}
	start_time = (struct timeval *)start;
	end_time   = (struct timeval *)end;

	
	/*printf("start_time.tv_sec = %ld, start_time.tv_usec = %ld, end_time.tv_sec = %ld, end_time.tv_usec = %ld \r\n",
	start_time->tv_sec,start_time->tv_usec, end_time->tv_sec,end_time->tv_usec);*/

	if (end_time->tv_sec < start_time->tv_sec)
	{
		assert(0);
		return -1;
	}

	sec = end_time->tv_sec - start_time->tv_sec;

	if (end_time->tv_usec >= start_time->tv_usec)
	{
		usec = end_time->tv_usec - start_time->tv_usec;
	}
	else
	{
		sec = sec -1;
		usec = (1000000 - start_time->tv_usec) + end_time->tv_usec;
	}

	usec = (sec*1000000) + usec;

	printf("time(us)\t\t\t%ld \r\n", usec);
	
	return 0;	
}

int chararray2int(char * p)
{
    int result =0;
    
    result = (int)p[0];
    result = result<<8;
    result = result + (int)p[1];
    result = result<<8;
    result = result + (int)p[2];
    result = result<<8;
    result = result + (int)p[3];
    
    return result;
}

