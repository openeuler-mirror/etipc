#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/queue.h>
#include <sys/select.h>
#include <linux/tipc.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/poll.h>
/*
f--------------first msg
e--------------end msg
n--------------next msg
s--------------stop
r--------------response
*/


#include "tipc_test_pub.h"

int run_type = -1;/*1:发送者，2:接收者*/
int flag = 0;
int main(int argc, char *argv[])
{
    struct sockaddr_tipc sa_dest,sa_src;
    int fd, msg_num = 0, i;
    int package_num, sleep_time;
    struct route_msg *rt_msg;
    char *msg_buf;
    int msg_len, j;
    fd_set rfds;
    int retval = -1;
    int sa_src_len = sizeof(struct sockaddr_tipc);
    char *p;
    int ins = 0;

    struct timeval tv1;
	struct timeval tv2;

	memset(&tv1, 0,sizeof(struct timeval));
	memset(&tv2, 0,sizeof(struct timeval));
    
    msg_num = 1000;
    package_num = 10000;
    sleep_time = 1;
    msg_len = 1000;
    
    if(argc >= 3)
    {
	msg_num = atoi(argv[1]);
	msg_len = atoi(argv[2]);
    }
    if (argc > 3)
    	ins = atoi(argv[3]);
    
	if (msg_len < sizeof(*rt_msg))
		msg_len = sizeof(*rt_msg);

    
    fd = tipc_create_port(TIPC_RM_PORT_TYPE, ins);
    memset(&sa_dest, 0, sizeof(struct sockaddr_tipc));
	sa_dest.family = AF_TIPC;
	sa_dest.addrtype = TIPC_ADDR_NAMESEQ;
	sa_dest.addr.nameseq.type = TIPC_FES_PORT_TYPE;    
	sa_dest.addr.nameseq.lower = ins;
	sa_dest.addr.nameseq.upper = 1000;
	sa_dest.scope = TIPC_CLUSTER_SCOPE;

    printf("*******************************************************\n");
    printf("Num of send msg\t\t\t%d\n", msg_num);	

	rt_msg = (struct route_msg *)malloc(sizeof(struct route_msg));
	assert(rt_msg);
	memset(rt_msg, 0, sizeof(struct route_msg));
	rt_msg->pstr = (char *)malloc(msg_len-4);
	memset(rt_msg->pstr, 0 , msg_len-4);
	msg_buf = (char *)malloc(msg_len);
	memset(msg_buf, 0 , msg_len);
	

    rt_msg->index = -1;
    p = rt_msg->pstr;for(j =0;j<msg_len-4; j++){ *p ='f'; p++;}/*first msg*/
    /*printf("line:84:fd = %d.\n", fd);*/
    memcpy(msg_buf, rt_msg, 4);
    memcpy(msg_buf+4, rt_msg->pstr, msg_len-4);
    retval = sendto(fd, msg_buf, msg_len, 0, (struct sockaddr *)&sa_dest, sizeof(struct sockaddr_tipc));
    /*p = (char *)msg_buf;for (j=0;j < msg_len; j++) printf("%02X ", *p++);printf("\n");*/
    /*printf("Send the first msg.\n");*/

    gettimeofday(&tv1, NULL);/*取时间戳1*/
    
    for(i =0; i<msg_num; i++)
    {
        rt_msg->index = htonl(i);
        if(i == (msg_num-1)){
        	p = rt_msg->pstr;for(j =0;j<msg_len-4; j++){ *p = 'e';p++;}/*end*/}
        else{
        	p = rt_msg->pstr;for(j =0;j<msg_len-4; j++){ *p = 'n';p++;}/*next*/}
        retval =0;
        memcpy(msg_buf, rt_msg, 4);
        memcpy(msg_buf+4, rt_msg->pstr, msg_len-4);
        retval = sendto(fd, msg_buf, msg_len, 0, (struct sockaddr *)&sa_dest, sizeof(struct sockaddr_tipc));	
        /*p = (char *)msg_buf; for (j=0;j < msg_len; j++) printf("%02X ", *p++);printf("\n");*/
        /*printf("index = %d,retval= %d\n", i, retval);*/
        if(0 > retval)
        	flag ++;
        if(0 == i%package_num)
        	usleep(sleep_time);
    }

    gettimeofday(&tv2, NULL);/*取时间戳2*/

    printf("Send ");
    get_time_interval_info_us(&tv1, &tv2);
    
    printf("Num of failed to send\t\t%d\n",flag);
    printf("Num of send msg\t\t\t%d\nLength of msg\t\t\t%d\n", ntohl(*(unsigned int *)msg_buf)+1, retval);
    rt_msg->index = msg_num;
    p = rt_msg->pstr;for(j =0;j<msg_len-4; j++){ *p = 's';p++;}/*stop*/
    memcpy(msg_buf, rt_msg, 4);
    memcpy(msg_buf+4, rt_msg->pstr, msg_len-4);
    sendto(fd, msg_buf, msg_len, 0, (struct sockaddr *)&sa_dest, sizeof(struct sockaddr_tipc));
    /*p = (char *)msg_buf; for (j=0;j < msg_len; j++) printf("%02X ", *p++);printf("\n");*/
    free(rt_msg->pstr);
    free(rt_msg);

#if 1
    {/*recv response*/
   	FD_ZERO(&rfds);
   	FD_SET(fd, &rfds);
	retval = 1/*select(fd+1, &rfds, NULL, NULL, NULL )*/;
	if(retval == -1) 
		assert(0);
	else if(retval)
	{
		assert(FD_ISSET(fd, &rfds));
		retval = recvfrom(fd, msg_buf, msg_len, 0, (struct sockaddr *)&sa_src, &sa_src_len);
		/*p = (char *)msg_buf; for (j=0;j < msg_len; j++) printf("%02X ", *p++);printf("\n");*/
		if(retval == -1)
			assert(0);
		if('r' == *(msg_buf+4))/*response*/
		    printf("Num of peer revieved\t\t%d\n", ntohl(*(unsigned int *)msg_buf));
	}
    }
    
#endif   
    gettimeofday(&tv2, NULL);/*取时间戳2*/

    printf("Sent First to Recv Last ");
    get_time_interval_info_us(&tv1, &tv2);


    /*printf("Send process is end.\n");*/
    printf("*******************************************************\n");
    free(msg_buf);
    while (1)
    	usleep(1);
    
    
    return 0;
    

}

