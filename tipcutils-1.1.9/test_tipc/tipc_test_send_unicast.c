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
#define SEND_DEST_MAX 6

int run_type = -1;/*1:发送者，2:接收者*/
int flag = 0;
int failed[SEND_DEST_MAX] = {0};
int sent[SEND_DEST_MAX] = {0};

int main(int argc, char *argv[])
{
	struct sockaddr_tipc sa_dest[SEND_DEST_MAX],sa_src;
	int fd, msg_num = 0, i;
	int package_num, sleep_time;
	struct route_msg *rt_msg;
	char *msg_buf;
	int msg_len, j;
	fd_set rfds;
	int retval = -1;
	int sa_src_len = sizeof(struct sockaddr_tipc);
	char *p;
	int k = 0;
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
	
	if (msg_len < sizeof(*rt_msg))
		msg_len = sizeof(*rt_msg);
	
	if (argc > 3) {
		ins = atoi(argv[3]);
	}
	


	fd = tipc_create_port(TIPC_RM_PORT_TYPE, ins);
	for (i=0; i<SEND_DEST_MAX; i++) {
		memset(&sa_dest[i], 0, sizeof(struct sockaddr_tipc));
		sa_dest[i].family = AF_TIPC;
		sa_dest[i].addrtype = TIPC_ADDR_NAME;
		sa_dest[i].addr.name.name.type = TIPC_FES_PORT_TYPE;    
		sa_dest[i].addr.name.name.instance = i+ins;
		sa_dest[i].addr.name.domain = 0;
		
		sa_dest[i].scope = TIPC_CLUSTER_SCOPE;
		if (i%3 == 1) {
			sa_dest[i].addrtype = TIPC_ADDR_NAMESEQ;
			sa_dest[i].addr.nameseq.type = TIPC_FES_PORT_TYPE;    
			sa_dest[i].addr.nameseq.lower = ins+i;
			sa_dest[i].addr.nameseq.upper = 1000;
		}
	}
	

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
	for (i=0; i<SEND_DEST_MAX; i++)
		retval = sendto(fd, msg_buf, msg_len, 0, (struct sockaddr *)&sa_dest[i], sizeof(struct sockaddr_tipc));
	/*p = (char *)msg_buf;for (j=0;j < msg_len; j++) printf("%02X ", *p++);printf("\n");*/
	/*printf("Send the first msg.\n");*/

	printf("\n\n*******************************************************\n");
	printf("Ins <%d> Num of send msg\t\t\t%d\n", ins, msg_num);	

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
		retval = sendto(fd, msg_buf, msg_len, MSG_DONTWAIT, (struct sockaddr *)&sa_dest[k], sizeof(struct sockaddr_tipc));	
		/*p = (char *)msg_buf; for (j=0;j < msg_len; j++) printf("%02X ", *p++);printf("\n");*/
		/*printf("index = %d,retval= %d\n", i, retval);*/
		while(retval < 0 && k < SEND_DEST_MAX) {
			failed[k] ++;
			k++;
			retval = sendto(fd, msg_buf, msg_len, MSG_DONTWAIT, (struct sockaddr *)&sa_dest[k], sizeof(struct sockaddr_tipc));
		}

		if (retval > 0 && k<SEND_DEST_MAX)
			sent[k]++;		


		if(0 == i%package_num || k>=SEND_DEST_MAX)
			usleep(sleep_time);
		
		if (k > 1 && (i % 3 == 2))
			k = 0;
	}

	gettimeofday(&tv2, NULL);/*取时间戳2*/


	printf("Send ", ins);
	get_time_interval_info_us(&tv1, &tv2);

	for (k=0; k<SEND_DEST_MAX; k++) {
		printf("Num of [%d]  sent success/failed \t\t%d/%d\n", k, sent[k], failed[k]);
	}
	
	printf("Num of send msg\t\t\t%d\nLength of msg\t\t\t%d\n", ntohl(*(unsigned int *)msg_buf)+1, msg_len);
	rt_msg->index = htonl(msg_num);
	p = rt_msg->pstr;for(j =0;j<msg_len-4; j++){ *p = 's';p++;}/*stop*/
	memcpy(msg_buf, rt_msg, 4);
	memcpy(msg_buf+4, rt_msg->pstr, msg_len-4);
	for (i=0; i<SEND_DEST_MAX; i++) {
		retval = sendto(fd, msg_buf, msg_len, 0, (struct sockaddr *)&sa_dest[i], sizeof(struct sockaddr_tipc));
		if (retval > 0)
			k++;
	}
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
		msg_num = 0;
		for (;k;k--)
		{
			assert(FD_ISSET(fd, &rfds));
			retval = recvfrom(fd, msg_buf, msg_len, 0, (struct sockaddr *)&sa_src, &sa_src_len);
			/*p = (char *)msg_buf; for (j=0;j < msg_len; j++) printf("%02X ", *p++);printf("\n");*/
			if(retval < 0)
				continue;
			if('r' == *(msg_buf+4))/*response*/ {
				int n = ntohl(*(unsigned int *)msg_buf);
				if (n <= 0)
					continue;
				msg_num += n;
				printf("Num of peer received\t\t%d, total %d\n", n, msg_num);
			}
		}

		printf("Num of all peers revieved\t\t%d\n", msg_num);
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

