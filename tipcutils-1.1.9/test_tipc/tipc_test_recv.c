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

#include "tipc_test_pub.h"

/*
f--------------first msg
e--------------end msg
n--------------next msg
s--------------stop
r--------------response
*/

int main(int argc, char *argv[])
{
        int j,fd, msg_len, retval, count = 0;
        char *msg_buf;
	fd_set rfds;
	struct sockaddr_tipc sa_src;
	struct route_msg *rt_msg;
	struct sockaddr_tipc sa_dest;

        struct timeval tv1;
	struct timeval tv2;
	char *p;
	int ins = 0;

        msg_len = 100;
	
        if (argc > 1)
        {
		msg_len = atoi(argv[1]);
	}


        
	memset(&tv1, 0, sizeof(struct timeval));
	memset(&tv2, 0, sizeof(struct timeval));
	
	int sa_src_len = sizeof(struct sockaddr_tipc);
	
	memset(&sa_src, 0, sizeof(struct sockaddr_tipc));	

	rt_msg = (struct route_msg *)malloc(sizeof(struct route_msg));
	assert(rt_msg);
	memset(rt_msg, 0, sizeof(struct route_msg));
	rt_msg->pstr = (char *)malloc(msg_len-4);
	msg_buf = (char *)malloc(msg_len);
	memset(msg_buf, 0, msg_len);

	if (argc > 2) {
		for (j=2; j < argc; j++) {
			int cid = 0;
			ins = atoi(argv[j]);
			cid = fork();
			if (cid < 0) {
				printf("fork failed\n");
				exit(cid);
			} else if (cid == 0) {
				printf("fork recv %d...\n", ins);
				break;
			}
		}

		if (j >= argc) {
			printf("root recv sleeping ...\n");
			while (1)
				usleep(1);
		}
	}
	
	fd = tipc_create_port(TIPC_FES_PORT_TYPE, ins);

    	memset(&sa_dest, 0, sizeof(struct sockaddr_tipc));
	sa_dest.family = AF_TIPC;
	sa_dest.addrtype = TIPC_ADDR_NAME;
	sa_dest.addr.name.name.type = TIPC_RM_PORT_TYPE;    
	sa_dest.addr.name.name.instance = TIPC_RM_PORT_INSTANCE;
	sa_dest.addr.name.domain = 0;
	sa_dest.scope = TIPC_CLUSTER_SCOPE;
recv_ready: 
	count = 0;
	/*printf("The recieve process is ready.\n");*/
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	retval = 1/*select(fd+1, &rfds, NULL, NULL, NULL )*/;
	if(retval == -1) 
		assert(0);
	else if(retval) {
		assert(FD_ISSET(fd, &rfds));
		retval = recvfrom(fd, msg_buf, msg_len, 0, (struct sockaddr *)&sa_src, &sa_src_len);
		/*p = (char *)msg_buf; for (j=0;j < msg_len; j++) printf("%02X ", *p++);printf("\n");*/
		if(retval == -1)
			assert(0);
		if('f' == *(msg_buf+4)){
			gettimeofday(&tv1, NULL);/*取时间戳1*/
			/*printf("First msg revieved!\n");*/
		}
	}
	for(;;) {
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		
		retval = 1/*select(fd+1, &rfds, NULL, NULL, NULL )*/;
		if(retval == -1) 
			assert(0);
		else if(retval) {
			assert(FD_ISSET(fd, &rfds));
			retval = recvfrom(fd, msg_buf, msg_len, 0, (struct sockaddr *)&sa_src, &sa_src_len);
			/*printf("*%d", chararray2int(msg_buf));*/
			/*p = (char *)msg_buf; for (j=0;j < msg_len; j++) printf("%02X ", *p++);printf("\n");*/
			if(retval < 0)
				continue;
			if('e' == *(msg_buf+4))
			    printf("\n\n\nIns %d receive Index of end msg\t\t\t%d\n", ins, ntohl(*(unsigned int *)msg_buf));
			if('s' == *(msg_buf+4))
			{
			    gettimeofday(&tv2, NULL);/*取时间戳2*/
			    /*printf("Last msg recieved!\n");*/
			    break;
			}
				
		}
		count++;
		
	}

	printf("*******************************************************\n");

	printf("Ins %d Recieve ", ins);
	get_time_interval_info_us(&tv1, &tv2);
	printf("Num of recieved msg\t\t%d\nlength of msg\t\t\t%d\n", count, retval);
	
#if 1
	/*printf("Response to source peer!\n");*/
	rt_msg->index = htonl(count);
	p = rt_msg->pstr;for(j =0;j<msg_len-4; j++){ *p ='r';p++;}
        /*printf("line:118:fd = %d.*(msg->pstr) = %c\n", fd, *(rt_msg->pstr));*/
        memcpy(msg_buf, rt_msg, 4);
        memcpy(msg_buf+4, rt_msg->pstr, msg_len-4);
	sendto(fd, msg_buf, msg_len, 0, (struct sockaddr *)&sa_dest, sizeof(struct sockaddr_tipc));
	/*p = (char *)msg_buf; for (j=0;j < msg_len; j++) printf("%02X ", *p++);printf("\n");*/

	/*printf("The recieve process is end!\n");*/
	printf("*******************************************************\n\n\n");
#endif
goto recv_ready;

        free(msg_buf);
        free(rt_msg->pstr);
        free(rt_msg);

    
	
	return 0;
    
}

