
#define	TIPC_RM_PORT_TYPE	0x1000001
#define	TIPC_FES_PORT_TYPE	0x1000002


#define	TIPC_RM_PORT_INSTANCE	0
#define	TIPC_FES_PORT_INSTANCE	0

#define RUN_TYPE_SEND 1
#define	RUN_TYPE_RECV 2

struct route_msg {
    int index;
    char *pstr;
};




extern int tipc_create_port(int type, int instance);
extern unsigned int get_time_interval_info_us(void * start, void *end);
extern int chararray2int(char * p);



