#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <byteswap.h>

#include <fcntl.h>
#include <time.h>
#include <sys/syslog.h>
#include <signal.h>
#include <net/if.h>



#include "../include/librdi.h"
int main(int argp, char **envp)
{
struct rdi_mem rdi_mem;
struct rdi_mac_s rdi_mac;
/*
 * * Command line parsing
 * */
memset((void *)&rdi_mem, 0, sizeof(struct rdi_mem) );
memset((void *)&rdi_mac, 0, sizeof(struct rdi_mac_s) );
/* Redirect matching packets command – redirect all packets coming on port1 with 00:e0:ed:54:7a:79 source MAC address to port3 with the same MAC address, Rule Id is 300*/
memcpy((void *)&rdi_mac.mac,(void *)"00:e0:ed:54:7a:79", strlen("00:e0:ed:54:7a:79") );
rdi_mem.port=1;
rdi_mem.src_port=1;
rdi_mem.dst_port=3;
rdi_mem.redir_port=3;
rdi_mem.rule_id=300;
memcpy((void *)&rdi_mem.src_mac,(void *)&rdi_mac,sizeof(struct rdi_mac_s));
memcpy((void *)&rdi_mem.dst_mac,(void *)&rdi_mac,sizeof(struct rdi_mac_s));
rdi_add_rule_dir(0, &rdi_mem, RDI_FLCM_DEV);
 return 0;
}
