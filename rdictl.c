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
#define VER_STR_SET "6.0.10.7.10"
#define APP_NAME     "RDIF Control utility"
#define PROG_NAME    "rdifctl"
#define UTIL_VER      VER_STR_SET
#define INFO_ENTRY "info"
#define HELP_ENTRY "help"

#define COPYRT_MSG   "Copyright Silicom Ltd.\n"
#define RDI_CONF_PATH   "/etc/rdi/rdi.conf"
#define RDICTL_LOG_PATH "/var/log/rdictl.log"
#define RDICTL_PID_PATH "/var/run/rdictl.pid" 

#define OK                           1
#define ERROR                        0 

static pid_t pid;

#define DUMP_VAL64(name, value)              \
    if (value)                               \
    {                                        \
        printf("%30s: %llu\n", name, value); \
    }



static void str_low(char *str){
    int i;

    for (i=0;i<strlen(str);i++)
        if ((str[i]>=65)&&(str[i]<=90))
            str[i]+=32;
}

static unsigned long str_to_hex(char *p) {
    unsigned long      hex    = 0;
    unsigned long     length = strlen(p), shift  = 0;
    unsigned char     dig    = 0;

    str_low(p);
    if (*p++ != '0' || *p++ != 'x') {
        return 0;
    }

    length = strlen(p);

    if (length == 0 )
        return 0;

    do {
        dig  = p[--length];
        dig  = dig<'a' ? (dig - '0') : (dig - 'a' + 0xa);
        hex |= (dig<<shift);
        shift += 4;
    }while (length);
    return hex;
}

static int
xdigit2i(int digit)
{
    if (digit >= '0' && digit <= '9') return(digit - '0'     );
    if (digit >= 'a' && digit <= 'f') return(digit - 'a' + 10);
    if (digit >= 'A' && digit <= 'F') return(digit - 'A' + 10);
    return 0;
}

static int parse_bypass_mode(char *param){
    int bypass_mode=-1;

    if (!strcmp(param, "on"))
        bypass_mode=1;
    else if (!strcmp(param, "off"))
        bypass_mode=0;
    return bypass_mode;
}



static int
//rdi_parse_macaddr(char *str, rdi_mac_t macaddr)
rdi_parse_macaddr(char *str, unsigned char *macaddr)
{
    char *s;
    int i;

    if (strchr(str, ':')) {             /* Colon format */
        s = str;
        for (i = 0; i < 6; i++) {
            if (!isxdigit((unsigned)*s)) {  /* bad character */
                return -1;
            }
            macaddr[i] = xdigit2i((unsigned)*(s++));
            if (isxdigit((unsigned)*s)) {
                macaddr[i] *= 16;
                macaddr[i] += xdigit2i((unsigned)*(s++));
            }
            if ((i < 5) && (*(s++) != ':')) {  /* bad character */
                return -1;
            }
        }
        if (*s) {
            return -1;
        }
    } else {  /* Handle 0x... format */
        return -1;
    }

    return 0;
}

static int
rdi_parse_port_mask(char *str, unsigned char *list)
{
    char *s;
    int j, len, pos;
	int port;
	
	len = sizeof(str);

	if(!len)
		return 0;

   {            
        s = strtok(str, ",");
   
		while( s != NULL ) 
		{
			j = 0;
			pos = 0;
			port = atoi(s);
			j = port / 8;
			pos = port % 8;
			if(j < 16)
			list[j] |= (1 << pos);
			
			s = strtok(NULL, ",");
		}
    } 

#if 0
	 
    {  
		int i = 0, j = 0;   

		for (i = 1; i < 69; i++){
			j = i / 8;
			if((list[j] >> (i % 8))&0x1)
				printf("port %d ", i);
		}
					printf("\n");
	}
#endif

    return 0;
}

static int
rdi_parse_lbg_ports(char *str, int *list)
{
    char *s;
    int j = 0, len;
	int port;
	
	len = sizeof(str);

	if(!len)
		return 0;

   {            
        s = strtok(str, ",");
   
		while( s != NULL ) 
		{
			port = atoi(s);

			if(port) {
				list[j] = port;
				j++;
				if(j >= 16)
					break;
			}
			
			s = strtok(NULL, ",");

		}
    }

    return j;
}



static int
rdi_parse_bp_data(char *str, unsigned char *list)
{
    char *s;
    int j=0, len;
	int data;
	
	len = sizeof(str);

	if(!len)
		return 0;

   {            
        s = strtok(str, ",");
   
		while(( s != NULL ) && (j < 8192))
		{
			data=(data=str_to_hex(s))==0? atoi(s):data;
			list[j]=(unsigned char)data;
			printf("%d  0x%x ", j, list[j]);

			s = strtok(NULL, ",");
			j++;
		}
    }
	printf("\n"); 


    return j;
}





int read_rdi_conf(const char * file_path);

char rdd_cfg[][8] = 
{"INLINE1", "INLINE2", "TAP", "MON1", "MON2", "SWITCH"};

void redir_usage()
{ 
    printf("Usage: "PROG_NAME" <command> [parameters]\n");
    printf("   Commands List:\n");
    printf("set_cfg - set the device to predefined configuration\n");
    printf("get_dev_num - get total number of rdi devices.\n");
    printf("get_cfg - get current configuration mode\n");
	printf("get_port_link <port> - get link status \n");
	printf("temp_write <addr> <length (1)> <reg>\n");
	printf("temp_read <addr> <length>\n");
	printf("temp1_write <addr> <length (1)> <reg>\n");
	printf("temp1_read <addr> <length>\n");
    printf("dir     - add the rule of a port with direction matching packets to another port\n");
	printf("lb     - add the rule of a port with send matching packets to load balance group (LBG)\n");
    printf("drop    - drop matching packets\n");
    printf("permit  - permit matching packets\n");
	printf("set_prio  - set switch priority for the packet\n");
    printf("set_vlan <vlan_act> - set vlan\n");
    printf("set_vlan_pri <vlan_pri_act>   - set vlan priority\n");
#if 0
    printf("mod1    - set to mod1: ISL tagging for all ports and LBG on internal (host) ports\n");
    printf("mod2    - set to mod2: ISL tagging for all ports\n");
    printf("mod0    - clear to initial (remove ISL tagging)\n");
#endif
    printf("stat port <port>  - get statistic for specific port (port is mandatory)\n");
	printf("prio_stat port <port>  - get priority statistic for specific port (port is mandatory)\n");
	printf("reset_stat port <port>  - reset statistic for specific port (port is mandatory)\n");
    printf("rule_stat <rule_id>  <group>- get statistic (pkts counter) for specific rule (rule_id is mandatory)\n");
    printf("query_list <group> - query rule_id list\n");
    printf("clear - clear rule stack\n");
    printf("clear_group <group> - clear rule stack for specific group\n");
    printf("set_port_mask <ingress_port> <egress_port_list example: 1,5,7> - set egress port mask\n");
    printf("get_port_mask <ingress_port>  - get egress port list\n");
    printf("set_reg <addr> <val> - write to RRC register\n");
    printf("get_reg <addr>  - read from RRC register\n");
#if 0
	printf("cpld_write <addr> <val> - write to CPLD\n");
    printf("cpld_read <addr>  - read from CPLD\n");
#endif
	
	printf("bp_write <dev_addr> <len> <data1,data2,data3...>\n");
    printf("bp_read <dev_addr> <len>\n");
	
	printf("fci_write <FCI num (1/2)> <offset> <page> <len> <data1,data2,data3...>\n");
    printf("fci_read <<FCI num (1/2)> <offset> <page> <len>\n");

	printf("fci_rx_write <FCI num (1/2)> <offset> <page> <len> <data1,data2,data3...>\n");
    printf("fci_rx_read <<FCI num (1/2)> <offset> <page> <len>\n");

	printf("set_gpio_dir <gpio> <dir> <value> - set GPIO direction & value\n");
	printf("             gpio: gpio num; dir: 0 - input; 1 - output; 2 - open drain\n");
    printf("get_gpio_dir <gpio> - get GPIO direction\n");

	printf("set_gpio <gpio> <value> - set GPIO value\n");
    printf("get_gpio <gpio> - get GPIO value\n");  
	printf("prbs <prbs> <dir> <port> - prbs test prbs supp. 7,15,23,31,11,9\n"); 
	printf("get_port_state <port>\n");
	printf("loopback <txrx/rxtx/off (1/2/0)> <port>\n");
    printf("remove <rule_id> <group> remove rule\n");
    printf("query <rule_id> <group> query rule\n");

    printf("lbg_query_list - query LBG list\n");
    printf("lbg_create  <port list, example: 1,2> - create LBG\n");
    printf("lbg_del <lbg>  - delete LBG\n");

    printf("mir_query_list - query mirror list\n");
    printf("mir_query_port_list <mirrror_port> - query mirror ports list\n");
    printf("mir_create <mirror_port example: 1> <mirror_ports_list example: 2,3> - create mirror\n");
    printf("mir_add_port <mirror_port> <port> - add port to mirror\n");
    printf("mir_del_port <mirror_port> <port> - delete port from mirror\n");
    printf("mir_del <mirror_port>  - delete mirror\n");



    printf("l3_hash <hash params> - set l3 hash\n");
    printf("l2_hash <hash params> - set l2 hash\n");
    printf("get_l3_hash - get l3 hash\n");
    printf("get_l2_hash - get l2 hash\n");


    printf("info         - print Program Information.\n");
    printf("help         - print this message.\n");
    printf("[parameters] :\n");
    printf("               for 'permit', 'dir', 'set_prio' and 'drop' commands:\n");
    printf("               rule_id <rule_id>\n");
    printf("               src_ip <src_ip>\n");
    printf("               dst_ip <dst_ip>\n");

    printf("               dst_port <dst_port>\n");
    printf("               src_port <src_port>\n");
    printf("               src_ip_mask <src_ip_mask>\n");
    printf("               dst_ip_mask <dst_ip_mask>\n");

    printf("               src_ip6 <src_ip6>\n");
    printf("               dst_ip6 <dst_ip6>\n");

    printf("               src_ip6_mask <src_ip6_mask>\n");
    printf("               dst_ip6_mask <dst_ip6_mask>\n");


    printf("               group number <group>\n");
    printf("               ip_proto <ip_proto>\n");
    printf("               src_port_mask <src_port_mask>\n");
    printf("               dst_port_mask <dst_port_mask>\n");
    printf("               vlan <vlan>\n");
    printf("               vlan_tag <vlan_tag> 1, 2, 3 ,4 for none, standard, user A, user B\n");
    printf("               vlan_mask <vlan_mask>\n");
	printf("               prio <0...15>\n");
#if 0
    printf("               mpls_type <multi | uni; mandatory for all MPLS qual's>\n");
    printf("               mpls_label <mpls label, 20 bits>\n");
    printf("               mpls_exp_bits <mpls exp bits, 3 bits>\n");
    printf("               mpls_s_bit <mpls_s_bit, 1 bit>\n"); 
    printf("               mpls_label_mask <mpls label_mask, 20 bits>\n");
    printf("               mpls_exp_bits_mask <mpls exp bits_mask, 3 bits>\n");
    printf("               mpls_s_bit_mask <mpls_s_bit_mask, 1 bit>\n"); 
#endif
    printf("               ether_type <ether_type>\n");

    printf("               src_mac <Source MAC address>\n");
    printf("               dst_mac <Destination MAC address>\n");
#if 0
    printf("               udf_offset <User Defined Field offset (0...31)>\n");
    printf("               udf_data <User Defined Field 4-byte data; zero-offset is 2-byte>\n");
    printf("               udf_mask <User Defined Field mask>\n");
#endif
    
    printf("               port <1...5>\n");
	printf("               group - ACL number <0...15>\n");

    printf("               redir_port <1...5> (mandatory for dir command)\n");
	printf("               lbg_num Load Balance Group (LBG) number (for lb command)\n");

    printf("for 'set_cfg':\n");
    printf("               <5> for MON2 (default mode) - egress disabled\n");
											  
    printf("for l3_hash:\n");
    printf("               src_ip_hash, mask of src ip\n");
    printf("               dst_ip_hash, mask of dst ip\n");
    printf("               src_port_hash, mask of src port\n");
    printf("               dst_port_hash, mask of dst port\n"); 
    printf("               dscp_hash, 0x0-0xff\n");
    printf("               isl_usr_hash, 0x0-0xff\n");
    printf("               proto_hash, protocol mask\n");
    printf("               flow_hash, 0x0-0xffff\n");
    printf("               sym_l3_hash, on|off\n");
    printf("               sym_l4_hash, on|off\n");

	printf("               random_next_hop, on|off\n");
    printf("               random_other, on|off\n");
	printf("               random_only, on|off\n");


    printf("for l2_hash:\n");
	printf("               profile_idx, 0...16 default 0\n");
    printf("               src_mac_hash, in MAC format\n");
    printf("               dst_mac_hash, in MAC format\n");
    printf("               ether_type_hash, 0x0-0xfff\n");
    printf("               vlan_id_hash,  0x0-0xfff\n");
    printf("               vlan_pri_hash,  0x0-0xf\n");
    printf("               vlan2_id_hash,  0x0-0xfff\n");
    printf("               vlan2_pri_hash,  0x0-0xf\n");
    printf("               sym_mac_hash, on|off\n");



    printf("\nEntire numerical paramters are in decimal format (123) or hex format (0xabc),\n");
    printf("MAC is in aa:bb:cc:dd:ee:ff format.\n");



#if 0    
    printf("\n\nread_phy <phy_addr> <dev> <addr> - read PHY registers\n");
    printf("write_phy <phy_addr> <dev> <addr> <value> - write PHY registers\n\n");
#endif
    printf("Example:\n");
    printf("         "PROG_NAME" drop port 1 src_ip 196.0.0.126\n");
	printf("         "PROG_NAME" set_port_mask 5 1,2,3,4\n");
	printf("         "PROG_NAME" temp_write 0x4c 1 1\n");
	printf("         "PROG_NAME" temp_read 0x4c 1\n");
    fflush(stdout);

}


#define RDI_PORT_UMAP(a) (a+6)
#define RDI_PORT_MAP(a) (a-6)


int rdi_port_umap(int port){
    int ret= RDI_PORT_UMAP(port);


    if ((ret < 24) || (ret > 27)) {
        printf("Error: invalid mir_port/redir_port/port input, you can only enter 0-3\n");
        fflush(stdout);
        //    return -1; 
    }
    return ret;

}

int rdi_port_map(int port){
    if ((port!=0)&&((port < 24) || (port > 27))) {
        printf("Error: invalid mir_port/redir_port/port output!\n");
        fflush(stdout);
        //    return -1; 
    }
    return( port==0?port:RDI_PORT_MAP(port));

}



int rdi_parse_cmd(int ac, char **av){

    int cfg = 0, i=0, j=0, rule_id=0, dev=0, type=RDI_FLCM_DEV, if_index=0, action=0;
    rdi_mem_t rdi_mem;
    rdi_l2_hash_t l2_hash;
    rdi_l3_hash_t l3_hash;
    rdi_vlan_stat_cnt_t rdi_vlan_stat;
    rdi_stat_cnt_t rdi_stat;
    rdi_lbg_query_list_t rdi_lbg_query_list;
    rdi_lbg_list_t rdi_lbg_list;
	rdi_query_list_t rdi_query_list;

    int m;
    //struct in_addr in_addr;



    bzero(&rdi_mem, sizeof(rdi_mem_t));
    bzero(&rdi_lbg_query_list, sizeof(rdi_lbg_query_list_t));
    bzero(&rdi_query_list, sizeof(rdi_query_list_t));
    bzero(&l2_hash, sizeof(rdi_l2_hash_t));
    bzero(&l3_hash, sizeof(rdi_l3_hash_t));
	bzero(&rdi_lbg_list, sizeof(rdi_lbg_list_t));


    if (ac >1) {
        for (i=1;i <ac;i++) {
            start_cmd:
            if (!strcasecmp(av[i], "clear") ) {
                if ((rdi_clear_rules(dev, type))<0)
                    printf("Fail\n");
                else printf("Ok\n");
                fflush(stdout);
            } else if (!strcasecmp(av[i], "init") ) {
                if ((rdi_init(dev, if_index, type))<0)
                    printf("Fail\n");
                else printf("Ok\n");
                fflush(stdout);
            } else if (!strcasecmp(av[i], "mod1") ) {
                if ((rdi_set_mod1(dev, type))<0)
                    printf("Fail\n");
                else printf("Ok\n");
                fflush(stdout);
            } else if (!strcasecmp(av[i], "mod0") ) {
                if ((rdi_set_mod0(dev, type))<0)
                    printf("Fail\n");
                else printf("Ok\n");
                fflush(stdout);
            } else if (!strcasecmp(av[i], "mod2") ) {
                if ((rdi_set_mod2(dev, type))<0)
                    printf("Fail\n");
                else printf("Ok\n");
                fflush(stdout);
            } else if (!strcasecmp(av[i], "install") ) {
                if ((rdi_install_rules(dev,type))<0)
                    printf("Fail\n");
                else printf("Ok\n");
                fflush(stdout);
            } else if (!strcasecmp(av[i], "query_list") ) {
                int group=0;
                if (!type)
                    type=RDI_FLCM_DEV;
                if (type==RDI_FLCM_DEV) {
                    if (av[++i])
                        group=(group=str_to_hex(av[i]))==0? atoi(av[i]):group;
                }

                if ((rdi_entry_query_list(dev, group, &rdi_query_list, type))<0)
                    printf("Fail\n");

                else {
                    if (rdi_query_list.rdi_id_list.rule_num) {
                        if (rdi_query_list.rdi_id_list.rule_num <= 4096) {

                            for (m=0; m<rdi_query_list.rdi_id_list.rule_num;m++) {
                                printf("%d ", rdi_query_list.rdi_id_list.id_list[m]);
                            }
                        }
                    }

                    printf("\n");
                }
                fflush(stdout);
            } else if (!strcasecmp(av[i], "mir_query_list") ) {
                if (!type)
                    type=RDI_FLCM_DEV;
                /*if (type==RDI_FLCM_DEV) {
                    if (av[++i])
                        group=(group=str_to_hex(av[i]))==0? atoi(av[i]):group;
                }*/

                if ((rdi_mir_query_entry_list(dev, &rdi_lbg_query_list, type))<0)
                    printf("Fail\n");

                else {
                    if (rdi_lbg_query_list.rdi_lbg_list.num) {
                        for (m=0; m<rdi_lbg_query_list.rdi_lbg_list.num;m++) {
                            printf("%d ", rdi_lbg_query_list.rdi_lbg_list.list[m]);
                        }
                    }

                    printf("\n");
                }
                fflush(stdout);
            } else if (!strcasecmp(av[i], "mir_query_port_list") ) {
                int lbg=0;
                if (!type)
                    type=RDI_FLCM_DEV;
                if (type==RDI_FLCM_DEV) {
                    if (av[++i])
                        lbg=(lbg=str_to_hex(av[i]))==0? atoi(av[i]):lbg;
                }

                if ((rdi_mir_port_query_entry_list(dev, lbg, &rdi_lbg_query_list, type))<0)
                    printf("Fail\n");

                else {
                    if (rdi_lbg_query_list.rdi_lbg_list.num) {
                        for (m=0; m<rdi_lbg_query_list.rdi_lbg_list.num;m++) {
                            printf("%d ", rdi_lbg_query_list.rdi_lbg_list.list[m]);
                        }
                    }

                    printf("\n");
                }
                fflush(stdout);
            } else if (!strcasecmp(av[i], "mir_del") ) {
                int lbg=0;

                if (!type)
                    type=RDI_FLCM_DEV;
                if (type==RDI_FLCM_DEV) {
                    if (av[++i])
                        lbg=atoi(av[i]);
                }


                if ((lbg)&&(!rdi_mir_remove(dev, lbg, type))) {
                    printf("Mirror %d is removed\n", lbg);
                    fflush(stdout); 
                } else {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                }
            }  else if (!strcasecmp(av[i], "mir_create") ) {
                int lbg=0;

				if (av[++i])
					lbg=atoi(av[i]);

				if (av[++i]) {
					rdi_lbg_list.num = rdi_parse_lbg_ports(av[i], 
							rdi_lbg_list.list);

				}  else {
                    printf("Please add mirror ports set!\n");
                    fflush(stdout);
                    return -1;
                }

                if (!type)
                    type=RDI_FLCM_DEV;

                if (rdi_mir_add_fn(dev, lbg, &rdi_lbg_list, type)) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
                    printf("Mirror %d is added\n", lbg);
                    fflush(stdout);
                }
            } else if (!strcasecmp(av[i], "mir_del_port") ) {
                int lbg=0,port=0;

                if (!type)
                    type=RDI_FLCM_DEV;
                if (av[++i])
                    lbg=atoi(av[i]);
                if (av[++i])
                    port=atoi(av[i]);
                else {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                }

                if ((lbg)&&(!(rdi_mir_port_remove(dev, lbg, port, type)))) {
                    printf("port %d removed from mirror %d\n", port, lbg);
                    fflush(stdout);

                } else {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;   
                }
            } else if (!strcasecmp(av[i], "mir_add_port") ) {
                int lbg=0, port=0;

                if (!type)
                    type=RDI_FLCM_DEV;
                if (av[++i])
                    lbg=atoi(av[i]);
                if (av[++i])
                    port=atoi(av[i]);
                else {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } 

                if ((lbg)&&(!(rdi_mir_port_add(dev, lbg,port, type)))) {
                    printf("port %d added to mirror %d\n", port, lbg);
                    fflush(stdout);


                } else {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;

                }
            } else if (!strcasecmp(av[i], "lbg_query_list") ) {
                if (!type)
                    type=RDI_FLCM_DEV;
                /*if (type==RDI_FLCM_DEV) {
                    if (av[++i])
                        group=(group=str_to_hex(av[i]))==0? atoi(av[i]):group;
                }*/

                if ((rdi_lbg_query_entry_list(dev, &rdi_lbg_query_list, type))<0)
                    printf("Fail\n");

                else {
                    if (rdi_lbg_query_list.rdi_lbg_list.num) {
                        for (m=0; m<rdi_lbg_query_list.rdi_lbg_list.num;m++) {
                            printf("%d ", rdi_lbg_query_list.rdi_lbg_list.list[m]);
                        }
                    }

                    printf("\n");
                }
                fflush(stdout);
            } else if (!strcasecmp(av[i], "lbg_query_port_list") ) {
                int lbg=0;
                if (!type)
                    type=RDI_FLCM_DEV;
                if (type==RDI_FLCM_DEV) {
                    if (av[++i])
                        lbg=(lbg=str_to_hex(av[i]))==0? atoi(av[i]):lbg;
                }

                if ((rdi_lbg_port_query_entry_list(dev, lbg, &rdi_lbg_query_list, type))<0)
                    printf("Fail\n");

                else {
                    if (rdi_lbg_query_list.rdi_lbg_list.num) {

                        for (m=0; m<rdi_lbg_query_list.rdi_lbg_list.num;m++) {
                            printf("%d ", rdi_lbg_query_list.rdi_lbg_list.list[m]);
                        }
                    }

                    printf("\n");
                }
                fflush(stdout);
            } else if (!strcasecmp(av[i], "lbg_del") ) {
                int lbg=0;

                if (!type)
                    type=RDI_FLCM_DEV;
                if (type==RDI_FLCM_DEV) {
                    if (av[++i])
                        lbg=atoi(av[i]);
                }


                if (!rdi_lbg_remove(dev, lbg, type)) {
                    printf("LBG %d is removed\n", lbg);
                    fflush(stdout); 
                } else {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                }
            } else if (!strcasecmp(av[i], "lbg_create") ) {
                int lbg=0;

				if (av[++i]) {
					rdi_lbg_list.num = rdi_parse_lbg_ports(av[i], 
							rdi_lbg_list.list);

				}  else {
                    printf("Please add LBG ports set!\n");
                    fflush(stdout);
                    return -1;

                }

                if (!type)
                    type=RDI_FLCM_DEV;

                if (rdi_lbg_add_fn(dev, &lbg, &rdi_lbg_list, type)) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
                    printf("LBG %d is added\n", lbg);
                    fflush(stdout);
                }
            } else if (!strcasecmp(av[i], "lbg_del_port") ) {
                int lbg=0,port=0;

                if (!type)
                    type=RDI_FLCM_DEV;
                if (av[++i])
                    lbg=atoi(av[i]);
                if (av[++i])
                    port=atoi(av[i]);
                else {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                }


                if ((lbg)&&(!(rdi_lbg_port_remove(dev, lbg, port, type)))) {
                    printf("port %d removed from LBG %d\n", port, lbg);
                    fflush(stdout);

                } else {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;   
                }
            } else if (!strcasecmp(av[i], "lbg_add_port") ) {
                int lbg=0, port=0;

                if (!type)
                    type=RDI_FLCM_DEV;
                if (av[++i])
                    lbg=atoi(av[i]);
                if (av[++i])
                    port=atoi(av[i]);
                else {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } 

                if ((lbg)&&(!(rdi_lbg_port_add(dev, lbg,port, type)))) {
                    printf("port %d added to LBG %d\n", port, lbg);
                    fflush(stdout);


                } else {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;

                }
            } else if (!strcasecmp(av[i], "get_l2_hash") ) {

                if (!type)
                    type=RDI_FLCM_DEV;
                memset(&l2_hash,0,sizeof(rdi_l2_hash_t));

                if (rdi_get_l2_hash(dev, &l2_hash, type)) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
					printf("dst_mac mask  %02X %02X %02X %02X %02X %02X\n", l2_hash.dst_mac_mask[0], l2_hash.dst_mac_mask[1], l2_hash.dst_mac_mask[2],
                           l2_hash.dst_mac_mask[3], l2_hash.dst_mac_mask[4], l2_hash.dst_mac_mask[5]);
					printf("src_mac mask  %02X %02X %02X %02X %02X %02X\n", l2_hash.src_mac_mask[0], l2_hash.src_mac_mask[1], l2_hash.src_mac_mask[2],
                           l2_hash.src_mac_mask[3], l2_hash.src_mac_mask[4], l2_hash.src_mac_mask[5]);
                    printf("ether type mask 0x%x\n", l2_hash.ether_type_mask);
                    printf("symmetrizing MAC 0x%x\n",l2_hash.sym_mac);
                    printf("vlan id mask 0x%x\n",l2_hash.vlan_id_mask);
                    printf("vlan pri mask 0x%x\n",l2_hash.vlan_pri);
                    printf("vlan2 id mask 0x%x\n",l2_hash.vlan2_id_mask);
                    printf("vlan2 pri mask 0x%x\n",l2_hash.vlan2_pri);
					printf("profile index %d\n",l2_hash.profile_index);



                    fflush(stdout);
                }
            } else if (!strcasecmp(av[i], "get_l3_hash") ) {

                if (!type)
                    type=RDI_FLCM_DEV;
                memset(&l3_hash,0,sizeof(rdi_l3_hash_t));

                if (rdi_get_l3_hash(dev, &l3_hash, type)) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
                    printf("dscp mask 0x%x\n",l3_hash.dscp_mask);
					{
						char str[16];

						printf("src ip mask %s\n", inet_ntop(AF_INET, &l3_hash.src_ip_mask, str, 16) );
						printf("dst ip mask %s\n", inet_ntop(AF_INET, &l3_hash.dst_ip_mask, str, 16) );
					}

                    printf("src port mask 0x%x\n",l3_hash.src_port_mask);
                    printf("dst port mask 0x%x\n",l3_hash.dst_port_mask);

                    printf("flow mask 0x%x\n",l3_hash.flow_mask);
                    printf("ISL_USER mask 0x%x\n",l3_hash.isl_usr_mask);
                    printf("protocol mask 0x%x\n",l3_hash.proto_mask);

                    printf("random_next_hop %d\n",l3_hash.random_next_hop);
                    printf("random_other %d\n",l3_hash.random_other);
					printf("random_only %d\n",l3_hash.random_only);



                    fflush(stdout);
                }
            } else if (!strcasecmp(av[i], "clear_group") ) {
                int group=0;
                if (!type)
                    type=RDI_FLCM_DEV;
                if (type==RDI_FLCM_DEV) {
                    if (av[++i])
                        group=(group=str_to_hex(av[i]))==0? atoi(av[i]):group;
                }

                if ((rdi_clear_rules_group(dev, group, type))<0)
                    printf("Fail\n");

                else
                    printf("Ok\n");

                fflush(stdout);
            } else if (!strcasecmp(av[i], "-f")) {
                read_rdi_conf(NULL);
            } else if (!strcasecmp(av[i], "get_cfg")) {
                int conf=0;
                conf=rdi_get_cfg(dev, type);
                if (conf>0)
                    printf("dev %d: Current configuration is %s\n", dev, rdd_cfg[conf - 1]);
                else
                    printf("Fail\n");
                fflush(stdout);
            }else if (!strcasecmp(av[i], "get_temp")) {
                int conf=0;
                conf=rdi_get_temp(dev, type);
                if (conf>0)
                    printf("%dC\n", conf);
                else
                    printf("Fail\n");
                fflush(stdout);
            } else if (!strcasecmp(av[i], "get_dev_num")) {
                int conf=0;
                /*if (type==RDI_FLCM_DEV) {
                    printf("Not supported\n");
                    fflush(stdout);
                } else*/ {

                    conf=rdi_get_dev_num(type);

                    if (conf>0)
                        printf("Total number of devices is %d\n", conf);
                    else
                        printf("Fail\n");
                    fflush(stdout);
                }
            } else if (!strcasecmp(av[i], "-fp")) {
                if (av[++i]) {
                    read_rdi_conf(av[i]);
                }

            } else if (!strcasecmp(av[i], "set_cfg") ) {
                if (av[++i])
                    cfg=(cfg=str_to_hex(av[i]))==0? atoi(av[i]):cfg;



                if ((cfg < 1) || (cfg > 6)) {
                    printf("Error: invalid set_cfg input, you can only enter 1-5\n");
                    fflush(stdout);
                    return -1; 
                }
                if ((rdi_set_cfg(dev, cfg, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else
                    printf("Set configuration to %s\n", rdd_cfg[cfg - 1]);
            } else if (!strcasecmp(av[i], "type") ) {
                if (av[++i])
                    cfg=(cfg=str_to_hex(av[i]))==0? atoi(av[i]):cfg;



                if ((cfg !=1) || (cfg !=2)) {
                    printf("Error: invalid type input, you can only enter 0 (Intel) or 1(Broadcom)\n");
                    fflush(stdout);
                    return -1; 
                }
                if ((rdi_set_cfg(dev, cfg, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else
                    printf("Set configuration to %s\n", rdd_cfg[cfg - 1]);
            } else if (!strcasecmp(av[i], "dev") ) {


                //dn=rdi_get_dev_num(type);
                if (av[++i])
                    dev=(dev=str_to_hex(av[i]))==0? atoi(av[i]):dev;

                //if ((dn<=0)||(dev>=dn)) {
                //    printf("Device number error!\n" );
                //    fflush(stdout);
                //    return -1;
                //}

            } else if (!strcasecmp(av[i], "if_name") ) {
                char *if_name;
                if (av[++i]) {

                    if_name= av[i];
                    if_index=if_nametoindex(if_name);
                    if (if_index==0) {
                        printf("%s is not exist!\n",if_name);
                        fflush(stdout);

                        return ERROR;
                    }
                }

            } else if (!strcasecmp(av[i], "remove") ) {
                int group=0;
                if (av[++i])
                    cfg=(cfg=str_to_hex(av[i]))==0? atoi(av[i]):cfg;
                if (!type)
                    type=RDI_FLCM_DEV;
                if (type==RDI_FLCM_DEV) {
                    if (av[++i])
                        group=(group=str_to_hex(av[i]))==0? atoi(av[i]):group;
                }



                if ((rdi_entry_remove(dev, cfg, group, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {

                    printf("Rule %d is removed\n", cfg);
                    fflush(stdout);
                }
				return 0;

            } else if (!strcasecmp(av[i], "rule_stat")) {
                int ret=0, rule=0, group=0;
                rdi_rule_stat_cnt_t rdi_rule_stat;
                /*if (type==RDI_FLCM_DEV) {
                    printf("Not supported\n");
                    fflush(stdout);
                } else*/ {



                    if (av[++i])
                        rule=(rule=str_to_hex(av[i]))==0? atoi(av[i]):rule;
                    if (!type)
                        type=RDI_FLCM_DEV;

                    if (type==RDI_FLCM_DEV) {
                        if (av[++i])
                            group=(group=str_to_hex(av[i]))==0? atoi(av[i]):group;
                    }


                    memset(&rdi_rule_stat,0,sizeof(rdi_rule_stat_cnt_t));
                    ret=rdi_get_rule_stat(dev, rule, group, &rdi_rule_stat, type);

                    if (ret<0) {
                        printf("Get rule stat error\n");
                        fflush(stdout);
                    }


                    printf("Total packets %lli\n",rdi_rule_stat.counter);
                    fflush(stdout);
                }
                return 0;
                //rdi_installc_rules();

            }  else if (!strcasecmp(av[i], "get_port_link")) {
                int ret=0, port=0;
                /*if (type==RDI_FLCM_DEV) {
                    printf("Not supported\n");
                    fflush(stdout);
                } else*/ { 

                    if (av[++i])
                        port=(port=str_to_hex(av[i]))==0? atoi(av[i]):port;

                    ret=rdi_get_port_link(dev, port, type);
					if(ret < 0)
						printf("Fail\n");
					else if (!ret)
						printf("port %d is DOWN\n", port);
					else
						printf("port %d is UP\n", port);
                }
                return 0;
                //rdi_installc_rules();

            } else if (!strcasecmp(av[i], "read_phy") ) {
                int p, p1, addr, dev_id, val;

                if (av[++i])
                    p1=(p1=str_to_hex(av[i]))==0? atoll(av[i]):p1;

                p=p1;
                {



                    if (av[++i]) dev_id=atoi(av[i]);
                    if (av[++i])
                        addr=(addr=str_to_hex(av[i]))==0? atoll(av[i]):addr;

                    printf("unit=%d, phy_addr=%d, dev=%d, addr=%d\n", dev, p1, dev_id, addr);
                    if ((val=rdi_read_phy(dev, p, dev_id, addr, type))<0) {
                        printf("Fail\n");
                        return -1;
                    } else
                        printf("value=0x%x\n", val);
                }
				return 0;
            } else if (!strcasecmp(av[i], "write_phy") ) {
                int p, p1, addr, dev_id, val;
                if (av[++i])
                    p1=(p1=str_to_hex(av[i]))==0? atoll(av[i]):p1;
                p=p1;

                {
                    if (av[++i]) dev_id=atoi(av[i]);

                    //if (av[++i]) addr=atoi(av[i]);
                    if (av[++i])
                        addr=(addr=str_to_hex(av[i]))==0? atoll(av[i]):addr;

                    //if (av[++i]) dev_id=atoi(av[i]);
                    if (av[++i])
                        val=(val=str_to_hex(av[i]))==0? atoll(av[i]):val;

                    printf("!unit=%d, phy_addr=%d, dev=0x%x, addr=%d, value=%d\n", dev, p1, addr, dev_id, val);
                    if ((val=rdi_write_phy(dev, p,  dev_id, addr, val, type))<0) {
                        printf("Fail\n");
                        return -1;
                    } else
                        printf("Ok\n");
                }
				return 0;
            } else if (!strcasecmp(av[i], "set_port_mask") ) {
					
				rdi_mask_t mask1; 
				
				memset(&mask1, 0, sizeof(rdi_mask_t));

				
				if (av[++i])
					rdi_parse_port_mask(av[i], mask1.ingress);
				else {
                    printf("Please set egress port number!\n");
                    fflush(stdout);
                    return -1;

                }
				
				if (av[++i])
					rdi_parse_port_mask(av[i], mask1.egress);
                else {
                    printf("Please set ingress ports number!\n");
                    fflush(stdout);
                    return -1;

                }

                if (!type)
                    type=RDI_FLCM_DEV;
                if ((rdi_set_mask(dev, &mask1, type)) < 0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else printf("Ok\n");

				return 0;
 
            } else if (!strcasecmp(av[i], "cpld_write") ) {
                unsigned int addr=0, value=0;
                if (av[++i])
                    addr=(addr=str_to_hex(av[i]))==0? atoi(av[i]):addr;
                else {
                    printf("Please set address!\n");
                    fflush(stdout);
                    return -1;

                }
                if (av[++i])
                    value=(value=str_to_hex(av[i]))==0? atoi(av[i]):value;
                else {
                    printf("Please set value!\n");
                    fflush(stdout);
                    return -1;

                }


                if (!type)
                    type=RDI_FLCM_DEV;

                if ((rdi_cpld_write(dev, addr, value, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else printf("Ok\n");

				return 0;
            } 
			else if (!strcasecmp(av[i], "get_port_mask") ) {
				rdi_mask_t mask1; 
				
				memset(&mask1, 0, sizeof(rdi_mask_t));

				
				if (av[++i])
					rdi_parse_port_mask(av[i], mask1.ingress);
				else {
                    printf("Please set egress port number!\n");
                    fflush(stdout);
                    return -1;

                }

                if (!type)
                    type=RDI_FLCM_DEV;

                if ((rdi_get_mask(dev, &mask1, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {  
					int i = 0, j = 0;   
					for (i = 1; i < 11; i++){
						j = i / 8;
						if((mask1.egress[j] >> (i % 8))&0x1)
							printf("%d ", i);
					}
					printf("\n");
				}
				return 0;
            }

			else if (!strcasecmp(av[i], "bp_read") ) {
				unsigned int dev_addr=0, num=0;
				rdi_bp_query_data_t rdi_bp_query_data;

                if (av[++i])
                    dev_addr=(dev_addr=str_to_hex(av[i]))==0? atoi(av[i]):dev_addr;
                else {
                    printf("Please set device!\n");
                    fflush(stdout);
                    return -1;

                }

				if (av[++i])
                    num=(num=str_to_hex(av[i]))==0? atoi(av[i]):num;
                else {
                    printf("Please set num bytes!\n");
                    fflush(stdout);
                    return -1;

                }
				if((!num) || (num > 4096))
					printf("Number bytes error!\n");

				memset(&rdi_bp_query_data, 0, sizeof(rdi_bp_query_data_t));
                if (!type)
                    type=RDI_FLCM_DEV;

				rdi_bp_query_data.data.num=num;

				if ((rdi_bp_read(dev, dev_addr, &rdi_bp_query_data, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {  
					int i = 0;   
					for (i = 0; i < num; i++){
						printf("%x ", rdi_bp_query_data.data.list[i]);
					}
					printf("\n");
				}
				return 0;

            }
			else if (!strcasecmp(av[i], "fci_read") ) {
				unsigned int dev_addr = 0, num = 0;
				unsigned int page = 0, offset = 0;
				rdi_bp_query_data_t rdi_bp_query_data;

                if (av[++i]) {
                    dev_addr=(dev_addr=str_to_hex(av[i]))==0? atoi(av[i]):dev_addr;
					if((dev_addr < 0) || (dev_addr > 2)) {
						printf("Please set FCI number 1 or 2\n");
						fflush(stdout);
						return -1;
					}
				} else {
                    printf("Please set FCI number!\n");
                    fflush(stdout);
                    return -1;
                }

				if (av[++i]) {
                    offset = (offset = str_to_hex(av[i])) == 0? atoi(av[i]):offset;
					if((offset < 0) || (offset > 256)) {
						printf("Please set offset 0..256\n");
						fflush(stdout);
						return -1;
					}
					
				} else {
                    printf("Please set offset 0..256\n");
                    fflush(stdout);
                    return -1;
                }

				if (av[++i]) {
                    page = (page = str_to_hex(av[i])) == 0? atoi(av[i]):page;

				} else {
                    printf("Please set page!\n");
                    fflush(stdout);
                    return -1;
                }

				if (av[++i])
                    num=(num=str_to_hex(av[i]))==0? atoi(av[i]):num;
                else {
                    printf("Please set num bytes!\n");
                    fflush(stdout);
                    return -1;

                }
				if((!num) || (num > 4096)) {
					printf("Number bytes error!\n");
					fflush(stdout);
					return -1;
				}


				memset(&rdi_bp_query_data, 0, sizeof(rdi_bp_query_data_t));
                if (!type)
                    type=RDI_FLCM_DEV;

				rdi_bp_query_data.data.num=num;

				if ((rdi_fci_read(dev, dev_addr, offset, page, &rdi_bp_query_data, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {  
					int i = 0;   
					for (i = 0; i < num; i++){
						printf("%d ", rdi_bp_query_data.data.list[i]);
					}
					printf("\n");
				}
				return 0;

            }

			else if (!strcasecmp(av[i], "fci_rx_read") ) {
				unsigned int dev_addr = 0, num = 0;
				unsigned int page = 0, offset = 0;
				rdi_bp_query_data_t rdi_bp_query_data;

                if (av[++i]) {
                    dev_addr=(dev_addr=str_to_hex(av[i]))==0? atoi(av[i]):dev_addr;
					if((dev_addr < 0) || (dev_addr > 2)) {
						printf("Please set FCI number 1 or 2\n");
						fflush(stdout);
						return -1;
					}
				} else {
                    printf("Please set FCI number!\n");
                    fflush(stdout);
                    return -1;
                }

				if (av[++i]) {
                    offset = (offset = str_to_hex(av[i])) == 0? atoi(av[i]):offset;
					if((offset < 0) || (offset > 256)) {
						printf("Please set offset 0..256\n");
						fflush(stdout);
						return -1;
					}
					
				} else {
                    printf("Please set offset 0..256\n");
                    fflush(stdout);
                    return -1;
                }

				if (av[++i]) {
                    page = (page = str_to_hex(av[i])) == 0? atoi(av[i]):page;

				} else {
                    printf("Please set page!\n");
                    fflush(stdout);
                    return -1;
                }

				if (av[++i])
                    num=(num=str_to_hex(av[i]))==0? atoi(av[i]):num;
                else {
                    printf("Please set num bytes!\n");
                    fflush(stdout);
                    return -1;

                }
				if((!num) || (num > 4096)) {
					printf("Number bytes error!\n");
					fflush(stdout);
					return -1;
				}


				memset(&rdi_bp_query_data, 0, sizeof(rdi_bp_query_data_t));
                if (!type)
                    type=RDI_FLCM_DEV;

				rdi_bp_query_data.data.num=num;

				if ((rdi_fci_rx_read(dev, dev_addr, offset, page, &rdi_bp_query_data, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {  
					int i = 0;   
					for (i = 0; i < num; i++){
						printf("%d ", rdi_bp_query_data.data.list[i]);
					}
					printf("\n");
				}
				return 0;

            }
			
			else if (!strcasecmp(av[i], "bp_write") ) {
				unsigned int dev_addr=0, num=0, num1=0;
				rdi_bp_query_data_t rdi_bp_query_data;

                if (av[++i])
                    dev_addr=(dev_addr=str_to_hex(av[i]))==0? atoi(av[i]):dev_addr;
                else {
                    printf("Please set device!\n");
                    fflush(stdout);
                    return -1;

                }

				if (av[++i])
                    num=(num=str_to_hex(av[i]))==0? atoi(av[i]):num;
                else {
                    printf("Please set num bytes!\n");
                    fflush(stdout);
                    return -1;

                }
				if((!num) || (num > 8192)) {
					printf("Number bytes error!\n");
					fflush(stdout);
					return -1;
				}

				memset(&rdi_bp_query_data, 0, sizeof(rdi_bp_query_data_t));

                if (!type)
                    type=RDI_FLCM_DEV;

				rdi_bp_query_data.data.num=num;
               /* rdi_bp_query_data.data.list[0] = addr&0xff;*/

				if (av[++i]) 
					num1=rdi_parse_bp_data(av[i], rdi_bp_query_data.data.list);
				if(num1!=num) {
					printf("Data bytes error! num = %d num1 = %d\n", num, num1);
					fflush(stdout);
				}

				printf("data ");
				for (i = 0; i < num; i++){
					printf("%x ", rdi_bp_query_data.data.list[i]);
				}
				printf("\n");


				if ((rdi_bp_write(dev, dev_addr, &rdi_bp_query_data, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
					printf("Ok\n");
				}
				return 0;

            } 
			else if (!strcasecmp(av[i], "fci_write") ) {
				unsigned int dev_addr = 0, offset = 0, num = 0, num1 = 0;
				unsigned int page = 0;
				rdi_bp_query_data_t rdi_bp_query_data;

                if (av[++i]) {
                    dev_addr=(dev_addr=str_to_hex(av[i]))==0? atoi(av[i]):dev_addr;
					if((dev_addr < 0) || (dev_addr > 2)) {
						printf("Please set FCI number 1 or 2\n");
						fflush(stdout);
						return -1;
					}
				} else {
                    printf("Please set FCI number!\n");
                    fflush(stdout);
                    return -1;
                }

				if (av[++i]) {
                    offset = (offset = str_to_hex(av[i])) == 0? atoi(av[i]):offset;
					if((offset < 0) || (offset > 256)) {
						printf("Please set offset 0..256\n");
						fflush(stdout);
						return -1;
					}
				} else {
                    printf("Please set offset!\n");
                    fflush(stdout);
                    return -1;
                }

				if (av[++i]) {
                    page = (page = str_to_hex(av[i])) == 0? atoi(av[i]):page;

				} else {
                    printf("Please set page!\n");
                    fflush(stdout);
                    return -1;
                }

				if (av[++i])
                    num=(num=str_to_hex(av[i]))==0? atoi(av[i]):num;
                else {
                    printf("Please set num bytes!\n");
                    fflush(stdout);
                    return -1;

                }
				if((!num) || (num > 4096)) {
					printf("Number bytes error!\n");
					fflush(stdout);
					return -1;
				}

				memset(&rdi_bp_query_data, 0, sizeof(rdi_bp_query_data_t));

                if (!type)
                    type=RDI_FLCM_DEV;

				rdi_bp_query_data.data.num=num;
               /* rdi_bp_query_data.data.list[0] = addr&0xff;*/

				if (av[++i]) 
					num1=rdi_parse_bp_data(av[i], rdi_bp_query_data.data.list);
				if(num1!=num) {
					printf("Data bytes error! num = %d num1 = %d\n", num, num1);
					fflush(stdout);
				}

				printf("data ");
				for (i = 0; i < num; i++){
					printf("%x ", rdi_bp_query_data.data.list[i]);
				}
				printf("\n");


				if ((rdi_fci_write(dev, dev_addr, offset, page, &rdi_bp_query_data, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
					printf("Ok\n");
				}
				return 0;

            } 

			else if (!strcasecmp(av[i], "fci_rx_write") ) {
				unsigned int dev_addr = 0, offset = 0, num = 0, num1 = 0;
				unsigned int page = 0;
				rdi_bp_query_data_t rdi_bp_query_data;

                if (av[++i]) {
                    dev_addr=(dev_addr=str_to_hex(av[i]))==0? atoi(av[i]):dev_addr;
					if((dev_addr < 0) || (dev_addr > 2)) {
						printf("Please set FCI number 1 or 2\n");
						fflush(stdout);
						return -1;
					}
				} else {
                    printf("Please set FCI number!\n");
                    fflush(stdout);
                    return -1;
                }

				if (av[++i]) {
                    offset = (offset = str_to_hex(av[i])) == 0? atoi(av[i]):offset;
					if((offset < 0) || (offset > 256)) {
						printf("Please set offset 0..256\n");
						fflush(stdout);
						return -1;
					}
				} else {
                    printf("Please set offset!\n");
                    fflush(stdout);
                    return -1;
                }

				if (av[++i]) {
                    page = (page = str_to_hex(av[i])) == 0? atoi(av[i]):page;

				} else {
                    printf("Please set page!\n");
                    fflush(stdout);
                    return -1;
                }

				if (av[++i])
                    num=(num=str_to_hex(av[i]))==0? atoi(av[i]):num;
                else {
                    printf("Please set num bytes!\n");
                    fflush(stdout);
                    return -1;

                }
				if((!num) || (num > 4096)) {
					printf("Number bytes error!\n");
					fflush(stdout);
					return -1;
				}

				memset(&rdi_bp_query_data, 0, sizeof(rdi_bp_query_data_t));

                if (!type)
                    type=RDI_FLCM_DEV;

				rdi_bp_query_data.data.num=num;
               /* rdi_bp_query_data.data.list[0] = addr&0xff;*/

				if (av[++i]) 
					num1=rdi_parse_bp_data(av[i], rdi_bp_query_data.data.list);
				if(num1!=num) {
					printf("Data bytes error! num = %d num1 = %d\n", num, num1);
					fflush(stdout);
				}

				printf("data ");
				for (i = 0; i < num; i++){
					printf("%x ", rdi_bp_query_data.data.list[i]);
				}
				printf("\n");


				if ((rdi_fci_rx_write(dev, dev_addr, offset, page, &rdi_bp_query_data, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
					printf("Ok\n");
				}
				return 0;

            } 

			else if (!strcasecmp(av[i], "temp_read") ) {
				unsigned int dev_addr=0, num=0;
				rdi_bp_query_data_t rdi_bp_query_data;

                if (av[++i])
                    dev_addr=(dev_addr=str_to_hex(av[i]))==0? atoi(av[i]):dev_addr;
                else {
                    printf("Please set device!\n");
                    fflush(stdout);
                    return -1;

                }

				if (av[++i])
                    num=(num=str_to_hex(av[i]))==0? atoi(av[i]):num;
                else {
                    printf("Please set num bytes!\n");
                    fflush(stdout);
                    return -1;

                }
				if((!num) || (num > 8192))
					printf("Number bytes error!\n");

				memset(&rdi_bp_query_data, 0, sizeof(rdi_bp_query_data_t));
                if (!type)
                    type=RDI_FLCM_DEV;

				rdi_bp_query_data.data.num=num;

				if ((rdi_temp_read(dev, dev_addr, &rdi_bp_query_data, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {  
					int i = 0;   
					for (i = 0; i < num; i++){
						printf("%d ", rdi_bp_query_data.data.list[i]);
					}
					printf("\n");
				}
				return 0;

            }
			else if (!strcasecmp(av[i], "temp1_read") ) {
				unsigned int dev_addr=0, num=0;
				rdi_bp_query_data_t rdi_bp_query_data;

                if (av[++i])
                    dev_addr=(dev_addr=str_to_hex(av[i]))==0? atoi(av[i]):dev_addr;
                else {
                    printf("Please set device!\n");
                    fflush(stdout);
                    return -1;

                }

				if (av[++i])
                    num=(num=str_to_hex(av[i]))==0? atoi(av[i]):num;
                else {
                    printf("Please set num bytes!\n");
                    fflush(stdout);
                    return -1;

                }
				if((!num) || (num > 8192))
					printf("Number bytes error!\n");

				memset(&rdi_bp_query_data, 0, sizeof(rdi_bp_query_data_t));
                if (!type)
                    type=RDI_FLCM_DEV;

				rdi_bp_query_data.data.num=num;

				if ((rdi_temp1_read(dev, dev_addr, &rdi_bp_query_data, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {  
					int i = 0;   
					for (i = 0; i < num; i++){
						printf("%d ", rdi_bp_query_data.data.list[i]);
					}
					printf("\n");
				}
				return 0;

            }
			
			else if (!strcasecmp(av[i], "temp_write") ) {
				unsigned int dev_addr=0, num=0, num1=0;
				rdi_bp_query_data_t rdi_bp_query_data;

                if (av[++i])
                    dev_addr=(dev_addr=str_to_hex(av[i]))==0? atoi(av[i]):dev_addr;
                else {
                    printf("Please set device!\n");
                    fflush(stdout);
                    return -1;

                }

				if (av[++i])
                    num=(num=str_to_hex(av[i]))==0? atoi(av[i]):num;
                else {
                    printf("Please set num bytes!\n");
                    fflush(stdout);
                    return -1;

                }
				if((!num) || (num > 8192)) {
					printf("Number bytes error!\n");
					fflush(stdout);
					return -1;
				}

				memset(&rdi_bp_query_data, 0, sizeof(rdi_bp_query_data_t));

                if (!type)
                    type=RDI_FLCM_DEV;

				rdi_bp_query_data.data.num=num;
               /* rdi_bp_query_data.data.list[0] = addr&0xff;*/

				if (av[++i]) 
					num1=rdi_parse_bp_data(av[i], rdi_bp_query_data.data.list);
				if(num1!=num) {
					printf("Data bytes error! num = %d num1 = %d\n", num, num1);
					fflush(stdout);
				}

				printf("data ");
				for (i = 0; i < num; i++){
					printf("%x ", rdi_bp_query_data.data.list[i]);
				}
				printf("\n");


				if ((rdi_temp_write(dev, dev_addr, &rdi_bp_query_data, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
					printf("Ok\n");
				}
				return 0;
            }
			else if (!strcasecmp(av[i], "temp1_write") ) {
				unsigned int dev_addr=0, num=0, num1=0;
				rdi_bp_query_data_t rdi_bp_query_data;

                if (av[++i])
                    dev_addr=(dev_addr=str_to_hex(av[i]))==0? atoi(av[i]):dev_addr;
                else {
                    printf("Please set device!\n");
                    fflush(stdout);
                    return -1;

                }

				if (av[++i])
                    num=(num=str_to_hex(av[i]))==0? atoi(av[i]):num;
                else {
                    printf("Please set num bytes!\n");
                    fflush(stdout);
                    return -1;

                }
				if((!num) || (num > 8192)) {
					printf("Number bytes error!\n");
					fflush(stdout);
					return -1;
				}

				memset(&rdi_bp_query_data, 0, sizeof(rdi_bp_query_data_t));

                if (!type)
                    type=RDI_FLCM_DEV;

				rdi_bp_query_data.data.num=num;
               /* rdi_bp_query_data.data.list[0] = addr&0xff;*/

				if (av[++i]) 
					num1=rdi_parse_bp_data(av[i], rdi_bp_query_data.data.list);
				if(num1!=num) {
					printf("Data bytes error! num = %d num1 = %d\n", num, num1);
					fflush(stdout);
				}

				printf("data ");
				for (i = 0; i < num; i++){
					printf("%x ", rdi_bp_query_data.data.list[i]);
				}
				printf("\n");


				if ((rdi_temp1_write(dev, dev_addr, &rdi_bp_query_data, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
					printf("Ok\n");
				}
				return 0;
            }
			
			else if (!strcasecmp(av[i], "cpld_read") ) {
                unsigned int addr=0;
                unsigned char val=0;

                if (av[++i])
                    addr=(addr=str_to_hex(av[i]))==0? atoi(av[i]):addr;
                else {
                    printf("Please set egress port number!\n");
                    fflush(stdout);
                    return -1;

                }


                if (!type)
                    type=RDI_FLCM_DEV;

                if ((rdi_cpld_read(dev, addr, &val, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else printf("0x%x\n", val);

				return 0;
            }


			else if (!strcasecmp(av[i], "set_gpio_dir") ) {
				int gpio=0, dir=0, val=0;

                if (av[++i])
                    gpio=(gpio=str_to_hex(av[i]))==0? atoi(av[i]):gpio;
                else {
                    printf("Please set gpio number!\n");
                    fflush(stdout);
                    return -1;

                }

				if (av[++i])
                    dir=(dir=str_to_hex(av[i]))==0? atoi(av[i]):dir;
                else {
                    printf("Please set direction!\n");
                    fflush(stdout);
                    return -1;
                }
				if((dir < 0) || (dir > 3))
				{
                    printf("Please set direction 0...3!\n");
                    fflush(stdout);
                    return -1;

				}
				
				if(dir)	{
					if (av[++i])
						val=(val=str_to_hex(av[i]))==0? atoi(av[i]):val;
					else {
						printf("Please set initial value!\n");
						fflush(stdout);
						return -1;
					}
				}


                if (!type)
                    type=RDI_FLCM_DEV;


				if ((rdi_set_gpio_dir(dev, gpio, dir, val, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
					printf("Ok\n");
				}
				return 0;

            }

			else if (!strcasecmp(av[i], "get_gpio_dir") ) {
				int gpio=0, val=0;

                if (av[++i])
                    gpio=(gpio=str_to_hex(av[i]))==0? atoi(av[i]):gpio;
                else {
                    printf("Please set gpio number!\n");
                    fflush(stdout);
                    return -1;

                }

                if (!type)
                    type=RDI_FLCM_DEV;


				if ((val = rdi_get_gpio_dir(dev, gpio, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
					printf("value = %d\n", val);
				}
				return 0;

            }

			else if (!strcasecmp(av[i], "prbs") ) {
				int prbs=0, dir=0, port=0;

                if (av[++i])
                    prbs=(prbs=str_to_hex(av[i]))==0? atoi(av[i]):prbs;
                else {
                    printf("Please set set prbs patterns: 7 15 23 31 11 9!\n");
                    fflush(stdout);
                    return -1;
                }

				if (av[++i])
                    dir=(dir=str_to_hex(av[i]))==0? atoi(av[i]):dir;
                else {
                    printf("Please set direction rx - 0 tx - 1!\n");
                    fflush(stdout);
                    return -1;
                }
				if((dir < 0) || (dir > 1))
				{
                    printf("Please set direction 0...1!\n");
                    fflush(stdout);
                    return -1;

				}
				
				if (av[++i])
						port=(port=str_to_hex(av[i]))==0? atoi(av[i]):port;
				else {
						printf("Please set port\n");
						fflush(stdout);
						return -1;
				}


                if (!type)
                    type=RDI_FLCM_DEV;
				printf("set prbs %d dir %d port %d\n", prbs, dir, port);

				if ((rdi_set_prbs(dev, prbs, dir, port, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
					printf("Ok\n");
				}
				return 0;

            }

			else if (!strcasecmp(av[i], "set_gpio") ) {
				int gpio=0, val=0;

                if (av[++i])
                    gpio=(gpio=str_to_hex(av[i]))==0? atoi(av[i]):gpio;
                else {
                    printf("Please set gpio number!\n");
                    fflush(stdout);
                    return -1;

                }
				
				if (av[++i])
						val=(val=str_to_hex(av[i]))==0? atoi(av[i]):val;
				else {
					printf("Please set value!\n");
					fflush(stdout);
					return -1;
				}

                if (!type)
                    type=RDI_FLCM_DEV;

				if ((rdi_set_gpio(dev, gpio, val, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
					printf("Ok\n");
				}
				return 0;
            }

			else if (!strcasecmp(av[i], "get_gpio") ) {
				int gpio=0, val=0;

                if (av[++i])
                    gpio=(gpio=str_to_hex(av[i]))==0? atoi(av[i]):gpio;
                else {
                    printf("Please set gpio number!\n");
                    fflush(stdout);
                    return -1;

                }

                if (!type)
                    type=RDI_FLCM_DEV;


				if ((val = rdi_get_gpio(dev, gpio, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
					printf("value = %d\n", val);
				}
				return 0;

            }

			else if (!strcasecmp(av[i], "loopback") ) {
				int val=0, port=0;

                if (av[++i])
                    val=(val=str_to_hex(av[i]))==0? atoi(av[i]):val;
                else {
                    printf("Please set txrx/rxtx/off (1/2/0)\n");
                    fflush(stdout);
                    return -1;

                }
				
				if (av[++i])
						port=(port=str_to_hex(av[i]))==0? atoi(av[i]):port;
				else {
					printf("Please set value!\n");
					fflush(stdout);
					return -1;
				}

                if (!type)
                    type=RDI_FLCM_DEV;

				if ((rdi_set_loopback(dev, val, port, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
					printf("Ok\n");
				}
				return 0;
            }
			 else if (!strcasecmp(av[i], "get_port_state") ) {
				int port = 0, mode = 0, state = 0, info[4] = {0}, val = 0;

                if (av[++i])
                    port = (port = str_to_hex(av[i])) == 0 ? atoi(av[i]):port;
                else {
                    printf("Please set port number!\n");
                    fflush(stdout);
                    return -1;

                }

                if (!type)
                    type=RDI_FLCM_DEV;


				if ((val = rdi_get_port_state(dev, port, &mode, &state, &info[0], type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
					printf("mode %x, state %x, info0 %x info1 %x info2 %x info3 %x\n", mode, state, 
						info[0], info[1], info[2], info[3]);
				}
				return 0;

            }


			else if (!strcasecmp(av[i], "set_reg") ) {
				int addr=0, val=0;

                if (av[++i])
                    addr=(addr=str_to_hex(av[i]))==0? atoi(av[i]):addr;
                else {
                    printf("Please set gpio number!\n");
                    fflush(stdout);
                    return -1;

                }
				
				if (av[++i])
						val=(val=str_to_hex(av[i]))==0? atoi(av[i]):val;
				else {
					printf("Please set value!\n");
					fflush(stdout);
					return -1;
				}

                if (!type)
                    type=RDI_FLCM_DEV;

				if ((rdi_set_reg(dev, (unsigned int)addr, (unsigned int)val, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
					printf("Ok\n");
				}
				return 0;

            }

			else if (!strcasecmp(av[i], "get_reg") ) {
				int addr=0, val=0, ret=0;

                if (av[++i])
                    addr=(addr=str_to_hex(av[i]))==0? atoi(av[i]):addr;
                else {
                    printf("Please set gpio number!\n");
                    fflush(stdout);
                    return -1;

                }

                if (!type)
                    type=RDI_FLCM_DEV;


				if ((ret = rdi_get_reg(dev, (unsigned int) addr, (unsigned int *)&val, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {
					printf("value = 0x%x\n", val);
				}
				return 0;

            }

            else if (!strcasecmp(av[i], "query") ) {
                unsigned int group=0;
                if (av[++i])
                    cfg=(cfg=str_to_hex(av[i]))==0? atoi(av[i]):cfg;
                rdi_mem.rule_id=cfg;

                if (av[++i])
                    group=(cfg=str_to_hex(av[i]))==0? atoi(av[i]):group;
                rdi_mem.group=group;


                if (!type)
                    type=RDI_FLCM_DEV;

                if ((rdi_entry_query(dev, &rdi_mem, type))<0) {
                    printf("Fail\n");
                    fflush(stdout);
                    return -1;
                } else {

                    fflush(stdout);
                    switch (rdi_mem.rule_act) {
                    case 1 << RDI_ACT_DROP:
                        printf("Action: drop\n");
                        break;

                    case 1 << RDI_ACT_PERMIT:
                        printf("Action: permit\n");
                        break;

                    case 1 << RDI_ACT_REDIRECT:
                        printf("Action: dir\n");
                        break;

                    case 1 << RDI_ACT_MIRROR:
                        printf("Action: mir\n");
                        break;

                    case 1 << RDI_ACT_SET_SWITCH_PRI:
                        printf("Action: set_prio\n");
						printf("Prio %d\n", rdi_mem.usr_act);
                        break;

                    case 1 << RDI_ACT_LOAD_BALANCE:
                        printf("Action: lb\n");
                        break;

                    }
                    // rdi_mem.port= rdi_port_map(rdi_mem.port);
                    printf("Port %d\n", rdi_mem.port);
                    //  rdi_mem.redir_port= rdi_port_map(rdi_mem.redir_port);

                    printf("Redir Port %d\n", rdi_mem.redir_port);
                    // rdi_mem.mirror_port= rdi_port_map(rdi_mem.mirror_port);
                    printf("Mirror Port %d\n", rdi_mem.mirror_port);
                    printf("Ip Protocol %d\n", rdi_mem.ip_protocol);
                    printf("Dest Port %d\n", rdi_mem.dst_port);
                    printf("Dest Port Mask 0x%x\n", rdi_mem.dst_port_mask);
                    //   rdi_mem.src_port= rdi_port_map(rdi_mem.src_port);
                    printf("Src Port %d\n", rdi_mem.src_port);
                    printf("Src Port Mask 0x%x\n", rdi_mem.src_port_mask);
                    printf("Vlan %d\n", rdi_mem.vlan);
                    printf("Vlan mask %d\n", rdi_mem.vlan_mask);
#if 0
                    in_addr.s_addr= bswap_32(rdi_mem.src_ip);
                    printf("Src Ip %s\n", inet_ntoa(in_addr) );

                    in_addr.s_addr= bswap_32(rdi_mem.src_ip_mask);
                    printf("Src Ip Mask %s\n", inet_ntoa(in_addr) );

                    in_addr.s_addr= bswap_32(rdi_mem.dst_ip);
                    printf("Dest Ip %s\n", inet_ntoa(in_addr) );


                    in_addr.s_addr= bswap_32(rdi_mem.dst_ip_mask);
                    printf("Dest Ip Mask %s\n", inet_ntoa(in_addr) );
#endif

                    {
                        char str[16];

                        printf("Src Ip %s\n", inet_ntop(AF_INET, &rdi_mem.src_ip, str, 16) );
                        printf("Src Ip Mask %s\n", inet_ntop(AF_INET, &rdi_mem.src_ip_mask, str, 16) );

                        printf("Dst Ip %s\n", inet_ntop(AF_INET, &rdi_mem.dst_ip, str, 16) );
                        printf("Dst Ip Mask %s\n", inet_ntop(AF_INET, &rdi_mem.dst_ip_mask, str, 16) );
                    }


                    //// 
                    {
                        char str[46];

                        printf("Src Ip6 %s\n", inet_ntop(AF_INET6, rdi_mem.src_ip6.ip, str, 46) );
                        printf("Src Ip6 Mask %s\n", inet_ntop(AF_INET6, rdi_mem.src_ip6_mask.ip, str, 46) );

                        printf("Dst Ip6 %s\n", inet_ntop(AF_INET6, rdi_mem.dst_ip6.ip, str, 46) );
                        printf("Dst Ip6 Mask %s\n", inet_ntop(AF_INET6, rdi_mem.dst_ip6_mask.ip, str, 46) );
                    }


                    if (rdi_mem.ether_type)
                        printf("ether_type %d\n", rdi_mem.ether_type);

                    printf("UDF offset %d\n", rdi_mem.rdi_udf.offset);
                    printf("UDF data %d\n", rdi_mem.rdi_udf.data);
                    printf("UDF mask %d\n", rdi_mem.rdi_udf.mask);
                    printf("src_mac %02X %02X %02X %02X %02X %02X\n", rdi_mem.src_mac.mac[0], rdi_mem.src_mac.mac[1], rdi_mem.src_mac.mac[2],
                           rdi_mem.src_mac.mac[3], rdi_mem.src_mac.mac[4], rdi_mem.src_mac.mac[5]);
                    printf("dst_mac %02X %02X %02X %02X %02X %02X\n", rdi_mem.dst_mac.mac[0], rdi_mem.dst_mac.mac[1], rdi_mem.dst_mac.mac[2],
                           rdi_mem.dst_mac.mac[3], rdi_mem.dst_mac.mac[4], rdi_mem.dst_mac.mac[5]);


                    if (rdi_mem.mpls_type) {

                        printf("MPLS type %s\n", rdi_mem.mpls_type==1?"unicast":"multicast");
                        printf("MPLS label %d\n", rdi_mem.mpls_label);
                        printf("MPLS label mask %d\n", rdi_mem.mpls_label_mask);
                        printf("MPLS exp bits %d\n", rdi_mem.mpls_exp_bits);
                        printf("MPLS exp bits mask %d\n", rdi_mem.mpls_exp_bits_mask);
                        printf("MPLS stack bit %d\n", rdi_mem.mpls_s_bit);
                        printf("MPLS stack bit mask %d\n", rdi_mem.mpls_s_bit_mask);

                    }

                    fflush(stdout);
					return 0;
                }
            }

            else if ((!strcasecmp(av[i], "dir"))||
                     (!strcasecmp(av[i], "mir"))||
					 (!strcasecmp(av[i], "lb"))||
                     (!strcasecmp(av[i], "set_vlan"))||
                     (!strcasecmp(av[i], "set_user"))||
                     (!strcasecmp(av[i], "set_vlan_pri"))||
                     (!strcasecmp(av[i], "l2_hash"))||
                     (!strcasecmp(av[i], "l3_hash"))||
                     (!strcasecmp(av[i], "vlan_stat"))||
                     (!strcasecmp(av[i], "rule_stat"))||
					 (!strcasecmp(av[i], "get_port_link"))||
                     (!strcasecmp(av[i], "get_power"))||
                     (!strcasecmp(av[i], "stat"))||
					 (!strcasecmp(av[i], "prio_stat"))||
					 (!strcasecmp(av[i], "reset_stat"))||
                     (!strcasecmp(av[i], "permit"))||
					 (!strcasecmp(av[i], "set_prio"))||
                     (!strcasecmp(av[i], "drop"))) {
                j=i;

                for (;++i<ac;) {
                    if ((!strcasecmp(av[i], "set_cfg"))||
                        (!strcasecmp(av[i], "remove"))||
                        (!strcasecmp(av[i], "get_cfg"))||
						(!strcasecmp(av[i], "get_temp"))||
                        (!strcasecmp(av[i], "get_power"))||
                        (!strcasecmp(av[i], "clear"))||
                        (!strcasecmp(av[i], "l2_hash"))||
                        (!strcasecmp(av[i], "l3_hash"))||
                        (!strcasecmp(av[i], "vlan_stat"))||
                        (!strcasecmp(av[i], "rule_stat"))||
					    (!strcasecmp(av[i], "get_port_link"))||		
                        (!strcasecmp(av[i], "install"))||
                        (!strcasecmp(av[i], "get_dev_num"))||
                        (!strcasecmp(av[i], "query_list"))||
                        (!strcasecmp(av[i], "query"))||
                        (!strcasecmp(av[i], "set_port_mask"))||
                        (!strcasecmp(av[i], "get_port_mask"))||
						(!strcasecmp(av[i], "cpld_read"))||
                        (!strcasecmp(av[i], "cpld_write"))||
                        (!strcasecmp(av[i], "-fp"))||
                        (!strcasecmp(av[i], "-f")))
                        break;

                    if (!strcasecmp(av[i], "dir") ) {
                        action|=1<<RDI_ACT_REDIRECT;

                    } else
                        if (!strcasecmp(av[i], "lb") ) {
                        action|=1<<RDI_ACT_LOAD_BALANCE;

                    }else
                        if (!strcasecmp(av[i], "mir") ) {
                        action|=1<<RDI_ACT_MIRROR;

                    } else
                        if (!strcasecmp(av[i], "set_vlan") ) {
                        action|=1<<RDI_ACT_SET_VLAN;

                    } else
                        if (!strcasecmp(av[i], "set_user") ) {
                        action|=1<<RDI_ACT_SET_USER;

                    } else

                        if (!strcasecmp(av[i], "set_vlan_pri") ) {
                        action|=1<<RDI_ACT_SET_VLAN_PRI;

                    } else
                        if (!strcasecmp(av[i], "set_vlan_pri") ) {
                        action|=1<<RDI_ACT_SET_VLAN_PRI;

                    } else
                        if (!strcasecmp(av[i], "permit") ) {
                        action|=1<<RDI_ACT_PERMIT;

                    } else
                        if (!strcasecmp(av[i], "drop") ) {

                        action|=1<<RDI_ACT_DROP;

                    } else


                        if (!strcasecmp(av[i], "src_ip") ) {
                        //if (av[++i]) {
                        //    rdi_mem.src_ip=bswap_32(inet_addr(av[i]));
                        //}
                        if (av[++i]) {
                            if ((inet_pton(AF_INET, av[i], (void *)&rdi_mem.src_ip))==1)
                                rdi_mem.src_ip6.flag=0;
                        }

                    } else if (!strcasecmp(av[i], "src_ip_mask")) {
                        // if (av[++i])
                        //     rdi_mem.dst_ip=bswap_32(inet_addr(av[i]));
                        if (av[++i]) {
                            if ((inet_pton(AF_INET, av[i], (void *)&rdi_mem.src_ip_mask))==1)
                                rdi_mem.src_ip6.flag=0;
                        }

                    } else if (!strcasecmp(av[i], "dst_ip")) {
                        // if (av[++i])
                        //     rdi_mem.dst_ip=bswap_32(inet_addr(av[i]));
                        if (av[++i]) {
                            if ((inet_pton(AF_INET, av[i], (void *)&rdi_mem.dst_ip))==1)
                                rdi_mem.dst_ip6.flag=0;
                        }

                    } else if (!strcasecmp(av[i], "dst_ip_mask")) {
                        // if (av[++i])
                        //     rdi_mem.dst_ip=bswap_32(inet_addr(av[i]));
                        if (av[++i]) {
                            if ((inet_pton(AF_INET, av[i], (void *)&rdi_mem.dst_ip_mask))==1)
                                rdi_mem.dst_ip6.flag=0;
                        }

                    } else if (!strcasecmp(av[i], "src_ip6") ) {

                        if (av[++i]) {
                            if ((inet_pton(AF_INET6, av[i], (void *)rdi_mem.src_ip6.ip))==1)
                                rdi_mem.src_ip6.flag=1;
                        }
                    } else if (!strcasecmp(av[i], "dst_ip6") ) {

                        if (av[++i]) {
                            if ((inet_pton(AF_INET6, av[i], (void *)rdi_mem.dst_ip6.ip))==1)
                                rdi_mem.dst_ip6.flag=1;
                        }
                    } else if (!strcasecmp(av[i], "src_ip6_mask") ) {

                        if (av[++i]) {
                            if ((inet_pton(AF_INET6, av[i], (void *)rdi_mem.src_ip6_mask.ip))!=1)
                                memset(rdi_mem.src_ip6.ip,0, 16);
                        }
                    } else if (!strcasecmp(av[i], "dst_ip6_mask") ) {

                        if (av[++i]) {
                            if ((inet_pton(AF_INET6, av[i], (void *)rdi_mem.dst_ip6_mask.ip))!=1)
                                memset(rdi_mem.dst_ip6.ip,0, 16);
                        }
                    } else if (!strcasecmp(av[i], "ether_type")) {
                        if (av[++i])
                            rdi_mem.ether_type=(rdi_mem.ether_type=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.ether_type;


                    } else if (!strcasecmp(av[i], "ether_type_hash")) {
						
                        if (av[++i]) {
                            l2_hash.ether_type_mask =
								(l2_hash.ether_type_mask=str_to_hex(av[i]))==0? atoi(av[i]):l2_hash.ether_type_mask;
							
							l2_hash.l2_hash_set|=RDI_L2_HASH_ETHER_TYPE;
						}	


                    } else if (!strcasecmp(av[i], "sym_mac_hash")) {
                        if (av[++i]) {
                            if (parse_bypass_mode(av[i])>=0) {
                                l2_hash.sym_mac= parse_bypass_mode(av[i]);
                                l2_hash.l2_hash_set|=RDI_L2_HASH_SYM_MAC;
                            }

                        }

                    }  else if (!strcasecmp(av[i], "sym_l3_hash")) {
                        if (av[++i]) {
                            if (parse_bypass_mode(av[i])>=0) {
                                l3_hash.sym_l3_fields= parse_bypass_mode(av[i]);
                                l3_hash.l3_hash_set|=RDI_L3_HASH_SYM_L3_FIELDS;
                            }

                        }

                    } else if (!strcasecmp(av[i], "sym_l4_hash")) {
                        if (av[++i]) {
                            if (parse_bypass_mode(av[i])>=0) {
                                l3_hash.sym_l4_fields= parse_bypass_mode(av[i]);
                                l3_hash.l3_hash_set|=RDI_L3_HASH_SYM_L4_FIELDS;
                            }

                        }


                    }  else if (!strcasecmp(av[i], "src_ip_hash")) {
						
                        if (av[++i]) {
                            if ((inet_pton(AF_INET, av[i], (void *)&l3_hash.src_ip_mask))==1)
                                l3_hash.l3_hash_set|=RDI_L3_HASH_SIP;

                        }



                    } else if (!strcasecmp(av[i], "dst_ip_hash")) {
						
                        if (av[++i]) {
                            if ((inet_pton(AF_INET, av[i], (void *)&l3_hash.dst_ip_mask))==1)
                                l3_hash.l3_hash_set|=RDI_L3_HASH_DIP;

                        }

                    }


                    else if (!strcasecmp(av[i], "src_mac")) {
                        if (av[++i]) {
                            rdi_parse_macaddr(av[i], rdi_mem.src_mac.mac);
                            rdi_mem.src_mac.flag=1;
                            printf("src_mac %02X %02X %02X %02X %02X %02X\n", rdi_mem.src_mac.mac[0], rdi_mem.src_mac.mac[1], rdi_mem.src_mac.mac[2],
                                   rdi_mem.src_mac.mac[3], rdi_mem.src_mac.mac[4], rdi_mem.src_mac.mac[5]);

                        }
                    } else if (!strcasecmp(av[i], "src_mac_hash")) {
						
                        if (av[++i]) {
								rdi_parse_macaddr(av[i], l2_hash.src_mac_mask);
								l2_hash.l2_hash_set|=RDI_L2_HASH_SMAC;
								printf("src_mac_hash %02X %02X %02X %02X %02X %02X\n", l2_hash.src_mac_mask[0], l2_hash.src_mac_mask[1], l2_hash.src_mac_mask[2],
                                   l2_hash.src_mac_mask[3], l2_hash.src_mac_mask[4], l2_hash.src_mac_mask[5]);
                        }


                    } else if (!strcasecmp(av[i], "dst_mac_hash")) {
  						
                        if (av[++i]) {
								rdi_parse_macaddr(av[i], l2_hash.dst_mac_mask);
								l2_hash.l2_hash_set|=RDI_L2_HASH_DMAC;
								printf("src_mac_hash %02X %02X %02X %02X %02X %02X\n", l2_hash.dst_mac_mask[0], l2_hash.dst_mac_mask[1], l2_hash.dst_mac_mask[2],
                                   l2_hash.dst_mac_mask[3], l2_hash.dst_mac_mask[4], l2_hash.dst_mac_mask[5]);
                        }

                    } else if (!strcasecmp(av[i], "dst_mac")) {
                        if (av[++i]) {
                            rdi_parse_macaddr(av[i], rdi_mem.dst_mac.mac);
                            rdi_mem.dst_mac.flag=1;
                            printf("dst_mac %02X %02X %02X %02X %02X %02X\n", rdi_mem.dst_mac.mac[0], rdi_mem.dst_mac.mac[1], rdi_mem.dst_mac.mac[2],
                                   rdi_mem.dst_mac.mac[3], rdi_mem.dst_mac.mac[4], rdi_mem.dst_mac.mac[5]);

                        }
                    } else if (!strcasecmp(av[i], "udf_offset")) {
                        if (av[++i]) {
                            rdi_mem.rdi_udf.offset=(rdi_mem.rdi_udf.offset=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.rdi_udf.offset;
                            if (rdi_mem.rdi_udf.offset>31) {
                                printf("Error: UDF offset must be from 0 to 31\n");
                                return -1;

                            }
                            rdi_mem.rdi_udf.flag=1;

                        }
                    } else if (!strcasecmp(av[i], "udf_data")) {
                        if (av[++i]) {
                            rdi_mem.rdi_udf.data=(rdi_mem.rdi_udf.data=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.rdi_udf.data;

                        }
                    } else if (!strcasecmp(av[i], "udf_mask")) {
                        if (av[++i]) {
                            rdi_mem.rdi_udf.mask=(rdi_mem.rdi_udf.mask=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.rdi_udf.mask;
                        }
                    } else if (!strcasecmp(av[i], "mpls_type")) {
                        if (av[++i]) {
                            if (!strcasecmp(av[i], "uni"))
                                rdi_mem.mpls_type=1;
                            if (!strcasecmp(av[i], "multi"))
                                rdi_mem.mpls_type=2;
                        }
                    } else if (!strcasecmp(av[i], "mpls_label")) {
                        if (av[++i])
                            rdi_mem.mpls_label=(rdi_mem.mpls_label=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.mpls_label;



                    } else if (!strcasecmp(av[i], "mpls_label_mask")) {
                        if (av[++i])
                            rdi_mem.mpls_label_mask=(rdi_mem.mpls_label_mask=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.mpls_label_mask;

                    } else if (!strcasecmp(av[i], "mpls_exp_bits")) {
                        if (av[++i])
                            rdi_mem.mpls_exp_bits=(rdi_mem.mpls_exp_bits=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.mpls_exp_bits;

                    } else if (!strcasecmp(av[i], "mpls_exp_bits_mask")) {
                        if (av[++i])
                            rdi_mem.mpls_exp_bits_mask=(rdi_mem.mpls_exp_bits_mask=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.mpls_exp_bits_mask;


                    } else if (!strcasecmp(av[i], "mpls_s_bit")) {
                        if (av[++i])
                            rdi_mem.mpls_s_bit=(rdi_mem.mpls_s_bit=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.mpls_s_bit;

                    } else if (!strcasecmp(av[i], "mpls_s_bit_mask")) {
                        if (av[++i])
                            rdi_mem.mpls_s_bit_mask=(rdi_mem.mpls_s_bit_mask=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.mpls_s_bit_mask;

                    } else if (!strcasecmp(av[i], "src_port")) {
                        if (av[++i])
                            rdi_mem.src_port=(rdi_mem.src_port=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.src_port;

                    } else if (!strcasecmp(av[i], "dst_port")) {
                        if (av[++i])
                            rdi_mem.dst_port=(rdi_mem.dst_port=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.dst_port;


                    } else if (!strcasecmp(av[i], "src_port_mask")) {
                        if (av[++i])
                            rdi_mem.src_port_mask=(rdi_mem.src_port_mask=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.src_port_mask;


                    } else if (!strcasecmp(av[i], "src_port_hash")) {

                        if (av[++i]) {
                            l3_hash.src_port_mask=(l3_hash.src_port_mask=str_to_hex(av[i]))==0? atoi(av[i]):l3_hash.src_port_mask;
                            l3_hash.l3_hash_set|=RDI_L3_HASH_SPORT;

                        }   

                    } else if (!strcasecmp(av[i], "dst_port_hash")) {
						if (av[++i]) {
                            l3_hash.dst_port_mask=(l3_hash.dst_port_mask=str_to_hex(av[i]))==0? atoi(av[i]):l3_hash.dst_port_mask;
							l3_hash.l3_hash_set|=RDI_L3_HASH_DPORT;

						} 

                    } else if (!strcasecmp(av[i], "isl_usr_hash")) {

                        if (av[++i]) {
                            l3_hash.dst_port_mask=(l3_hash.isl_usr_mask=str_to_hex(av[i]))==0? atoi(av[i]):l3_hash.isl_usr_mask;
                            l3_hash.l3_hash_set|=RDI_L3_HASH_ISL_USR;

                        }
                    } else if (!strcasecmp(av[i], "dscp_hash")) {
                        if (av[++i]) {
                            l3_hash.dscp_mask=(l3_hash.dscp_mask=str_to_hex(av[i]))==0? atoi(av[i]):l3_hash.dscp_mask;
                            l3_hash.l3_hash_set|=RDI_L3_HASH_DSCP;
                        }

                    } else if (!strcasecmp(av[i], "proto_hash")) {

                        if (av[++i]) {
                            l3_hash.proto_mask=(l3_hash.proto_mask=str_to_hex(av[i]))==0? atoi(av[i]):l3_hash.proto_mask;
                            l3_hash.l3_hash_set|=RDI_L3_HASH_PROTO;
                        }


                    } else if (!strcasecmp(av[i], "custom_hash")) {
                        if (av[++i]) {

                            l3_hash.custom_mask=(l3_hash.custom_mask=str_to_hex(av[i]))==0? atoi(av[i]):l3_hash.custom_mask;
                            l3_hash.l3_hash_set|=RDI_L3_HASH_CUSTOM;  

                        }
                    }  else if (!strcasecmp(av[i], "flow_hash")) {
                        if (av[++i]) {

                            l3_hash.flow_mask=(l3_hash.flow_mask=str_to_hex(av[i]))==0? atoi(av[i]):l3_hash.flow_mask;
                            l3_hash.l3_hash_set|=RDI_L3_HASH_FLOW;

                        }
                    } else if (!strcasecmp(av[i], "random_next_hop")) {
                        if (av[++i]) {
                            if (parse_bypass_mode(av[i])>=0) {
                                l3_hash.random_next_hop= parse_bypass_mode(av[i]);
                                l3_hash.l3_hash_set|=RDI_L3_HASH_RND_NEXT_HOP;
                            }

                        }

                    } else if (!strcasecmp(av[i], "random_other")) {
                        if (av[++i]) {
                            if (parse_bypass_mode(av[i])>=0) {
                                l3_hash.random_other= parse_bypass_mode(av[i]);
                                l3_hash.l3_hash_set|=RDI_L3_HASH_RND_OTHER;
                            }

                        }

                    } else if (!strcasecmp(av[i], "random_only")) {
                        if (av[++i]) {
                            if (parse_bypass_mode(av[i])>=0) {
                                l3_hash.random_only= parse_bypass_mode(av[i]);
                                l3_hash.l3_hash_set|=RDI_L3_HASH_RND_ONLY;
                            }

                        }

                    } else if (!strcasecmp(av[i], "dst_port_mask")) {
                        if (av[++i])
                            rdi_mem.dst_port_mask=(rdi_mem.dst_port_mask=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.dst_port_mask;


                    } else if (!strcasecmp(av[i], "ip_proto")) {
                        if (av[++i])
                            rdi_mem.ip_protocol=(rdi_mem.ip_protocol=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.ip_protocol;


                    } else if (!strcasecmp(av[i], "vlan")) {
                        if (av[++i])
                            rdi_mem.vlan=(rdi_mem.vlan=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.vlan;



                    } else if (!strcasecmp(av[i], "vlan_tag")) {
                        if (av[++i])
                            rdi_mem.vlan_tag=(rdi_mem.vlan_tag=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.vlan_tag;



                    } else if (!strcasecmp(av[i], "vlan_act")) {
                        if (av[++i])
                            rdi_mem.vlan_act=(rdi_mem.vlan_act=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.vlan_act;



                    } else if (!strcasecmp(av[i], "user_act")) {
                        if (av[++i])
                            rdi_mem.usr_act=(rdi_mem.usr_act=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.usr_act;



                    } else if (!strcasecmp(av[i], "vlan_pri_act")) {
                        if (av[++i])
                            rdi_mem.vlan_pri_act=(rdi_mem.vlan_pri_act=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.vlan_pri_act;



                    } else if (!strcasecmp(av[i], "vlan_mask")) {
                        if (av[++i])
                            rdi_mem.vlan_mask=(rdi_mem.vlan_mask=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.vlan_mask;



                    } else if (!strcasecmp(av[i], "vlan_id_hash")) {
                        if (av[++i]) {
                            l2_hash.vlan_id_mask =
								(l2_hash.vlan_id_mask=str_to_hex(av[i]))==0? atoi(av[i]):l2_hash.vlan_id_mask;
							
							l2_hash.l2_hash_set|=RDI_L2_HASH_VLAN_ID;
						}

                    } else if (!strcasecmp(av[i], "vlan_pri_hash")) {

						if (av[++i]) {
                            l2_hash.vlan_pri =
								(l2_hash.vlan_pri=str_to_hex(av[i]))==0? atoi(av[i]):l2_hash.vlan_pri;
							
							l2_hash.l2_hash_set|=RDI_L2_HASH_VLAN_PRI;
						}



                    } else if (!strcasecmp(av[i], "vlan2_id_hash")) {
                        if (av[++i]) {
                            l2_hash.vlan2_id_mask =
								(l2_hash.vlan2_id_mask=str_to_hex(av[i]))==0? atoi(av[i]):l2_hash.vlan2_id_mask;
							
							l2_hash.l2_hash_set|=RDI_L2_HASH_VLAN2_ID;
						}

                    } else if (!strcasecmp(av[i], "vlan2_pri_hash")) {

						if (av[++i]) {
                            l2_hash.vlan2_pri =
								(l2_hash.vlan2_pri=str_to_hex(av[i]))==0? atoi(av[i]):l2_hash.vlan2_pri;
							
							l2_hash.l2_hash_set|=RDI_L2_HASH_VLAN2_PRI;
						}

                    }else if (!strcasecmp(av[i], "profile_idx")) {

						if (av[++i]) {
                            l2_hash.profile_index =
								(l2_hash.profile_index=str_to_hex(av[i]))==0? atoi(av[i]):l2_hash.profile_index;
							l2_hash.l2_hash_set|=RDI_L2_HASH_PROFILE_IDX;
							
						}

                    } else if (!strcasecmp(av[i], "redir_port")) {
                        if (av[++i])
                            rdi_mem.redir_port=(rdi_mem.redir_port=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.redir_port;



                    } 
					else if (!strcasecmp(av[i], "lbg_num")) {
                        if (av[++i])
                            rdi_mem.redir_port=(rdi_mem.redir_port=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.redir_port;


                    } 
					else if (!strcasecmp(av[i], "mir_port")) {

                        if (av[++i])
                            rdi_mem.mirror_port=(rdi_mem.mirror_port=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.mirror_port;



                    } else if (!strcasecmp(av[i], "rule_id")) {
                        if (av[++i])
                            rdi_mem.rule_id=(rdi_mem.rule_id=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.rule_id;



                    } else if (!strcasecmp(av[i], "group")) {
                        if (av[++i])
                            rdi_mem.group=(rdi_mem.group=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.group;
                        if (!rdi_mem.group)
                            rdi_mem.group=0;



                    } else if (!strcasecmp(av[i], "prio")) {
                        if (av[++i])
                            rdi_mem.usr_act=(rdi_mem.usr_act=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.usr_act;
                    } 

                    else if (!strcasecmp(av[i], "port")) {
                        if (av[++i])
                            rdi_mem.port=(rdi_mem.port=str_to_hex(av[i]))==0? atoi(av[i]):rdi_mem.port;



                    } else {
                        goto err_cmd;
                    }
                }
                if ((!rdi_mem.mpls_type)&&
                    ((rdi_mem.mpls_label)||(rdi_mem.mpls_exp_bits)||
                     (rdi_mem.mpls_s_bit))) {
                    printf("Error: mpls_type isn't defined!\n");
                    fflush(stdout);
                    return -1;
                }
                // rdi_mem.port=rdi_port_umap(rdi_mem.port);
                if (rdi_mem.port<0)
                    return -1;
                if (!strcasecmp(av[j], "dir") ) {
                    action|=1<<RDI_ACT_REDIRECT;

                }
                if (!strcasecmp(av[j], "lb") ) {
                    action|=1<<RDI_ACT_LOAD_BALANCE;

                }

                if (!strcasecmp(av[j], "mir") ) {
                    action|=1<<RDI_ACT_MIRROR;

                }
                if (!strcasecmp(av[j], "set_vlan") ) {
                    action|=1<<RDI_ACT_SET_VLAN;

                }
                if (!strcasecmp(av[j], "set_user") ) {
                    action|=1<<RDI_ACT_SET_USER;

                }

                if (!strcasecmp(av[j], "set_vlan_pri") ) {
                    action|=1<<RDI_ACT_SET_VLAN_PRI;

                }
                if (!strcasecmp(av[j], "set_vlan_pri") ) {
                    action|=1<<RDI_ACT_SET_VLAN_PRI;

                }
                if (!strcasecmp(av[j], "permit") ) {
                    action|=1<<RDI_ACT_PERMIT;

                }
                if (!strcasecmp(av[j], "drop") ) {

                    action|=1<<RDI_ACT_DROP;

                }
                if (!strcasecmp(av[j], "set_prio") ) {

                    action|=1<<RDI_ACT_SET_SWITCH_PRI;

                }


                if (action) {
                    //  rdi_mem.redir_port=rdi_port_umap(rdi_mem.redir_port);

                    if (!rdi_mem.group)
                        rdi_mem.group=0;
                    rule_id=rdi_add_rule(dev, &rdi_mem, action, type);
                    //rdi_install_rules(); 

                } else if (!strcasecmp(av[j], "l2_hash")) {
                    // rdi_mem.mirror_port=rdi_port_umap(rdi_mem.mirror_port);
                    if ((l2_hash.l2_hash_set)&&(!rdi_set_l2_hash(dev, &l2_hash, type))) {
                            printf("Ok\n");
                            return 0;
                        }
                    else {
                        printf("Fail\n");
                        return -1;
                    } 


                } else if (!strcasecmp(av[j], "l3_hash")) {
                    // rdi_mem.mirror_port=rdi_port_umap(rdi_mem.mirror_port);
                    //rdi_install_rules();
                    if ((l3_hash.l3_hash_set)&&(!rdi_set_l3_hash(dev, &l3_hash, type))) {
                            printf("Ok\n");
                            return 0;
                        }
                    else {
                        printf("Fail\n");
                        return -1;
                    }   

                } else if (!strcasecmp(av[j], "vlan_stat")) {
                    int ret=0;
                    if (type==RDI_FLCM_DEV) {
                        printf("Not supported\n");
                        fflush(stdout);
                        return 0;
                    } else {


                        memset(&rdi_vlan_stat,0,sizeof(rdi_vlan_stat_cnt_t));
                        ret=rdi_get_vlan_stat(dev, rdi_mem.port, &rdi_vlan_stat, type);
                        if (ret<0) {
                            printf("Get VLAN stat error\n");
                            fflush(stdout);
                            return -1;
                        }

                        printf("RX VLAN drops %lli\n",rdi_vlan_stat.vland);
                        printf("TX VLAN tagged packets %lli\n",rdi_vlan_stat.tvlan);
                        printf("Packets dropped due to invalid VLAN counter %lli\n",rdi_vlan_stat.tvland);
                        fflush(stdout);
                        return 0;
                    }     //rdi_install_rules();


                } else if (!strcasecmp(av[j], "stat")) {
                    int ret=0;
                    memset(&rdi_stat,0,sizeof(rdi_stat_cnt_t));
                    ret=rdi_get_stat(dev, rdi_mem.port, &rdi_stat, type);
                    if (ret<0) {
                        printf("Fail\n");
                        fflush(stdout);
                        return -1;
                    }

                    if (type==RDI_FLCM_DEV) {
                        rdif_stat_cnt_t  *counters=&rdi_stat.rdif;

                        DUMP_VAL64("cntRxUcstPkts", counters->cntRxUcstPkts);

                        DUMP_VAL64("cntRxUcstPktsNonIP", counters->cntRxUcstPktsNonIP);

                        DUMP_VAL64("cntRxUcstPktsIPv4", counters->cntRxUcstPktsIPv4);

                        DUMP_VAL64("cntRxUcstPktsIPv6", counters->cntRxUcstPktsIPv6);

                        DUMP_VAL64("cntRxBcstPkts", counters->cntRxBcstPkts);

                        DUMP_VAL64("cntRxBcstPktsNonIP", counters->cntRxBcstPktsNonIP);

                        DUMP_VAL64("cntRxBcstPktsIPv4", counters->cntRxBcstPktsIPv4);

                        DUMP_VAL64("cntRxBcstPktsIPv6", counters->cntRxBcstPktsIPv6);

                        DUMP_VAL64("cntRxMcstPkts", counters->cntRxMcstPkts);

                        DUMP_VAL64("cntRxMcstPktsNonIP", counters->cntRxMcstPktsNonIP);

                        DUMP_VAL64("cntRxMcstPktsIPv4", counters->cntRxMcstPktsIPv4);

                        DUMP_VAL64("cntRxMcstPktsIPv6", counters->cntRxMcstPktsIPv6);

                        DUMP_VAL64("cntRxPausePkts", counters->cntRxPausePkts);

                        DUMP_VAL64("cntRxCBPausePkts", counters->cntRxCBPausePkts);

                        DUMP_VAL64("cntRxFCSErrors", counters->cntRxFCSErrors);

                        DUMP_VAL64("cntRxSymbolErrors", counters->cntRxSymbolErrors);

                        DUMP_VAL64("cntRxFrameSizeErrors", counters->cntRxFrameSizeErrors);

                        DUMP_VAL64("cntRxMinTo63Pkts", counters->cntRxMinTo63Pkts);

                        DUMP_VAL64("cntRx64Pkts", counters->cntRx64Pkts);

                        DUMP_VAL64("cntRx65to127Pkts", counters->cntRx65to127Pkts);

                        DUMP_VAL64("cntRx128to255Pkts", counters->cntRx128to255Pkts);

                        DUMP_VAL64("cntRx256to511Pkts", counters->cntRx256to511Pkts);

                        DUMP_VAL64("cntRx512to1023Pkts", counters->cntRx512to1023Pkts);

                        DUMP_VAL64("cntRx1024to1522Pkts", counters->cntRx1024to1522Pkts);

                        DUMP_VAL64("cntRx1523to2047Pkts", counters->cntRx1523to2047Pkts);

                        DUMP_VAL64("cntRx2048to4095Pkts", counters->cntRx2048to4095Pkts);

                        DUMP_VAL64("cntRx4096to8191Pkts", counters->cntRx4096to8191Pkts);

                        DUMP_VAL64("cntRx8192to10239Pkts", counters->cntRx8192to10239Pkts);

                        DUMP_VAL64("cntRx10240toMaxPkts", counters->cntRx10240toMaxPkts);

                        DUMP_VAL64("cntRxFragmentPkts", counters->cntRxFragmentPkts);

                        DUMP_VAL64("cntRxUndersizedPkts", counters->cntRxUndersizedPkts);

                        DUMP_VAL64("cntRxJabberPkts", counters->cntRxJabberPkts);

                        DUMP_VAL64("cntRxOversizedPkts", counters->cntRxOversizedPkts);

                        DUMP_VAL64("cntRxGoodOctets", counters->cntRxGoodOctets);

                        DUMP_VAL64("cntRxOctetsNonIp", counters->cntRxOctetsNonIp);

                        DUMP_VAL64("cntRxOctetsIPv4", counters->cntRxOctetsIPv4);

                        DUMP_VAL64("cntRxOctetsIPv6", counters->cntRxOctetsIPv6);

                        DUMP_VAL64("cntRxBadOctets", counters->cntRxBadOctets);

                        DUMP_VAL64("cntRxPriorityPkts", counters->cntRxPriorityPkts);

                        DUMP_VAL64("cntRxPriorityOctets", counters->cntRxPriorityOctets);

                        DUMP_VAL64("cntTxUcstPkts", counters->cntTxUcstPkts);

                        DUMP_VAL64("cntTxBcstPkts", counters->cntTxBcstPkts);

                        DUMP_VAL64("cntTxMcstPkts", counters->cntTxMcstPkts);

                        DUMP_VAL64("cntTxPausePkts", counters->cntTxPausePkts);

                        DUMP_VAL64("cntTxFCSErroredPkts", counters->cntTxFCSErroredPkts);

                        DUMP_VAL64("cntTxErrorDropPkts", counters->cntTxErrorDropPkts);

                        DUMP_VAL64("cntTxTimeOutPkts", counters->cntTxTimeOutPkts);

                        DUMP_VAL64("cntTxLoopbackPkts", counters->cntTxLoopbackPkts);

                        DUMP_VAL64("cntTxMinTo63Pkts", counters->cntTxMinTo63Pkts);

                        DUMP_VAL64("cntTx64Pkts", counters->cntTx64Pkts);

                        DUMP_VAL64("cntTx65to127Pkts", counters->cntTx65to127Pkts);

                        DUMP_VAL64("cntTx128to255Pkts", counters->cntTx128to255Pkts);

                        DUMP_VAL64("cntTx256to511Pkts", counters->cntTx256to511Pkts);

                        DUMP_VAL64("cntTx512to1023Pkts", counters->cntTx512to1023Pkts);

                        DUMP_VAL64("cntTx1024to1522Pkts", counters->cntTx1024to1522Pkts);

                        DUMP_VAL64("cntTx1523to2047Pkts", counters->cntTx1523to2047Pkts);

                        DUMP_VAL64("cntTx2048to4095Pkts", counters->cntTx2048to4095Pkts);

                        DUMP_VAL64("cntTx4096to8191Pkts", counters->cntTx4096to8191Pkts);

                        DUMP_VAL64("cntTx8192to10239Pkts", counters->cntTx8192to10239Pkts);

                        DUMP_VAL64("cntTx10240toMaxPkts", counters->cntTx10240toMaxPkts);

                        DUMP_VAL64("cntTxOctets", counters->cntTxOctets);

                        DUMP_VAL64("cntTxErrorOctets", counters->cntTxErrorOctets);

                        DUMP_VAL64("cntTxCMDropPkts", counters->cntTxCMDropPkts);

                        DUMP_VAL64("cntFIDForwardedPkts", counters->cntFIDForwardedPkts);

                        DUMP_VAL64("cntFloodForwardedPkts", counters->cntFloodForwardedPkts);

                        DUMP_VAL64("cntSpeciallyHandledPkts", counters->cntSpeciallyHandledPkts);

                        DUMP_VAL64("cntParseErrDropPkts", counters->cntParseErrDropPkts);

                        DUMP_VAL64("cntParityErrorPkts", counters->cntParityErrorPkts);

                        DUMP_VAL64("cntTrappedPkts", counters->cntTrappedPkts);

                        DUMP_VAL64("cntPauseDropPkts", counters->cntPauseDropPkts);

                        DUMP_VAL64("cntSTPDropPkts", counters->cntSTPDropPkts);

                        DUMP_VAL64("cntReservedTrapPkts", counters->cntReservedTrapPkts);

                        DUMP_VAL64("cntSecurityViolationPkts", counters->cntSecurityViolationPkts);

                        DUMP_VAL64("cntVLANTagDropPkts", counters->cntVLANTagDropPkts);

                        DUMP_VAL64("cntVLANIngressBVPkts", counters->cntVLANIngressBVPkts);

                        DUMP_VAL64("cntVLANEgressBVPkts", counters->cntVLANEgressBVPkts);

                        DUMP_VAL64("cntGlortMissDropPkts", counters->cntGlortMissDropPkts);

                        DUMP_VAL64("cntFFUDropPkts", counters->cntFFUDropPkts);

                        DUMP_VAL64("cntPolicerDropPkts", counters->cntPolicerDropPkts);

                        DUMP_VAL64("cntTTLDropPkts", counters->cntTTLDropPkts);

                        DUMP_VAL64("cntCmPrivDropPkts", counters->cntCmPrivDropPkts);

                        DUMP_VAL64("cntSmp0DropPkts", counters->cntSmp0DropPkts);

                        DUMP_VAL64("cntSmp1DropPkts", counters->cntSmp1DropPkts);

                        DUMP_VAL64("cntRxHog0DropPkts", counters->cntRxHog0DropPkts);

                        DUMP_VAL64("cntRxHog1DropPkts", counters->cntRxHog1DropPkts);

                        DUMP_VAL64("cntTxHog0DropPkts", counters->cntTxHog0DropPkts);

                        DUMP_VAL64("cntTxHog1DropPkts", counters->cntTxHog1DropPkts);

                        DUMP_VAL64("cntRateLimit0DropPkts", counters->cntRateLimit0DropPkts);

                        DUMP_VAL64("cntRateLimit1DropPkts", counters->cntRateLimit1DropPkts);

                        DUMP_VAL64("cntBadSmpDropPkts", counters->cntBadSmpDropPkts);

                        DUMP_VAL64("cntTriggerDropRedirPkts", counters->cntTriggerDropRedirPkts);

                        DUMP_VAL64("cntTriggerDropPkts", counters->cntTriggerDropPkts);

                        DUMP_VAL64("cntTriggerRedirPkts", counters->cntTriggerRedirPkts);

                        DUMP_VAL64("cntTriggerMirroredPkts", counters->cntTriggerMirroredPkts);

                        DUMP_VAL64("cntBroadcastDropPkts", counters->cntBroadcastDropPkts);

                        DUMP_VAL64("cntDLFDropPkts", counters->cntDLFDropPkts);

                        DUMP_VAL64("cntRxCMDropPkts", counters->cntRxCMDropPkts);

                        DUMP_VAL64("cntUnderrunPkts", counters->cntUnderrunPkts);

                        DUMP_VAL64("cntOverrunPkts", counters->cntOverrunPkts);

                        DUMP_VAL64("cntCorruptedPkts", counters->cntCorruptedPkts);

                        DUMP_VAL64("cntStatsDropCountTx", counters->cntStatsDropCountTx);

                        DUMP_VAL64("cntStatsDropCountRx", counters->cntStatsDropCountRx);

                        fflush(stdout);
                    } else {

                        printf("Total packets %lli\n",rdi_stat.rdib.total);
                        printf("RX noerror %lli\n",rdi_stat.rdib.rxnoerror);
                        printf("TX noerror %lli\n",rdi_stat.rdib.txnoerror);
                        printf("RX discard %lli\n",rdi_stat.rdib.rxdrop);
                        printf("TX discard %lli\n",rdi_stat.rdib.txdrop);
                        fflush(stdout);
                    }
                    return 0;
                    //rdi_install_rules();


                } else if (!strcasecmp(av[j], "prio_stat")) {
                    int ret = 0, i = 0;
					rdif_prio_stat_cnt_t  *counters = &rdi_stat.prio_rdif;

                    memset(&rdi_stat, 0, sizeof(rdi_stat_cnt_t));
                    ret=rdi_get_prio_stat(dev, rdi_mem.port, &rdi_stat, type);
                    if (ret<0) {
                        printf("Fail\n");
                        fflush(stdout);
                        return -1;
                    }
					for (i = 0; i < 16; i++) {
						if (counters->cntRxPriorityPkts[i]) {
							printf("cntRxPriorityPkts[%i]: %llu\n", i, counters->cntRxPriorityPkts[i]);
						}
        
					}
                    fflush(stdout);
                    return 0;
                    //rdi_install_rules();
                
                } else if (!strcasecmp(av[j], "reset_stat")) {
                    int ret = 0;

                    ret = rdi_reset_stat(dev, rdi_mem.port, type);
                    if (ret<0) {
                        printf("Fail\n");
                        ret = -1;
                    }
					else printf("Ok\n");
                    fflush(stdout);
                    return ret;
                    //rdi_install_rules();
                
                } else if (!strcasecmp(av[j], "get_power")) {
                    int ret=0;
                    rdi_sfi_diag_t sfi_diag;
                    if (type==RDI_FLCM_DEV) {
                        printf("Not supported\n");
                        fflush(stdout);
                        return 0;
                    } else {



                        memset(&sfi_diag,0,sizeof(rdi_sfi_diag_t));
                        if ((rdi_mem.port!=0)&&(rdi_mem.port!=1)) {
                            printf("Port number error; only external ports 0 or 1 must be used\n");
                            fflush(stdout);
                            return -1;  
                        }
                        ret=rdi_get_power(dev, rdi_mem.port, &sfi_diag, type);
                        if (ret<0) {
                            printf("Get TX/RX power error\n");
                            fflush(stdout);
                            return -1;
                        }

                        printf("dev %d port %d: TX output power=%d uW\n", dev, rdi_mem.port, sfi_diag.tx_power/10);
                        printf("dev %d port %d: RX input power=%d uW\n", dev, rdi_mem.port, sfi_diag.rx_power/10);
                        fflush(stdout);
                        return 0;
                    }
                    //rdi_install_rules();


                } else {
                    printf("Unknown command!\n");
                    fflush(stdout);
                    return -1;
                }
                if (rule_id < 0) {
                    printf("Rule settings error!\n");
                    fflush(stdout);
                    return -1;
                } else
                    printf("Rule ID is %d\n", rule_id);
                fflush(stdout);
                /* if ((rdi_install_rules(dev))<0)
                     printf("Install rules failed!\n");*/

                if (i <ac) {

                    goto start_cmd;
                }


            } else {
                goto err_cmd;
            }
        }
    }


    return 0;

    err_cmd:
    redir_usage();
    return -1;



}

void rdi_get_cmd(char *dst);

int read_rdi_conf(const char * file_path){
    const char * file, * chptr, * end;
    char * buf;
    char * dst;
    int fd;
    off_t file_length;

    if (file_path==NULL)
        file_path= RDI_CONF_PATH;
    fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        printf("Can't open file %s!\n",file_path); 
        fflush(stdout);
        return -1;
    }

    file_length = lseek(fd, 0, SEEK_END);
    if (file_length == -1 || lseek(fd, 0, 0) == -1) {
        (void) close(fd);
        return -1;
    }

    file = (const char *)alloca(file_length + 1);
    if (read(fd, (char *)file, file_length) != file_length) {
        (void) close(fd);
        return -1;
    }
    if (close(fd) == -1)
        return -1;

    dst = buf = (char *)alloca(file_length + 1);

    chptr = file;
    end = (file + file_length);
    while (chptr < end) {
        switch (*chptr) {
        case '\n':
            *dst = '\0';
            dst = buf;
            while (*dst && isspace(*dst)) dst++;
            if (*dst && *dst != '#') {

                rdi_get_cmd(dst);
            }
            chptr++;
            break;
        case '\\':
            *dst++ = *chptr++;
            if (chptr < end) {
                if (*chptr == '\n')
                    dst--, chptr++;
                else
                    *dst++ = *chptr++;
            }
            break;
        default:
            *dst++ = *chptr++;
            break;
        }
    }

    return 0;
} 

void rdi_get_cmd(char *line){

    int argc=1;           
    char * argv[256]; 
    size_t len;
    char * buf;
    char * dst;
    const char * chptr, * end;


    len= strlen(line);

    dst = buf = (char *)alloca(len + 1);

    chptr = line;
    end = (line + len+1);


    dst=(char *) chptr;
    buf=dst;


    while (chptr < end) {
        if ((isspace(*chptr))||(*chptr=='\0')) {
            *dst='\0';
            argv[argc]=buf;
            argc++;
            chptr++;
            dst++;
            while ( (chptr < end) && isspace(*chptr)) {
                chptr++;
                dst++;
            }
            if (*chptr=='\0')
                goto start_parse;
            buf=dst;
        } else *dst++ = *chptr++;
        //chptr++;
        //dst++;
    }
    start_parse:
    rdi_parse_cmd(argc, argv);


}

void catcher( int sig ){
    time_t t;
    char last_log[2048];
    FILE * stream,* proc_stream;

    memset(last_log,0,2048);
    time( &t );
    switch (sig) {
    case SIGUSR1:{  
            if ((stream=fopen (RDICTL_LOG_PATH, "a"))!=NULL) {
                if ((proc_stream=fopen ("/proc/net/rdictl_event", "r"))!=NULL) {
                    if (fread(last_log,1,2048,proc_stream))
                        fprintf(stream,"%s%s\n",ctime(&t),last_log);
                    fclose(proc_stream);
                }
                fclose(stream);
            }
            break;


        }
    case SIGTERM:{
            if ((stream=fopen (RDICTL_LOG_PATH, "a"))!=NULL) {

                fprintf(stream,"%sexiting...\n\n",ctime(&t));
                fclose(stream);
            }
            unlink(RDICTL_PID_PATH);
            exit(0);
        }
    }
}


static void start_daemon(int ac, char **av){
    struct sigaction sigact;
    sigset_t block_set;

    /*if ((rdi_probe())!=0)
        return;*/

    /*rdi_init();*/
    rdi_parse_cmd(ac, av);

    sigfillset( &sigact.sa_mask );
    sigact.sa_flags = 0;
    sigact.sa_handler = catcher;
    sigaction( SIGUSR1, &sigact, NULL );
    sigaction( SIGINT, &sigact, NULL );
    sigaction( SIGTERM, &sigact, NULL );

    sigemptyset( &block_set );
    sigact.sa_flags = 0;
    sigact.sa_handler = catcher;

    while (1) {
        sigsuspend( &block_set );
    }


}




int main(int ac, char **av){
    int i=0;
    FILE *fp;
    pid_t proc_pid;
    int file_length;
    const char * file;
    int fd;


    if (ac==1) {

        redir_usage();
        return -1;



    }
    if ((ac==2)&& (strcmp(av[1],"get_cfg"))
        && (strcmp(av[1],"get_dev_num"))
		&& (strcmp(av[1],"get_temp"))
        && (strcmp(av[1],"-f"))
        && (strcmp(av[1],"clear"))
        && (strcmp(av[1],"lbg_create"))
        && (strcmp(av[1],"get_l2_hash"))
        && (strcmp(av[1],"get_l3_hash"))
        && (strcmp(av[1],"lbg_query_list"))
		&& (strcmp(av[1],"mir_query_list"))
        && (strcmp(av[1],"mod1"))
        && (strcmp(av[1],"mod0"))
        && (strcmp(av[1],"mod2"))
        && (strcmp(av[1],"install"))
        && (strcmp(av[1],"stat"))
		&& (strcmp(av[1],"prio_stat"))
        && (strcmp(av[1],"clear_group"))
        && (strcmp(av[1],"query_list"))) {
        i=1;
        if (!strcmp(av[i], INFO_ENTRY)) {
            printf(APP_NAME" Version "UTIL_VER" \n");
            printf(COPYRT_MSG"\n");
            fflush(stdout);
            return 0;
        } else if (!strcmp(av[i], HELP_ENTRY)) {

            redir_usage();
            return 0;
        } else {

            redir_usage();
            return -1;


        }
    }

/*    if((rdi_init())<0){
    printf("Fail\n");
    return -1;
    };*/
    return(rdi_parse_cmd(ac, av));


    if ((fd=open(RDICTL_PID_PATH, O_RDONLY))>0) {
        file_length = lseek(fd, 0, SEEK_END);
        if (file_length != -1 && lseek(fd, 0, 0) != -1) {
            file = (const char *)alloca(file_length + 1);
            if (read(fd, (char *)file, file_length) == file_length) {
                kill(atoll(file),SIGKILL);
            }
        }
        close(fd);
    }
    pid=fork();

    if (pid<0) {
        perror("fork");
        return ERROR;
    }
    if (pid==0) {
        setsid();
        fp=fopen(RDICTL_PID_PATH,"w");
        if (fp) {
            proc_pid=getpid();
            fprintf(fp,"%ld\n",(long)proc_pid);
            fclose(fp);
        }
        start_daemon(ac, av);
    }
    return 0;



}




