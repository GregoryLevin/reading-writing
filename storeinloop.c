#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <time.h>

#define BUFFER_SIZE 1500
#define ETHER_TYPE      0x0800
#define ETHER_INTERFACE2 "p1p1"
#define ETHER_INTERFACE1 "enp131s0"
#define DEST_MAC_ADDRESS_0_2 0x0
#define DEST_MAC_ADDRESS_1_2 0xE0
#define DEST_MAC_ADDRESS_2_2 0xED
#define DEST_MAC_ADDRESS_3_2 0x54
#define DEST_MAC_ADDRESS_4_2 0x7A
#define DEST_MAC_ADDRESS_5_2 0x79
#define DEST_MAC_ADDRESS_0_1 0x0
#define DEST_MAC_ADDRESS_1_1 0xE0
#define DEST_MAC_ADDRESS_2_1 0xED
#define DEST_MAC_ADDRESS_3_1 0x54
#define DEST_MAC_ADDRESS_4_1 0x7A
#define DEST_MAC_ADDRESS_5_1 0x78
#define MAX_FILENAME_PATH 1000


int main(int argc, char **argv)
{
        int sockfd,sockfd_r;
	int sockopt;
        size_t numbytes;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct ifreq if_ip;	/* get ip addr */
        struct ifreq ifopts_r;    /* set promiscuous mode */
        struct ifreq if_ip_r;     /* get ip addr */
        unsigned char sendbuf[BUFFER_SIZE];
        unsigned char recvbuf[BUFFER_SIZE];
        struct ether_header *eh = (struct ether_header *) sendbuf;
        struct ether_header *eh_r = (struct ether_header *) recvbuf;
        struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
        struct sockaddr_ll socket_address;
        int buf_size;
        int count,i;
        int delay_ms;
        char file_name_with_path[MAX_FILENAME_PATH];
        FILE *input_file;
        long int offset_in_file = 0l;
        int send = 0;
        int eof = 0;
        long int common_counter = 0l;
        int direction = 0;

        if( argc != 6) {
          printf("incorrect number of parameters. Expected 5 parameters\n");
          printf("storeinloop filename_with_path buffer_size delay_msi send==1 direction\n");
          return -1;
        }
        //count = (int)strtol(argv[1],0,10);
        strcpy((char *)&file_name_with_path[0], argv[1]);
        buf_size = (int)strtol(argv[2],0,10);
        delay_ms = (int)strtol(argv[3],0,10);
        send = (int)strtol(argv[4],0,10);

        printf("Parameters:--------------\n");
        printf("File name and path      %s\n", file_name_with_path);
        printf("Size of the buffer      %d\n", buf_size);
        printf("Delay ms between buffers %d\n", delay_ms);

        if(send == 1)
          printf("Sending file to loop...\n");
        else
          printf("Receiving file from loop...\n");

        if(direction == 1)
        {
          printf("Sending file to loop...at %s\n", ETHER_INTERFACE1);
          printf("Receiving file from loop...at %s\n", ETHER_INTERFACE2);
        }
        else
        {
          printf("Sending file to  loop...at %s\n", ETHER_INTERFACE2);
          printf("Receiving file from loop...at %s\n", ETHER_INTERFACE1);
        }

        if (buf_size> BUFFER_SIZE)
        {
           if(send==1)
           	printf("Sending buffer too big(%d MAX)\n", BUFFER_SIZE);
           else
                printf("Receiving buffer too big(%d MAX)\n",BUFFER_SIZE);
           return -2;
        }

        
      
        if(send == 1)
          input_file = fopen(file_name_with_path,"r");
        else
          input_file = fopen(file_name_with_path,"a");
        

        if(input_file < 0)
        {
           printf("Cannot open file %s\n", file_name_with_path);
           return -3;
        }       

         memset(&if_ip, 0, sizeof(struct ifreq));

        if(send == 1)
        {
             // Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
             if ((sockfd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
                perror("listener: socket");
                return -1;
               }
        }
        else        
        {
             if ((sockfd_r = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
                perror("listener: socket");
                return -1;      
             }
        }


        if(send == 1)
        {
              if(direction == 1)
              {
                 strncpy(if_ip.ifr_name, ETHER_INTERFACE1, IFNAMSIZ-1);
                 strncpy(ifopts.ifr_name, ETHER_INTERFACE1, IFNAMSIZ-1);
              }
              else {
                 strncpy(if_ip.ifr_name, ETHER_INTERFACE2, IFNAMSIZ-1);
                 strncpy(ifopts.ifr_name, ETHER_INTERFACE2, IFNAMSIZ-1);
              }
        }
        else {
              if(direction == 1)
              {
                 strncpy(if_ip_r.ifr_name, ETHER_INTERFACE2, IFNAMSIZ-1);
                 strncpy(ifopts_r.ifr_name, ETHER_INTERFACE2, IFNAMSIZ-1);
              }
              else
              {
                 strncpy(if_ip_r.ifr_name, ETHER_INTERFACE1, IFNAMSIZ-1);
                 strncpy(ifopts_r.ifr_name, ETHER_INTERFACE1, IFNAMSIZ-1);
              }
        }

        if(send == 1)
        {
              if(ioctl(sockfd, SIOCGIFINDEX, &if_ip) < 0)
                perror("SIOCGIFINDEX");


              if(ioctl(sockfd, SIOCGIFHWADDR, &ifopts) < 0)
                perror("SIOCGIHWADDR");

        }
        else
        {
              if(ioctl(sockfd_r, SIOCGIFINDEX, &if_ip_r) < 0)
                perror("SIOCGIFINDEX");


              if(ioctl(sockfd_r, SIOCGIFHWADDR, &ifopts_r) < 0)
                perror("SIOCGIHWADDR");

        }
     
         if(send == 1)
        {
            eh->ether_shost[0] = ((uint8_t *)&ifopts.ifr_hwaddr.sa_data)[0];
            eh->ether_shost[1] = ((uint8_t *)&ifopts.ifr_hwaddr.sa_data)[1];
            eh->ether_shost[2] = ((uint8_t *)&ifopts.ifr_hwaddr.sa_data)[2];
            eh->ether_shost[3] = ((uint8_t *)&ifopts.ifr_hwaddr.sa_data)[3];
            eh->ether_shost[4] = ((uint8_t *)&ifopts.ifr_hwaddr.sa_data)[4];
            eh->ether_shost[5] = ((uint8_t *)&ifopts.ifr_hwaddr.sa_data)[5];
            if(direction == 1)
            {
               eh->ether_dhost[0] = DEST_MAC_ADDRESS_0_1;
               eh->ether_dhost[1] = DEST_MAC_ADDRESS_1_1;
               eh->ether_dhost[2] = DEST_MAC_ADDRESS_2_1;
               eh->ether_dhost[3] = DEST_MAC_ADDRESS_3_1;
               eh->ether_dhost[4] = DEST_MAC_ADDRESS_4_1;
               eh->ether_dhost[5] = DEST_MAC_ADDRESS_5_1;
            }
            else
            {
               eh->ether_dhost[0] = DEST_MAC_ADDRESS_0_2;
               eh->ether_dhost[1] = DEST_MAC_ADDRESS_1_2;
               eh->ether_dhost[2] = DEST_MAC_ADDRESS_2_2;
               eh->ether_dhost[3] = DEST_MAC_ADDRESS_3_2;
               eh->ether_dhost[4] = DEST_MAC_ADDRESS_4_2;
               eh->ether_dhost[5] = DEST_MAC_ADDRESS_5_2;
            }
            eh->ether_type = htons(ETH_P_ALL);

            socket_address.sll_ifindex = if_ip.ifr_ifindex;
            socket_address.sll_halen = ETH_ALEN;
            if(direction == 1)
            {
               socket_address.sll_addr[0] = DEST_MAC_ADDRESS_0_1;
               socket_address.sll_addr[1] = DEST_MAC_ADDRESS_1_1;
               socket_address.sll_addr[2] = DEST_MAC_ADDRESS_2_1;
               socket_address.sll_addr[3] = DEST_MAC_ADDRESS_3_1;
               socket_address.sll_addr[4] = DEST_MAC_ADDRESS_4_1;
               socket_address.sll_addr[5] = DEST_MAC_ADDRESS_5_1;
            }
            else {
               socket_address.sll_addr[0] = DEST_MAC_ADDRESS_0_2;
               socket_address.sll_addr[1] = DEST_MAC_ADDRESS_1_2;
               socket_address.sll_addr[2] = DEST_MAC_ADDRESS_2_2;
               socket_address.sll_addr[3] = DEST_MAC_ADDRESS_3_2;
               socket_address.sll_addr[4] = DEST_MAC_ADDRESS_4_2;
               socket_address.sll_addr[5] = DEST_MAC_ADDRESS_5_2;
            }
        }
        else
        {
            ioctl(sockfd_r, SIOCGIFFLAGS, &ifopts_r);
            ifopts_r.ifr_flags |= IFF_PROMISC;
            ioctl(sockfd_r, SIOCSIFFLAGS, &ifopts_r);

            if(setsockopt(sockfd_r, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
                perror("setsockopt");
                close(sockfd);
                return -2;
             }
             /* Bind to device */
             if (setsockopt(sockfd_r, SOL_SOCKET, SO_BINDTODEVICE, if_ip_r.ifr_name, IFNAMSIZ-1) == -1)      {
                perror("SO_BINDTODEVICE");
                close(sockfd);
                return -3;
             }

        }


        count = 0;
        common_counter = 0l;

        for(i = 0; eof == 0; i++)
        {
            if(send == 1)
            {
            	if(fseek(input_file, offset_in_file,SEEK_SET) != 0)
            	{
              		eof = 1;
              		break;
            	}
            	count = fread(&sendbuf, buf_size, 1, input_file);
            	if(count <= 0)
            	{
                	eof = 1;
                	printf("End of file reached");
                	break;
            	}
            	offset_in_file += (long int)count;

            	if (sendto(sockfd, &sendbuf, buf_size, 0, (struct sockaddr*)&socket_address,sizeof(struct sockaddr_ll)) < 0)
               		printf("send RAW failed\n");
                else
                   common_counter += (long int)buf_size;
             }
             else
             {
                 numbytes = recvfrom(sockfd_r, sendbuf, buf_size, 0, 0, 0);
                 printf("listener: got packet %ld bytes\n", numbytes);
                 fwrite(sendbuf,numbytes,1,input_file);
                 common_counter += (long int)numbytes;
             }
             usleep(delay_ms); 
             if(send == 1)
                printf("Sent %ld bytes\n",common_counter);
             else
                printf("Received %ld bytes\n",common_counter);
	}
        
    fclose(input_file);
    return 0;
}
