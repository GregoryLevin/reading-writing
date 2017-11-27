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
#include <zlib.h>

#define BUFFER_SIZE 9600
#define ETHER_INTERFACE2 "p1p1"
#define ETHER_INTERFACE1 "enp131s0"
#define SRC_MAC_ADDRESS_0_2 0x0
#define SRC_MAC_ADDRESS_1_2 0xE0
#define SRC_MAC_ADDRESS_2_2 0xED
#define SRC_MAC_ADDRESS_3_2 0x54
#define SRC_MAC_ADDRESS_4_2 0x7A
#define SRC_MAC_ADDRESS_5_2 0x79
#define SRC_MAC_ADDRESS_0_1 0x0
#define SRC_MAC_ADDRESS_1_1 0xE0
#define SRC_MAC_ADDRESS_2_1 0xED
#define SRC_MAC_ADDRESS_3_1 0x54
#define SRC_MAC_ADDRESS_4_1 0x7A
#define SRC_MAC_ADDRESS_5_1 0x78
#define MAX_FILENAME_PATH 1000

int main(int argc, char **argv)
{
        int sockfd;
        struct ifreq ifopts;    /* set promiscuous mode */
        struct ifreq if_ip;     /* get ip addr */
        unsigned char sendbuf[BUFFER_SIZE];
        struct ether_header *eh = (struct ether_header *) sendbuf;
        struct sockaddr_ll socket_address;
        int buf_size;
        int count,i;
        int delay_ms;
        char file_name_with_path[MAX_FILENAME_PATH];
        FILE *input_file;
        long int offset_in_file = 0l;
        int eof = 0;
        long int common_counter = 0l;
        char interf[100]; 
        int random_int; 
        unsigned char dest_mac_0;
        unsigned char dest_mac_1;
        unsigned char dest_mac_2;
        unsigned char dest_mac_3;
        unsigned char dest_mac_4;
        unsigned char dest_mac_5;
        struct timespec tv,trem;
        int ether_header_sz = sizeof(struct ether_header);
        unsigned long crc;

        if( argc < 3) {
          printf("incorrect number of parameters. Expected at least 2 parameters\n");
          printf("filetx interface filename_with_path [delay_ms] [buffer_size]\n");
          return -1;
        }
        
        
        strcpy(interf,argv[1]);

        strcpy((char *)&file_name_with_path[0], argv[2]);

        if(argc >= 4)
           delay_ms = (int)strtol(argv[3],0,10);
        else
           delay_ms = 100;
 
        if(argc >= 5)
           buf_size = (int)strtol(argv[4],0,10);
        else
           buf_size = 1500;


        printf("Parameters:--------------\n");

        printf("Interface %s\n", interf);

        printf("File name and path      %s\n", file_name_with_path);
        printf("Delay ms between buffers %d\n", delay_ms);
        printf("Size of the buffer      %d\n", buf_size);

        if (buf_size> BUFFER_SIZE)
        {
           printf("Sending buffer too big(%d MAX)\n", BUFFER_SIZE);
           return -2;
        }

        srand(time(NULL));   // should only be called once
        random_int = rand();      // returns a pseudo-random integer between 0 and RAND_MAX
        dest_mac_0 = (unsigned char)(random_int&((int)0xFF));
        dest_mac_1 = (unsigned char)((random_int&((int)0xFF00))>>8);
        dest_mac_2 = (unsigned char)((random_int&((int)0xFF0000))>>16);
        dest_mac_3 = (unsigned char)((random_int&((int)0xFF000000))>>24);

        random_int = rand();

        dest_mac_4 = (unsigned char)(random_int&((int)0xFF));
        dest_mac_5 = (unsigned char)((random_int&((int)0xFF00))>>8);

        printf("Dest MAC generated %02x:%02x:%02x:%02x:%02x:%02x\n", dest_mac_0,
               dest_mac_1,dest_mac_2,dest_mac_3,dest_mac_4,dest_mac_5);


        tv.tv_sec = (time_t)(delay_ms/1000);
        tv.tv_nsec = ((long)(delay_ms%1000))*1000000l;


        input_file = fopen(file_name_with_path,"r");

        if(input_file < 0)
        {
           printf("Cannot open file %s\n", file_name_with_path);
           return -3;
        }

        memset(&if_ip, 0, sizeof(struct ifreq));


        if ((sockfd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
                perror("listener: socket");
                return -4;
        }
  
        strncpy(if_ip.ifr_name, interf, IFNAMSIZ-1);
        strncpy(ifopts.ifr_name, interf, IFNAMSIZ-1);

        if(ioctl(sockfd, SIOCGIFINDEX, &if_ip) < 0)
          perror("SIOCGIFINDEX");


        if(ioctl(sockfd, SIOCGIFHWADDR, &ifopts) < 0)
          perror("SIOCGIHWADDR");

            socket_address.sll_ifindex = if_ip.ifr_ifindex;
            socket_address.sll_halen = ETH_ALEN;

            socket_address.sll_addr[0] = dest_mac_0;
            socket_address.sll_addr[1] = dest_mac_1;
            socket_address.sll_addr[2] = dest_mac_2;
            socket_address.sll_addr[3] = dest_mac_3;
            socket_address.sll_addr[4] = dest_mac_4;
            socket_address.sll_addr[5] = dest_mac_5;

            count = 0;
            common_counter = 0l;
            offset_in_file = 0l;  

            for(i = 0; eof == 0; i++)
            {
              if(fseek(input_file, offset_in_file,SEEK_SET) != 0)
              {
                 eof = 1;
              }
              count = fread((&sendbuf[0] + ether_header_sz), 1, buf_size - ether_header_sz - sizeof(long int), input_file);
              if(count <= 0)
              {
                 eof = 1;
                 printf("End of file reached\n");
              }
              else
              {
                eh->ether_shost[0] = ((uint8_t *)&ifopts.ifr_hwaddr.sa_data)[0];
                eh->ether_shost[1] = ((uint8_t *)&ifopts.ifr_hwaddr.sa_data)[1];
                eh->ether_shost[2] = ((uint8_t *)&ifopts.ifr_hwaddr.sa_data)[2];
                eh->ether_shost[3] = ((uint8_t *)&ifopts.ifr_hwaddr.sa_data)[3];
                eh->ether_shost[4] = ((uint8_t *)&ifopts.ifr_hwaddr.sa_data)[4];
                eh->ether_shost[5] = ((uint8_t *)&ifopts.ifr_hwaddr.sa_data)[5];

                eh->ether_dhost[0] = dest_mac_0;
                eh->ether_dhost[1] = dest_mac_1;
                eh->ether_dhost[2] = dest_mac_2;
                eh->ether_dhost[3] = dest_mac_3;
                eh->ether_dhost[4] = dest_mac_4;
                eh->ether_dhost[5] = dest_mac_5;

                eh->ether_type = htons(ETH_P_ALL);

      
                offset_in_file += (long int)count;

                crc = crc32(0, Z_NULL, 0);
                crc = crc32(crc, (const unsigned char *)sendbuf, count + ether_header_sz);
                memcpy(&sendbuf[0] + count + ether_header_sz, &crc, sizeof(unsigned long));


                if (sendto(sockfd, (unsigned char *)&sendbuf[0], count + ether_header_sz + sizeof(unsigned long), 0, (struct sockaddr*)&socket_address,sizeof(struct sockaddr_ll)) < 0)
                    printf("send RAW failed\n");
                 else
                    common_counter += (long int)(count + ether_header_sz + sizeof(unsigned long));
              }

              nanosleep(&tv,&trem);
                
              printf("Sent %ld bytes\n",common_counter);
              if(eof == 1)
                break;
           }

      printf("Result-------------------------------------------------\n");
      printf("File name and path      %s\n", file_name_with_path);
      printf("Sent %d packets  each %d bytes all together %ld bytes\n", i, buf_size, common_counter);
      printf("Dest MAC generated %02x:%02x:%02x:%02x:%02x:%02x\n", dest_mac_0,
               dest_mac_1,dest_mac_2,dest_mac_3,dest_mac_4,dest_mac_5);

      fclose(input_file);
      return 0;
} 
