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
#include <pcap.h>


#define BUFFER_SIZE 9600
#define ETHER_TYPE      0x0800
#define ETHER_INTERFACE1 "enp131s0"
#define ETHER_INTERFACE2 "p1p1"
#define MAX_PACKETS_CATCH 200


int main(int argc, char **argv)
{
        pcap_t *handle1;
        char errbuf[PCAP_ERRBUF_SIZE];
        unsigned char recvbuf[BUFFER_SIZE][MAX_PACKETS_CATCH];
        int buf_length[MAX_PACKETS_CATCH];
        long unsigned int packet_number[MAX_PACKETS_CATCH];
        long unsigned int i;
        int num_bytes,count;
        int header_offset = sizeof(struct ether_header);
        char dev1[100];
        char interf[100];
        struct bpf_program fp;          /* The compiled filter expression */
        char filter_exp[] = "port 53";/* The IP of our sniffing device */
        bpf_u_int32 mask;               /* The netmask of our sniffing device */
        bpf_u_int32 net;                /* The IP of our sniffing device */
        struct pcap_pkthdr header;      /* The header that pcap gives us */
        const u_char *packet;           /* The actual packet */
        int catch,k,n;


        if( argc != 2) {
          printf("incorrect number of parameters. Expected 2 parameters\n");
          printf("filerx interface\n");
          return -1;
        }
   
        strcpy( interf, argv[1]);
        

        printf("Packages from %s\n", interf);
        strcpy((char *)dev1, interf);


        if (pcap_lookupnet(dev1, &net, &mask, errbuf) == -1) {
             fprintf(stderr, "Can't get netmask for device %s\n", dev1);
             net = 0;
             mask = 0;
             return -2;
        }

       handle1 = pcap_open_live(dev1, BUFFER_SIZE, 1, 1000, errbuf);

       if (handle1 == 0) {
          fprintf(stderr, "Couldn't open device %s: %s\n", dev1, errbuf);
          return -3;
       }
         
       if (pcap_compile(handle1, &fp, filter_exp, 0, net) == -1) {
          fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle1));
          return -4;
       }

    /*   if (pcap_setfilter(handle1, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle1));
			return -5;
       }*/

       if(pcap_setdirection(handle1, PCAP_D_IN) == -1)
       {
          fprintf(stderr,"Couldn't set only receiving direction\n");             
       }


       catch = 0;

       for(i = 0l;;) {
           packet = pcap_next(handle1, &header);

           num_bytes = header.len;

           if(header.len > 0)
           {
              header.len = 0;     
              printf("\nlistener: got packet #%ld %d bytes\n", ++i,num_bytes);
              if(num_bytes > BUFFER_SIZE)
                num_bytes = BUFFER_SIZE;
              for(n = 0; n < num_bytes;n++)
                 recvbuf[n][catch] = *(packet + n);
              buf_length[catch] = num_bytes;
              packet_number[catch] = i;
              if(catch < MAX_PACKETS_CATCH)
                catch++;
           }
           else 
           {
             for(k = 0; k < catch; k++)
             {  
               printf("\nReceived packet number %ld\n", packet_number[k]);
               if(buf_length[k] >= 0)
               {
                 printf("Source MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                 recvbuf[6][k],
                 recvbuf[7][k],
                 recvbuf[8][k],
                 recvbuf[9][k],
                 recvbuf[10][k],
                 recvbuf[11][k]);
                 printf("Destination MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                 recvbuf[0][k],
                 recvbuf[1][k],
                 recvbuf[2][k],
                 recvbuf[3][k],
                 recvbuf[4][k],
                 recvbuf[5][k]);
                 printf("Data-----------------------------------------------\n");
                 buf_length[k] -= header_offset + sizeof(unsigned long);
                 if(buf_length[k] > 0)
                 {
                    for(count = 0; count < buf_length[k]; count++)
                    {
                       if((recvbuf[count + header_offset][k]< 32)||(recvbuf[count + header_offset][k] > 126))
                          recvbuf[count + header_offset][k] = '*';
                    }
                    for(count = 0; count < buf_length[k]; count++)
                    {
                      printf("%c",recvbuf[count + header_offset][k]);
                      if((count%50 == 0)&&(count != 0))
                         printf("\n"); 
                    }
                }
             }
           }
           catch = 0;
          }
        }
    pcap_close(handle1);
    return 0;
}
