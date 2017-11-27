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

int main(int argc, char **argv)
{
        pcap_t *handle1;
        char errbuf[PCAP_ERRBUF_SIZE];
        unsigned char recvbuf[BUFFER_SIZE];
        struct ether_header *eh;
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

       for(i = 0l;;) {
           packet = pcap_next(handle1, &header);

           num_bytes = header.len;

           if(header.len > 0)
           {
              header.len = 0;     
              printf("\nlistener: got packet #%ld %d bytes\n", ++i,num_bytes);

           if(num_bytes > BUFFER_SIZE)
             num_bytes = BUFFER_SIZE;

           if(num_bytes >= header_offset)
           {
               eh = (struct ether_header *)packet; 
               printf("Source MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
               eh->ether_shost[0],
               eh->ether_shost[1],
               eh->ether_shost[2],
               eh->ether_shost[3],
               eh->ether_shost[4],
               eh->ether_shost[5]);
               printf("Destination MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
               eh->ether_dhost[0],
               eh->ether_dhost[1],
               eh->ether_dhost[2],
               eh->ether_dhost[3],
               eh->ether_dhost[4],
               eh->ether_dhost[5]);
               printf("Data-----------------------------------------------\n");
               num_bytes -= header_offset + sizeof(unsigned long);
               if(num_bytes > 0)
               {

                 memcpy((void *)&recvbuf[0],(void *)(packet + header_offset),num_bytes);
                 for(count = 0; count < num_bytes; count++)
                 {
                   if((recvbuf[count]< 32)||(recvbuf[count] > 126))
                       recvbuf[count] = '*';
                 }
                 for(count = 0; count < num_bytes; count++)
                 {
                   printf("%c",recvbuf[count]);
                   if((count%50 == 0)&&(count != 0))
                      printf("\n"); 
                 }
              }
             }
           }
        }
    pcap_close(handle1);
    return 0;
}
