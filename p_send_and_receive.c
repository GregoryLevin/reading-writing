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

#define BUFFER_SIZE 1500 
#define ETHER_TYPE	0x0800
#define ETHER_INTERFACE1 "enp131s0"
#define ETHER_INTERFACE2 "p1p1"

#define MAC_ADDRESS_0_1 0x00;
#define MAC_ADDRESS_1_1 0xe0;
#define MAC_ADDRESS_2_1 0xED;
#define MAC_ADDRESS_3_1 0x54;
#define MAC_ADDRESS_4_1 0x7A;
#define MAC_ADDRESS_5_1 0x79;
#define MAC_ADDRESS_0_2 0x00;
#define MAC_ADDRESS_1_2 0xe0;
#define MAC_ADDRESS_2_2 0xED;
#define MAC_ADDRESS_3_2 0x54;
#define MAC_ADDRESS_4_2 0x7A;
#define MAC_ADDRESS_5_2 0x78;



int main(int argc, char **argv)
{
        pcap_t *handle1;
        pcap_t *handle2;
        char errbuf[PCAP_ERRBUF_SIZE];
        uint8_t sendbuf[BUFFER_SIZE];
        int buf_size;
        int count,i;
        char pattern;
        int delay_ms;
        int direction = 0;
        int mac_enable = 0;
        char dev1[100];
        char dev2[100];
        struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[] = "port 53";/* The IP of our sniffing device */
        bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */
        bpf_u_int32 mask2;               /* The netmask of our sniffing device */
        bpf_u_int32 net2;                /* The IP of our sniffing device */
        char filename[1000];
        FILE *fptr;
        struct pcap_pkthdr header;	/* The header that pcap gives us */
        const u_char *packet;		/* The actual packet */
        struct ether_header *eh = (struct ether_header *) sendbuf;
        struct timespec tim, tim_rem;

        if( argc != 8) {
          printf("incorrect number of parameters. Expected 7 parameters\n");
          printf("p_send_and_receive file_name_and_path number_of_repeats buffer_size pattern delay_ms direction=1 MAC=1\n");
          return -1;
        }
   
        strcpy(filename, argv[1]);
        count = (int)strtol(argv[2],0,10);
        buf_size = (int)strtol(argv[3],0,10);
        pattern = ((strtol(argv[4],0,16))&0x000000FF);
        delay_ms = (int)strtol(argv[5],0,10);
        direction = (int)strtol(argv[6],0,10);
        mac_enable = (int)strtol(argv[7],0,10);

        printf("Parameters:--------------\n");
        printf("Number of repeats        %d\n", count);
        printf("Size of the buffer       %d\n", buf_size);
        printf("Pattern of data          0x%x\n",(0xFF&pattern));
        printf("Delay ms between S and R %d\n", delay_ms);
        

        tim.tv_sec = 0;
        tim.tv_nsec = (long int)delay_ms*1000;

        if(mac_enable == 1)
          printf("MAC addressing enabled in packages\n");

        switch(direction)
        {
           case 1:
              printf("Sending from interf %s to interf %s\n",ETHER_INTERFACE1,ETHER_INTERFACE2);
              strcpy((char *)dev1, ETHER_INTERFACE1);
              strcpy((char *)dev2, ETHER_INTERFACE2);
              break;
           default:
              printf("Sending from interf %s to interf %s\n",ETHER_INTERFACE2,ETHER_INTERFACE1);
              strcpy((char *)dev1, ETHER_INTERFACE2);
              strcpy((char *)dev2, ETHER_INTERFACE1);
              break;
        }

        if (buf_size > BUFFER_SIZE)
        {
           printf("Sending buffer too big(%d MAX)\n", BUFFER_SIZE);
           return -2;
        }

        memset(&sendbuf,pattern,BUFFER_SIZE);


        if(mac_enable == 1)
        {
           //Construct the ethernet header
           memset(sendbuf, 0,sizeof(struct ether_header));
           /* Ethernet header */
          if(direction == 1)
          {
            eh->ether_shost[0] = MAC_ADDRESS_0_1;
            eh->ether_shost[1] = MAC_ADDRESS_1_1;
            eh->ether_shost[2] = MAC_ADDRESS_2_1;
            eh->ether_shost[3] = MAC_ADDRESS_3_1;
            eh->ether_shost[4] = MAC_ADDRESS_4_1;
            eh->ether_shost[5] = MAC_ADDRESS_5_1;
            eh->ether_dhost[0] = MAC_ADDRESS_0_2;
            eh->ether_dhost[1] = MAC_ADDRESS_1_2;
            eh->ether_dhost[2] = MAC_ADDRESS_2_2;
            eh->ether_dhost[3] = MAC_ADDRESS_3_2;
            eh->ether_dhost[4] = MAC_ADDRESS_4_2;
            eh->ether_dhost[5] = MAC_ADDRESS_5_2;
         }
         else
         {
            eh->ether_shost[0] = MAC_ADDRESS_0_2;
            eh->ether_shost[1] = MAC_ADDRESS_1_2;
            eh->ether_shost[2] = MAC_ADDRESS_2_2;
            eh->ether_shost[3] = MAC_ADDRESS_3_2;
            eh->ether_shost[4] = MAC_ADDRESS_4_2;
            eh->ether_shost[5] = MAC_ADDRESS_5_2;
            eh->ether_dhost[0] = MAC_ADDRESS_0_1;
            eh->ether_dhost[1] = MAC_ADDRESS_1_1;
            eh->ether_dhost[2] = MAC_ADDRESS_2_1;
            eh->ether_dhost[3] = MAC_ADDRESS_3_1;
            eh->ether_dhost[4] = MAC_ADDRESS_4_1;
            eh->ether_dhost[5] = MAC_ADDRESS_5_1;
         }
       }


       if (pcap_lookupnet(dev1, &net, &mask, errbuf) == -1) {
	     fprintf(stderr, "Can't get netmask for device %s\n", dev1);
	     net = 0;
	     mask = 0;
             return -3;
	 }

        if (pcap_lookupnet(dev2, &net2, &mask2, errbuf) == -1) {
             fprintf(stderr, "Can't get netmask for device %s\n", dev2);
             net = 0;
             mask = 0;
             return -3;
        }


       handle1 = pcap_open_live(dev1, 200, 1, count, errbuf);

       if (handle1 == 0) {
          fprintf(stderr, "Couldn't open device %s: %s\n", dev1, errbuf);
          return -4;
       }

       handle2 = pcap_open_live(dev2, 200, 1, count, errbuf);

       if (handle2 == 0) {
          fprintf(stderr, "Couldn't open device %s: %s\n", dev2, errbuf);
          return -4;
       }


       if (pcap_compile(handle1, &fp, filter_exp, 0, net) == -1) {
	  fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle1));
	  return -5;
	 }

       if (pcap_compile(handle2, &fp, filter_exp, 0, net) == -1) {
          fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle2));
          return -5;
         }

       fptr = fopen(filename,"a");
       if(fptr <= 0)
       {
         fprintf(stderr, "Couldn't open file %s\n", filename);
         return -6;
       }
       for(i = 0; i < count; i++)
       {
               if(pcap_sendpacket(handle1, (const u_char *)&sendbuf,buf_size) < 0)
               {
                 printf("[Error] Packet Send Failed");
                 break;
               }
               else
                  printf("Sent package %d bytes...\n", buf_size);

               nanosleep(&tim, &tim_rem);
               //usleep(delay_ms);

               packet = pcap_next(handle2, &header);
               printf("Jacked a packet with length of [%d]\n", header.len);
               if(header.len > 0){
                 fwrite((char *)packet, 1 , header.len, fptr );
                 printf("Received package %d bytes...\n", header.len);
               }
       }

       if(direction == 1)
          printf("The %d packets have been sent from %s \n", i, ETHER_INTERFACE1);
       else
           printf("The %d packets have been sent from %s \n", i, ETHER_INTERFACE2);
       pcap_close(handle1);
       pcap_close(handle2);
       fclose(fptr);
       return 0;                                                                
}
