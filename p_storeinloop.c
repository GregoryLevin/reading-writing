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
#define MAX_FILENAME_PATH 1000

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
        char infilename[MAX_FILENAME_PATH];
        char outfilename[MAX_FILENAME_PATH];
        FILE *fptr_in;
        FILE *fptr_out;
        struct pcap_pkthdr header;	/* The header that pcap gives us */
        const u_char *packet;		/* The actual packet */
        long int offset_in_file = 0l;
        int eof = 0;
        long int common_counter = 0l;
        long int common_counter_r = 0l;
        int trigger = 0;
        struct ether_header *eh = (struct ether_header *) sendbuf;
        struct timespec tim, tim_rem;


        if( argc != 7) {
          printf("incorrect number of parameters. Expected 6 parameters\n");
          printf("p_storeinloop input_file_name_and_path output_file_name_and_path buffer_size delay_ms direction=1 MAC=1\n");
          return -1;
        }
   
        strcpy(infilename, argv[1]);
        strcpy(outfilename, argv[2]);
        buf_size = (int)strtol(argv[3],0,10);
        delay_ms = (int)strtol(argv[4],0,10);
        direction = (int)strtol(argv[5],0,10);
        mac_enable = (int)strtol(argv[6],0,10);

        printf("Parameters:--------------\n");
        printf("Size of the buffer       %d\n", buf_size);
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

       if (pcap_lookupnet(dev1, &net, &mask, errbuf) == -1) {
	     fprintf(stderr, "Can't get netmask for device %s\n", dev1);
	     net = 0;
	     mask = 0;
             return -3;
	 }

        if (pcap_lookupnet(dev2, &net2, &mask2, errbuf) == -1) {
             fprintf(stderr, "Can't get netmask for device %s\n", dev2);
             net2 = 0;
             mask2 = 0;
             return -3;
        }


       handle1 = pcap_open_live(dev1, 200, 1, 500, errbuf);

       if (handle1 == 0) {
          fprintf(stderr, "Couldn't open device %s: %s\n", dev1, errbuf);
          return -4;
       }

       handle2 = pcap_open_live(dev2, 200, 1, 500, errbuf);

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

       fptr_in = fopen(infilename,"r");
       if(fptr_in <= 0)
       {
         fprintf(stderr, "Couldn't open file for reading %s\n", infilename);
         return -6;
       }

       fptr_out = fopen(outfilename,"a");
       if(fptr_out <= 0)
       {
         fprintf(stderr, "Couldn't open file for writing %s\n", outfilename);
         return -6;
       }

       count = 0;

       common_counter = 0l;

       common_counter_r = 0l;

       trigger = 1;

       offset_in_file = 0l;

       eof = 0;

       for(i = 0; trigger < 3; i++)
       {
                
                if((trigger < 2)&&(eof == 0))
                {
                   if(fseek(fptr_in, offset_in_file,SEEK_SET) != 0)
                   {
                        eof = 1;
                        trigger = 2;
                        break;
                   }

                   count = fread(&sendbuf, 1, buf_size, fptr_in);
                   if(count <= 0)
                   {
                        eof = 1;
                        trigger = 2;
                        printf("End of file %s reached\n", infilename);
                   }

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
                 

                   offset_in_file += (long int)count;
           

                   if(pcap_sendpacket(handle1, (const u_char *)&sendbuf,buf_size) < 0)
                   {
                      printf("[Error] Packet Send Failed");
                   }
                   else {
                         common_counter += (long int)buf_size;
                         printf("Sent %d bytes...\n", buf_size); 
                       }
               }
              
               nanosleep(&tim, &tim_rem);
               //usleep(delay_ms);

               packet = pcap_next(handle2, &header);
               printf("Jacked a packet with length of [%d]\n", header.len);
               if((header.len == 0)&&(trigger == 2))
                   trigger = 3;
               if(header.len > 0)
               { 
                  fwrite((char *)packet, 1 , header.len, fptr_out );
                  common_counter_r += (long int)header.len;
               }
       }

       if(direction == 1)
          printf("The %d packets have been sent from %s \n", i, ETHER_INTERFACE1);
       else
           printf("The %d packets have been sent from %s \n", i, ETHER_INTERFACE2);

       printf("Send %ld bytes\n",common_counter);
       printf("Received %ld bytes\n",common_counter_r);

       pcap_close(handle1);
       pcap_close(handle2);
       fclose(fptr_in);
       fclose(fptr_out);
       return 0;                                                                
}
