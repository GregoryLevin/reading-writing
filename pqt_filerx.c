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

typedef struct sorting_index_n {
  short int order_index;
  short int frame_index;
} sorting_index;


#define BUFFER_SIZE 9600
#define ETHER_TYPE      0x0800
#define ETHER_INTERFACE1 "enp131s0"
#define ETHER_INTERFACE2 "p1p1"
#define MAX_PACKETS_CATCH 200
#define MAX_PACKETS_INDEX 1000
#define MAX_FILENAME_PATH 1000

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
        char file_name_with_path[MAX_FILENAME_PATH];
        FILE *output_file;
        int order_block, catch_block;
        sorting_index sorting_table[MAX_PACKETS_CATCH];
        sorting_index sorting_elem;
           

        if( argc != 3) {
          printf("incorrect number of parameters. Expected 2 parameters\n");
          printf("filerx interface output_filename\n");
          return -1;
        }
   
        strcpy( interf, argv[1]);
        
        strcpy(file_name_with_path,argv[2]);

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

       for(order_block = 0; order_block < MAX_PACKETS_CATCH; order_block++)
       {
         sorting_table[order_block].order_index = MAX_PACKETS_INDEX;
       }

       output_file = fopen(file_name_with_path,"a");
       if(output_file == 0)
       {
           return -5;
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
             //Initially read block indexes
             order_block = 0;
             for(k = 0; k < catch; k++)
             {
                sorting_table[order_block].order_index = recvbuf[header_offset][k];
                sorting_table[order_block++].frame_index = k;

             }
             //Sorting table
             catch_block = 0;
             for(k = 0; k < catch; k++)
             {
                sorting_elem = sorting_table[catch_block];
                catch_block++;
                for( n = catch_block; n < catch; n++)
                {
                    if(sorting_elem.order_index > sorting_table[n].order_index)
                    {
                        sorting_table[catch_block - 1] = sorting_table[n];
                        sorting_table[n] = sorting_elem;
                        sorting_elem = sorting_table[catch_block - 1];
                    }
                }
             }

             for(n = 0; n < catch; n++)
             {  
               if(buf_length[sorting_table[n].frame_index] >= 0)
               {
                    printf("Received block of data\n");
                    printf("Source MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                    recvbuf[6][sorting_table[n].frame_index],
                    recvbuf[7][sorting_table[n].frame_index],
                    recvbuf[8][sorting_table[n].frame_index],
                    recvbuf[9][sorting_table[n].frame_index],
                    recvbuf[10][sorting_table[n].frame_index],
                    recvbuf[11][sorting_table[n].frame_index]);
                    printf("Destination MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                    recvbuf[0][sorting_table[n].frame_index],
                    recvbuf[1][sorting_table[n].frame_index],
                    recvbuf[2][sorting_table[n].frame_index],
                    recvbuf[3][sorting_table[n].frame_index],
                    recvbuf[4][sorting_table[n].frame_index],
                    recvbuf[5][sorting_table[n].frame_index]);
                    printf("Current block %d\n",sorting_table[n].order_index);
                    buf_length[sorting_table[n].frame_index] -= header_offset +  sizeof(unsigned long) + 1;
                    if(buf_length[sorting_table[n].frame_index] > 0)
                    {
                     for(count = 0; count < buf_length[sorting_table[n].frame_index]; count++)
                     {
                     
                        fprintf(output_file,"%c",recvbuf[count + header_offset + 1][sorting_table[n].frame_index]);
                     }
                  }
                }//if
             }//for
             catch_block = 0;
             for(n = 0; n < catch; n++)
             {
                if( sorting_table[n].order_index >  catch_block)
                {
                  fprintf(output_file,"Missed block %d of file %s\n", catch_block, file_name_with_path);
                  printf("Missed block %d of file %s\n", order_block, file_name_with_path);
                  catch_block = sorting_table[n].order_index;
                }
                sorting_table[n].order_index = MAX_PACKETS_INDEX;
                catch_block++;
             }
           catch = 0;
          }//else
        }//for(i...
    fclose(output_file);
    pcap_close(handle1);
    return 0;
}
