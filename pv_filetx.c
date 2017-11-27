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
#include <zlib.h>

#define BUFFER_SIZE 9600
#define MAX_FILENAME_PATH 1000
#define MAX_PARAMETER_LENGTH 100
#define ETHER_INTERFACE2 "enp131s0"
#define ETHER_INTERFACE1 "p1p1"
#define SRC_MAC_ADDRESS_0_1 0x0     /*p1p1*/
#define SRC_MAC_ADDRESS_1_1 0xE0
#define SRC_MAC_ADDRESS_2_1 0xED
#define SRC_MAC_ADDRESS_3_1 0x54
#define SRC_MAC_ADDRESS_4_1 0x7A
#define SRC_MAC_ADDRESS_5_1 0x78
#define SRC_MAC_ADDRESS_0_2 0x0    /*enp131s0*/
#define SRC_MAC_ADDRESS_1_2 0xE0
#define SRC_MAC_ADDRESS_2_2 0xED
#define SRC_MAC_ADDRESS_3_2 0x54
#define SRC_MAC_ADDRESS_4_2 0x7A
#define SRC_MAC_ADDRESS_5_2 0x79

typedef struct block_size_pair_n {
    unsigned int data;
    unsigned char flag;
} block_size_pair;

typedef struct block_size_n {
   block_size_pair b_all;
   block_size_pair b_start;
   block_size_pair b_stop;
   block_size_pair b_increm;
} block_size;

int main(int argc, char **argv)
{
        pcap_t *handle1;
        char errbuf[PCAP_ERRBUF_SIZE];
        unsigned char sendbuf[BUFFER_SIZE];
        struct ether_header *eh = (struct ether_header *) sendbuf;
        int buf_size;
        int count,i;
        int delay_ms;
        char file_name_with_path[MAX_FILENAME_PATH];
        FILE *input_file;
        long int offset_in_file = 0l;
        int eof = 0;
        long int common_counter = 0l;
        char src_mac_string[MAX_PARAMETER_LENGTH];
        char src_mac_flag = 0; 
        int random_int;
        unsigned char src_mac_0;
        unsigned char src_mac_1;
        unsigned char src_mac_2;
        unsigned char src_mac_3;
        unsigned char src_mac_4;
        unsigned char src_mac_5; 
        unsigned char dest_mac_0;
        unsigned char dest_mac_1;
        unsigned char dest_mac_2;
        unsigned char dest_mac_3;
        unsigned char dest_mac_4;
        unsigned char dest_mac_5;
        struct timespec tv,trem;
        char dev1[MAX_PARAMETER_LENGTH];
        struct bpf_program fp;
        char filter_exp[] = "port 53";/* The IP of our sniffing device */
        bpf_u_int32 mask;               /* The netmask of our sniffing device */
        bpf_u_int32 net;                /* The IP of our sniffing device */
        int ether_header_sz = sizeof(struct ether_header);
        int predef_mac;
        unsigned long crc;
        unsigned int ether_type;
        int param_index = 3;
        int all_param_done = 0;
        char next_param_input[MAX_PARAMETER_LENGTH];
        int buf_start, buf_end, buf_increm;
        block_size  block_dim; 
   
        if( argc < 3) {
          printf("incorrect number of parameters. Expected at least 2 parameters\n");
          printf("filetx interface filename_with_path\n");
          printf(" [-d] [delay_ms] default 100 ms\n");
          printf(" [-b] [buffer_size] default 1500 bytes\n");
          printf( " [ -bs  buffer_start -bi buffer_increment -bc buffer_finish, exclude -b ]\n");
          printf(" [-m] [MAC address] default current src address\n");
          printf(" [-e] [ether_type] default 0x9999\n");
          return -1;
        }
                
        strcpy(dev1,argv[1]);

        if(strcmp(dev1,ETHER_INTERFACE1)==0)
          predef_mac = 1;
        else {
          if(strcmp(dev1,ETHER_INTERFACE2)==0)
            predef_mac = 2;
          else
            predef_mac = 0;
        }


        strcpy((char *)&file_name_with_path[0], argv[2]);

        //Default parameters
        delay_ms = 100;
        buf_size = 1500;
        block_dim.b_all.data = buf_size;
        block_dim.b_all.flag = 0;
        block_dim.b_start.data = 0;
        block_dim.b_start.flag = 0;
        block_dim.b_stop.data = 0;
        block_dim.b_stop.flag = 0;
        block_dim.b_increm.data = 0;
        block_dim.b_increm.flag = 0;
        src_mac_flag = 0;
        ether_type = 0x9999;

      


        if(argc > 3)
        {
          while(all_param_done == 0)
          {
             strcpy((char *)&next_param_input[0],argv[param_index]);
             if(next_param_input[0] != '-')
             {
               printf("Incorrect parameter switch...%s\n", next_param_input);
               return -2;
             }
             param_index += 1;
             if(argc < param_index + 1)
             {
               printf("Not enough parameters...%d\n", argc - 1);
               return -2;
             }
             if(strcmp(next_param_input,"-d") == 0)
             {
                    delay_ms = (int)strtol(argv[param_index],0,10);      
             }
             else
             {
               if(strcmp(next_param_input,"-b") == 0)
               {
                    buf_size = (int)strtol(argv[param_index],0,10);
                    block_dim.b_all.data = buf_size;
                    block_dim.b_all.flag = 1;
               }
               else 
               {
                  if(strcmp(next_param_input,"-m") == 0)
                  {
                    strcpy((char *)&src_mac_string[0], argv[param_index]);
                    src_mac_flag = 1;
                  }
                  else 
                  {
                     if(strcmp(next_param_input,"-e") == 0) 
                     { 
                       ether_type = (unsigned int)strtol(argv[param_index],0,16);  
                     }   
                     else
                     {
                       
                        if(strcmp(next_param_input, "-bs") == 0)
                        {
                           block_dim.b_start.data = (unsigned int)strtol(argv[param_index],0,10);
                           block_dim.b_start.flag = 1;
                        }
                        else {
                           if(strcmp(next_param_input,"-bi") == 0)
                           {
                              block_dim.b_increm.data = (unsigned int)strtol(argv[param_index],0,10);
                              block_dim.b_increm.flag = 1;
                           }
                           else {
                              if(strcmp(next_param_input,"-bc") == 0)
                              {
                                 block_dim.b_stop.data = (unsigned int)strtol(argv[param_index],0,10);
                                 block_dim.b_stop.flag = 1;
                              }
                              else {
                                 printf("Incorrect symbol parameter switch...%s\n",next_param_input);
                                 return -2;
                              }
                           }
                         }
                       }
                     }
                  }
             }
             if(argc < param_index + 2)
             {
                all_param_done = 1;
                break;
             }
             else
                param_index += 1;
          }
        } 

        if(((block_dim.b_start.flag == 1)||(block_dim.b_stop.flag == 1)||(block_dim.b_increm.flag == 1))&&(block_dim.b_all.flag == 1))
        {
           printf("Contraversy buffer size parameters -b or -bs, -bi, -bc\n");
           return -2;
        }

        if(((block_dim.b_start.flag * block_dim.b_stop.flag * block_dim.b_increm.flag) == 0)&&((block_dim.b_start.flag == 1)||(block_dim.b_stop.flag == 1)||(block_dim.b_increm.flag == 1)))
        {
           printf("Please define full set of parameters -bs, -bi, -bc\n");
           return -2;
        }

        printf("Parameters:--------------\n");

        printf("Interface %s\n", dev1);

        printf("File name and path      %s\n", file_name_with_path);
        printf("Delay ms between buffers %d\n", delay_ms);
        printf("Size of the buffer      %d\n", buf_size);

        if (buf_size> BUFFER_SIZE)
        {
           printf("Sending buffer too big(%d MAX)\n", BUFFER_SIZE);
           return -2;
        }

        if((predef_mac == 0)&&(argc < 6)) {
           printf("Please assign MAC address or choose known interface\n");
           return -3;
        }

        if(argc >= 7)
           printf("Ethernet type is %x\n", ether_type);

        srand(time(NULL));   // should only be called once
        random_int = rand();      // returns a pseudo-random integer between 0 and RAND_MAX
        dest_mac_5 = (unsigned char)(random_int&((int)0xFF));
        dest_mac_4 = (unsigned char)((random_int&((int)0xFF00))>>8);
        dest_mac_3 = (unsigned char)((random_int&((int)0xFF0000))>>16);
        //dest_mac_2 = (unsigned char)((random_int&((int)0xFF000000))>>24);

        //random_int = rand();

        //dest_mac_1 = (unsigned char)(random_int&((int)0xFF));
        //dest_mac_0 = (unsigned char)((random_int&((int)0xFF00))>>8);

        if(src_mac_flag == 0)
        {

            //random_int = rand();
            //src_mac_0 = (unsigned char)(random_int&((int)0xFF));
            //src_mac_1 = (unsigned char)((random_int&((int)0xFF00))>>8);
            //src_mac_2 = (unsigned char)((random_int&((int)0xFF0000))>>16);
            //src_mac_3 = (unsigned char)((random_int&((int)0xFF000000))>>24);
      
            //random_int = rand();
            //src_mac_4 = (unsigned char)(random_int&((int)0xFF));
            //src_mac_5 = (unsigned char)((random_int&((int)0xFF00))>>8);

            //printf("Source MAC generated %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac_0,
            //   src_mac_1,src_mac_2,src_mac_3,src_mac_4,src_mac_5);
            if(predef_mac == 1)
            {
               src_mac_0 = SRC_MAC_ADDRESS_0_1;
               src_mac_1 = SRC_MAC_ADDRESS_1_1;
               src_mac_2 = SRC_MAC_ADDRESS_2_1;
               src_mac_3 = SRC_MAC_ADDRESS_3_1;
               src_mac_4 = SRC_MAC_ADDRESS_4_1;
               src_mac_5 = SRC_MAC_ADDRESS_5_1;
            }
            else {
               src_mac_0 = SRC_MAC_ADDRESS_0_2;
               src_mac_1 = SRC_MAC_ADDRESS_1_2;
               src_mac_2 = SRC_MAC_ADDRESS_2_2;
               src_mac_3 = SRC_MAC_ADDRESS_3_2;
               src_mac_4 = SRC_MAC_ADDRESS_4_2;
               src_mac_5 = SRC_MAC_ADDRESS_5_2;

            }
        }
        else {
            src_mac_0 = (unsigned char)strtol(strtok(src_mac_string,":"),0,16);
            src_mac_1 = (unsigned char)strtol(strtok(0,":"),0,16);
            src_mac_2 = (unsigned char)strtol(strtok(0,":"),0,16);
            src_mac_3 = (unsigned char)strtol(strtok(0,":"),0,16);
            src_mac_4 = (unsigned char)strtol(strtok(0,":"),0,16);
            src_mac_5 = (unsigned char)strtol(strtok(0,":"),0,16);
        }
  
        dest_mac_0 =  src_mac_0;
        dest_mac_1 =  src_mac_1;
        dest_mac_2 =  src_mac_2;

        printf("Source MAC choosen %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac_0,
               src_mac_1,src_mac_2,src_mac_3,src_mac_4,src_mac_5);

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

        
        if (pcap_lookupnet(dev1, &net, &mask, errbuf) == -1) {
             fprintf(stderr, "Can't get netmask for device %s\n", dev1);
             net = 0;
             mask = 0;
             return -4;
         }
         
         handle1 = pcap_open_live(dev1, BUFFER_SIZE, 1, 200, errbuf);
         if (handle1 == 0) {
             fprintf(stderr, "Couldn't open device %s: %s\n", dev1, errbuf);
             return -5;
         }

          if (pcap_compile(handle1, &fp, filter_exp, 0, net) == -1) {
             fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle1));
             return -6;
         }

        
         count = 0;
         common_counter = 0l;
         offset_in_file = 0l;
  
         if(block_dim.b_all.flag == 1)
         {
           buf_size = block_dim.b_all.data;
         }
         else
         {
           if(block_dim.b_start.flag == 1)
           {
              buf_start = block_dim.b_start.data;
              buf_end = block_dim.b_stop.data;
              buf_increm = block_dim.b_increm.data;
           }
         }         

         if(block_dim.b_start.flag == 1)
         {
           buf_size = buf_start;
           if(buf_increm < 0)
             buf_size = buf_end;
         }

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

             if(block_dim.b_start.flag == 1)
             {
               buf_size += buf_increm;
               if((buf_size > buf_end)&&(buf_increm > 0))
                  buf_size = buf_start;
               if((buf_size <= (ether_header_sz + sizeof(unsigned long)))&&(buf_increm < 0))
                  buf_size = buf_end;
            }

            offset_in_file += (unsigned long)count;

            memset(sendbuf, 0,sizeof(struct ether_header));

            eh->ether_shost[0] = src_mac_0;
            eh->ether_shost[1] = src_mac_1;
            eh->ether_shost[2] = src_mac_2;
            eh->ether_shost[3] = src_mac_3;
            eh->ether_shost[4] = src_mac_4;
            eh->ether_shost[5] = src_mac_5;
            eh->ether_dhost[0] = dest_mac_0;
            eh->ether_dhost[1] = dest_mac_1;
            eh->ether_dhost[2] = dest_mac_2;
            eh->ether_dhost[3] = dest_mac_3;
            eh->ether_dhost[4] = dest_mac_4;
            eh->ether_dhost[5] = dest_mac_5;

            eh->ether_type =htons(ether_type); 
      
            crc = crc32(0, Z_NULL, 0);
	    crc = crc32(crc, (const unsigned char *)sendbuf, count +  ether_header_sz);
	    memcpy(sendbuf + count + ether_header_sz, &crc, sizeof(unsigned long));

            if(count > 0)
            {
               if(pcap_sendpacket(handle1, (const u_char *)&sendbuf, count + ether_header_sz + sizeof(unsigned long)) < 0)
               {
                 printf("[Error] Packet Send Failed");
                 break;
               }
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

      if(src_mac_flag == 1)
        printf("Source MAC entered %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac_0,
               src_mac_1,src_mac_2,src_mac_3,src_mac_4,src_mac_5);
      else
        printf("Source MAC choosen: %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac_0,
               src_mac_1,src_mac_2,src_mac_3,src_mac_4,src_mac_5);

      
      printf("Dest MAC generated %02x:%02x:%02x:%02x:%02x:%02x\n", dest_mac_0,
               dest_mac_1,dest_mac_2,dest_mac_3,dest_mac_4,dest_mac_5);


      pcap_close(handle1);
      fclose(input_file);
      return 0;
}

