#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <time.h>
#include <pcap.h>
#include <zlib.h>

#define BUFFER_SIZE 1500
#define MAX_FILENAME_PATH 1000
#define MAX_PARAMETER_LENGTH 100
#define MAX_REMOTE_PARAM  1500
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
#define ETHER_TYPE_BEGIN  0x9990
#define ETHER_TYPE_END	  0x999F
#define ETHER_TYPE_CONTINUE 0x9999
#define MAX_LONG_LIMIT    1000000
#define MINIMUM_PACKET_SIZE  64

typedef union m_counter_n{
  unsigned char counter_bytes[4];
  long int counter;
} m_counter;

typedef struct mandatory_n {
  int filename;
  int input_interface;
  int output_interface;
  int receive_proc;
  int ether_type;
} mandatory;

int main(int argc, char **argv)
{
        pcap_t *handle1;
        char errbuf[PCAP_ERRBUF_SIZE];
        unsigned char sendbuf[BUFFER_SIZE];
        struct ether_header *eh = (struct ether_header *) sendbuf;
        int buf_size;
        int count,offset;
        long long int i;
        int delay_ms;
        char file_name_with_path[MAX_FILENAME_PATH];
        char output_file_name_with_path[MAX_FILENAME_PATH];
        char temp_file_name_with_path[MAX_FILENAME_PATH];
        char perm_remote_param[MAX_REMOTE_PARAM];
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
        char dev_output[MAX_PARAMETER_LENGTH];
        struct bpf_program fp;
        char filter_exp[] = "port 53";/* The IP of our sniffing device */
        bpf_u_int32 mask;               /* The netmask of our sniffing device */
        bpf_u_int32 net;                /* The IP of our sniffing device */
        int ether_header_sz = sizeof(struct ether_header);
        unsigned char *my_order_ptr = (unsigned char *)((unsigned char *)&sendbuf[0] + sizeof(struct ether_header));
        int my_ip_hdr_sz = 2*sizeof(m_counter);
        int predef_mac;
        unsigned long crc;
        unsigned int ether_type;
        int param_index = 1;
        int all_param_done = 0;
        char next_param_input[MAX_PARAMETER_LENGTH];
        long long int file_block_counter = 0ll;
        m_counter block_counter[2];
        int quiet = 0;
        int needed_load = 0, k;
        struct stat fileStat;
        mandatory m_data;
        char *temp_cp;
        int f_remote_param = 0;

        if( argc < 5) {
          printf("incorrect number of parameters. Expected at least 2 mandatory parameters\n");
          printf("ptl3_filetx -tx input_interface -f filename_with_path\n");
          printf(" [-d] [delay_ms] default 100 ms\n");
          printf(" [-b] [buffer_size] default 1500 bytes\n");
          printf(" [-m] [MAC address] default current src address\n");
          printf(" [-e] [ether_type] default 0x9999\n");
          printf(" [-q] [yes] quiet execution\n");
          printf(" [-rx] output_interface\n");
          printf(" [-r] [yes] call receiving program in another terminal\n"); 
          return -1;
        }

        //Default parameters
        delay_ms = 100;
        buf_size = 1500;
        src_mac_flag = 0;
        ether_type = 0x9999;
        quiet = 0;
        m_data.filename = 0;
        m_data.input_interface = 0;
        m_data.output_interface = 1;
        m_data.receive_proc = 1;
        m_data.ether_type = 1;
     

        if(argc > 1)
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
                       m_data.ether_type = 2;
                     }
                     else
                     {       
                         if(strcmp(next_param_input,"-q") == 0)
                         {
                           if(strcmp("yes",argv[param_index]) == 0)
                             quiet = 1;
                         }
                         else
                         {
                             if(strcmp(next_param_input,"-f") == 0)
                             {
                                strcpy((char *)&file_name_with_path[0], argv[param_index]);
                                if(stat(file_name_with_path,&fileStat) < 0)
                                {
                                  printf("File %s does not exists\n", file_name_with_path);
                                  return -3;
                                }
                                m_data.filename = 1;
                             }
                             else {
                                if(strcmp(next_param_input,"-tx") == 0)
                                {
                                   strcpy(dev1,argv[param_index]);

                                   if(strcmp(dev1,ETHER_INTERFACE1)==0)
                                   {
                                      predef_mac = 1;
                                      strcpy(dev_output,ETHER_INTERFACE2);
                                   }
                                   else {
                                      if(strcmp(dev1,ETHER_INTERFACE2)==0)
                                         predef_mac = 2;
                                      else
                                         predef_mac = 0;
                                      strcpy(dev_output,ETHER_INTERFACE1);
                                   }
                                   m_data.input_interface = 1;
    
                                }
                                else
                                {
                                   if(strcmp(next_param_input,"-rx") == 0)
                                   {
                                      strcpy(dev_output,argv[param_index]);
                                      m_data.output_interface = 2;
                                   }
                                   else {
                                      if(strcmp(next_param_input,"-r") == 0)
                                      {
                                        if(strcmp("yes",argv[param_index]) == 0)
                                        {
                                          m_data.receive_proc = 2;
                                        }
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

        printf("Parameters:--------------\n");

        printf("Input interface %s\n", dev1);

        if(predef_mac != 0)
           printf("Output interface %s\n", dev_output);

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

        if((m_data.input_interface * m_data.filename) == 0) {
          printf("Please enter both manadory parameters -f filename -tx interface\n");
          return -3;
        }

        if(m_data.ether_type > 0)
           printf("Ethernet type is %x\n", ether_type);

        srand(time(NULL));   // should only be called once
        random_int = rand();      // returns a pseudo-random integer between 0 and RAND_MAX
        dest_mac_5 = (unsigned char)(random_int&((int)0xFF));
        dest_mac_4 = (unsigned char)((random_int&((int)0xFF00))>>8);
        dest_mac_3 = (unsigned char)((random_int&((int)0xFF0000))>>16);
        
        if(src_mac_flag == 0)
        {            
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
         file_block_counter = 0ll;

         for(i = 0; eof == 0; i++)
         {
            if(fseek(input_file, offset_in_file,SEEK_SET) != 0)
            {
              eof = 1;
            }

            count = fread((&sendbuf[0] + ether_header_sz + my_ip_hdr_sz), 1, buf_size - ether_header_sz - my_ip_hdr_sz - sizeof(long int), input_file);
            if(count <= 0)
            {
               eof = 1;
               printf("End of file reached\n");
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

            if(i == 0)
               ether_type = ETHER_TYPE_BEGIN;
            else
               ether_type = ETHER_TYPE_CONTINUE;

            if(count < buf_size - ether_header_sz - my_ip_hdr_sz - sizeof(long int))
              ether_type = ETHER_TYPE_END;

            eh->ether_type =htons(ether_type);

            block_counter[0].counter = (long int)htonl(file_block_counter/MAX_LONG_LIMIT);
            *(my_order_ptr + 3) = (unsigned char)block_counter[0].counter_bytes[3];
            *(my_order_ptr + 2) = (unsigned char)block_counter[0].counter_bytes[2];
            *(my_order_ptr + 1) = (unsigned char)block_counter[0].counter_bytes[1];
            *my_order_ptr = (unsigned char)block_counter[0].counter_bytes[0];

            block_counter[1].counter = (long int)htonl(file_block_counter%MAX_LONG_LIMIT);
            *(my_order_ptr + 7) = (unsigned char)block_counter[1].counter_bytes[3];
            *(my_order_ptr + 6) = (unsigned char)block_counter[1].counter_bytes[2];
            *(my_order_ptr + 5) = (unsigned char)block_counter[1].counter_bytes[1];
            *(my_order_ptr + 4)= (unsigned char)block_counter[1].counter_bytes[0];
            file_block_counter++;

            if(count > 0)
            {
              needed_load = count + ether_header_sz + my_ip_hdr_sz + sizeof(unsigned long);
              if(needed_load < MINIMUM_PACKET_SIZE)
              {
                offset = count + ether_header_sz + my_ip_hdr_sz;
                for(k = 0; (offset + k) <  MINIMUM_PACKET_SIZE - sizeof(unsigned long); k++)
                {
                   sendbuf[offset + k] = '*';
                   count++;
                }
              }
              else
                needed_load = 0;
            }

            crc = crc32(0, Z_NULL, 0);
            crc = crc32(crc, (const unsigned char *)sendbuf, count +  ether_header_sz);
            memcpy(sendbuf + count + ether_header_sz + my_ip_hdr_sz, &crc, sizeof(unsigned long));

            if(count > 0)
            {
               if(pcap_sendpacket(handle1, (const u_char *)&sendbuf, count + ether_header_sz + my_ip_hdr_sz + sizeof(unsigned long)) < 0)
               {
                 printf("[Error] Packet Send Failed");
                 break;
               }
                 else {
                    common_counter += (long int)(count + ether_header_sz + my_ip_hdr_sz + sizeof(unsigned long));
                }
              }

              nanosleep(&tv,&trem);

              if((quiet == 0)&&(count > 0))
                 printf("Sent %ld bytes, id# %lld \n",common_counter, file_block_counter - 1);
              if(eof == 1)
                break;
           }

      printf("Result-------------------------------------------------\n");
      printf("File name and path      %s\n", file_name_with_path);
      printf("Sent %lld packets  each %d bytes all together %ld bytes\n", i, buf_size, common_counter);

      if(src_mac_flag == 1)
        printf("Source MAC entered %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac_0,
               src_mac_1,src_mac_2,src_mac_3,src_mac_4,src_mac_5);
      else
        printf("Source MAC choosen: %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac_0,
               src_mac_1,src_mac_2,src_mac_3,src_mac_4,src_mac_5);


      printf("Dest MAC generated %02x:%02x:%02x:%02x:%02x:%02x\n", dest_mac_0,
               dest_mac_1,dest_mac_2,dest_mac_3,dest_mac_4,dest_mac_5);


      printf("Sent %lld blocks at all\n", file_block_counter - 1);
     
      if((m_data.receive_proc > 1)&&(m_data.output_interface > 0))
      {
          temp_cp = strtok(file_name_with_path,"\\");
          if(temp_cp != 0)
          {
             strcpy(temp_file_name_with_path, temp_cp);
             f_remote_param = 0;
             while((temp_cp = strtok(0,"\\")) != 0)
             {
                strcat(temp_file_name_with_path,"\\");
                strcat(temp_file_name_with_path,temp_cp);
                f_remote_param = 1;
             }
             if(f_remote_param == 0)
             {
                temp_file_name_with_path[0] = 'r';
                temp_file_name_with_path[1] = 'x';
                strcat(output_file_name_with_path,temp_file_name_with_path);
             }
             else
             {
                 temp_cp = strtok(temp_file_name_with_path,"\\");
                 strcpy(output_file_name_with_path,"\\");
                 while((temp_cp = strtok(0,"\\")) != 0)
                 {
                    if((temp_cp[0] == 't')&&(temp_cp[1] == 'x'))
                       temp_cp[0] = 'r';
                    strcat(output_file_name_with_path,"\\");
                    strcat(output_file_name_with_path,temp_cp); 
                 }
             }
             sprintf(perm_remote_param,"sudo ./%s %s %s -t 30000 -p %lld\n","pqtl3_filerx", dev_output, output_file_name_with_path, file_block_counter - 1);
             printf("%s",perm_remote_param);            
          }
          else {
             m_data.receive_proc = 0; 
             printf("impossible to call remotely receiving procedure\n"); 
          }
      }

      pcap_close(handle1);
      fclose(input_file);
      return 0;
}

