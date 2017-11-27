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

#define MAX_PARAMETER_LENGTH 100
#define BUFFER_SIZE 1500
#define ETHER_TYPE      0x0800
#define ETHER_INTERFACE1 "enp131s0"
#define ETHER_INTERFACE2 "p1p1"
#define MAX_PACKETS_CATCH 50
#define MAX_PACKETS_LOW_MARGIN 10
#define MAX_PACKETS_HIGH_MARGIN 40
#define MAX_PACKETS_INDEX 0x6FFFFFFF
#define MAX_FILENAME_PATH 1000
#define TEMP_FILE_NAME  "temp_file.txt"
#define PROT_FILE_NAME  "protocol.txt"
#define EXTRA_WAIT_DELAY  1
#define EXTRA_WAIT_ATTEMPTS 30
#define MIN_PACKET_SIZE  64

typedef struct temp_buffer_n {
  unsigned int buf_length;
  long long int packet_index;
  unsigned char tempbuf[BUFFER_SIZE];
} temp_buffer;


typedef struct sorting_index_n {
  long long int order_index;
  long int frame_index;
  unsigned int buf_length;
  long long int packet_index;
} sorting_index;


int main(int argc, char **argv)
{
        pcap_t *handle1;
        char errbuf[PCAP_ERRBUF_SIZE];
        temp_buffer temp_buf;
        unsigned char recvbuf[BUFFER_SIZE][MAX_PACKETS_CATCH];
        //long long int packet_number;
        long long int i;
        int num_bytes,count;
        int header_offset = sizeof(struct ether_header);
        char dev1[100];
        char interf[100];
        char system_string[100];
        struct bpf_program fp;          /* The compiled filter expression */
        char filter_exp[] = "port 53";/* The IP of our sniffing device */
        bpf_u_int32 mask;               /* The netmask of our sniffing device */
        bpf_u_int32 net;                /* The IP of our sniffing device */
        struct pcap_pkthdr header;      /* The header that pcap gives us */
        const u_char *packet;           /* The actual packet */
        unsigned long int k,n;
        char file_name_with_path[MAX_FILENAME_PATH];
        FILE *output_file;
        long int order_block, catch_block;
        long long int current_catch,already_wrote_catch;
        sorting_index sorting_table[MAX_PACKETS_CATCH];
        sorting_index sorting_elem;
        long int ordering_counter;
        int all_bufs_processed,current_buf,set_blocks_read,current_buf_last; 
        int my_counter_sz = 2*sizeof(long int);    
        FILE *tmp_file;
        FILE *prot_file;
        unsigned long int tmp_file_offset;
        int just_receiving = 0;
        int just_processing = 0;
        int one_time_processing = 0;
        struct timespec tv,trem;
        int wait_counter = 0;
        int receiving_done = 0;
        int param_index = 3;
        int all_param_done = 0;
        char next_param_input[MAX_PARAMETER_LENGTH];
        int timeout_ms;
        int max_num_packets_received = 0;
        int quiet = 0;
        int recover = 1;
        int num_set = 0;
        int padding = 0;

        tv.tv_sec = (time_t)0;
        tv.tv_nsec = (long)(EXTRA_WAIT_DELAY)*1000l;

        if( argc < 3) {
          printf("incorrect number of parameters. Expected 2 mandatory parameters\n");
          printf("pqtl3_filerx interface output_filename [-t timeout] [-q yes] [-p count] [-r no]\n");
          return -1;
        }
   
        strcpy( interf, argv[1]);
        
        strcpy(file_name_with_path,argv[2]);

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
             if(strcmp(next_param_input,"-t") == 0)
             {
                timeout_ms = (int)strtol(argv[param_index],0,10);
             }
             else {
                if(strcmp(next_param_input,"-p") == 0)
                {
                   max_num_packets_received = (int)strtol(argv[param_index],0,10);
                   num_set = 1;
                }
                else {
                  if(strcmp(next_param_input,"-q") == 0)
                  {
                     if(strcmp("yes",argv[param_index]) == 0)
                       quiet = 1;
                  }
                  else {
                    if(strcmp(next_param_input,"-r") == 0)
                    {
                       if(strcmp("no",argv[param_index]) == 0)
                          recover = 0;
                    }
                    else {
                       printf("Incorrect symbol parameter switch...%s\n",next_param_input);
                       return -2;
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
       sprintf(system_string,"rm -f %s", TEMP_FILE_NAME);
       system(system_string);

       sprintf(system_string,"rm -f %s", PROT_FILE_NAME);
       system(system_string);

       prot_file = fopen(PROT_FILE_NAME,"a");
       if(prot_file == 0)
       {
           printf("Cannot open protocol file %s\n",PROT_FILE_NAME);
           return -5;
       }

       tmp_file = fopen(TEMP_FILE_NAME,"a+r");
       if(tmp_file == 0)
       {
           printf("Cannot open temp file %s\n",TEMP_FILE_NAME);
           return -5;
       }

       output_file = fopen(file_name_with_path,"a");
       if(output_file == 0)
       {
           printf("Cannot open output file %s\n", file_name_with_path);
           return -5;
       }

       current_catch = 0ll;
       already_wrote_catch = 0ll;
       just_receiving = 1;
       wait_counter = 0;
       receiving_done = 0;

       if(timeout_ms > 0)
         wait_counter = timeout_ms;
       else
         wait_counter = EXTRA_WAIT_ATTEMPTS;

       for(i = 0l;;) {
         while(just_receiving == 1) {
           packet = pcap_next(handle1, &header);

           num_bytes = header.len;

           if(header.len > 0)
           {
              header.len = 0;
              if(quiet == 0)     
                 printf("\nlistener: got packet #%lld %d bytes\n", ++i,num_bytes);
              fprintf(prot_file,"\nlistener: got packet #%lld %d bytes\n", i,num_bytes);
              if(num_bytes > BUFFER_SIZE)
                num_bytes = BUFFER_SIZE;
              for(n = 0; n < num_bytes;n++)
                 temp_buf.tempbuf[n] = *(packet + n);
              for(n = num_bytes; n < BUFFER_SIZE;n++)
                 temp_buf.tempbuf[n] = '0';
              temp_buf.buf_length = num_bytes;
              temp_buf.packet_index = i;
              fwrite((void *)&temp_buf, 1, sizeof(temp_buf), tmp_file);
              one_time_processing = 1;
              receiving_done++; 
              if(max_num_packets_received > 0)
                 max_num_packets_received--;      
           }
           else {
             just_receiving = 0;
             just_processing = 0;
           }
        }//while receive loop

        if((max_num_packets_received > 0)&&(num_set == 1))
        { //Count set from user interface, not all packets received
          if(wait_counter > 0)//Timeout set
          {
             wait_counter--;
             nanosleep(&tv,&trem);
             just_receiving = 1;
          }
          else //Timeout over
             just_processing = 1;
        }
        else
        {
           if((max_num_packets_received <= 0)&&(num_set == 1))
           { //All packets received
             just_processing = 1;
           }
           else
           { //Just timeout set and it is not over
             if(wait_counter > 0)
             {
               wait_counter--;
               nanosleep(&tv,&trem);
               just_receiving = 1;
             }
             else //Just timeout set and it is over
               just_processing = 1;
           }
        }//end checking waiting/no waiting conditions

   
        tmp_file_offset = 0l;
        current_buf_last = 0;
        while((one_time_processing == 1)&&(all_bufs_processed == 0)&&(just_processing == 1))
        {
          just_processing = 0;
          fflush(tmp_file);
          current_buf = 0;
          set_blocks_read = 0;
          while(set_blocks_read == 0)
          {
            fseek(tmp_file, SEEK_SET, tmp_file_offset);
            count = fread((void *)&temp_buf, 1, sizeof(temp_buf),tmp_file);

            if(count < sizeof(temp_buf))
            {
               current_buf_last = 1;
               one_time_processing = 0;
            }

            for(n = 0; n < temp_buf.buf_length; n++)
            {
               recvbuf[n][current_buf] = temp_buf.tempbuf[n];//copy buffer
            }

    
            sorting_table[current_buf].buf_length = temp_buf.buf_length;
            sorting_table[current_buf].packet_index = temp_buf.packet_index; 
                      
   
            if((current_buf >= MAX_PACKETS_CATCH - 1)||(current_buf_last == 1))
              set_blocks_read = 1;
            else {
              tmp_file_offset += sizeof(temp_buf); //read one buffer more
            }
            if(current_buf_last == 0)
              current_buf++;
            if((current_buf_last == 1)&&(count > 0))
              current_buf++;
          } //while(set_block_read... 
                   

          tmp_file_offset -= MAX_PACKETS_LOW_MARGIN * sizeof(temp_buf); //Shifting reading windows back for proper sorting

          if(current_buf_last == 1) //Check if the whole file processed
            all_bufs_processed = 1;

          //Initially read block indexes
          order_block = 0;

          
          
          for(k = 0; k < current_buf; k++)
          {
             /*This long int counter contain long long int counter / 1000000*/
             ordering_counter = 0l;
             ordering_counter = ((long int)recvbuf[header_offset][k]) << 24;
             ordering_counter += ((long int)recvbuf[header_offset + 1][k]) << 16;
             ordering_counter += ((long int)recvbuf[header_offset + 2][k]) << 8;
             ordering_counter += (long int)recvbuf[header_offset + 3][k];

             sorting_table[order_block].order_index = (long long int)ntohl(ordering_counter);

             sorting_table[order_block].order_index *= 1000000ll;

             /*This long int counter contain long long int counter as counter%1000000*/
             ordering_counter = ((long int)recvbuf[header_offset + 4][k]) << 24;
             ordering_counter += ((long int)recvbuf[header_offset + 5][k]) << 16;
             ordering_counter += ((long int)recvbuf[header_offset + 6][k]) << 8;
             ordering_counter += (long int)recvbuf[header_offset + 7][k];

             sorting_table[order_block].order_index += (long long int)ntohl(ordering_counter);
             sorting_table[order_block++].frame_index = k;
          }

          //Sort table by bubble sorting algorithm (only MAX_PACKETS CATCH size)
          catch_block = 1;
          current_catch = already_wrote_catch;//Keeping count already sorted blocks

          for(k = (int)(current_catch%MAX_PACKETS_CATCH); k < current_buf; k++)
          {
             sorting_elem = sorting_table[catch_block - 1];
             for( n = catch_block; n < current_buf; n++)
             {
                if(sorting_elem.order_index >  sorting_table[n].order_index)
                {
                        sorting_elem  = sorting_table[catch_block - 1];
                        sorting_table[catch_block - 1] = sorting_table[n];
                        sorting_table[n] = sorting_elem;
                        sorting_elem = sorting_table[catch_block];
                }
             }
             catch_block++;
          }
          //writing sorted blocks
          for(n = (int)(current_catch%((long long int)MAX_PACKETS_CATCH)); n < current_buf; n++)
          {  
                 
            if( sorting_table[n].order_index >  current_catch + MAX_PACKETS_CATCH)//Unsorted blocks that came ealier more than for MAX_PACKETS_CATCH
            {
              fprintf(prot_file,"Missed block %lld receiving id# %lld of file %s\n", sorting_table[n].order_index, sorting_table[n].packet_index, file_name_with_path);
              if(quiet == 0)
                printf("Missed block %lld receiving id# %lld of file %s\n", sorting_table[n].order_index, sorting_table[n].packet_index, file_name_with_path);
            }
            else 
            {
              if(sorting_table[n].buf_length >= 0)//Writing only non empty blocks
              {
                 if(quiet == 0)
                   printf("Received block of data\n");
                 fprintf(prot_file,"Received block of data\n");
                 if(quiet == 0)
                   printf("Source MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                    recvbuf[6][sorting_table[n].frame_index],
                    recvbuf[7][sorting_table[n].frame_index],
                    recvbuf[8][sorting_table[n].frame_index],
                    recvbuf[9][sorting_table[n].frame_index],
                    recvbuf[10][sorting_table[n].frame_index],
                    recvbuf[11][sorting_table[n].frame_index]);
                 fprintf(prot_file,"Source MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                    recvbuf[6][sorting_table[n].frame_index],
                    recvbuf[7][sorting_table[n].frame_index],
                    recvbuf[8][sorting_table[n].frame_index],
                    recvbuf[9][sorting_table[n].frame_index],
                    recvbuf[10][sorting_table[n].frame_index],
                    recvbuf[11][sorting_table[n].frame_index]);
                 
                 if(quiet == 0)  
                   printf("Destination MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                    recvbuf[0][sorting_table[n].frame_index],
                    recvbuf[1][sorting_table[n].frame_index],
                    recvbuf[2][sorting_table[n].frame_index],
                    recvbuf[3][sorting_table[n].frame_index],
                    recvbuf[4][sorting_table[n].frame_index],
                    recvbuf[5][sorting_table[n].frame_index]);
                 fprintf(prot_file,"Destination MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                    recvbuf[0][sorting_table[n].frame_index],
                    recvbuf[1][sorting_table[n].frame_index],
                    recvbuf[2][sorting_table[n].frame_index],
                    recvbuf[3][sorting_table[n].frame_index],
                    recvbuf[4][sorting_table[n].frame_index],
                    recvbuf[5][sorting_table[n].frame_index]);

                 fprintf(prot_file,"Current block %lld\n",sorting_table[n].order_index);

                 if(sorting_table[n].buf_length > header_offset + sizeof(unsigned long) + my_counter_sz)
                 {             
                    if(sorting_table[n].buf_length <= MIN_PACKET_SIZE)
                    {
                       padding = 0;
                       for(count = sorting_table[n].buf_length - (1 + sizeof(unsigned long)); count >= header_offset + my_counter_sz; count--)
                       {
                               if((recvbuf[count][sorting_table[n].frame_index] == '*')&&(recover > 0))
                                  padding++;
                               else
                                  break;
                       }
                       for(count = header_offset + my_counter_sz; count < (sorting_table[n].buf_length - (padding + sizeof(unsigned long))); count++)
                       {
                               fprintf(output_file,"%c",recvbuf[count][sorting_table[n].frame_index]);
                       }
                     }
                     else
                     {
                       for(count = header_offset + my_counter_sz; count < sorting_table[n].buf_length - sizeof(unsigned long); count++)
                       {
                          fprintf(output_file,"%c",recvbuf[count][sorting_table[n].frame_index]);

                       }
   
                     }
                     fflush(output_file);
                  }

              }//if non empty block
            }//block in order
            already_wrote_catch++;//remember processed counter
          }//writing sorted blocks
          for(n = 0; n < MAX_PACKETS_CATCH; n++)
          {
             sorting_table[n].order_index = MAX_PACKETS_INDEX;
          }
       }//all buffers processed
       //Preparing to process new file
       current_buf = 0;
       count = fread((void *)&temp_buf, 1, sizeof(temp_buf),tmp_file);
       if(count > 0)
       {
         fclose(tmp_file);
         sprintf(system_string,"rm -f %s", TEMP_FILE_NAME);
         system(system_string);
         tmp_file = fopen(TEMP_FILE_NAME,"a+r");
         if(tmp_file == 0)
         {
           printf("Cannot open temp file %s\n",TEMP_FILE_NAME);
           return -5;
         }
       }
       if((receiving_done > 1)&&(already_wrote_catch > 0ll))
         break;
       //current_catch = 0ll;
       //already_wrote_catch = 0ll;
       //all_bufs_processed= 0;
    }//for(i...

    fclose(output_file);
    fclose(tmp_file);
    fclose(prot_file);
    pcap_close(handle1);
    return 0;
}
