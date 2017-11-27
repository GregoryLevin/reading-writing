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
#define MAX_PACKETS_CATCH 30
#define MAX_FILENAME_PATH 1000
#define TEMP_FILE_NAME  "temp_file.txt"
#define PROT_FILE_NAME  "protocol.txt"
#define EXTRA_WAIT_DELAY  1 //useconds
#define EXTRA_WAIT_ATTEMPTS 300 //times repeat
#define MIN_PACKET_SIZE  64

typedef struct temp_buffer_n {
  unsigned int buf_length;
  long long int packet_index;
  unsigned char tempbuf[BUFFER_SIZE];
} temp_buffer;


typedef struct output_index_n {
  long long int order_index;
  char frame_busy;
  unsigned int buf_length;
  unsigned char buffer[BUFFER_SIZE];
} output_index;


int main(int argc, char **argv)
{
        pcap_t *handle1;
        char errbuf[PCAP_ERRBUF_SIZE];
        temp_buffer temp_buf;
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
        unsigned long int n;
        char file_name_with_path[MAX_FILENAME_PATH];
        FILE *output_file;
        output_index output_table[MAX_PACKETS_CATCH];
        long int ordering_counter;
        long long int temp_ordering,current_buf;
        int table_offset, circle_buf;
        int all_bufs_processed,set_blocks_read,current_buf_last; 
        int my_counter_sz = 2*sizeof(long int);    
        FILE *tmp_file;
        FILE *prot_file;
        unsigned long int tmp_file_offset;
        int just_receiving = 0;
        int just_processing = 0;
        int one_time_processing = 0;
        struct timespec tv,trem;
        int wait_counter = 0;
        long long int receiving_done = 0ll;
        long long int outputing_done = 0ll;
        int param_index = 3;
        int all_param_done = 0;
        char next_param_input[MAX_PARAMETER_LENGTH];
        int timeout_ms;
        int max_num_packets_received = 0;
        int max_num_packets_processed = 0;
        int quiet = 0;
        int recover = 1;
        int num_set = 0;
        int padding = 0;

        tv.tv_sec = (time_t)0;
        tv.tv_nsec = (long)(EXTRA_WAIT_DELAY)*1000l;

        if( argc < 3) {
          printf("incorrect number of parameters. Expected 2 mandatory parameters\n");
          printf("pqtl4_filerx interface output_filename [-t timeout] [-q yes] [-p count] [-r no]\n");
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
                   max_num_packets_processed = max_num_packets_received;
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

       just_receiving = 1;
       wait_counter = 0;
       receiving_done = 0ll;
       outputing_done = 0ll;

       if(timeout_ms > 0)
         wait_counter = timeout_ms;
       else
         wait_counter = EXTRA_WAIT_ATTEMPTS;

       for(i = 0l;;) {
         if( i > 1000000l)
           i = 0l;
         while(just_receiving == 1) {
           header.len =0;
           packet = pcap_next(handle1, &header);

           num_bytes = header.len;

           if(header.len > 0)
           {
              header.len = 0;
              if(num_bytes > BUFFER_SIZE)
                num_bytes = BUFFER_SIZE;
              if(quiet == 0)     
                 printf("\nlistener: got packet #%lld %d bytes\n", ++i,num_bytes);
              fprintf(prot_file,"\nlistener: got packet #%lld %d bytes\n", i,num_bytes);
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

   
        while((one_time_processing == 1)&&(just_processing == 1))
        {
          just_processing = 0;
          fflush(tmp_file);
          current_buf = 0ll;
          set_blocks_read = 0;
          all_bufs_processed = 0;
          while(all_bufs_processed == 0)
          {
            set_blocks_read = 0;
            current_buf += (long long int)circle_buf;

            if((current_buf >= (long long int)max_num_packets_processed)&&(num_set == 1))
              break;

            //if(outputing_done > 0)
            //  if(outputing_done == receiving_done)
            //     break;

            for(n = 0; n < MAX_PACKETS_CATCH; n++)
            {
               output_table[n].frame_busy = 0;
            }
            circle_buf = 0;
            tmp_file_offset = 0l;
            current_buf_last = 0;

            while(set_blocks_read == 0)
            {
              fseek(tmp_file, SEEK_SET, tmp_file_offset);
              count = fread((void *)&temp_buf, 1, sizeof(temp_buf),tmp_file);

              if(count < sizeof(temp_buf))
              {
                 current_buf_last = 1;
                 one_time_processing = 0;
              }
              temp_ordering = 0ll;        
              ordering_counter = 0l;
              /*This long int counter contain long long int counter as counter/1000000l*/
              ordering_counter = ((long int)temp_buf.tempbuf[header_offset + 3]) << 24;
              ordering_counter += ((long int)temp_buf.tempbuf[header_offset + 2]) << 16;
              ordering_counter += ((long int)temp_buf.tempbuf[header_offset + 1]) << 8;
              ordering_counter += (long int)temp_buf.tempbuf[header_offset + 0];

              temp_ordering = (long long int)ntohl(ordering_counter);

              temp_ordering *= 1000000ll;

              /*This long int counter contain long long int counter as counter%1000000*/
              ordering_counter = ((long int)temp_buf.tempbuf[header_offset + 7]) << 24;
              ordering_counter += ((long int)temp_buf.tempbuf[header_offset + 6]) << 16;
              ordering_counter += ((long int)temp_buf.tempbuf[header_offset + 5]) << 8;
              ordering_counter += (long int)temp_buf.tempbuf[header_offset + 4];

              temp_ordering += (long long int)ntohl(ordering_counter);
            
              if((temp_ordering < (current_buf + (long long int)MAX_PACKETS_CATCH))&&
                (temp_ordering >= current_buf)) 
              {
                 table_offset = (int)(temp_ordering%((long long int)MAX_PACKETS_CATCH));
                 if(output_table[table_offset].frame_busy == 1)
                 {
                   if(quiet == 0)
                      printf("Duplcated block %lld of file %s\n", temp_ordering,file_name_with_path);
                   fprintf(prot_file,"Duplcated block %lld of file %s\n", temp_ordering,file_name_with_path);
                 }
                 else
                 {
                    output_table[table_offset].frame_busy = 1;
                    output_table[table_offset].order_index = temp_ordering;
                    output_table[table_offset].buf_length = temp_buf.buf_length;
                    memcpy((void *)&output_table[table_offset].buffer[0],(void *)&temp_buf.tempbuf[0],temp_buf.buf_length);
                 }
                 circle_buf++;
             }
                      
   
              if((circle_buf > MAX_PACKETS_CATCH - 1)||(current_buf_last == 1))
                set_blocks_read = 1;
              else {
                tmp_file_offset += (long int)MAX_PACKETS_CATCH * (long int)sizeof(temp_buf); //read one buffer more
              }
            } //while(set_block_read...  

            //Check sequence of the blocks 
            for(n = 0; n < MAX_PACKETS_CATCH; n++)
            {  
                 
               if(output_table[n].frame_busy == 0)
               {
                 if(circle_buf >  n + 1)
                 {
                    fprintf(prot_file,"Missed block %lld of file %s\n", current_buf + (long long int)n, file_name_with_path);
                    if(quiet == 0)
                      printf("Missed block %lld of file %s\n", current_buf + (long long int)n, file_name_with_path);
                }
              }
              else 
              {
                 if(quiet == 0)
                   printf("Received block of data\n");
                 fprintf(prot_file,"Received block of data\n");
                 if(quiet == 0)
                   printf("Source MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                    output_table[n].buffer[6],
                    output_table[n].buffer[7],
                    output_table[n].buffer[8],
                    output_table[n].buffer[9],
                    output_table[n].buffer[10],
                    output_table[n].buffer[11]);
                 fprintf(prot_file,"Source MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                    output_table[n].buffer[6],
                    output_table[n].buffer[7],
                    output_table[n].buffer[8],
                    output_table[n].buffer[9],
                    output_table[n].buffer[10],
                    output_table[n].buffer[11]);
                 
                 if(quiet == 0)  
                   printf("Destination MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                    output_table[n].buffer[0],
                    output_table[n].buffer[1],
                    output_table[n].buffer[2],
                    output_table[n].buffer[3],
                    output_table[n].buffer[4],
                    output_table[n].buffer[5]);
                 fprintf(prot_file,"Destination MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                    output_table[n].buffer[0],
                    output_table[n].buffer[1],
                    output_table[n].buffer[2],
                    output_table[n].buffer[3],
                    output_table[n].buffer[4],
                    output_table[n].buffer[5]);
               
                  if(quiet == 0)
                    printf("Current block %lld\n",output_table[n].order_index);  
                  outputing_done++;
                  
                  fprintf(prot_file,"Current block %lld\n",output_table[n].order_index);

                  if(output_table[n].buf_length > header_offset + sizeof(unsigned long) + my_counter_sz)
                  {             
                    if(output_table[n].buf_length <= MIN_PACKET_SIZE)
                    {
                       padding = 0;
                       for(count = output_table[n].buf_length - (1 + sizeof(unsigned long)); count >= header_offset + my_counter_sz; count--)
                       {
                               if((output_table[n].buffer[count] == '*')&&(recover > 0))
                                  padding++;
                               else
                                  break;
                       }
                       for(count = header_offset + my_counter_sz; count < (output_table[n].buf_length - (padding + sizeof(unsigned long))); count++)
                       {
                               fprintf(output_file,"%c",output_table[n].buffer[count]);
                       }
                     }
                     else
                     {
                       for(count = header_offset + my_counter_sz; count < output_table[n].buf_length - sizeof(unsigned long); count++)
                       {
                          fprintf(output_file,"%c",output_table[n].buffer[count]);

                       }
   
                     }
                     fflush(output_file);
                  }

              }//if non empty block
            }//table output
          }//while(all_bufs_processed)          
       }//processing tmp file
       if(outputing_done > 0)
          break;
    }//for(i...

    fclose(output_file);
    fclose(tmp_file);
    fclose(prot_file);
    pcap_close(handle1);
    return 0;
}
