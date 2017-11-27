#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_IFCONFIG_LINE_SIZE 100
#define TEMP_IFCONFIG_OUTPUT   "last_ifconfig.txt"
#define MAX_COMMAND_LINE_SIZE  100
#define LOGICAL_INTERFACE      "enp131s0"
#define PHYSICAL_INTERFACE     "p1p1"
#define TEST_SAMPLE "sudo ./p_txpacket 5000 1500 aa" 

typedef struct {
  long int read_packets;
  long int read_errors;
  long int write_packets;
  long int write_errors;
} parsing_results;


typedef enum {
  READ_AMOUNT,
  READ_ERRORS_AMOUNT,
  WRITE_AMOUNT,
  WRITE_ERRORS_AMOUNT
} what_read;

typedef  enum {
  logical_card_interface,
  physical_card_interface
} card_interface;

int read_ifconfig_output(char *interface, parsing_results *p_r);


int main(int argc, char **argv)
{
   int current_delay = 1000;
   float maximum_criteria = 0.995;
   float minimum_criteria = 0.98;
   float current_criteria = 0;
   char command_line_copy[MAX_COMMAND_LINE_SIZE];
   parsing_results parsing_before_test, parsing_after_test;

   while(minimum_criteria >= current_criteria)
   {
      sprintf((char *)&command_line_copy[0],"ifconfig > %s", TEMP_IFCONFIG_OUTPUT);
      system(command_line_copy);
      if(read_ifconfig_output(LOGICAL_INTERFACE, &parsing_before_test) < 0)
        return -1;
      sprintf((char *)&command_line_copy[0],"%s %d 1", TEST_SAMPLE, current_delay);
      system(command_line_copy);
      sprintf((char *)&command_line_copy[0],"ifconfig > %s", TEMP_IFCONFIG_OUTPUT);
      system(command_line_copy);
      if(read_ifconfig_output(LOGICAL_INTERFACE, &parsing_after_test) < 0)
        return -2;

      current_criteria = (parsing_after_test.read_packets - parsing_before_test.read_packets)/
      (parsing_after_test.write_packets - parsing_before_test.write_packets);
      current_delay--;
   }
   printf("Optimal delay for  %f < delivery < %f is %d ms\n", minimum_criteria,maximum_criteria, current_delay);
   return 0;
}


int read_ifconfig_output(char *interface, parsing_results *p_r)
{
     card_interface card;
     char ifconfig_line[MAX_IFCONFIG_LINE_SIZE];
     FILE *cfg_output;
     char *token;
     int trigger = 0;
     what_read what_to_read;
     char comparision_string[MAX_IFCONFIG_LINE_SIZE];

     if(strcmp(interface,LOGICAL_INTERFACE) == 0)
       card = logical_card_interface;
     else
       card = physical_card_interface;
   
     cfg_output = fopen(TEMP_IFCONFIG_OUTPUT,"r");
     if(cfg_output < 0)
       return -1;

     while(fgets((char *)&ifconfig_line[0], MAX_IFCONFIG_LINE_SIZE, cfg_output) != 0)
     {
        token = strtok((char *)&ifconfig_line[0]," \n");
        switch(card) 
        {
          case logical_card_interface:
               sprintf((char *)comparision_string[0],"%s:",LOGICAL_INTERFACE);
               break;
          case physical_card_interface:
               sprintf((char *)comparision_string[0],"%s:",PHYSICAL_INTERFACE);                 break;   
        }
        if(strcmp((char *)token,(char *)&comparision_string[0]) == 0)
        {
           trigger = 1;//Start interface we are looking for
           continue;
        }
        if(trigger == 1)
        {
          if(strcmp(token,"RX") == 0)
          {
            token = strtok(0," \n");
            if(strcmp(token,"packets") == 0)
            {
               token = strtok(0," \n");
               what_to_read = READ_AMOUNT;
            }
            else {
              if(strcmp(token,"errors") == 0)
              {
                token = strtok(0," \n");
                what_to_read = READ_ERRORS_AMOUNT;
              }
            }
          }      
          else
          {
            if(strcmp(token,"TX") == 0)
            {
              token = strtok(0," \n");
              if(strcmp(token,"packets") == 0)
              {
               token = strtok(0," \n");
               what_to_read = WRITE_AMOUNT;
              }
              else {
                 if(strcmp(token,"errors") == 0)
                 {
                   token = strtok(0," \n");
                   what_to_read = WRITE_ERRORS_AMOUNT;
                 }
              }
            }
          }/*end of else*/
          switch(what_to_read)
          {
            case READ_AMOUNT:
                 p_r->read_packets = strtol(token,0,10);
            break;
            case READ_ERRORS_AMOUNT:
                 p_r->read_errors = strtol(token,0,10);
            break;
            case WRITE_AMOUNT:
                 p_r->write_packets = strtol(token,0,10);
            break;
            case WRITE_ERRORS_AMOUNT:
                 p_r->write_errors = strtol(token,0,10);
                 fclose(cfg_output);
                 return 0;
            break;
          }/*end of switch*/
        } /*End of trigger == 1*/
      } /*End of while */
   fclose(cfg_output);
   return 1;
}
