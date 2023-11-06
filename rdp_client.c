
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "rdp_packet.h"
#define RDP_PROTOCOL 27

int soc;
ssize_t res;


int main() {
   struct sockaddr_in daddr;
   struct in_addr address;
   char * server_address = "127.0.0.0"; 
   soc = socket(AF_INET, SOCK_RAW, RDP_PROTOCOL);
   if (soc < 0) {
      perror("Error creating socket:");
   }
   char * sendstring = "This is a test string literal to send \n";
   char buf[256];
   strcpy(buf, sendstring);
   daddr.sin_family = AF_INET;
   daddr.sin_port = 27; //0 on Linux raw sockets, though older versions put in the IP protocol number (i.e. 27 for RDP). not necessary as protocol
               //from the initial socket call is used.
   inet_pton(AF_INET, server_address, &address); 
   daddr.sin_addr = address;
   res = sendto(soc,buf,40, 0, (struct sockaddr *) &daddr, sizeof(daddr));
   if (res < 0) {
      perror("sendto socket failed: ");
   } 
   else {
      printf("msg sent \n");
   }
   return 0;
}
