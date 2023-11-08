
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
   //Now: send RDP SYN packet
   syn_packet_t syn_pkt;
   memset(&syn_packet, 0, sizeof(syn_packet);

   // Set RDP SYN flags and header fields
    syn_packet.header.flags.syn = 1;
    syn_packet.header.flags.version = 2;
    syn_packet.header.header_len = sizeof(syn_packet.header);
    syn_packet.header.src_port = htons(1234); // Source port
    syn_packet.header.dst_port = htons(12345); // Destination port
    syn_packet.header.datalen = htons(sizeof(rdp_syn_t)); // Length of SYN data
    syn_packet.header.sequence_num = htonl(0); // Initial sequence number
    syn_packet.header.ack_number = htonl(0); // Initial acknowledgment number
    syn_packet.header.checksum = 0; //Computed when packet is sent I suppose, and then recomputed by receiver

    syn_packet.syn.max_segment_size = htons(65536);
    syn_packet.syn_max_outstanding = htons(6);
    syn_packet.syn.sdm = 1; //deliver packets in order
    syn_packet.syn.options = 0;

    //Calculate 16bit (TCP) checksum, as defined on page 16 of RFC-793

    //send to command

   return 0;
}
