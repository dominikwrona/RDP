
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "rdp_packet.h"
#define RDP_PROTOCOL 27
#define MODULO_VALUE 2000000000 // 2 billion

int soc;
int res;

/******************
 * compute_checksum()
 * Calcualtes the Internet (TCP) checksum, as described in RFC 1071
*/
uint16_t compute_checksum(void * pkt, ssize_t len) {
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t*) pkt;

    while (len > 1) {
      sum += *ptr++;
      len -= 2;
   }
   if (len > 0) //if there is an extra byte unaccounted for
       sum += *(uint8_t *) ptr;
   //Fold 32-bit sum to 16 bits
   while (sum>>16)
       sum = (sum & 0xffff) + (sum >> 16);
   return (uint16_t)(~sum); 
}

uint32_t get_initial_sequence_num() {
   struct timespec ts;
   clock_gettime(CLOCK_MONOTONIC, &ts);  
   unsigned long long time_combined = (unsigned long long)ts.tv_sec * 1000000000 + ts.tv_nsec;
   unsigned int sequence_num = (unsigned int)(time_combined % MODULO_VALUE);
   return (uint32_t) sequence_num;
}

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
   memset(&syn_pkt, 0, sizeof(syn_pkt));

   // Set RDP SYN flags and header fields
    syn_pkt.header.flags.syn = 1;
    syn_pkt.header.flags.version = 2;
    syn_pkt.header.header_len = sizeof(syn_pkt.header);
    syn_pkt.header.src_port = htons(1234); // Source port
    syn_pkt.header.dst_port = htons(12345); // Destination port
    syn_pkt.header.datalen = 0; //htons(sizeof(rdp_syn_t)); // 4.3.1 notes it's zero, as syn data is theoretically header data
    syn_pkt.header.sequence_num = htonl(get_initial_sequence_num()); // Initial sequence number
    syn_pkt.header.ack_number = htonl(0); // Initial acknowledgment number
    syn_pkt.header.checksum = 0; //Computed when packet is sent I suppose, and then recomputed by receiver

    syn_pkt.syn.max_segment_size = htons((uint16_t)65536);
    syn_pkt.syn.max_outstanding = htons(6);
    syn_pkt.syn.sdm = 1; //deliver packets in order
    syn_pkt.syn.options = 0;

    //Calculate 16bit (TCP) checksum, see RFC 1071
    ssize_t len = sizeof(syn_pkt);
    syn_pkt.header.checksum = compute_checksum(&syn_pkt, len);
    //send to command
   res = sendto(soc, &syn_pkt, len, 0, (struct sockaddr *) &daddr, sizeof(daddr));
   if (res < 0) {
      perror("sendto socket failed: ");
   } 
   return 0;
}
