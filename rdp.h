#include <time.h>
#include <string.h>
#define MODULO_VALUE 2000000000 // 2 billion
#define MAX_PACKET_SIZE 65536 //placeholder, in RDP this is to be determined dynamically (maximum segment size field in a SYN segment). TCP is 65536 (2^16)


uint32_t get_initial_sequence_num() {
   struct timespec ts;
   clock_gettime(CLOCK_MONOTONIC, &ts);  
   unsigned long long time_combined = (unsigned long long)ts.tv_sec * 1000000000 + ts.tv_nsec;
   unsigned int sequence_num = (unsigned int)(time_combined % MODULO_VALUE);
   return (uint32_t) sequence_num;
}

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