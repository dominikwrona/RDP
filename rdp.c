
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "rdp_packet.h"

#define RDP_PROTOCOL 27
#define MAX_PACKET_SIZE 65536 //in RDP this is to be determined dynamically (maximum segment size field in a SYN segment). TCP is 65536 (2^16)
#define MIN_IP_HDR_LNGTH 20

struct sockaddr_in sockaddr;
struct in_addr address;
int sock;

int verify_rdp_syn_packet() {};
void verify_rdp_packet() {};
int verify_checksum(char * buffer, int len) {
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t*) buffer;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len > 0) // if there is an extra byte unaccounted for
        sum += *(uint8_t *) ptr;

    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)(~sum);
}
int verify_packet(char * buffer, int len) {
    if (len < sizeof(struct rdp_header))
        return 0; //too small to be an RDP packet
    struct rdp_header *header = (struct rdp_header *)buffer;
    //to be continued - analyse the header for proper version number, header len, and other attributes
    if (header->flags.version != 2) {
        printf("Unsupported version number %d\n", header->flags.version);
        return 0;
    }
    uint16_t checksum = header->checksum; uint16_t calculated;
    header->checksum = 0;
    calculated = verify_checksum(buffer, len);
    if (calculated != checksum) {
        printf("Checksum failed \n");
        return 0;
    }
    return 1;
}

int readloop() {
    //struct msghdr msg;
    ssize_t size;
    struct sockaddr_in src_addr;
    socklen_t saddr_len = sizeof(src_addr);
    char buffer[MAX_PACKET_SIZE];

    while (1) {
       //Receive a packet
       size = recvfrom(sock, buffer, MAX_PACKET_SIZE, 0, (struct sockaddr *) &src_addr, &saddr_len);
       if (size < 0) {
          perror("recvfrom failed");
          exit(EXIT_FAILURE);
       }
       printf("Received packet from %s with size %ld bytes \n", inet_ntoa(src_addr.sin_addr), size);
       if (size < MIN_IP_HDR_LNGTH) {
            printf("Packet too small to be valid\n");
            continue;
       }
        // Adjust the pointer to skip the IP header
        int ip_header_length = (buffer[0] & 0x0F) * 4;
        // Check for total minimum size
        if (size < ip_header_length + sizeof(struct rdp_header)) {
            printf("Packet too small to be RDP, IP header length: %d \n", ip_header_length);
            continue;
        }

        char *rdp_data = buffer + ip_header_length;
        if (verify_packet(rdp_data, size - ip_header_length)) {
           //decode packet -> step 1 verify if rdp syn packet or normal packet 
           printf("RDP packet detected! \n");
       }
       else {
        printf("packet is not an RDP packet \n");
       }
    }
    return 0;
}
/*
UPDATE: select a port as Open for RDP, visible with programs like nmap and netstat (needs kernel mod).

RAW Socket: does not use a port number, kernel automatically routs all non-TCP, non-UDP packets with socket's protocol number to that socket
The provisory implementation until kernel modifications can be made. If works correctly can then transfer it to kernel so that socket(), connect(),
bind() calls all work fluently with RDP SOCK_STREAM
*/
int main() {
    int status;
    char * server_address = "127.0.0.0"; //192.168.1.104";
    sock = socket(AF_INET, SOCK_RAW, RDP_PROTOCOL);
    if (sock < 0) {
	perror("Error creating socket \n");
    }
    //use a registered port (range 1024 - 49151), though Dynamic/Private (49152-65535) is also an option
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = 0; //0 on Linux raw sockets, though older versions put in the IP protocol number (i.e. 27 for RDP). not necessary as protocol
		//from the initial socket call is used.
    inet_pton(AF_INET, server_address, &address);
    sockaddr.sin_addr = address;
    //To-Do: implement a bind() that will open a local RDP port (in kernel implementation)
    readloop();
    //DO NOT HAVE TO BIND bc RAW SOCKET and will automatically match host IP
    return 0;

}
