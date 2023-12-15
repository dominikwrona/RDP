
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "rdp_packet.h"

#define RDP_PROTOCOL 27
#define MAX_PACKET_SIZE 65536 //in RDP this is to be determined dynamically (maximum segment size field in a SYN segment). TCP is 65536 (2^16)
#define MAX_SEGMENT_SIZE 1400 //to be safe; more generally use Path MTU Discovery to determine correct size and store in connection record. 
#define MIN_IP_HDR_LNGTH 20
#define MAX_CONNS 4096 //maximum number of connections the server will simultaneously handle (reject connection if 4097th arrives?)
#define MAX_SEGMENT_SIZE

struct sockaddr_in sockaddr;
struct in_addr address;
int sock;
struct connection_record * connections[MAX_CONNS]; //temporary solution pending further study
int hashtable_size = 4096;

/**
TO-DO: figure out how to manage/avoid collisions, or use 3rd party lib, or see how TCP does it
**/
struct hashtable_entry {
    unsigned long key; // hash of the connection details
    int array_index;   // Index of the connection in the connection record array
};

int calculate_hash(uint32_t src_address, uint16_t src_port, uint16_t dst_port) { //for the time being
    unsigned long hash = 0;

    // Mix src_address
    hash += (src_address >> 24) & 0xFF;
    hash += (src_address >> 16) & 0xFF;
    hash += (src_address >> 8) & 0xFF;
    hash += src_address & 0xFF;

    // Mix src_port and dst_port
    hash = hash * 31 + src_port;
    hash = hash * 31 + dst_port;

    return (int) hash % 4096; //4096 entries in hash table
}

int verify_rdp_syn_packet(syn_packet_t * syn_pkt, int size) {
    //verify syn flag is set and datalen = 0; 
    if (!syn_pkt->header.flags.syn || syn_pkt->header.datalen)
        return 0;
    if (size < (sizeof(struct rdp_header) + (sizeof(rdp_syn_t)))) //cannot check for raw equality as different compilers might add different paddings
        return 0;
    return 1;
};

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
/**********************
 * verify_packet() 
 * Verifies the integrity of the RDP packet - correct version number and checksum
************************/
int verify_packet(char * buffer, int len) {
    if (len < sizeof(struct rdp_header))
        return 0; //too small to be an RDP packet
    struct rdp_header *header = (struct rdp_header *)buffer;
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
int send_syn_ack(uint32_t iss, uint32_t rcv_iss, uint32_t dest_ip, uint16_t dest_port) {
    syn_packet_t syn_ack_pkt;

}

int readloop() {
    //struct msghdr msg;
    ssize_t size;
    struct sockaddr_in src_addr; //NOTE: sockaddr_in is the struct for IPv4, sockaddr_in6 is equivalent for IPv6
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
       /*** Check for 27 in IP Protocol number field
        * While in the current Linux raw socket implementation only packets with the protocol number
        * specified in the socket() call will be delivered, this may not be the case on other platforms
        * ***/
       unsigned char protocol = buffer[9];
       if (protocol != RDP_PROTOCOL) {
           printf("Non-RDP protocol listed, number %d \n", protocol);
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
            //TO-DO: Check if source address + source port + destination address + destination port is in Connection record, if not then
            //prepare for syn packet (i.e. must be a new connection or an invalid one)
            //Step 1: fetch source address and source port from IP packet
            uint32_t source_ip = ntohl(src_addr.sin_addr.s_addr);
            uint16_t sin_port = ntohs(src_addr.sin_port); //NOTE: should probably take this from RDP packet itself 
            //Step 2: fetch destination port from rdp_header
            struct rdp_header * rdp_hdr = (struct rdp_header *)rdp_data;
            uint16_t dest_port = ntohs(rdp_hdr->dst_port);
            //Step 3: calculate_hash()
            int index = calculate_hash(source_ip, sin_port, dest_port);
            if (connections[index] == NULL) {
                //No connection record exists: record new using syn packet or discard as corrupted
                printf("No connection record exists; attempting to start one for source ip %u, sin_port %d, dest_port %d... \n", source_ip, sin_port, dest_port);
                if (verify_rdp_syn_packet((syn_packet_t *) rdp_data, size - ip_header_length)) {
                    //create new connection record
                    connection[index] = malloc(sizeof(struct connection_record));
                    if (!connection[index]) {
                        perror("malloc for connection record failed \n"); continue; }
                    memset(connection[index], 0, sizeof(struct connection_record)); 
                    syn_packet_t * syn_pkt = (syn_packet_t *)rdp_data;
                    connections[index]->src_address = source_ip;
                    connections[index]->src_port = sin_port;
                    connections[index]->dst_port = dest_port;
                    connections[index]->state = SYN_RCVD; //a 'LISTEN' state would have to cooperate with kernel ports
                    connections[index]->rcv_irs = syn_pkt->header.sequence_num;
                    uint32_t iss = get_initial_sequence_num();
                    connections[index]->send_iss = iss;
                    /* ....  */ 
                    /*create receiver's initial sequence number and Send SYN acknowledgement back to sender*/
                    send_syn_ack(iss, syn_pkt->header.sequence_num, source_ip, dest_port);

                }
                else {
                    //don't create - ignore/error message/continue
                }
            }
            else {
                //connection record exists - continue operations with existing connection record
            }
           
       }
       else {
        printf("packet is not an RDP packet \n");
       }
    }
    return 0;
}
/*
UPDATE: select a port as Open for RDP, visible with programs like nmap and netstat (needs kernel mod).
netstat -aenp: shows every active connection with both local address and foreign address
RAW Socket: does not use a port number, kernel automatically routs all non-TCP, non-UDP packets with socket's protocol number to that socket
The provisory implementation until kernel modifications can be made. If works correctly can then transfer it to kernel so that socket(), connect(),
bind() calls all work fluently with RDP SOCK_STREAM

TO-DO: Close connections 3.2.5: close request from user results in RST segment sent to other side of connection
                          RST segment from other side results in connection closed on this side.
*/
int main() {
    char * server_address = "127.0.0.0"; //192.168.1.104";
    sock = socket(AF_INET, SOCK_RAW, RDP_PROTOCOL);
    if (sock < 0) {
	    perror("Error creating socket \n");
        exit(-1);
    }
    //use a registered port (range 1024 - 49151), though Dynamic/Private (49152-65535) is also an option
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = 0; //0 on Linux raw sockets, though older versions put in the IP protocol number (i.e. 27 for RDP). not necessary as protocol
		//from the initial socket call is used.
    inet_pton(AF_INET, server_address, &address);
    sockaddr.sin_addr = address;
    //To-Do: implement a bind() that will open a local RDP port (in kernel implementation)
    memset(connections, 0, sizeof(connections));
    readloop();
    //DO NOT HAVE TO BIND bc RAW SOCKET and will automatically match host IP
    return 0;

}

/*******************
 * Current more macro-level To-Dos:
 * Hash Table collision management
 * Path MTU Discovery for effective MTU and thus MSS calculation (this may require cooperation with kernel)
 * 
 * 
 * 
 * 
*/
