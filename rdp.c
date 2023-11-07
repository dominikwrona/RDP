
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

struct sockaddr_in sockaddr;
struct in_addr address;
int sock;

int readloop() {
    struct msghdr msg;
    size_t size;
    struct sockaddr_in src_addr;
    socklen_t saddr_len;
    char buffer[MAX_PACKET_SIZE];
  
    while (1) {
       //Receive a packet
       size = recvfrom(sock, buffer, MAX_PACKET_SIZE, 0, (struct sockaddr *) &src_addr, &saddr_len);
       if (size < 0) {
          perror("recvfrom failed");
          exit(EXIT_FAILURE);
       }
       printf("Received packet from %s with size %ld bytes \n", inet_ntoa(src_addr.sin_addr), size);  
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
