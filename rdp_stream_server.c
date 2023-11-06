
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>

#define RDP_PROTOCOL 27

/*******************
README

Current Linux kernel does not support an RDP socket as a SOCK_STREAM via the socket() call (as running this code piece
would show). Modifications would be necessary.
The alternative is to use SOCK_RAW to code outside the kernel. 

********************/



struct sockaddr_in sockaddr;
struct in_addr address;
int sock;


int main() {
    int status;
    char * server_address = "127.0.0.0"; //192.168.1.104";
    sock = socket(AF_INET, SOCK_STREAM, RDP_PROTOCOL);
    if (sock < 0) {
        perror("Error creating socket \n");
    }
    //use a registered port (range 1024 - 49151), though Dynamic/Private (49152-65535) is also an option
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = 0; //0 on Linux raw sockets, though older versions put in the IP protocol number (i.e. 27 for RDP). not necessary as protocol
                //from the initial socket call is used.
    inet_pton(AF_INET, server_address, &address); 
    sockaddr.sin_addr = address;
    status = connect(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (status < -1) {
        perror("Error connecting socket \n");
    }
}
