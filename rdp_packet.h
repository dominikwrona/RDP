

/***********************
The Reliable Delivery Protocol Packet (Version 2)

Control Flags:
Bit #
0     SYN
1     ACK
2     EACK
3     RST
4     NUL
5     Unused
6-7   Version number

Header length: Units are portrayed as describing pairs of 2 octets (2 bytes)
e.g. a header of 6 bytes will have value of 3 in header length; standard header w/out variable
header area will have length of 9 (i.e. 18 bytes)

Data length: does not include the RDP header

Variables header data: for SYN, ACK, EACK segments
************************/


struct rdp_flags {
    uint8_t syn:1; //Establish connection and synchronize sequence numbers
    uint8_t ack:1; //Acknowledge 
    uint8_t eak:1; //Extended acknowledgement (non-cumulative)
    uint8_t rst:1; //Reset the connection
    uint8_t nul:1; //This is a null (zero data length) segment)
    uint8_t unused:1;
    uint8_t version:2; //2 bit version number [with RFC 1151, guess we're at number 2]
};

struct rdp_header {
    struct rdp_flags flags;
    uint8_t header_len;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t datalen;
    uint32_t sequence_num;
    uint32_t ack_number;
    uint16_t checksum;
};

typedef struct rdp_packet {
    struct rdp_header header;
    char variable [];
} packet_t;
