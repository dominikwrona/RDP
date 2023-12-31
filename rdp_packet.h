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
typedef struct {
    uint16_t max_segment_size; //The largest size, in octets, of a single segment (i.e. RDP packet) that should be sent (depends on receiver's buffers) 
    uint16_t max_outstanding; //maximum num of segments that should be sent without getting an acknowledgement (reciever uses for flow control)
    uint16_t sdm:1; //Sequenced Delivery Mode: specifies whether segments should be delivered in sequence (1 - accord. to seq. number) or in arrival order (0)
    uint16_t options:15; //defined in RFC908 as two octets, even though only one bit currently in use, so keeping the other 15.
} rdp_syn_t;

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
    char pdata [];
} packet_t;

typedef struct {
    struct rdp_header header;
    rdp_syn_t syn;
} syn_packet_t;

/*TO-DO: see rfc908 3.2.4 -> CONNECTION RECORD 
each connection should have a record that may contain the following info:
State: OPEN, LISTEN, CLOSED, SYN-SENT, SYN-RCVD, CLOSE_WAIT (see 3.2.3)
Send Sequence Number variables: SND.NEXT -> sequence number of next segment
                    SND.UNA -> The sequence number of the oldest unacknowledged segment
                    SND.MAX -> maximum number of outstanding (unacknowledged) segments
                    SND.ISS -> initial send sequence number
Receive Sequence Number variables: RCV.CUR -> sequence number of last segment received correctly and in sequence
                    RCV.MAX -> maximum number of segments that can be buffered for this connection
                    RCV.IRS -> initial receive sequence number
                    RCVDSEQNO[n] -> the array of sequence numbers of segments that have been received and acknowledged out of sequence
CLOSEWAIT - timer for closing the CLOSE-WAIT state
SBUF.MAX - largest possible segment (in octets) that can legally be sent (established in initial SYN packets)
RBUF.MAX - largest possible segment that can be received
Variables from Current Segment: SEG.SEQ -> sequence number of the sequence currently being processed
                    SEG.ACK -> acknowledgement sequence number in the segment currently being processed
                    SEG.MAX -> max number of outstanding segments receive is willing to hold
                    SEG.BMAX -> max segment size (in octets/bytes) accepted by foreign host on connection */

#define CLOSED 0
#define OPEN 1
#define LISTEN 2
#define SYN_SENT 3
#define SYN_RCVD 4
#define CLOSE_WAIT 5

struct connection_record {
    uint32_t src_address;
    uint16_t src_port;
    uint16_t dst_port;
    unsigned char state; //one of 6, see above
    
    //used to be a union of two struct but decided the variables are important.
    uint32_t snd_nxt; //sequence number of next segment
    uint32_t snd_una; //The sequence number of the oldest unacknowledged segment
    uint32_t snd_max; //maximum number of outstanding (unacknowledged) segments
    uint32_t snd_iss; //initial send sequence number
    
    uint32_t rcv_cur; //sequence number of last segment received correctly and in sequence
    uint32_t rcv_max; //max number of segments that can be buffered for this connection
    uint32_t rcv_irs; //initial received segment
    uint32_t *rcv_iss; //pointer to array of sequence numbers of segments received out of order
    
    uint32_t seg_seq; //sequence number of segment currently being processed
    uint32_t seg_ack; //ack seq number of segment currently being processed
    uint32_t seg_qmax; //max number  (quantity) of outstanding segments receiver willing to hold (i.e. perhaps 0 means no out-of-sequence segments will be accepted)
    uint32_t seg_bmax; //max segment size (in octets/bytes) accepted by foreign host in this connection 
};