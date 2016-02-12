#ifndef PACKET_HEADERS_H
#define PACKET_HEADERS_H

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define UDP_LENGTH 8


struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];
        u_char  ether_shost[ETHER_ADDR_LEN];
        u_short ether_type;
};

struct sniff_ip {
        u_char  ip_vhl;                 // version & header length
        #define IP_HL(ip)               ((ip.ip_vhl) & 0x0f) //check!!!
        #define IP_V(ip)                (((s_pack->ip)->ip_vhl) >> 4)
        u_char  ip_tos;                 // type of service
        u_short ip_len;                 // total length
        u_short ip_id;                  // identification
        u_short ip_off;                 // fragment offset field
        #define IP_RF 0x8000
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        u_char  ip_ttl;                 // time to live
        u_char  ip_p;                   // protocol
        u_short ip_sum;
        struct  in_addr ip_src,ip_dst;
};

typedef u_int tcp_seq;

struct sniff_udp {
    u_short s_port;
    u_short d_port;
    u_short length;
    u_short k_sum;
};

struct sniff_tcp {
        u_short th_sport;               // source port
        u_short th_dport;               // destination port
        tcp_seq th_seq;                 // sequence number
        tcp_seq th_ack;                 // acknowledgement number
        u_char  th_offx2;               // data offset, rsvd
        #define TH_OFF(tcp)   ((tcp.th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS      (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;
        u_short th_sum;
        u_short th_urp;
};

#endif // PACKET_HEADERS_H
