#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#define MAC_SIZE (6) /* 6 bytes */

struct ip_hdr {
    /* This order because endianess is flipped*/
    unsigned int hdr_len : 4;
    unsigned int version : 4;
    uint8_t tos;
    uint16_t pack_len;
    uint16_t ident;
    uint16_t frag_off_and_flags; // weird
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t source_ip;
    uint32_t dest_ip;
} __attribute__((packed));


struct tcp_header {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;

    unsigned int reserved_1 : 4;
    unsigned int hdr_len : 4;

    unsigned int fin : 1;
    unsigned int syn : 1;
    unsigned int rst : 1;
    unsigned int psh : 1;
    unsigned int ack : 1;
    unsigned int urg : 1;
    unsigned int reserved_2 : 2;

    uint16_t win_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
} __attribute__((packed));


// Create new struct to hold pseudo IP data
struct Pseudo_IP_header {
    uint32_t source_ip;
    uint32_t dest_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_seg_len;
} __attribute__((packed));


struct udp_header {
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));

struct arp_packet {
    uint16_t hardware;
    uint16_t protocol;
    uint8_t hrd_addr_len;
    uint8_t prot_len;
    uint16_t opcode;
    u_char s_hrd_addr[MAC_SIZE];
    uint32_t s_pro_addr;
    u_char t_hrd_addr[MAC_SIZE];
    uint32_t t_pro_addr;
} __attribute__((packed));

struct ethernet_header {
     u_char dest_mac[MAC_SIZE];   // MAC addresses are 6 bytes
     u_char source_mac[MAC_SIZE];
     uint16_t type;
} __attribute__((packed));

#endif
