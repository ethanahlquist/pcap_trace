#include <stdio.h>
#include <pcap.h>
#include <pcap/pcap.h>

#include <netinet/ether.h>  // ether_ntoa()
#include <arpa/inet.h>      // ntohl()
#include <string.h>

#include "checksum.h"
#include "protocols.h"


#define ICMP_REPLY (0)
#define ICMP_REQUEST (8)

void ICMP_digest(const u_char *data, struct ip_hdr *iphdr)
{
    uint8_t type = *(uint8_t *)data;

    printf("\tICMP Header\n\n");
    switch (type) {

        case ICMP_REPLY:
            printf("\t\tType: %s\n", "Reply");
            break;

        case ICMP_REQUEST:
            printf("\t\tType: %s\n", "Request");
            break;

        default:
            printf("\t\tType: %d\n", type);
            break;
    }

}


#define HTTP_PORT (80)

void TCP_digest(const u_char *data, struct ip_hdr *iphdr)
{
    // Assign tcp_hdr to location of data ptr.
    struct tcp_header *tcp_hdr = (struct tcp_header*) data;

    printf("\tTCP Header\n\n");

    uint16_t port;
    if(HTTP_PORT == (port = ntohs(tcp_hdr->source_port)))
        printf("\t\tSource Port: %s\n", "HTTP");
    else
        printf("\t\tSource Port: :%d\n", port);

    if(HTTP_PORT == (port = ntohs(tcp_hdr->dest_port)))
        printf("\t\tDest Port: %s\n", "HTTP");
    else
        printf("\t\tDest Port: :%u\n", port);

    printf("\t\tSequence Number: %u\n", ntohl(tcp_hdr->seq_num));

    if(!tcp_hdr->ack)
        printf("\t\tACK Number: %s\n", "<not valid>");
    else
        printf("\t\tACK Number: %u\n", ntohl(tcp_hdr->ack_num));

    printf("\t\tACK Flag: %s\n", tcp_hdr->ack ? "Yes" : "No");
    printf("\t\tSYN Flag: %s\n", tcp_hdr->syn ? "Yes" : "No");

    printf("\t\tRST Flag: %s\n", tcp_hdr->rst ? "Yes" : "No");
    printf("\t\tFIN Flag: %s\n", tcp_hdr->fin ? "Yes" : "No");

    printf("\t\tWindow Size: %d\n", ntohs(tcp_hdr->win_size));

    uint16_t tcp_pdu_len = ntohs(iphdr->pack_len)-(4*iphdr->hdr_len);
    uint16_t tcp_data_len = tcp_pdu_len - sizeof(*tcp_hdr);

    /* Defined in "protocols.h" */
    struct Pseudo_IP_header pseudo_header = {
        iphdr->source_ip,
        iphdr->dest_ip,
        0,
        iphdr->protocol,
        htons(tcp_pdu_len)
    };

    // Declared mid-func since struct depends on [tcp_data_len]
    struct TCP_Pseudo {
        struct Pseudo_IP_header ip;
        struct tcp_header tcp;
        u_char data[tcp_data_len];
    } __attribute__((packed)) tcp_pseudo;

    memset(&tcp_pseudo, 0, sizeof(tcp_pseudo));

    /* Copy fields into tcp_pseudo */
    memcpy(&tcp_pseudo.ip, &pseudo_header, sizeof(pseudo_header));
    memcpy(&tcp_pseudo.tcp, tcp_hdr, sizeof(*tcp_hdr));
    memcpy(&tcp_pseudo.data, tcp_hdr+1, tcp_data_len);

    uint16_t total_cksum = in_cksum((unsigned short *) &tcp_pseudo, sizeof(tcp_pseudo));
    uint16_t check = ntohs(tcp_hdr->checksum);

    printf("\t\tChecksum: %s (0x%-x)\n\n",
            (total_cksum == 0x0000) ? "Correct": "Incorrect", check & 0xFFFF);
}


void UDP_digest(const u_char *data, struct ip_hdr *iphdr)
{
    struct udp_header *udp_hdr = (struct udp_header *) data;

    printf("\tUDP Header\n\n");
    printf("\t\tSource Port: : %d\n", ntohs(udp_hdr->source_port));
    printf("\t\tDest Port: : %d\n", ntohs(udp_hdr->dest_port));
}


#define IP_PROTOCOL_ICMP (1)
#define IP_PROTOCOL_TCP (6)
#define IP_PROTOCOL_UDP (17)

void IP_digest(const u_char *data)
{
    struct ip_hdr *iphdr = (struct ip_hdr *) data;

    printf("\tIP Header\n\n");
    printf("\t\tHeader Len: %d (bytes)\n", iphdr->hdr_len*4);
    printf("\t\tTOS: 0x%x\n", iphdr->tos);

    printf("\t\tTTL: %d\n", iphdr->ttl);
    printf("\t\tIP PDU Len: %d (bytes)\n", ntohs(iphdr->pack_len));

    /* Function pointer to remember which protocol to run next */
    void (*next_protocol)(const u_char *, struct ip_hdr *) = NULL;

    switch (iphdr->protocol) {
        case IP_PROTOCOL_ICMP:
            printf("\t\tProtocol: %s\n\n", "ICMP");
            next_protocol = ICMP_digest;
            break;
        case IP_PROTOCOL_TCP:
            printf("\t\tProtocol: %s\n\n", "TCP");
            next_protocol = TCP_digest;
            break;
        case IP_PROTOCOL_UDP:
            printf("\t\tProtocol: %s\n\n", "UDP");
            next_protocol = UDP_digest;
            break;
        default:
            printf("\t\tProtocol: %s\n\n", "Unknown");
    }

    uint16_t cksum = in_cksum((unsigned short *)iphdr, iphdr->hdr_len*4);

    printf("\t\tChecksum: %s (0x%-x)\n\n",
            (cksum == 0) ? "Correct": "Incorrect", iphdr->checksum & 0xFFFF);

    struct in_addr *sender_ip = (struct in_addr *) &iphdr->source_ip;
    struct in_addr *target_ip = (struct in_addr *) &iphdr->dest_ip;

    printf("\t\tSender IP: %s\n", inet_ntoa(*sender_ip));
    printf("\t\tDest IP: %s\n\n", inet_ntoa(*target_ip));

    // Make pointer to index right after the header
    const u_char *sublayer_data = (u_char*)(data + iphdr->hdr_len*4);

    // If function pointer is NOT NULL
    if(next_protocol)
        next_protocol(sublayer_data, iphdr);

}


#define ARP_REQUEST (1)
#define ARP_REPLY (2)

void ARP_digest(const u_char *data)
{
    struct arp_packet *arp = (struct arp_packet*) data;

    printf("\tARP header\n\n");

    switch (ntohs(arp->opcode)) {
        case ARP_REQUEST:
            printf("\t\tOpcode: %s\n", "Request");
            break;
        case ARP_REPLY:
            printf("\t\tOpcode: %s\n", "Reply");
            break;
        default:
            printf("\t\tOpcode: %s\n", "[Not implemented]");
    }

    struct ether_addr *sender_mac = (struct ether_addr *) &arp->s_hrd_addr;
    struct ether_addr *target_mac = (struct ether_addr *) &arp->t_hrd_addr;

    struct in_addr *sender_ip = (struct in_addr *) &arp->s_pro_addr;
    struct in_addr *target_ip = (struct in_addr *) &arp->t_pro_addr;

    printf("\t\tSender MAC: %s\n", ether_ntoa(sender_mac));
    printf("\t\tSender IP: %s\n", inet_ntoa(*sender_ip));
    printf("\t\tTarget MAC: %s\n", ether_ntoa(target_mac));
    printf("\t\tTarget IP: %s\n\n", inet_ntoa(*target_ip));
}


void ethernet_digest(struct pcap_pkthdr *pkt_header, const u_char *data)
{
    struct ethernet_header *eth = (struct ethernet_header*) data;

    printf("\tEthernet Header\n\n");
    printf("\t\tDest MAC: %s\n", ether_ntoa((struct ether_addr *)&eth->dest_mac));
    printf("\t\tSource MAC: %s\n", ether_ntoa((struct ether_addr *)&eth->source_mac));

    uint16_t type = ntohs(eth->type);

    // Make pointer to index right after the ether header
    const u_char *layer_data = (u_char*)(eth + 1);

    switch (type) {
        case ETHERTYPE_IP:
            printf("\t\tType: %s\n\n", "IP");
            IP_digest(layer_data);
            break;

        case ETHERTYPE_ARP:
            printf("\t\tType: %s\n\n", "ARP");
            ARP_digest(layer_data);
            break;

        default:
            break;
    }
}

void pkt_digest(struct pcap_pkthdr *header, const u_char *data)
{
    ethernet_digest(header, data);
}


int main(int argc, char *argv[])
{
    char *pcap_filename;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p;

    pcap_filename = argv[1];
    p = pcap_open_offline(pcap_filename, errbuf);

    if (p == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", pcap_filename, errbuf);
        return(2);
    }

    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    int ret;
    unsigned int i;

    for(i = 1; (1); i++){
        ret = pcap_next_ex(p, &pkt_header, &pkt_data);

        // no problems
        if(ret == 1){
            printf("\nPacket number: %u  ", i);
            printf("Frame Len: %d\n\n", pkt_header->len);
            pkt_digest(pkt_header, pkt_data);
        }

        // livecapture timout (shouldn't happen, we are reading from a file)
        else if(ret == 0)
            break;

        // error
        else if(ret == -1)
            break;

        // reached end of 'savefile'
        else if(ret == -2)
            break;

        else
            break;
    }

    pcap_close(p);
}
