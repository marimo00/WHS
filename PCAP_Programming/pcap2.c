#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h> // isprint 쓰려면 필요

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;        /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4,         // IP header length
                       iph_ver:4;         // IP version
    unsigned char      iph_tos;           // Type of service
    unsigned short int iph_len;           // IP Packet length (data + header)
    unsigned short int iph_ident;         // Identification
    unsigned short int iph_flag:3,        // Fragmentation flags
                       iph_offset:13;     // Flags offset
    unsigned char      iph_ttl;           // Time to Live
    unsigned char      iph_protocol;      // Protocol type
    unsigned short int iph_chksum;        // IP datagram checksum
    struct in_addr     iph_sourceip;      // Source IP address
    struct in_addr     iph_destip;        // Destination IP address
};

struct tcpheader {
    u_short tcp_sport;                   /* source port */
    u_short tcp_dport;                   /* destination port */
    u_int   tcp_seq;                     /* sequence number */
    u_int   tcp_ack;                     /* acknowledgement number */
    u_char  tcp_offx2;                   /* data offset, rsvd */
#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

void print_message(const u_char *data, int len) {
    printf("\nMessage:\n");
    for (int i = 0; i < len; i++) {
        printf("%c", isprint(data[i]) ? data[i] : '.');
    }
    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));

            int ip_header_size = ip->iph_ihl * 4;
            int tcp_header_size = TH_OFF(tcp) * 4;
            int headers_size = sizeof(struct ethheader) + ip_header_size + tcp_header_size;
            int data_size = header->caplen - headers_size;

            printf("\nEthernet Header:\n");
            printf("   Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("   Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            printf("\nIP Header:\n");
            printf("   Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("   Dst IP: %s\n", inet_ntoa(ip->iph_destip));

            printf("\nTCP Header:\n");
            printf("   Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("   Dst Port: %d\n", ntohs(tcp->tcp_dport));

           
            if (data_size > 0) {
                const u_char *data = packet + headers_size;
                print_message(data, data_size);
            }
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, 0, got_packet, NULL);

    pcap_close(handle);
    return 0;
}