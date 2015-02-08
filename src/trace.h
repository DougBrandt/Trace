/***********************************************************
 *
 *    Programmer:    Douglas Brandt
 *
 *    Description:   Implement a program named trace that will output
 *                   protocal header information for a number of header
 *                   types.  The pcap library API will be used to sniff
 *                   packets.
 *
 **********************************************************/

#ifndef _TRACE_H
#define _TRACE_H

#include <pcap/pcap.h>    // on some machines it is #include <pcap.h>
#include <stdint.h>
#include <endian.h>


/* Function Prototypes */
int packet_info(int pktCount, struct pcap_pkthdr *pkt_header);
int ethernet_header_info(const unsigned char *pkt_data);
int arp_header_info(const unsigned char *pkt_data);
int ip_header_info(const unsigned char *pkt_data);
int tcp_header_info(const unsigned char *pkt_data);
int tcp_checksum_checker(const unsigned char *pkt_data);
int udp_header_info(const unsigned char *pkt_data);
int icmp_header_info(const unsigned char *pkt_data);


/* Constants  */
#define BYTES_PER_WORD  4
#define ETHERNET_HEADER_SIZE  14
#define ETHERNET_ADDR_LEN  6
#define MAC_ADDR_LEN  6
#define IP_ADDR_LEN  4
#define IP_HEADER_SIZE  20
#define ETHERNET_TYPE_ARP  0x0806              /* Address Resolution */
#define ETHERNET_TYPE_IP  0x0800               /* Internet Protocol */
#define ARP_OP_REQUEST  1
#define ARP_OP_REPLY  2
#define INET_ADDR_STR_LEN 16
#define ICMP_PROTOCOL_NUM  1
#define TCP_PROTOCOL_NUM  6
#define UDP_PROTOCOL_NUM  17
#define ICMP_ECHO_REQUEST  8
#define ICMP_ECHO_REPLY  0
#define HTTP_PORT_NUMBER  80
#define TELNET_PORT_NUMBER  23
#define FTP_PORT_NUMBER  21
#define POP3_PORT_NUMBER  101
#define SMTP_PORT_NUMBER  25


/* Structures */
struct ethernet_header {
   uint8_t dhost[ETHERNET_ADDR_LEN];            /* Destination Host Address */
   uint8_t shost[ETHERNET_ADDR_LEN];            /* Source Host Address */
   uint16_t type;                               /* ARP, IP, Unknown */
} __attribute__((__packed__));


struct arp_header {
   uint16_t htype;                              /* Hardware Type */
   uint16_t ptype;                              /* Protocol Type */
   uint8_t haddr_len;                           /* Hardware Address Length */
   uint8_t paddr_len;                           /* Protocol Address Length */
   uint16_t opcode;                             /* Opcode - Request or Reply */
   uint8_t sender_MAC[MAC_ADDR_LEN];            /* Sender MAC Address */
   uint8_t sender_IP[IP_ADDR_LEN];              /* Sender IP */
   uint8_t target_MAC[MAC_ADDR_LEN];            /* Target MAC Address */
   uint8_t target_IP[IP_ADDR_LEN];              /* Target IP */
} __attribute__((__packed__));


struct ip_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
   uint32_t header_len:4;                       /* Header Length */
   uint32_t version:4;                          /* Version Number */
#elif __BYTE_ORDER == __BIG_ENDIAN
   uint32_t version:4;                          /* Version Number */
   uint32_t header_len:4;                       /* Header Length */
#else
#error __BYTE_ORDER must be defined
#endif
   uint8_t tos;                                 /* Type of Service */
   uint16_t tot_len;                            /* Total Length */
   uint16_t id;                                 /* Identification */
   uint16_t flags_and_frag_offset;              /* Flags and Fragment Offset */
   uint8_t ttl;                                 /* Time To Live */
   uint8_t protocol;                            /* Protocol */
   uint16_t hdr_checksum;                       /* Header Checksum */
   uint8_t src_IP[IP_ADDR_LEN];                 /* Source IP */
   uint8_t dest_IP[IP_ADDR_LEN];                /* Destination IP */
} __attribute__((__packed__));


struct tcp_header {
   uint16_t src_port;                           /* Source Port */
   uint16_t dest_port;                          /* Destination Port */
   uint32_t sequence;                           /* Sequence Number */
   uint32_t ack_num;                            /* Acknowledge Number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
   uint32_t reserved_p1:4;                      /* Reserved */
   uint32_t data_offset:4;                      /* Data Offset */
   uint32_t fin:1;                              /* FIN FLAG */
   uint32_t syn:1;                              /* SYN FLAG */
   uint32_t rst:1;                              /* RST FLAG */
   uint32_t psh:1;                              /* PSH FLAG */
   uint32_t ack:1;                              /* ACK FLAG */
   uint32_t urg:1;                              /* URG FLAG */
   uint32_t reserved_p2:2;                      /* Reserved */
#elif __BYTE_ORDER == __BIG_ENDIAN
   uint32_t reserved_p1:4;                      /* Reserved */
   uint32_t data_offset:4;                      /* Data Offset */
   uint32_t reserved_p2:2;                      /* Reserved */
   uint32_t urg:1;                              /* URG FLAG */
   uint32_t ack:1;                              /* ACK FLAG */
   uint32_t psh:1;                              /* PSH FLAG */
   uint32_t rst:1;                              /* RST FLAG */
   uint32_t syn:1;                              /* SYN FLAG */
   uint32_t fin:1;                              /* FIN FLAG */
#else
#error __BYTE_ORDER must be defined
#endif
   uint16_t window;                             /* Window Size */
   uint16_t checksum;                           /* Checksum */
   uint16_t urgent_pointer;                     /* Urgent Pointer */
} __attribute__((__packed__));


struct tcp_pseudo_header {
   uint8_t src_addr[IP_ADDR_LEN];               /* Source Address */
   uint8_t dest_addr[IP_ADDR_LEN];              /* Destination Address */
   uint8_t zeros;                               /* Zeros */
   uint8_t protocol;                            /* Protocol */
   uint16_t length;                             /* TCP Length */
} __attribute__((__packed__));


struct udp_header {
   uint16_t src_port;                           /* Source Port */
   uint16_t dest_port;                          /* Destination Port */
} __attribute__((__packed__));


struct icmp_header {
   uint8_t type;                                /* Type */
   uint8_t code;                                /* Code */
} __attribute__((__packed__));

#endif // _TRACE_H
