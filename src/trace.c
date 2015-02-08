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


#include "trace.h"                  // my define structs and function prototypes
#include "checksum.h"               // in_cksum()
#include <stdio.h>                  // fprintf()
#include <stdlib.h>                 // exit()
#include <string.h>                 // memcpy()
#include <pcap/pcap.h>              // pcap_open_offline(), pcap_close(), pcap_perror(), pcap_next_ex
#include <netinet/ether.h>          // ether_ntoa(),
#include <arpa/inet.h>              // ntohs(), htons(), inet_ntop()


int main(int argc, char *argv[]) {

   int retVal = 0, endLoop = 0, pktCount = 0;
   char errbuf[PCAP_ERRBUF_SIZE] = "";
   pcap_t *pcap_handle;
   struct pcap_pkthdr *pkt_header;
   const unsigned char *pkt_data;

   if (argc != 2) {
      fprintf(stderr, "usage: ./trace filename\n");
      exit(EXIT_FAILURE);
   }

   if ((pcap_handle = pcap_open_offline(argv[1], errbuf)) == NULL) {
      fprintf(stderr, "Failed to open pcap file %s: %s\n", argv[1], errbuf);
      exit(EXIT_FAILURE);
   }

   while (1) {
      pktCount++;
      retVal = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);

      switch (retVal) {
         case 1:     // read with no problems
            packet_info(pktCount, pkt_header);
            ethernet_header_info(pkt_data);
            break;
         case 0:     // live capture read success
            fprintf(stderr, "error: this program shouldn't be live capturing\n");
            endLoop = 1;
            break;
         case -1:    // error reading packet
            pcap_perror(pcap_handle, "pcap_next_ex failed\n");
            endLoop = 1;
            break;
         case -2:    // no more packets
            endLoop = 1;
            break;
         default:
            fprintf(stderr, "error: unknown return value from pcap_next_ex()\n");
            endLoop = 1;
            break;
      }

      if (endLoop) {
         break;
      }
   }

   pcap_close(pcap_handle);

   exit(EXIT_SUCCESS);
}

/**************************
 *
 *	Output the packet information:
 *      Packet Number and Packet Length
 *
 **************************/
int packet_info(int pktCount, struct pcap_pkthdr *pkt_header) {

   printf("\nPacket number: %d  Packet Len: %d\n\n", pktCount, pkt_header->len);

   return 0;
}

/**************************
 *
 *  Output the Ethernet Header information:
 *      Dest MAC:
 *      Sourcse MAC:
 *      Type: ARP/IP/Unknown
 *
 **************************/
int ethernet_header_info(const unsigned char *pkt_data) {

   struct ethernet_header *ethernet;
   ethernet = (struct ethernet_header *)(pkt_data);

   printf("\tEthernet Header\n");

   printf("\t\tDest MAC: %s\n", 
         ether_ntoa((const struct ether_addr *)(ethernet->dhost)));

   printf("\t\tSource MAC: %s\n", 
         ether_ntoa((const struct ether_addr *)(ethernet->shost)));

   if (ntohs(ethernet->type) == ETHERNET_TYPE_ARP) {
      printf("\t\tType: ARP\n\n");
      arp_header_info(pkt_data + ETHERNET_HEADER_SIZE);
   } else if (ntohs(ethernet->type) == ETHERNET_TYPE_IP) {
      printf("\t\tType: IP\n\n");
      ip_header_info(pkt_data + ETHERNET_HEADER_SIZE);
   } else {
      printf("\t\tType: Unknown\n\n");
   }

   return 0;
}


/**************************
 *
 *  Output the ARP Header information:
 *      Opcode:  Request/Reply
 *      Sender MAC:
 *      Sender IP:
 *      Target MAC:
 *      Target IP:
 *
 **************************/
int arp_header_info(const unsigned char *pkt_data) {

   char ip_addr_dest[INET_ADDR_STR_LEN] = "";
   struct arp_header *arp;
   arp = (struct arp_header *)(pkt_data);

   printf("\tARP header\n");

   if (ntohs(arp->opcode) == ARP_OP_REQUEST) {
      printf("\t\tOpcode: Request\n");
   } else {
      printf("\t\tOpcode: Reply\n");
   }

   printf("\t\tSender MAC: %s\n",
         ether_ntoa((const struct ether_addr *)(arp->sender_MAC)));

   inet_ntop(AF_INET, arp->sender_IP, ip_addr_dest, INET_ADDR_STR_LEN);
   printf("\t\tSender IP: %s\n", ip_addr_dest);

   printf("\t\tTarget MAC: %s\n",
         ether_ntoa((const struct ether_addr *)(arp->target_MAC)));

   inet_ntop(AF_INET, arp->target_IP, ip_addr_dest, INET_ADDR_STR_LEN);
   printf("\t\tTarget IP: %s\n\n", ip_addr_dest);

   return 0;
}

/**************************
 *
 *  Output the IP Header information:
 *      TOS:
 *      Time to live:
 *      Protocol:  ICMP/TCP/UDP/Unknown
 *      Header checksum:  Correct/Incorrect
 *      Source IP:
 *      Destination IP:
 *
 **************************/
int ip_header_info(const unsigned char *pkt_data) {

   int unknown_flag = 0;
   char ip_addr[INET_ADDR_STR_LEN] = "";
   struct ip_header *ip;
   ip = (struct ip_header *)(pkt_data);

   printf("\tIP Header\n");

   printf("\t\tTOS: 0x%x\n", ip->tos);

   printf("\t\tTTL: %u\n", ip->ttl);

   switch (ip->protocol) {
      case ICMP_PROTOCOL_NUM:
         printf("\t\tProtocol: ICMP\n");
         break;
      case TCP_PROTOCOL_NUM:
         printf("\t\tProtocol: TCP\n");
         break;
      case UDP_PROTOCOL_NUM:
         printf("\t\tProtocol: UDP\n");
         break;
      default:
         printf("\t\tProtocol: Unknown\n");
         unknown_flag = 1;
         break;
   }

   unsigned short checksum = in_cksum((unsigned short *)ip, 
         ip->header_len * BYTES_PER_WORD);

   if (checksum == 0) {
      printf("\t\tChecksum: Correct (0x%x)\n", ntohs(ip->hdr_checksum));
   } else {
      printf("\t\tChecksum: Incorrect (0x%x)\n", ntohs(ip->hdr_checksum));
   }

   inet_ntop(AF_INET, ip->src_IP, ip_addr, INET_ADDR_STR_LEN);
   printf("\t\tSender IP: %s\n", ip_addr);

   inet_ntop(AF_INET, ip->dest_IP, ip_addr, INET_ADDR_STR_LEN);
   if (unknown_flag) {
      printf("\t\tDest IP: %s\n", ip_addr);
   } else {
      printf("\t\tDest IP: %s\n\n", ip_addr);
   }

   switch (ip->protocol) {
      case ICMP_PROTOCOL_NUM:
         icmp_header_info(pkt_data + (ip->header_len * BYTES_PER_WORD));
         break;
      case TCP_PROTOCOL_NUM:
         tcp_header_info(pkt_data);
         break;
      case UDP_PROTOCOL_NUM:
         udp_header_info(pkt_data + (ip->header_len * BYTES_PER_WORD));
         break;
      default:
         break;
   }

   return 0;
}

/**************************
 *
 *  Output the TCP Header information:
 *      Source Port:  HTTP(80)/Telnet(23)/FTP(21)/POP3(101)/
 *                    SMTP(25)/otherwise output port number
 *      Dest Port:    HTTP(80)/Telnet(23)/FTP(21)/POP3(101)/
 *                    SMTP(25)/otherwise output port number
 *      Sequence Number:
 *      ACK Number:
 *      SYN Flag:  (Yes or No)
 *      RST Flag:  (Yes or No)
 *      FIN Flag:  (Yes or No)
 *      Window Size:
 *
 **************************/
int tcp_header_info(const unsigned char *pkt_data) {

   struct ip_header *ip;
   ip = (struct ip_header *)(pkt_data);
   struct tcp_header *tcp;
   tcp = (struct tcp_header *)(pkt_data + (ip->header_len * BYTES_PER_WORD));

   printf("\tTCP Header\n");

   switch (ntohs(tcp->src_port)) {
      case HTTP_PORT_NUMBER:
         printf("\t\tSource Port: HTTP\n");
         break;
      case TELNET_PORT_NUMBER:
         printf("\t\tSource Port: Telnet\n");
         break;
      case FTP_PORT_NUMBER:
         printf("\t\tSource Port: FTP\n");
         break;
      case POP3_PORT_NUMBER:
         printf("\t\tSource Port: POP3\n");
         break;
      case SMTP_PORT_NUMBER:
         printf("\t\tSource Port: SMTP\n");
         break;
      default:
         printf("\t\tSource Port:  %u\n", ntohs(tcp->src_port));
         break;
   }

   switch (ntohs(tcp->dest_port)) {
      case HTTP_PORT_NUMBER:
         printf("\t\tDest Port: HTTP\n");
         break;
      case TELNET_PORT_NUMBER:
         printf("\t\tDest Port: Telnet\n");
         break;
      case FTP_PORT_NUMBER:
         printf("\t\tDest Port: FTP\n");
         break;
      case POP3_PORT_NUMBER:
         printf("\t\tDest Port: POP3\n");
         break;
      case SMTP_PORT_NUMBER:
         printf("\t\tDest Port: SMTP\n");
         break;
      default:
         printf("\t\tDest Port:  %u\n", ntohs(tcp->dest_port));
         break;
   }

   printf("\t\tSequence Number: %u\n", ntohl(tcp->sequence));

   printf("\t\tACK Number: %u\n", ntohl(tcp->ack_num));

   printf("\t\tSYN Flag: %s\n", tcp->syn ? "Yes" : "No");

   printf("\t\tRST Flag: %s\n", tcp->rst ? "Yes" : "No");

   printf("\t\tFIN Flag: %s\n", tcp->fin ? "Yes" : "No");

   printf("\t\tWindow Size: %u\n", ntohs(tcp->window));

   tcp_checksum_checker(pkt_data);

   return 0;
}


/**************************
 *
 *  Output the TCP Header information:
 *      Checksum:  (Correct or Incorrect)
 *
 **************************/
int tcp_checksum_checker(const unsigned char *pkt_data) {

   struct ip_header *ip;
   ip = (struct ip_header *)(pkt_data);
   struct tcp_header *tcp;
   tcp = (struct tcp_header *)(pkt_data + (ip->header_len * BYTES_PER_WORD));

   uint32_t tot_checksum_length = sizeof(struct tcp_pseudo_header) + 
      ntohs(ip->tot_len) - 
      (ip->header_len * BYTES_PER_WORD);

   unsigned char *total_hdr = (unsigned char *)malloc(tot_checksum_length);

   struct tcp_pseudo_header *tcp_pseudo_hdr = (struct tcp_pseudo_header *)total_hdr;

   memcpy(tcp_pseudo_hdr->src_addr, ip->src_IP, IP_ADDR_LEN);
   memcpy(tcp_pseudo_hdr->dest_addr, ip->dest_IP, IP_ADDR_LEN);
   tcp_pseudo_hdr->zeros = 0;
   tcp_pseudo_hdr->protocol = ip->protocol;
   tcp_pseudo_hdr->length = htons(ntohs(ip->tot_len) - 
         (ip->header_len * BYTES_PER_WORD));

   memcpy(total_hdr + sizeof(struct tcp_pseudo_header), tcp, 
         tcp->data_offset * BYTES_PER_WORD);

   memcpy(total_hdr + sizeof(struct tcp_pseudo_header), tcp, 
         ntohs(ip->tot_len) - (ip->header_len * BYTES_PER_WORD));

   unsigned short checksum = in_cksum((unsigned short *)total_hdr, 
         tot_checksum_length);

   if (checksum == 0) {
      printf("\t\tChecksum: Correct (0x%x)\n", ntohs(tcp->checksum));
   } else {
      printf("\t\tChecksum: Incorrect (0x%x)\n", ntohs(tcp->checksum));
   }

   free(total_hdr);
   total_hdr = NULL;

   return 0;
}

/**************************
 *
 *  Output the UDP Header information:
 *      Source Port:  HTTP(80)/Telnet(23)/FTP(21)/POP3(101)/
 *                    SMTP(25)/otherwise output port number
 *      Dest Port:    HTTP(80)/Telnet(23)/FTP(21)/POP3(101)/
 *                    SMTP(25)/otherwise output port number
 *
 **************************/
int udp_header_info(const unsigned char *pkt_data) {

   struct udp_header *udp;
   udp = (struct udp_header *)(pkt_data);

   printf("\tUDP Header\n");

   switch (ntohs(udp->src_port)) {
      case HTTP_PORT_NUMBER:
         printf("\t\tSource Port: HTTP\n");
         break;
      case TELNET_PORT_NUMBER:
         printf("\t\tSource Port: Telnet\n");
         break;
      case FTP_PORT_NUMBER:
         printf("\t\tSource Port: FTP\n");
         break;
      case POP3_PORT_NUMBER:
         printf("\t\tSource Port: POP3\n");
         break;
      case SMTP_PORT_NUMBER:
         printf("\t\tSource Port: SMTP\n");
         break;
      default:
         printf("\t\tSource Port:  %u\n", ntohs(udp->src_port));
         break;
   }

   switch (ntohs(udp->dest_port)) {
      case HTTP_PORT_NUMBER:
         printf("\t\tDest Port: HTTP\n");
         break;
      case TELNET_PORT_NUMBER:
         printf("\t\tDest Port: Telnet\n");
         break;
      case FTP_PORT_NUMBER:
         printf("\t\tDest Port: FTP\n");
         break;
      case POP3_PORT_NUMBER:
         printf("\t\tDest Port: POP3\n");
         break;
      case SMTP_PORT_NUMBER:
         printf("\t\tDest Port: SMTP\n");
         break;
      default:
         printf("\t\tDest Port:  %u\n", ntohs(udp->dest_port));
         break;
   }

   return 0;
}

/**************************
 *
 *  Output the ICMP Header information:
 *      Type:  Echo Request/Echo Reply/Unknown
 *
 **************************/
int icmp_header_info(const unsigned char *pkt_data) {

   struct icmp_header *icmp;
   icmp = (struct icmp_header *)(pkt_data);

   printf("\tICMP Header\n");

   switch (icmp->type) {
      case ICMP_ECHO_REQUEST:
         printf("\t\tType: Request\n");
         break;
      case ICMP_ECHO_REPLY:
         printf("\t\tType: Reply\n");
         break;
      default:
         printf("\t\tType: Unknown\n");
         break;
   }

   return 0;
}

