#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800
#define IP_ADDR_LEN 4 


struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_ip_hdr{
   u_int8_t ip_hl:4, ip_v:4;
   u_int8_t ip_tos;
   u_int16_t ip_len;
   u_int16_t ip_id;
   u_int16_t ip_off;
   u_int8_t ip_ttl;
   u_int8_t protocol;
   u_int16_t checksum;
   u_int8_t ip_src[IP_ADDR_LEN];
   u_int8_t ip_dst[IP_ADDR_LEN];
};

struct libnet_tcp_hdr{
	u_int16_t srcPort;
	u_int16_t destPort;
	u_int32_t seqNo;
	u_int32_t ackNo;
	u_int8_t reserved:4, offset:4;
	u_int8_t flags;
	u_int16_t windowSize;
	u_int16_t checksum;
	u_int16_t urg;
	u_int8_t payload[10];
};


void printMac(u_int8_t* m) {
   printf("%02x:%02x:%02x:%02x:%02x:%02x",m[0],m[1],m[2],m[3],m[4],m[5]);
}

void printIp(struct libnet_ip_hdr* m){
   printf("%u.%u.%u.%u ",m->ip_src[0],m->ip_src[1],m->ip_src[2],m->ip_src[3]);
   printf("%u.%u.%u.%u\n",m->ip_dst[0],m->ip_dst[1],m->ip_dst[2],m->ip_dst[3]);
}

void printPort(struct libnet_tcp_hdr* m){
	printf("%u  %u\n", ntohs(m->srcPort), ntohs(m->destPort));
}

void usage() {
   printf("syntax: pcap-test <interface>\n");
   printf("sample: pcap-test wlan0\n");
}

typedef struct {
   char* dev_;
} Param;

Param param = {
   .dev_ = NULL
};
// had
bool parse(Param* param, int argc, char* argv[]) {
   if (argc != 2) {
      usage();
      return false;
   }
   param->dev_ = argv[1];
   return true;
}

int main(int argc, char* argv[]) {
   if (!parse(&param, argc, argv))
      return -1;

   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
   if (pcap == NULL) {
      fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
      return -1;
   }

   while (true) {
      struct pcap_pkthdr* header;
      const u_char* packet;
      int res = pcap_next_ex(pcap, &header, &packet);
      if (res == 0) continue;
      if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
         printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
         break;
      } 
      // had
      
      //printf("%u bytes captured\n", header->caplen);
      struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
      struct libnet_ip_hdr* ip_hdr = (struct libnet_ip_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
      struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ip_hdr));
      
      if(ntohs(eth_hdr->ether_type)!=ETHERTYPE_IP) continue;
      if(ip_hdr->protocol!=0x06) continue;
      printf("%u bytes captured\n", header->caplen);
      printMac(eth_hdr->ether_shost);
      printf(" ");
      printMac(eth_hdr->ether_dhost);
      printf("\n");
      
      printIp(ip_hdr);
      
      printPort(tcp_hdr);

	for(int i=0; i<10; i++){
		printf("%c",(tcp_hdr->payload[i]));
	}
	printf("\n");
                  
   }

   pcap_close(pcap);
}
