#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <stdlib.h>

struct EthernetHeader {
        uint8_t destmac[6]; /// 이더넷은 L2레이어이기 때문에 mac주소 데이터만 포함하고 있다
        uint8_t srcmac[6];
        uint8_t ethtype[2]; /// L3 프로토콜의 정보를 담고있다
    };

    struct IPHeader {
        uint8_t ip_ver_and_len; /// 8바이트 이하의 자료형이 없어서 2가지의 헤더를 포함했다
        uint8_t ip_tos; ///
        uint16_t ip_total_len;

        uint16_t ip_id;
        uint16_t ip_offset;

        uint8_t ip_ttl;
        uint8_t ip_proto;
        uint16_t ip_checksum;

        uint8_t ip_scradd[4];
        uint8_t ip_destaddr[4];
    };

    struct TCPHeader {
        uint16_t src_port;
        uint16_t dest_port;

        uint32_t sequence;
        uint32_t ack;
        uint32_t flags;

        uint16_t window;
        uint16_t checksum;
        uint16_t pointer;
    };

void usage() {

  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");

}


void print_mac(uint8_t *mac){
    for (int i =0; i < 6; i++){
        if (i != 0) printf(":");
        printf(" %02X", mac[i]);
    }
}

void print_ip(uint8_t *ip) {
  printf("ip: %u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(uint16_t *p){
    uint16_t port = *p;
    port = (uint16_t)((port>>8)|(port<<8));

    printf("port: %u\n", port);
}

int main(int argc, char* argv[]) {

  if (argc != 2) {
    usage();
    return -1;

  }



  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;

  }



  while (true) {

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;


        struct EthernetHeader *eth = (struct EthernetHeader*)packet;
        struct IPHeader *ip = (struct IPHeader*)eth+sizeof(EthernetHeader);
        struct TCPHeader *p = (struct TCPHeader*)ip+sizeof(IPHeader);
    printf("========================================================\n");
    printf("%u bytes captured\n", header->caplen);


           print_mac(eth->destmac);
           print_mac(eth->srcmac);
           print_mac(eth->ethtype);
           print_ip(ip->ip_scradd);
           print_ip(&ip->ip_ver_and_len);
           print_ip(&ip->ip_tos);
           /// 2.2
           print_ip(&ip->ip_ttl);
           print_ip(&ip->ip_proto);
           print_port(&p->src_port);
           print_port(&p->dest_port);



}
  pcap_close(handle);

  return 0;

    }
