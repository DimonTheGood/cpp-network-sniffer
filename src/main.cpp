#include <iostream>    
#include <pcap.h>        
#include <net/ethernet.h> 
#include <netinet/ip.h>   
#include <netinet/ip6.h>  
#include <netinet/udp.h>
#include <netinet/tcp.h> 
#include <arpa/inet.h>   


void print_dns_name(const u_char *reader) {
    while (*reader != 0) {
        int len = *reader;
        reader++;
        for (int i = 0; i < len; i++) {
            std::cout << *reader;
            reader++;
        }
        if (*reader != 0) std::cout << ".";
    }
    std::cout << std::endl;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    struct ether_header *eth = (struct ether_header *)pkt_data;
    uint16_t type = ntohs(eth->ether_type);

    // --- ОБРАБОТКА IPv4 ---
    if (type == ETHERTYPE_IP) {
        struct ip *ip_hdr = (struct ip *)(pkt_data + 14);
        int ip_len = ip_hdr->ip_hl * 4; 
        
        std::cout << "\n[IPv4] " << inet_ntoa(ip_hdr->ip_src) << " -> " << inet_ntoa(ip_hdr->ip_dst);
        
        // 1. Проверка на UDP
        if (ip_hdr->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_hdr = (struct udphdr *)(pkt_data + 14 + ip_len);
            uint16_t sport = ntohs(udp_hdr->uh_sport);
            uint16_t dport = ntohs(udp_hdr->uh_dport);
            
            // Анализ DNS (запросы имен сайтов)
            if (dport == 53 || sport == 53) {
                std::cout << " | DNS Query: ";
                // Пропускаем: Eth(14) + IP(ip_len) + UDP(8) + DNS_Header(12)
                print_dns_name(pkt_data + 14 + ip_len + 8 + 12);
            }
            // Анализ DHCP (имена устройств)
            else if (dport == 67 || dport == 68 || sport == 67 || sport == 68) {
                std::cout << " | DHCP Detected";
                const u_char *dhcp_opts = pkt_data + 14 + ip_len + 8 + 240;
                int i = 0;
                while (i < 300) {
                    if (dhcp_opts[i] == 255) break;
                    if (dhcp_opts[i] == 0) { i++; continue; }
                    if (dhcp_opts[i] == 12) { // Код опции Host Name
                        std::cout << " | DEVICE NAME: ";
                        for (int j = 0; j < dhcp_opts[i+1]; j++) printf("%c", dhcp_opts[i+2+j]);
                        break;
                    }
                    i += 2 + dhcp_opts[i+1];
                }
                std::cout << std::endl;
            } else {
                std::cout << " | UDP Port: " << sport << " -> " << dport << std::endl;
            }
        }
        // 2. Проверка на TCP
        else if (ip_hdr->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_hdr = (struct tcphdr *)(pkt_data + 14 + ip_len);
            uint16_t sport = ntohs(tcp_hdr->th_sport);
            uint16_t dport = ntohs(tcp_hdr->th_dport);
            
            if (dport == 53 || sport == 53) {
                std::cout << " | DNS over TCP (Rare)";
                // В TCP DNS пакете есть лишние 2 байта длины перед заголовком
                print_dns_name(pkt_data + 14 + ip_len + (tcp_hdr->th_off * 4) + 2 + 12);
            } else {
                std::cout << " | TCP Port: " << sport << " -> " << dport << std::endl;
            }
        }
    } 
    // --- ОБРАБОТКА IPv6 ---
    else if (type == ETHERTYPE_IPV6) {
        struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(pkt_data + 14);
        char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_str, INET6_ADDRSTRLEN);
        std::cout << "\n[IPv6] " << src_str << " -> " << dst_str << std::endl;
    }
}

int main() {
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *dev = "eth0"; //ИМЯ ВАШЕГО СЕТЕВОГО УСТРОЙСТВА

    handle = pcap_open_live(dev, 65535, 1, 1000, errbuff);
    if (handle == NULL) {
        std::cerr << "Couldn't open device: " << errbuff << std::endl;
        return 1;
    }

    std::cout << "Sniffer started! Listening for DNS, DHCP, TCP and UDP..." << std::endl;
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}