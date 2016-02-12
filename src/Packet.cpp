#include <stdlib.h>
#include "Packet.h"

using namespace std;

Packet::Packet(const struct pcap_pkthdr * head): is_broken(false) {
    // Why I can't define and implement this in header?
    header = *head;
};

Packet::Packet(const Packet& pack): // wow default copy-constructor do the same?
    header(pack.header),
    ethernet(pack.ethernet),
    ip(pack.ip), tcp(pack.tcp), udp(pack.udp),
    payload(pack.payload),
    size_ip(pack.size_ip),
    size_tcp(pack.size_tcp),
    size_payload(pack.size_payload),
    size_udp(pack.size_udp)
    {};


void Packet::parse(const u_char * packet) {
    // u_char * packet ---> |ethernet_header|ip_header|transport_layer_header|payload|
    // will displace poiner and parse headers-payload

    ethernet = *(sniff_ethernet*)packet;

    ip = *(sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4; // ip_hl in 32-bytes words * 4 to bytes

    if (size_ip < 20) {
        is_broken = true;
        return;
    }

    switch(ip.ip_p) {
        case IPPROTO_TCP:
            tcp = *(sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp) * 4;

            if (size_tcp < 20) {
                return; // is_broken = true;
            }

            size_payload = ntohs(ip.ip_len) - (size_ip + size_tcp);
            payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

            break;
        case IPPROTO_UDP:

            udp = *(sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
            size_udp = UDP_LENGTH;

            if (size_udp < 8) { // lol
                is_broken = true;
                return;
            }

            size_payload = ntohs(ip.ip_len) - (size_ip + size_udp);
            payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_udp);

            break;
        default:
            is_broken = true;
            return;
    }
    return;
};



pcap_pkthdr Packet::get_header() const {
    return header;
}


sniff_ip Packet::get_ip() const {
    return ip;
}

sniff_tcp Packet::get_tcp() const {
    return tcp;
}

sniff_udp Packet::get_udp() const {
    return udp;
}
