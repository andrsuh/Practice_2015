#ifndef PACKET_H
#define PACKET_H

#include <pcap.h>
#include <cstring>
#include <iostream>
#include <netinet/in.h>

#include "Packet_headers.h"


class Packet {
    pcap_pkthdr header;
    sniff_ethernet ethernet;
    sniff_ip ip;
    sniff_tcp tcp;
    sniff_udp udp;
    std::string payload;
    int size_ip;
    int size_tcp;
    int size_payload;
    int size_udp;

public:
    explicit Packet(const struct pcap_pkthdr * head);
    explicit Packet(const Packet& pack);

    bool is_broken;

    void parse(const u_char * packet);

    pcap_pkthdr get_header() const;
    int get_size_payload() const  { return size_payload; };
    std::string get_pload() const { return payload; };
    sniff_ip get_ip() const;
    sniff_tcp get_tcp() const;
    sniff_udp get_udp() const;
};

#endif // PACKET_H
