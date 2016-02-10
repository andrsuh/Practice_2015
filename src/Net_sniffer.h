#ifndef NET_SNIFFER_H
#define NET_SNIFFER_H

#include <pcap.h>
#include "Packet.h"
#include <string>


class Net_sniffer {
private:
    std::string device;
    bool is_live; // mode online net traffic or *.pcap file with damp
    std::string filter_exp;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle;
    bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

public:
    Net_sniffer();
    Net_sniffer(const std::string& device, const std::string& protocol, bool mode);

    void start_sniff();
    static void got_packet(u_char *args, const pcap_pkthdr *header, const u_char *packet);
};

#endif // NET_SNIFFER_H
