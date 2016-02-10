#include "Session.h"
// #include "Packet.h"
// #include <sys/socket.h>
// #include <netinet/in.h>
#include <utility>
#include <arpa/inet.h>

#include <iostream>

using namespace std;

Session::Session() {
}

Session::Session(const Packet& p){
    sniff_ip ip = p.get_ip();
    sniff_tcp tcp = p.get_tcp();
    sniff_udp udp = p.get_udp();
    ip_src = ip.ip_src;
    ip_dst = ip.ip_dst;
    protocol = ip.ip_p;
    switch(ip.ip_p) {
        case IPPROTO_TCP:
            port_src = tcp.th_sport;
            port_dst = tcp.th_dport;
            prot = "TCP";
            break;
        case IPPROTO_UDP:
            port_src = udp.s_port;
            port_dst = udp.d_port;
            prot = "UDP";
            break;
    }
}

bool Session::operator<(const Session& other) const {
    if (ip_src.s_addr != other.ip_src.s_addr)
        return ip_src.s_addr < other.ip_src.s_addr;
    if (ip_dst.s_addr != other.ip_dst.s_addr)
        return ip_dst.s_addr < other.ip_dst.s_addr;
    if (port_src != other.port_src)
        return port_src < other.port_src;
    if (port_dst != other.port_dst)
        return port_dst < other.port_dst;
    return protocol < other.protocol;
}

void Session::print_session() const {
    cout << "From ip: " << inet_ntoa(ip_src) << "  ";
    cout << "To ip: " << inet_ntoa(ip_dst) << "     ";
    cout << "From port: " << ntohs(port_src) << "    ";
    cout << "To port: " << ntohs(port_dst) << "    ";
    cout << "Protocol " << prot << endl;
}

void Session::session_reverse() {
    // in_addr tmp_ip; // using std::swap
    // u_short tmp_port;
    // tmp_ip = ip_src;
    // ip_src = ip_dst;
    // ip_dst = tmp_ip;
    // tmp_port = port_src;
    // port_src = port_dst;
    // port_dst = tmp_port;
    swap(ip_src, ip_dst);
    swap(port_src, port_dst);
}
