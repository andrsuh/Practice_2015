#ifndef SESSION_H
#define SESSION_H

#include <string>
#include <netinet/in.h>
#include "Packet.h"


struct Session {
    in_addr ip_src; // souce ip address
    in_addr ip_dst; // destenation ip
    u_short port_src; // net ports
    u_short port_dst;
    std::string prot;
    u_char protocol;
    int time_to_live;
    int last_packet_time; // the arrival time of the last packet

    explicit Session();
    explicit Session(const Packet& p);

    bool is_alive() const;
    void print_session() const; // opeartor<<??
    bool operator<(const Session& b) const;
    void session_reverse();
};

#endif // SESSION_H
