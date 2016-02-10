#ifndef SIGNATURE_ANALISATOR_H
#define SIGNATURE_ANALISATOR_H

#include <fstream>
#include <regex>
#include <vector>
#include "Packet.h"
// #include "Session_info.h"
#include "Session.h"


struct Traffic {
    std::string type; // type as BROWSING, VIDEO, AUDIO etc
    std::regex signature; // as example "HTTP/1.*"
    size_t priority;
    size_t num_pack; // how many packets enough to confirm the belong type

    Traffic(const std::string& signature, const std::string& type, int p, int n):
        signature(signature), type(type), priority(p), num_pack(n) {}
};

class Session_data {
private:
    bool solution = false; // have we solution?
    int solution_priority = -1; // its difficult to explain
    size_t solution_num_pack = 0; // how many packets we have in moment
    std::string session_solution;
    size_t last_packet_time = 0; // last activity in this session

    // In our case, we do not need to store packets.
    // But we expect to use it in the future
    std::vector<Packet> upload;
    std::vector<Packet> download;

    void set_last_packet_time(const int new_time_val);
public:

    bool has_solution() const { return solution; }
    std::string get_session_solution() const { return session_solution; }
    void set_session_solution(const std::string& solution, int priority, int num_pack);

    void to_upload(const Packet& pack);
    void to_download(const Packet& pack);

    std::vector<Packet>& get_upload() { return upload; }
    std::vector<Packet>& get_download() { return download; }

    int get_last_packet_time() const { return last_packet_time; }

};


class Signature_analysis {
private:
    std::map<Session, Session_data> sessions_list;
    std::vector<Traffic> sign_type_list;
    std::ofstream out;

    int host_ip; // our address. attention! it must be contains in xml!
    int last_activity_time = 0;
    int sessions_lifetime; // in xml
    int time_to_check;

    bool debug = false;
    std::string pcap_fname;
    std::ofstream dbg_out;


    void load_configurations(const std::string& config_file_name);
    void load_signatures_list(const std::string& f_name);
    void checking_for_signatures(const Packet& pack, Session_data& ) const;
    void start_sessions_kill();
    bool is_alive(const Session_data& s_data) const;
    void free_session_packets(Session_data& s_data);
public:

    Signature_analysis(const std::string& config_xml_name, const std::string& mode, const std::string& pcap_file);
    ~Signature_analysis();

    void print_sessions_list();
    void add_packet(const Packet& pack);

};

#endif // SIGNATURE_ANALISATOR_H
