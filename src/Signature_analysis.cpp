#include <iostream>
#include <arpa/inet.h>
#include "Configuration.h"
#include "Session.h"
#include "Signature_analysis.h"

using namespace std;


void Session_data::to_upload(const Packet& pack) {
    set_last_packet_time(pack.get_header().ts.tv_sec);
    upload.push_back(pack);
}

void Session_data::to_download(const Packet& pack) {
    set_last_packet_time(pack.get_header().ts.tv_sec);
    download.push_back(pack);
}

void Session_data::set_last_packet_time(const int new_time_val) {
    if (last_packet_time < new_time_val) {
        last_packet_time = new_time_val;
    }
}

void Session_data::set_session_solution(
    const string& solut, int priority, int num_pack
) {
    if (solution_priority < priority) {
        session_solution = solut;
        solution_priority = priority;
        solution_num_pack = num_pack;
    }
    if (solution_priority == priority && session_solution == solut) {
        if (--solution_num_pack == 0) {
            solution = true;
        }
    }
}

Signature_analysis::Signature_analysis(const std::string& config_xml_name,
        const std::string& mode, const std::string& pcap_file
    ): pcap_fname(pcap_file) {

    if (mode == "debug") { // fuu
        debug = true;
    }
    load_configurations(config_xml_name);
}

void Signature_analysis::load_configurations(const string& config_file_name) {
    Config * config = Config::get_config(); // instancing of singletone
    config->load_xml_file(config_file_name); // swaping xml with base configurations

    string f_name, host;
    in_addr ip;

    config->get_tag("sign_config"); // next peace of code sould be rewrite with templates
    config->get_attribute_str("file_name", f_name);
    config->get_attribute_str("host_ip", host); // to get host address
    inet_aton(host.c_str(), &ip);
    host_ip = ip.s_addr;
    config->get_attribute_int("session_lifetime", &sessions_lifetime);
    config->get_attribute_int("time_to_check", &time_to_check);

    load_signatures_list(f_name);
}

void Signature_analysis::load_signatures_list(const string& f_name) {
    Config * config = Config::get_config(); // instancing of singletone
    config->load_xml_file(f_name); // swaping xml with list of regexes

    do {
        string sign, type;
        int priority, num_pack;
        config->get_attribute_str("sign", sign);
        config->get_attribute_str("type", type);
        config->get_attribute_int("priority", &priority);
        config->get_attribute_int("num_pack", &num_pack);
        Traffic traffic(sign, type, priority, num_pack);
        sign_type_list.push_back(traffic);
    }
    while (config->next_tag());
    // for (auto iter: sign_type_list) {
    //     cout << iter.type << endl;
    // }
}


void Signature_analysis::add_packet(const Packet& pack) {
    // check how much time passed since last cleanup
    if (pack.get_header().ts.tv_sec - last_activity_time >= time_to_check && last_activity_time) {
        start_sessions_kill();
        last_activity_time = pack.get_header().ts.tv_sec;
    }

    Session session(pack); // get session relevant to this packet

    if (session.ip_src.s_addr != host_ip) {
        session.session_reverse();
    }

    auto iter = sessions_list.find(session);
    if (iter != sessions_list.end()) {
        if (sessions_list[session].has_solution()) {
            return;
        }
        sessions_list[session].to_upload(pack); // if exsists -> add to upload
    }
    else {
        session.session_reverse(); // if exsists -> add, else -> create
        iter = sessions_list.find(session);
        if (iter != sessions_list.end()) {
            if (sessions_list[session].has_solution()) {
                return;
            }
            sessions_list[session].to_download(pack);
        }
        else {
            session.session_reverse();
            sessions_list[session].to_upload(pack);
        }
    }

    checking_for_signatures(pack, sessions_list[session]); // does it contains

    if (sessions_list[session].has_solution()) {
        if (debug) {
            dbg_out.open("sig_results.txt", ios::app);
            dbg_out << sessions_list[session].get_session_solution() << endl;
            //dbg_out.close();
        }
        else {
            // Session_info* s_inf = Session_info::get_session_info();
            // s_inf->set_sign_solution(session, sessions_list[session].get_session_solution());
            //s_inf->set_stat_solution(session, "none");
            cout << sessions_list[session].get_session_solution() << endl;
        }
    }

}

void Signature_analysis::checking_for_signatures(
    const Packet& pack, Session_data& session
) const {
    string payload = pack.get_pload();
    for (size_t i = 0; i < sign_type_list.size(); ++i) {
        // check matchind on regex in the contents of the package
        if (regex_search(payload, sign_type_list[i].signature)) {
           session.set_session_solution(
               sign_type_list[i].type,
               sign_type_list[i].priority,
               sign_type_list[i].num_pack
           );
        }
    }
}

void Signature_analysis::start_sessions_kill() {
    for (auto iter: sessions_list) {
        if (!is_alive(iter.second)) {
            // Session_info* s_inf = Session_info::get_session_info();
            // if (!debug) {
            //     s_inf->set_sign_solution(iter->first, "none");
            // }
            // free_session_packets(iter->second);
            sessions_list.erase(iter.first);
        }
    }
}

bool Signature_analysis::is_alive(const Session_data& s_data) const {
    return !(last_activity_time - s_data.get_last_packet_time() > sessions_lifetime);
}

Signature_analysis::~Signature_analysis() {}

void Signature_analysis::print_sessions_list() {
    ofstream s_out;
    s_out.open("session_without_solution_pload.txt", ios::out);
    for (auto iter: sessions_list) {
        Session session = iter.first;
        Session_data s_date = iter.second;

        if (!s_date.has_solution()) {
            session.print_session();

            vector<Packet> upload = s_date.get_upload();
            vector<Packet> download = s_date.get_download();

            for (size_t i = 0; i < download.size(); ++i) {
                s_out << download[i].get_pload() << endl;
            }
            s_out << endl << "----------------------------------" << endl;
            for (size_t i = 0; i < upload.size(); ++i) {
                s_out << upload[i].get_pload() << endl;
            }
            s_out << endl << "/********************************/" << endl;
        }
    }
    // out.close();
}
