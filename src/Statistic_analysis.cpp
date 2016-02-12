#include <iostream>
#include <fstream>
#include <netinet/in.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <float.h>

#include "Solution_info.h"
#include "Statistic_analysis.h"


using namespace std;

Statistic_analysis::Statistic_analysis(const std::string& config_xml_name,
    const std::string& stage, const std::string& working_mode,
    const std::string& learning_type, const std::string& device):
    pcap_filename(device), learning_type(learning_type) {

    work_mode = (working_mode == "learn") ? LEARNING_MODE : DETECTION_MODE;
    dev_mode = (stage == "debug") ? DEBUG_MODE : WORKING_MODE;

    get_config(config_xml_name);
    dbg_processed_sessions_counter = 0;
    last_process_time = 0;
    if (dev_mode == DEBUG_MODE) {
    	dbg_result_filename = "build/results.txt";
        mkdir("build/result", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    }
}

void Statistic_analysis::get_config(const string& filename) { // initialization
    main_config = Config::get_config(); // instancing singleton
    main_config->load_xml_file(filename); //  swapping config xnl file
    main_config->get_tag("stat_config");

    string f_name;
    main_config->get_attribute_str("file_name", f_name);
    string tmp;
    main_config->get_attribute_str("host_ip", tmp);
    in_addr temp2;
    int t = inet_aton(tmp.c_str(), &temp2);
    host_ip = temp2.s_addr;

    main_config->get_attribute("state_period", state_period);
    main_config->get_attribute("state_limit", state_limit);
    main_config->get_attribute("session_time_limit", session_time_limit);
    main_config->get_attribute("none_limit", none_limit);
    main_config->get_attribute("time_to_live", time_to_live);

    main_config->load_xml_file(f_name);
    if (work_mode == DETECTION_MODE) {
         do {
            vector<double> v(4);
            string type;
            main_config->get_attribute_str("type", type);
            main_config->get_attribute("none", v[0]);
            main_config->get_attribute("upload", v[1]);
            main_config->get_attribute("download", v[2]);
            main_config->get_attribute("interactive", v[3]);
            statistic_data.insert(pair<string, vector<double> >(type, v));
        } while (main_config->next_tag());
    }
}

void Statistic_analysis::add_packet(const Packet& p) {
    // cout << "add" << process_interval << endl;
    int p_time = p.get_header().ts.tv_sec;
    if (p_time - last_process_time > process_interval) {
        process_dead_sessions(p_time);
        last_process_time = p_time;
    }

    int p_size = p.get_size_payload();
    Session session(p); // get session relevant to this packet

    bool is_reversed = false; // it means that ip_src == host_ip
    if (session.ip_src.s_addr != host_ip) {
        is_reversed = true;
        session.session_reverse();
    }

    auto it = pack_time.find(session);
    if (!is_reversed && it != pack_time.end()) {   // packet to uplink
        add_second(it->second.uplink, it->second, p_time, p_size);
    } else if (is_reversed && it != pack_time.end()) {   // packet to downlink
        add_second(it->second.downlink, it->second, p_time, p_size);
    } else {
        Packages new_session = pack_time[session];
        if (!is_reversed) {
            add_second(new_session.uplink, new_session, p_time, p_size);
        }
        else {
            add_second(new_session.downlink, new_session, p_time, p_size);
        }
    }
}

void Statistic_analysis::process_dead_sessions(int current_time) {
    auto it = pack_time.begin();
    while (it != pack_time.end()) {
        if (!it->second.is_alive(current_time, time_to_live)) {
            process_session(it->first, it->second);
            pack_time.erase(it++);
        }
        else it++;
    }
}

// its return bool but what for
bool Statistic_analysis::process_session(const Session& s, Packages& p) {

    Solution_info * s_inf = Solution_info::get_session_info();

    if (p.downlink.size() < session_time_limit
            && p.uplink.size() < session_time_limit)
    { // short session
        s_inf->set_stat_solution(s, "none");
        return false;
    }


    fill_if_not_equal(p);

    // if true -> at least one window in vector has traffic
    bool state_uplink = fill_state(p.uplink, p.up_state);
    bool state_downlink = fill_state(p.downlink, p.down_state);

    if ((state_uplink || state_downlink) && fill_period_type(p)) {
        if (dev_mode == DEBUG_MODE) {
            dbg_write_session_to_file(s, p);
        }
        if (work_mode == LEARNING_MODE) {
            main_config->write_stat_to_xml(learning_type,
                                            pcap_filename, p.type_percent);
        }
        if (work_mode == DETECTION_MODE) {
            string decision = get_nearest(p);
            dbg_write_decision(decision);
            s_inf->set_stat_solution(s, decision); // print session
        }
    } else {
        s_inf->set_stat_solution(s, "none");
    }

    ++dbg_processed_sessions_counter;

    return true;
}

bool Statistic_analysis::fill_state(const vector<int>& v, vector<bool>& state) {
	int false_counter = 0; // how many window has no traffic (less than boundary)
    int sum_over_window = 0; // size_t

    size_t index = 0;
    for (auto i: v) {
        sum_over_window += i;
		if (index++ % state_period == 0) {
		    if (sum_over_window > state_limit) {
			    state.push_back(true);
		    }
		    else {
                ++false_counter;
			    state.push_back(false);
		    }
		    sum_over_window = 0;
	    }
    }

	return !(false_counter == state.size());
}

bool Statistic_analysis::fill_period_type(Packages& p) {
    static int counter = 0;

    ++counter;

    int null_counter = 0; // count NONE Traffic type
    Traffic_type traffic_type;

    // for every window will detect traffic traffic_type
    // if we had up and down traffic in moment -> INTERACTIVE etc.
    for (size_t i = 0; i < p.up_state.size(); ++i) {
        if (p.up_state[i] && p.down_state[i]) {
            traffic_type = TYPE_INTERACTIVE;
        }
        else if (!p.up_state[i] && p.down_state[i]) {
            traffic_type = TYPE_DOWNLOAD;
        }
        else if (p.up_state[i] && !p.down_state[i]) {
            traffic_type = TYPE_UPLOAD;
        }
        else {
            traffic_type = TYPE_NONE;
            ++null_counter;
        }
        p.period_type.push_back(traffic_type);
        p.type_percent[(int)traffic_type]++;
    }

    for (size_t i = 0; i < p.type_percent.size(); ++i) {
        p.type_percent[i] /= p.up_state.size();
    }

    return !(p.type_percent[TYPE_NONE] > none_limit);
}

void Statistic_analysis::fill_if_not_equal(Packages& p) {
    if (p.downlink.size() > p.uplink.size()) {
        p.uplink.resize(p.downlink.size());
    }
    else if (p.downlink.size() < p.uplink.size()) {
        p.downlink.resize(p.uplink.size());
    }
}

void Statistic_analysis::process_all_sessions() {
    for (auto iter: pack_time) {
        process_session(iter.first, iter.second);
        pack_time.erase(iter.first);
    }
}

bool Packages::is_alive(int current_time, int time_to_live) {
    return (current_time - last_packet_time()) < time_to_live;
}

int Packages::last_packet_time() {
    return (uplink.size() > downlink.size()) ?
    uplink.size() + init_sec : downlink.size() + init_sec;
}

void Statistic_analysis::add_second(vector<int>& link, Packages& pack,
    int p_time, int size) {

    if (pack.init_sec == 0) {
        pack.init_sec = p_time; // if its first packet -> its start session time
    }

    // link.size() == current second since session start
    if (p_time > pack.init_sec + link.size() - 1) {
        link.resize(p_time - pack.init_sec + 1);
    }

    link[link.size() - 1] += size; // summ all payload sizes in this second
}

bool Statistic_analysis::hosts_equal(Session const &s1, Session const &s2) const {
    return (s1.ip_src.s_addr == s2.ip_src.s_addr && s1.ip_dst.s_addr == s2.ip_dst.s_addr);
}

void Statistic_analysis::move_session(const vector<int>& src,
    const int src_init_sec, vector<int>& dst, const int dst_init_sec) {

    if (src_init_sec + src.size() - dst_init_sec > dst.size()) {
        dst.resize(src_init_sec + src.size() - dst_init_sec);
    }
    for (size_t i = 0; i < src.size(); ++i) {
        dst[src_init_sec - dst_init_sec + i] += src[i];
    }
}

void Statistic_analysis::merge_sessions() {
    auto prev = pack_time.begin();
    auto cur = pack_time.begin();
    cur++;
    bool flag = false;
    while (cur != pack_time.end()) {
        if (hosts_equal(prev->first, cur->first)) {
            if (cur->second.init_sec < prev->second.init_sec) { // сессия cur началась раньше
                move_session(
                    prev->second.uplink, prev->second.init_sec,
                    cur->second.uplink, cur->second.init_sec
                );
                move_session(
                    prev->second.downlink, prev->second.init_sec,
                    cur->second.downlink, cur->second.init_sec
                );
                pack_time.erase(prev++);
                ++cur;
            }
            else {
                move_session(
                    cur->second.uplink, cur->second.init_sec,
                    prev->second.uplink, prev->second.init_sec
                );
                move_session(
                    cur->second.downlink, cur->second.init_sec,
                    prev->second.downlink, prev->second.init_sec
                );
                pack_time.erase(cur++);
            }
        } else {
            prev = cur;
            ++cur;
        }
    }
}

string Statistic_analysis::get_nearest(Packages& p) const {
    double min = DBL_MAX;
    string min_name;

    for(auto iter: statistic_data) {
        double d = 0;
        for (size_t j = 0; j < p.type_percent.size(); ++j) {
            d += (
                p.type_percent[j] - iter.second[j]) * (p.type_percent[j] - iter.second[j]
            );
        }
        if (d < min) {
            min_name = iter.first;
            min = d;
        }
    }

    return min_name;
}

Statistic_analysis::~Statistic_analysis() {
    merge_sessions();
    process_all_sessions();
}


void Statistic_analysis::dbg_write_session_to_file(const Session& first,
        const Packages& second) const {

    string file_name = "build/result/ses" +
        to_string(dbg_processed_sessions_counter) + "_uplink.txt";
    ofstream out_up(file_name);

    for (size_t i = 0; i < second.uplink.size(); ++i) {
        out_up << i << " " << second.uplink[i] << endl;
    }
    out_up.close();

    file_name = "result/ses" +
        to_string(dbg_processed_sessions_counter) + "_downlink.txt";
    ofstream out_down(file_name);
    for (size_t i = 0; i < second.downlink.size(); ++i) {
        out_down << i << " " <<  second.downlink[i] << endl;
    }
    out_down.close();

    int period = state_period;
    file_name = "result/ses" +
        to_string(dbg_processed_sessions_counter) + "_up_state.txt";
    ofstream out_up_state(file_name);
    if (second.up_state.size() != 0) {
        out_up_state << 0 << " " << second.up_state[0] << endl;
    }

    for (size_t i = 0; i < second.up_state.size(); ++i) {
        out_up_state << (i + 1) * period - 1 << " " << second.up_state[i] << endl;
    }
    out_up_state.close();

    file_name = "result/ses" +
        to_string(dbg_processed_sessions_counter) + "_down_state.txt";
    ofstream out_down_state(file_name);
    if (second.down_state.size() != 0) {
        out_down_state << 0 << " " << second.down_state[0] << endl;
    }
    for (size_t i = 0; i < second.down_state.size(); ++i) {
        out_down_state << (i + 1) * period - 1 << " " << second.down_state[i] << endl;
    }
    out_down_state.close();

    file_name = "result/ses" +
        to_string(dbg_processed_sessions_counter) + "_period_types.txt";
    ofstream out_period_types(file_name);

    if (second.period_type.size() != 0) {
        out_period_types << 0 << " " << second.period_type[0] << endl;
    }
    for (size_t i = 0; i < second.period_type.size(); ++i) {
        out_period_types << (i + 1) * period - 1 << " " << second.period_type[i] << endl;
        out_period_types << (i + 1) * period - 1 << " " << second.period_type[i] << endl;
    }
    out_period_types.close();
}

void Statistic_analysis::dbg_write_decision(const string& decision) const {
    ofstream out_up(dbg_result_filename, ios::app);
    out_up << pcap_filename << " " << decision << endl;
}

void Statistic_analysis::dbg_dead_session_inform(const Session& ses) const {
    cout << "Session from ip " << inet_ntoa(ses.ip_src);
    cout << " to " << inet_ntoa(ses.ip_dst) << " ";
    cout << ses.port_src << " ";
    cout << ses.port_dst << " ";
    cout << "  IS DEAD" << endl << endl;
}
