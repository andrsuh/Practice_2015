#ifndef STATISTIC_ANALYSIS_H
#define STATISTIC_ANALYSIS_H

#include <pcap.h>
#include <map>
#include <vector>
#include <string>

#include "Packet.h"
#include "Session.h"
#include "Configuration.h"

enum Traffic_type {
    TYPE_NONE, TYPE_UPLOAD, TYPE_DOWNLOAD, TYPE_INTERACTIVE
};

struct Packages {
    std::vector<int> uplink;
    std::vector<int> downlink;
    std::vector<bool> up_state;
    std::vector<bool> down_state;
    std::vector<Traffic_type> period_type;
    std::vector<double> type_percent;
    int init_sec; // time_t
    int last_packet_time(); // size_t
    bool is_alive(int, int);
    Packages() {
        type_percent.resize(4);
        init_sec = 0;
    }
};

enum Development_mode {WORKING_MODE, DEBUG_MODE};
enum Working_mode {LEARNING_MODE, DETECTION_MODE};

class Statistic_analysis {
private:
    Config * main_config;
    int process_interval = 15;       // session processing interval (look for the dead and remove)
    std::string pcap_filename;  // file of the learning program *.pcap
    Development_mode dev_mode;
    Working_mode work_mode;

    std::string learning_type; // traffic type
    int state_period;          // time in seconds (size of window) -- size_t
    int state_limit;           // boundary in bytes (yes / no traffic over period)
    int session_time_limit;    // minimum duration of the session (time)
    double none_limit;         // boundary for "none" state in percent
    int time_to_live;
    int host_ip;
    int last_process_time;
    std::map<Session, Packages> pack_time;
    std::multimap<std::string, std::vector<double> > statistic_data;

    void get_config(const std::string& name);
    bool process_session(const Session& s, Packages& p);
    void process_dead_sessions(int current_time);
    void process_all_sessions();
    void merge_sessions();
    void move_session(const std::vector<int>& src,
        const int src_init_sec, std::vector<int>& dst,
        const int dst_init_sec);
    bool fill_state(const std::vector<int>& data,
        std::vector<bool>& state);
    bool fill_period_type(Packages& p);
    void fill_if_not_equal(Packages& p); // addind "0" in vector before other vector size
    void add_second(std::vector<int>& v,
        Packages& p, int p_time, int size);
    std::string get_nearest(Packages& p) const;

private:
    std::string dbg_result_filename;
    int dbg_processed_sessions_counter; // size_t
    void dbg_write_decision(const std::string& decision) const;
    void dbg_write_session_to_file(const Session& first,
        const Packages& second) const;
    void dbg_dead_session_inform(const Session& ses) const;

public:
    explicit Statistic_analysis(const std::string& config_xml, const std::string& stage,
        const std::string& working_mode, const std::string& learning_type,
        const std::string& device);

    ~Statistic_analysis();
    void add_packet(const Packet& p);
    bool hosts_equal(Session const &s1, Session const &s2) const;
};


#endif
