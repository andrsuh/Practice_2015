#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include "../lib/tinyxml/tinyxml.h"
#include "../lib/tinyxml/tinystr.h"
#include <vector>


class Config {
private:
    static Config *config;
    std::string file_name;
    bool in_process;
    TiXmlDocument document;
    TiXmlElement *current_element;
    Config() {};
public:
    static Config* get_config() {
        if (config == 0) {
            config = new Config();
        }
        return config;
    }

    ~Config() { delete config;}

    bool load_xml_file(const std::string& f_name);

    bool next_tag();

    bool get_tag(const std::string& name);

    bool get_attribute_str(const std::string& atr_name, std::string& value);

    bool get_attribute_int(const std::string& atr_name, int *value);
    
    bool get_attribute_double(const std::string& atr_name, double *value);

    void write_stat_to_xml(const std::string& traffic_type, const std::string& pcap_filename,
                                                 const std::vector<double>& data);
};

#endif
