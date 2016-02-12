#ifndef CONFIG_H
#define CONFIG_H

#include <typeinfo>
#include <string>
#include <vector>

#include "../lib/tinyxml/tinyxml.h"
#include "../lib/tinyxml/tinystr.h"

class Config {
private:
    static Config * config;
    std::string file_name;
    bool in_process;
    TiXmlDocument document;
    TiXmlElement * current_element;
    Config() {};
public:
    static Config * get_config() {
        if (config == nullptr) {
            config = new Config();
        }
        return config;
    }

    ~Config() { delete config;}

    bool load_xml_file(const std::string& f_name);

    bool next_tag();
    bool get_tag(const std::string& name);

    bool get_attribute_str(const std::string& atr_name, std::string& value);
    template <class T>
    bool get_attribute(const std::string& name, T& value);

    void write_stat_to_xml(const std::string& traffic_type,
        const std::string& pcap_filename, const std::vector<double>& data);
};

template <class T>
bool Config::get_attribute(const std::string& name, T& value) {
    TiXmlAttribute *attr = current_element->FirstAttribute();
    while (attr != nullptr) {
        size_t state;
        if (strcmp(attr->Name(), name.c_str()) == 0) {
            if (typeid(T) == typeid(int)) {
                state = attr->QueryIntValue((int*)&value);
            }
            if (typeid(T) == typeid(double)) {
                state = attr->QueryDoubleValue((double*)&value);
            }
            if (state == TIXML_SUCCESS) {
                return true;
            }
        }
        attr = attr->Next();
    }
    return false;
}

#endif // CONFIG_H
