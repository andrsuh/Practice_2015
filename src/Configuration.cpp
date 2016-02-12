#include <iostream>
#include <stdio.h>

#include "Configuration.h"

using namespace std;

Config * Config::config = nullptr;

bool Config::load_xml_file(const string &f_name) {
    file_name = f_name;
    in_process = true;
    bool load_status = document.LoadFile(file_name.c_str(), TIXML_DEFAULT_ENCODING);
    if (!load_status) {
        return false;
    }
    current_element = document.RootElement()->FirstChildElement();
    return true;
}

// i dont understand why it works
bool Config::next_tag() {
    if (current_element->NextSiblingElement() == nullptr) {
        current_element = current_element->Parent()->NextSiblingElement();
        while (current_element != nullptr) {
            if (!current_element->NoChildren()) {
                current_element = current_element->FirstChildElement();
                return true;
            }
        }
        return false;
    }
    else {
        current_element = current_element->NextSiblingElement();
        return true;
    }
}

bool Config::get_tag(const std::string& name) {
    current_element = document.RootElement();
    while (current_element != nullptr) {
        if (!current_element->NoChildren()) {
            current_element = current_element->FirstChildElement();
        }
        while (current_element != nullptr) {
            if (strcmp(current_element->Value(), name.c_str()) == 0) {
                return true;
            }
            current_element = current_element->NextSiblingElement();
        }
        current_element = current_element->Parent()->NextSiblingElement();
    }
    return false;
}

bool Config::get_attribute_str(const string& name, string& value) {
    TiXmlAttribute * attr = current_element->FirstAttribute();
    while (attr != nullptr) {
        if (strcmp(attr->Name(), name.c_str()) == 0) {
            value = attr->Value();
            return true;
        }
        attr = attr->Next();
    }
    return false;
}


void Config::write_stat_to_xml(const string& traffic_type,
    const string& pcap_filename, const vector<double>& data) {

    TiXmlElement *root = document.RootElement(); //pointer to root element
    TiXmlElement * element = new TiXmlElement("s");
    element->SetAttribute("type", traffic_type.c_str());
    element->SetAttribute("file_name", pcap_filename.c_str());
    element->SetDoubleAttribute("none", (double )data[0]);
    element->SetDoubleAttribute("upload", (double)data[1]);
    element->SetDoubleAttribute("download", (double )data[2]);
    element->SetDoubleAttribute("interactive", (double) data[3]);
    for (size_t i = 0; i < data.size(); ++i) {
        cout << data[i] << " ";
    }
    cout << endl;

    root->InsertEndChild( *element);
    document.SaveFile(file_name.c_str());
}
