#ifndef ANALYZERS_H
#define ANALYZERS_H

#include "Signature_analysis.h"
#include "Statistic_analysis.h"

class Analyzers {
    Signature_analysis sig_analysator;
    Statistic_analysis stat_analysator;
public:
    Analyzers();
    Analyzers(const std::string& config_xml_name, const std::string& stage,
        const std::string& working_mode, const std::string& learning_type,
        const std::string& device);
    Signature_analysis& get_signature_analysis() { return sig_analysator; };
    Statistic_analysis& get_statistic_analysys() { return stat_analysator; };
    static void sigfunc(int sig);
};

#endif // ANALYZERS_H
