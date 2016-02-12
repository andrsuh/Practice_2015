#include <iostream>
#include <tclap/CmdLine.h>

#include "Net_sniffer.h"
#include "Analyzers.h"

using namespace std;

int main(int argc, char **argv) {
    try {
        TCLAP::CmdLine cmd("Command description message", ' ', "0.9");
        vector<string> allowed(2);

        allowed[0] = "live";
        allowed[1] = "offline";
        TCLAP::ValuesConstraint<string> allowedVals(allowed);
        TCLAP::ValueArg<std::string> mode_arg(
            "m","mode","Set mode", false, "live", &allowedVals
        );
        TCLAP::ValueArg<std::string> device_arg(
            "d","device","Set device or *.pcap file", false, "wlan0", "string"
        );

        allowed[0] = "determine";
        allowed[1] = "learn";
        TCLAP::ValuesConstraint<string> allowedVals2(allowed);
        TCLAP::ValueArg<std::string> work_mode_arg(
            "a","action","Set the action", false, "determine", &allowedVals2
        );
        TCLAP::ValueArg<std::string> learning_type_arg(
            "t","type","Set the learning type", false, "browsing", "string"
        );

        allowed[0] = "debug";
        allowed[1] = "release";
        TCLAP::ValuesConstraint<string> allowedVals3( allowed );;
        TCLAP::ValueArg<std::string> dev_stage_arg(
            "s","stage","Set the stage", false, "release", &allowedVals3
        );
        TCLAP::ValueArg<std::string> config_filename_arg(
            "c","config_filename","Enter config filename",
            false, "xml/configurations.xml", "string"
        );

        cmd.add(mode_arg);
        cmd.add(device_arg);
        cmd.add(work_mode_arg);
        cmd.add(dev_stage_arg);
        cmd.add(learning_type_arg);
        cmd.add(config_filename_arg);
        cmd.parse(argc, argv);
        string mode = mode_arg.getValue();
        string device = device_arg.getValue();

        Analyzers analyzers(config_filename_arg.getValue(),
                            dev_stage_arg.getValue(),
                            work_mode_arg.getValue(),
                            learning_type_arg.getValue(),
                            device_arg.getValue()
                        );
        Net_sniffer n_sniffer("wlan0", "ip", true);
        n_sniffer.start_sniff(analyzers);
    }
    catch (runtime_error e) {
        cout << e.what() << endl;
    }
}
