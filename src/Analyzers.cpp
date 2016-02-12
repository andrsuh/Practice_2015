#include <signal.h>
#include <stdlib.h>
#include <iostream>
#include "Analyzers.h"

void Analyzers::sigfunc(int sig) {
    char c;
    if (sig != SIGINT) {
        return;
    }
    else {
        printf("\nХотите завершить программу (y/n) : ");
        while((c = getchar()) == 'n')
            return;
        exit (0);
    }
}

Analyzers::Analyzers(const std::string& config_xml,
                    const std::string& stage,
                    const std::string& working_mode,
                    const std::string& learning_type,
                    const std::string& device):
        stat_analysator(
            config_xml, stage, working_mode, learning_type, device
        ),
        sig_analysator(
            config_xml, stage, device
        ) {
    signal(SIGINT,sigfunc); // interrupt signal
}
