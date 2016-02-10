#include <iostream>
#include "Net_sniffer.h"

// #define SNAP_LEN 1518
// #define SIZE_ETHERNET 14
// #define ETHER_ADDR_LEN 6
// #define UDP_LENGTH 8

using namespace std;

int main(int argc, char **argv) {
    try {
        Net_sniffer n_sniffer("wlan0", "ip", true);
        n_sniffer.start_sniff();
    }
    catch (runtime_error e) {
        cout << e.what() << endl;
    }
}
