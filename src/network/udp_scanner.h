#ifndef NETWORK_UDP_SCANNER_H
#define NETWORK_UDP_SCANNER_H

#include "socket_sys.h"
#include <string>

struct UdpResult {
    bool    responded = false;
    int     bytes = 0;
    std::string  reply_hex;
    long long ms = 0;
    std::string  err;
};

UdpResult udp_probe(const std::string& host, int port, const unsigned char* payload, int plen, int timeout_ms);

#endif // NETWORK_UDP_SCANNER_H