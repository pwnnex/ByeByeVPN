#ifndef NETWORK_PORT_SCAN_H
#define NETWORK_PORT_SCAN_H

#include <vector>
#include <string>
#include "tcp_scanner.h"

std::vector<int> build_tcp_ports();
extern const std::vector<int> UDP_SCAN_PORTS;

const char* port_hint(int p);

struct TcpOpen {
    int port;
    long long connect_ms;
    std::string banner;
    std::string err;
};

struct ScanStats {
    size_t scanned  = 0;
    size_t timeouts = 0;
    size_t refused  = 0;
    size_t other    = 0;
    bool   skipped  = false;
};

std::vector<TcpOpen> scan_tcp(const std::string& host, const std::vector<int>& ports, int threads, int to_ms, ScanStats* stats = nullptr);

#endif // NETWORK_PORT_SCAN_H