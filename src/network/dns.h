#ifndef NETWORK_DNS_H
#define NETWORK_DNS_H

#include <string>
#include <vector>

struct Resolved {
    std::string host;
    std::string primary_ip;
    std::vector<std::string> ips;
    std::string family;
    std::string err;
    long long ms = 0;
};

Resolved resolve_host(const std::string& host);

#endif // NETWORK_DNS_H