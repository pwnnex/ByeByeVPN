// DNS resolution. always prefers IPv4 to dodge happy-eyeballs into
// silently-failing v6 paths on RU/CIS ISPs.
#pragma once

#include "../common/winhdr.h"
#include <string>
#include <vector>

struct Resolved {
    std::string host;
    std::string primary_ip;
    std::vector<std::string> ips;
    std::string family; // "v4" / "v6" / "mixed(v4-preferred)"
    std::string err;
    long long   ms = 0;
};

// stringify a sockaddr (v4 or v6).
std::string sa_ip(const sockaddr* sa);

// resolve a host name. returns Resolved with err set on failure.
Resolved resolve_host(const std::string& host);
