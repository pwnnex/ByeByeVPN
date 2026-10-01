// SPDX-License-Identifier: GPL-3.0-or-later
// dns resolution. always prefers ipv4 to dodge happy-eyeballs into
// silently-failing v6 paths on ru/cis isps.
#pragma once

#include <string>
#include <vector>
struct sockaddr;

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
