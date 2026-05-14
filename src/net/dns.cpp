// SPDX-License-Identifier: GPL-3.0-or-later
#include "dns.h"

#include <algorithm>
#include <chrono>

using std::string;
using std::vector;

string sa_ip(const sockaddr* sa) {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (sa->sa_family == AF_INET) {
        auto* s4 = (sockaddr_in*)sa;
        InetNtopA(AF_INET, &s4->sin_addr, buf, sizeof(buf));
    } else {
        auto* s6 = (sockaddr_in6*)sa;
        InetNtopA(AF_INET6, &s6->sin6_addr, buf, sizeof(buf));
    }
    return buf;
}

Resolved resolve_host(const string& host) {
    Resolved r; r.host = host;
    auto t0 = std::chrono::steady_clock::now();
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    addrinfo* ai = nullptr;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &ai);
    if (rc != 0) { r.err = gai_strerrorA(rc); return r; }

    // split by family; v4 first so primary_ip is never v6 on dual-stack
    // resolves. fixes the "works with IP, breaks with hostname" symptom on
    // v4-only ISP connections common in RU/CIS where v6 silently times out.
    vector<string> v4_ips, v6_ips;
    for (auto* p = ai; p; p = p->ai_next) {
        string ip = sa_ip(p->ai_addr);
        if (p->ai_family == AF_INET) {
            if (std::find(v4_ips.begin(), v4_ips.end(), ip) == v4_ips.end())
                v4_ips.push_back(ip);
        } else if (p->ai_family == AF_INET6) {
            if (std::find(v6_ips.begin(), v6_ips.end(), ip) == v6_ips.end())
                v6_ips.push_back(ip);
        }
    }
    freeaddrinfo(ai);
    for (auto& s: v4_ips) r.ips.push_back(s);
    for (auto& s: v6_ips) r.ips.push_back(s);
    if (!r.ips.empty()) r.primary_ip = r.ips.front();
    bool has4 = !v4_ips.empty(), has6 = !v6_ips.empty();
    r.family = (has4 && has6) ? "mixed(v4-preferred)"
             : has4 ? "v4"
             : has6 ? "v6" : "";
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    return r;
}