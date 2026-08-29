// SPDX-License-Identifier: GPL-3.0-or-later
#include "icmp.h"
#include "../common/tspu.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>

TraceResult trace_hops(const std::string& target, int max_hops) {
    TraceResult result;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    addrinfo* addresses = nullptr;
    if (getaddrinfo(target.c_str(), nullptr, &hints, &addresses) != 0 || !addresses)
        return result;

    char numeric[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(addresses->ai_addr)->sin_addr,
              numeric, sizeof(numeric));
    freeaddrinfo(addresses);
    max_hops = std::max(1, std::min(max_hops, 64));

    // The address is canonicalized above and max_hops is clamped, so neither
    // user-supplied value is interpreted by the shell.
    std::string command = "/usr/sbin/traceroute -n -q 1 -w 1 -m " +
                          std::to_string(max_hops) + " " + numeric + " 2>/dev/null";
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) return result;
    char line[512];
    int previous_rtt = 0;
    while (fgets(line, sizeof(line), pipe)) {
        std::istringstream in(line);
        int ttl = 0;
        std::string address;
        if (!(in >> ttl >> address) || ttl <= 0) continue;
        TraceHop hop;
        hop.ttl = ttl;
        if (address == "*") {
            hop.rtt_ms = -1;
        } else {
            double milliseconds = 0.0;
            if (!(in >> milliseconds)) continue;
            hop.addr = address;
            hop.rtt_ms = static_cast<int>(milliseconds + 0.5);
            if (previous_rtt > 0)
                result.max_rtt_jump_ms = std::max(result.max_rtt_jump_ms,
                                                   hop.rtt_ms - previous_rtt);
            if (hop.rtt_ms > 150) ++result.long_hops;
            previous_rtt = hop.rtt_ms;
            ++result.hop_count;
            if (hop.addr == numeric) result.reached_target = true;
            if (looks_like_tspu_hop(hop.addr)) ++result.tspu_hops;
        }
        result.hops.push_back(std::move(hop));
        if (result.reached_target) break;
    }
    pclose(pipe);
    result.ok = result.hop_count > 0;
    return result;
}
