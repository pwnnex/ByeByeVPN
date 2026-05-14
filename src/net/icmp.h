// SPDX-License-Identifier: GPL-3.0-or-later
// ICMP echo-based traceroute via IcmpSendEcho2 (no admin required).
// counts hops, biggest RTT step, hops over 150ms, and tspu mgmt-subnet hits.
#pragma once

#include <string>
#include <vector>

struct TraceHop {
    int         ttl    = 0;
    std::string addr;        // IPv4 string
    int         rtt_ms = 0;  // -1 on no-reply
};

struct TraceResult {
    bool ok               = false;
    int  hop_count        = 0;
    bool reached_target   = false;
    int  max_rtt_jump_ms  = 0;
    int  long_hops        = 0;   // RTT > 150ms
    int  tspu_hops        = 0;   // hops matching tspu mgmt-subnet layout
    std::vector<TraceHop> hops;
};

TraceResult trace_hops(const std::string& target_ip, int max_hops = 18);