#ifndef ANALYSIS_TRACEROUTE_H
#define ANALYSIS_TRACEROUTE_H

#include <string>
#include <vector>

struct TraceHop {
    int   ttl = 0;
    std::string addr;
    int   rtt_ms = 0;
};

struct TraceResult {
    bool  ok = false;
    int   hop_count = 0;
    bool  reached_target = false;
    int   max_rtt_jump_ms = 0;
    int   long_hops = 0;
    int   tspu_hops  = 0;
    std::vector<TraceHop> hops;
};

TraceResult trace_hops(const std::string& target_ip, int max_hops = 18);

#endif // ANALYSIS_TRACEROUTE_H