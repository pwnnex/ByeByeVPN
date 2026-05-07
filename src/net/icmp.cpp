#include "icmp.h"
#include "../common/winhdr.h"
#include "../common/tspu.h"

#include <vector>

using std::vector;

TraceResult trace_hops(const std::string& target_ip, int max_hops) {
    TraceResult r;
    // resolve once — only IPv4 (ICMP4).
    struct in_addr dst{}; dst.s_addr = 0;
    struct addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* ai = nullptr;
    if (getaddrinfo(target_ip.c_str(), nullptr, &hints, &ai) != 0 || !ai) return r;
    for (auto* p = ai; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            dst = ((sockaddr_in*)p->ai_addr)->sin_addr;
            break;
        }
    }
    freeaddrinfo(ai);
    if (dst.s_addr == 0) return r;

    HANDLE h = IcmpCreateFile();
    if (h == INVALID_HANDLE_VALUE) return r;

    // standard windows ping payload (32 bytes), identical to what ping.exe sends
    const char payload[] = "abcdefghijklmnopqrstuvwabcdefghi";
    const DWORD rcvsz = sizeof(ICMP_ECHO_REPLY) + sizeof(payload) + 8 + 128;
    vector<unsigned char> rcv(rcvsz);

    int prev_rtt = 0;
    for (int ttl = 1; ttl <= max_hops; ++ttl) {
        IP_OPTION_INFORMATION opt{};
        opt.Ttl = (unsigned char)ttl;
        opt.Tos = 0;
        opt.Flags = 0;
        opt.OptionsSize = 0;
        opt.OptionsData = nullptr;
        DWORD n = IcmpSendEcho2(h, nullptr, nullptr, nullptr, dst.s_addr,
                                (LPVOID)payload, sizeof(payload),
                                &opt, rcv.data(), (DWORD)rcv.size(), 1500);
        TraceHop hop; hop.ttl = ttl;
        if (n > 0) {
            auto* rep = (ICMP_ECHO_REPLY*)rcv.data();
            struct in_addr a{}; a.s_addr = rep->Address;
            char buf[INET_ADDRSTRLEN] = {0};
            InetNtopA(AF_INET, &a, buf, sizeof(buf));
            hop.addr = buf;
            hop.rtt_ms = (int)rep->RoundTripTime;
            if (prev_rtt > 0) {
                int delta = hop.rtt_ms - prev_rtt;
                if (delta > r.max_rtt_jump_ms) r.max_rtt_jump_ms = delta;
            }
            if (hop.rtt_ms > 150) ++r.long_hops;
            prev_rtt = hop.rtt_ms;
            r.hops.push_back(hop);
            if (rep->Status == IP_SUCCESS && rep->Address == dst.s_addr) {
                r.reached_target = true;
                break;
            }
        } else {
            hop.rtt_ms = -1;
            r.hops.push_back(hop);
        }
    }
    IcmpCloseHandle(h);
    r.hop_count = 0;
    for (auto& hop: r.hops) if (hop.rtt_ms >= 0) ++r.hop_count;
    for (auto& hop: r.hops) {
        if (hop.rtt_ms >= 0 && looks_like_tspu_hop(hop.addr)) ++r.tspu_hops;
    }
    r.ok = (r.hop_count > 0);
    return r;
}
