#include "traceroute.h"
#include "tspu.h"
#include "../network/socket_sys.h"
#include <chrono>
#include <cstring>
#ifndef _WIN32
#include <unistd.h>
#endif

#ifdef _WIN32
#include <iphlpapi.h>
#include <icmpapi.h>
#endif

TraceResult trace_hops(const std::string& target_ip, int max_hops) {
    TraceResult r;
#ifdef _WIN32
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

    const char payload[] = "abcdefghijklmnopqrstuvwabcdefghi";
    const DWORD rcvsz = sizeof(ICMP_ECHO_REPLY) + sizeof(payload) + 8 + 128;
    std::vector<unsigned char> rcv(rcvsz);

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
#else
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

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s < 0) {
        s = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if (s < 0) return r;
    }

    struct timeval tv;
    tv.tv_sec = 1; tv.tv_usec = 500000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    int prev_rtt = 0;
    uint16_t id = (uint16_t)(getpid() & 0xFFFF);
    uint16_t seq = 1;

    for (int ttl = 1; ttl <= max_hops; ++ttl) {
        setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        
        struct icmp_hdr {
            uint8_t type;
            uint8_t code;
            uint16_t cksum;
            uint16_t id;
            uint16_t seq;
            char data[32];
        } icmp_pkt;
        memset(&icmp_pkt, 0, sizeof(icmp_pkt));
        icmp_pkt.type = 8; 
        icmp_pkt.id = htons(id);
        icmp_pkt.seq = htons(seq++);
        memcpy(icmp_pkt.data, "abcdefghijklmnopqrstuvwabcdefghi", 32);

        uint32_t sum = 0;
        uint16_t* ptr = (uint16_t*)&icmp_pkt;
        for (size_t i = 0; i < sizeof(icmp_pkt) / 2; ++i) sum += ntohs(ptr[i]);
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        icmp_pkt.cksum = htons(~sum);

        struct sockaddr_in saddr{};
        saddr.sin_family = AF_INET;
        saddr.sin_addr = dst;

        auto t0 = std::chrono::steady_clock::now();
        sendto(s, &icmp_pkt, sizeof(icmp_pkt), 0, (struct sockaddr*)&saddr, sizeof(saddr));

        TraceHop hop; hop.ttl = ttl;
        char buf[512];
        struct sockaddr_in raddr{};
        socklen_t rlen = sizeof(raddr);
        
        bool got_reply = false;
        auto deadline = t0 + std::chrono::milliseconds(1500);
        while (std::chrono::steady_clock::now() < deadline) {
            int n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr*)&raddr, &rlen);
            if (n > 0) {
                auto t1 = std::chrono::steady_clock::now();
                hop.rtt_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
                char abuf[INET_ADDRSTRLEN]={0};
                inet_ntop(AF_INET, &raddr.sin_addr, abuf, sizeof(abuf));
                hop.addr = abuf;
                
                int iphdr_len = (buf[0] & 0x0f) * 4;
                if (n >= iphdr_len + 8) {
                    uint8_t type = buf[iphdr_len];
                    if (type == 11 || type == 0) {
                        got_reply = true;
                        if (type == 0) r.reached_target = true;
                        break;
                    }
                }
            }
        }
        
        if (got_reply) {
            if (prev_rtt > 0) {
                int delta = hop.rtt_ms - prev_rtt;
                if (delta > r.max_rtt_jump_ms) r.max_rtt_jump_ms = delta;
            }
            if (hop.rtt_ms > 150) ++r.long_hops;
            prev_rtt = hop.rtt_ms;
            r.hops.push_back(hop);
            if (r.reached_target) break;
        } else {
            hop.rtt_ms = -1;
            r.hops.push_back(hop);
        }
    }
    closesocket(s);

    r.hop_count = 0;
    for (auto& hop: r.hops) if (hop.rtt_ms >= 0) ++r.hop_count;
    for (auto& hop: r.hops) {
        if (hop.rtt_ms >= 0 && looks_like_tspu_hop(hop.addr)) ++r.tspu_hops;
    }
    r.ok = (r.hop_count > 0);
#endif
    return r;
}