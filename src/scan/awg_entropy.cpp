// SPDX-License-Identifier: GPL-3.0-or-later
#include "awg_entropy.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <map>
#include <set>
#include <tuple>

namespace {
uint16_t be16(const uint8_t* p) { return uint16_t((unsigned(p[0]) << 8) | p[1]); }
uint32_t le32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
template<size_t N> double entropy(const std::array<size_t,N>& counts, size_t n) {
    if (!n) return 0;
    double h = 0;
    for (auto c : counts) if (c) { double p = double(c) / double(n); h -= p * std::log2(p); }
    return h;
}
}

AwgPacket awg_observe(const uint8_t* p, size_t n) {
    AwgPacket r;
    r.payload_size = n;
    if (!p || !n) return r;
    std::array<size_t,256> bytes{};
    std::array<size_t,16> nibbles{};
    for (size_t i = 0; i < n; ++i) { ++bytes[p[i]]; ++nibbles[p[i] >> 4]; ++nibbles[p[i] & 15]; }
    r.byte_entropy = entropy(bytes,n);
    r.nibble_entropy = entropy(nibbles,2*n);
    // nibbles behave better than 256 bins on short packets
    // random-looking data still isn't an awg signature
    r.random_like = n >= 64 && r.nibble_entropy >= 3.85 && double(bytes[0])/double(n) < 0.08;
    using M = AwgPacket::Marker;
    if (n >= 4) {
        uint32_t type = le32(p);
        if ((type == 1 && n == 148) || (type == 2 && n == 92) || (type == 3 && n == 64) ||
            (type == 4 && n >= 32 && (n-32)%16 == 0)) r.marker = M::WireGuard;
    }
    // need framing in both directions to suppress a candidate
    // one quic-shaped cps decoy doesn't count
    if (n >= 7 && (p[0]&0xc0) == 0xc0) {
        uint32_t version = (uint32_t(be16(p+1)) << 16) | be16(p+3);
        size_t dl = p[5];
        if ((version == 1 || version == 0x6b3343cf) && dl <= 20 && n >= 7+dl &&
            p[6+dl] <= 20 && n >= 7+dl+p[6+dl]) r.marker = M::QuicLong;
    }
    if (n >= 13 && p[0] >= 20 && p[0] <= 23 && p[1] == 0xfe &&
        (p[2] == 0xfd || p[2] == 0xff) && be16(p+11) <= n-13) r.marker = M::Dtls;
    if (n >= 20 && !(p[0]&0xc0) && p[4] == 0x21 && p[5] == 0x12 && p[6] == 0xa4 && p[7] == 0x42 &&
        be16(p+2)%4 == 0 && be16(p+2) == n-20) r.marker = M::Stun;
    // dns isn't inferred from a port number or a random 12-byte header.
    if (n >= 17 && !(p[3]&0x40) && ((p[2]>>3)&15) == 0 && be16(p+4) == 1 && be16(p+6) < 128) {
        size_t pos = 12;
        bool valid = true;
        while (pos < n && p[pos]) {
            size_t len = p[pos++];
            if (len > 63 || len > n-pos) { valid = false; break; }
            for (size_t j=0;j<len;++j) if (p[pos+j] < 33 || p[pos+j] > 126) valid = false;
            pos += len;
        }
        if (valid && pos+5 <= n && p[pos] == 0 && be16(p+pos+3) == 1) r.marker = M::Dns;
    }
    return r;
}

std::vector<AwgFlow> awg_analyze(const std::vector<AwgPacket>& packets) {
    using Key = std::tuple<std::string,std::string,std::string>;
    std::map<Key,std::vector<const AwgPacket*>> groups;
    for (const auto& p : packets) {
        auto ends = std::minmax(p.src,p.dst);
        groups[{p.scope,ends.first,ends.second}].push_back(&p);
    }
    std::vector<AwgFlow> out;
    for (auto& [key, ps] : groups) {
        std::stable_sort(ps.begin(),ps.end(),[](auto a,auto b){return a->time_ns < b->time_ns;});
        AwgFlow f;
        std::tie(f.scope,f.endpoint_a,f.endpoint_b) = key;
        std::array<std::array<size_t,2>,6> markers{};
        for (auto p : ps) {
            bool reverse = p->src != f.endpoint_a;
            if (reverse) ++f.b_to_a; else ++f.a_to_b;
            ++markers[size_t(p->marker)][reverse ? 1 : 0];
            if (p->payload_size >= 64) {
                ++f.sampled;
                f.mean_byte_entropy += p->byte_entropy;
                f.mean_nibble_entropy += p->nibble_entropy;
                if (p->random_like) ++f.random_packets;
            }
        }
        f.packets = ps.size();
        if (f.sampled) { f.mean_byte_entropy /= double(f.sampled); f.mean_nibble_entropy /= double(f.sampled); }
        for (size_t m=1;m<markers.size();++m)
            if (markers[m][0] && markers[m][1] && markers[m][0]+markers[m][1] >= 3) f.competing_protocol = true;
        // idle/start -> one-way train -> reply -> two-way encrypted traffic
        // need two repeats; no fixed s1/s2, headers, 16-byte sizes or 120s timer
        // awg 3.x can hide those; the thresholds below are just a heuristic
        for (size_t i=0;i<ps.size();++i) {
            if (i && ps[i]->time_ns-ps[i-1]->time_ns < 1000000000ULL) continue;
            size_t j=i, random=0, bytes=0;
            std::set<size_t> sizes;
            while (j<ps.size() && j-i<64 && ps[j]->src == ps[i]->src &&
                   ps[j]->time_ns-ps[i]->time_ns <= 250000000ULL) {
                if (ps[j]->random_like) ++random;
                bytes += ps[j]->payload_size;
                sizes.insert(ps[j]->payload_size);
                ++j;
            }
            size_t n=j-i;
            if (n<4 || sizes.size()<3 || bytes<512 || random*4<n*3 || j==ps.size() ||
                ps[j]->src == ps[i]->src || ps[j]->time_ns-ps[j-1]->time_ns>1000000000ULL) continue;
            size_t forward=0, backward=0, encrypted=0;
            for (size_t k=j;k<ps.size() && ps[k]->time_ns-ps[j]->time_ns<=5000000000ULL;++k) {
                if (ps[k]->src == ps[i]->src) ++forward; else ++backward;
                if (ps[k]->random_like) ++encrypted;
            }
            if (forward>=3 && backward>=3 && encrypted>=6) ++f.candidate_bursts;
        }
        if (f.competing_protocol) {
            f.verdict = "OTHER_PROTOCOL_HINT";
            f.evidence.push_back("Repeated bidirectional WireGuard/QUIC/DTLS/STUN/DNS framing; entropy is not specific to AWG");
        } else if (f.sampled>=12 && f.a_to_b>=3 && f.b_to_a>=3) {
            if (f.random_packets*10 >= f.sampled*7) {
                f.verdict = f.candidate_bursts>=2 ? "AWG_COMPATIBLE_HEURISTIC" : "ENCRYPTED_UDP_INCONCLUSIVE";
                f.evidence.push_back("High nibble entropy in at least 70% of UDP payloads >=64 bytes");
                if (f.candidate_bursts) f.evidence.push_back("Variable-length pre-response trains followed by bidirectional random-like traffic: " + std::to_string(f.candidate_bursts));
            } else f.verdict = "NO_MATCH";
        }
        f.evidence.push_back("Not protocol proof; AWG 2.x/3.x versions cannot be distinguished by entropy; missing pattern does not exclude AWG");
        out.push_back(std::move(f));
    }
    return out;
}
