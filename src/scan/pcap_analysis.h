// SPDX-License-Identifier: GPL-3.0-or-later
// pcap: what an inline box reads from the owner's own client traffic. the
// tls clienthello (sni, ja4, grease, ech, post-quantum share), the shape of
// the first records, dns sent in the clear and who else the machine talked
// to. a capture file in, nothing sent.
#pragma once

#include "../common/outcome.h"

#include <cstdint>
#include <string>
#include <vector>

// first flights after the outer handshake, as plaintext lengths:
// f1 client, f2 server, f3 client
struct Flights {
    std::vector<uint32_t> f1, f2, f3;
};

enum class InnerState { NotChecked, TooShort, Match, NoMatch };

struct TlsFlow {
    std::string client, server;          // ip:port
    bool        quic = false;
    std::string sni, ja4, alpn, ja4s, version;
    bool        grease = false;          // chromium and safari send it, firefox, go and openssl do not
    bool        ech = false;             // encrypted_client_hello extension present
    bool        pq = false;              // a post-quantum hybrid group offered
    std::vector<uint32_t> c2s, s2c;      // wire lengths of the first data records, each way
    uint64_t    c2s_bytes = 0, s2c_bytes = 0;
    double      seconds = 0;
    InnerState  inner = InnerState::NotChecked;
    std::string inner_detail;
};

// the inner-handshake rule per server address
struct InnerSummary {
    std::string server;
    size_t      flows = 0, checked = 0, matched = 0;
    Outcome     outcome = Outcome::NotApplicable;
    std::string reason;
};

struct DnsQuery {
    std::string resolver;                // ip:port
    std::string name;
    uint16_t    qtype = 0;
    bool        tcp = false;
};

// one remote endpoint the capture talked to, keyed by protocol, address, port
struct Peer {
    std::string addr;                    // v6 in brackets
    uint16_t    port = 0;
    uint8_t     proto = 0;               // 6 tcp, 17 udp
    bool        v6 = false, local = false;
    uint64_t    packets = 0, bytes = 0;
    size_t      flows = 0;
};

struct PcapReport {
    bool        ok = false;
    std::string error;
    size_t      records = 0, skipped = 0, tcp_segments = 0, udp_datagrams = 0;
    std::vector<TlsFlow>      tls;
    std::vector<InnerSummary> inner;
    std::vector<DnsQuery>     dns;       // cleartext port 53 queries
    std::vector<Peer>         peers;     // busiest first
};

// what leaves the machine readable: cleartext dns, traffic beside the node
struct LeakView {
    Outcome     dns = Outcome::NotApplicable;
    std::string dns_reason;
    Outcome     outside = Outcome::NotApplicable;
    std::string outside_reason;
    size_t      outside_peers = 0, outside_v6 = 0;
    uint64_t    outside_packets = 0, outside_bytes = 0;
    std::string node;                    // normalized, empty when not given or not an address
};

PcapReport pcap_analyze(const std::vector<uint8_t>& bytes);
LeakView pcap_leaks(const PcapReport& r, const std::string& node);
std::string pcap_report_json(const PcapReport& r, const LeakView& v);

// an address as the capture decoder prints it ("1.2.3.4", "[2001:db8:0:0:0:0:0:1]"); empty if not one
std::string capture_address(const std::string& text);

// the inner-handshake rule on plaintext lengths; empty when it does not hold
std::string inner_handshake_match(const Flights& f);

// combined per-server outcome: two matching flows make it positive
Outcome inner_server_outcome(size_t checked, size_t matched);

// private, loopback, link-local, multicast, unique-local
bool peer_is_local(const std::string& addr);

// well-known dns-over-https names a clienthello may carry
bool doh_name(const std::string& sni);
