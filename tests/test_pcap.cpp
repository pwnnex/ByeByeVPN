// SPDX-License-Identifier: GPL-3.0-or-later
#include "doctest.h"
#include "../src/scan/pcap_analysis.h"
#include "../src/scan/chrome_ch.h"
#include "../src/scan/quic.h"

#include <string>
#include <vector>

namespace {
using Bytes = std::vector<uint8_t>;

void put(Bytes& b, uint32_t v, size_t n) {
    for (size_t i = 0; i < n; ++i) b.push_back(uint8_t(v >> (8 * (n - 1 - i))));
}
void put_le(Bytes& b, uint32_t v) {
    for (size_t i = 0; i < 4; ++i) b.push_back(uint8_t(v >> (8 * i)));
}

// classic pcap, raw ip link, microsecond stamps
struct Cap {
    Bytes b;
    uint32_t us = 0;
    Cap() {
        put_le(b, 0xa1b2c3d4);
        b.push_back(2); b.push_back(0); b.push_back(4); b.push_back(0);
        put_le(b, 0); put_le(b, 0); put_le(b, 65535); put_le(b, 101);
    }
    void packet(const Bytes& ip) {
        us += 1000;
        put_le(b, 1700000000); put_le(b, us);
        put_le(b, uint32_t(ip.size())); put_le(b, uint32_t(ip.size()));
        b.insert(b.end(), ip.begin(), ip.end());
    }
};

Bytes v4(const uint8_t a[4], const uint8_t z[4], uint8_t proto, const Bytes& l4) {
    Bytes ip = {0x45, 0, 0, 0, 0, 1, 0x40, 0, 64, proto, 0, 0};
    ip.insert(ip.end(), a, a + 4);
    ip.insert(ip.end(), z, z + 4);
    uint32_t total = uint32_t(ip.size() + l4.size());
    ip[2] = uint8_t(total >> 8); ip[3] = uint8_t(total);
    ip.insert(ip.end(), l4.begin(), l4.end());
    return ip;
}
Bytes tcp(uint16_t sp, uint16_t dp, uint32_t seq, uint8_t flags, const Bytes& payload) {
    Bytes t;
    put(t, sp, 2); put(t, dp, 2); put(t, seq, 4); put(t, 0, 4);
    t.push_back(0x50); t.push_back(flags); put(t, 65535, 2); put(t, 0, 4);
    t.insert(t.end(), payload.begin(), payload.end());
    return t;
}
Bytes udp(uint16_t sp, uint16_t dp, const Bytes& payload) {
    Bytes u;
    put(u, sp, 2); put(u, dp, 2); put(u, uint32_t(payload.size() + 8), 2); put(u, 0, 2);
    u.insert(u.end(), payload.begin(), payload.end());
    return u;
}
Bytes record(uint8_t type, size_t len) {
    Bytes r = {type, 3, 3, uint8_t(len >> 8), uint8_t(len)};
    for (size_t i = 0; i < len; ++i) r.push_back(uint8_t(i * 37 + 11));
    return r;
}
Bytes server_hello() {
    Bytes body = {3, 3};
    for (int i = 0; i < 32; ++i) body.push_back(uint8_t(i));
    body.push_back(32);
    for (int i = 0; i < 32; ++i) body.push_back(uint8_t(0x40 + i));
    body.push_back(0x13); body.push_back(0x01); body.push_back(0);
    Bytes ext = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20};
    for (int i = 0; i < 32; ++i) ext.push_back(uint8_t(0x80 + i));
    put(body, uint32_t(ext.size()), 2);
    body.insert(body.end(), ext.begin(), ext.end());
    Bytes hs = {2};
    put(hs, uint32_t(body.size()), 3);
    hs.insert(hs.end(), body.begin(), body.end());
    Bytes r = {22, 3, 3};
    put(r, uint32_t(hs.size()), 2);
    r.insert(r.end(), hs.begin(), hs.end());
    return r;
}

const uint8_t CLIENT[4] = {192, 168, 1, 20};
const uint8_t NODE[4] = {203, 0, 113, 5};

// one tls 1.3 connection: handshake, then three data flights of the given plaintext sizes
void tls_flow(Cap& cap, uint16_t cport, size_t f1, size_t f2, size_t f3, bool split_hello = false) {
    uint32_t cs = 1000, ss = 900000;
    auto c = [&](const Bytes& p, uint8_t fl = 0x18) {
        cap.packet(v4(CLIENT, NODE, 6, tcp(cport, 443, cs, fl, p)));
        cs += uint32_t(p.size());
    };
    auto s = [&](const Bytes& p, uint8_t fl = 0x18) {
        cap.packet(v4(NODE, CLIENT, 6, tcp(443, cport, ss, fl, p)));
        ss += uint32_t(p.size());
    };
    c({}, 0x02); cs += 1;
    s({}, 0x12); ss += 1;
    Bytes hello = build_chromelike_clienthello("www.example.com");
    if (split_hello) {
        // second half first, then the first half
        Bytes a(hello.begin(), hello.begin() + 100), b(hello.begin() + 100, hello.end());
        cap.packet(v4(CLIENT, NODE, 6, tcp(cport, 443, cs + 100, 0x18, b)));
        cap.packet(v4(CLIENT, NODE, 6, tcp(cport, 443, cs, 0x18, a)));
        cs += uint32_t(hello.size());
    } else {
        c(hello);
    }
    Bytes flight = server_hello();
    Bytes ccs = {20, 3, 3, 0, 1, 1};
    flight.insert(flight.end(), ccs.begin(), ccs.end());
    Bytes enc = record(23, 2400);
    flight.insert(flight.end(), enc.begin(), enc.end());
    s(flight);
    Bytes fin = ccs;
    Bytes f = record(23, 53);
    fin.insert(fin.end(), f.begin(), f.end());
    c(fin);
    c(record(23, f1 + 17));
    s(record(23, 250));          // a ticket would land here only after f1 in time, keep it in f2
    s(record(23, f2 + 17));
    c(record(23, f3 + 17));
    s(record(23, 1200));
}

Bytes dns_query(const std::string& name, uint16_t id) {
    Bytes q;
    put(q, id, 2); put(q, 0x0100, 2); put(q, 1, 2); put(q, 0, 2); put(q, 0, 2); put(q, 0, 2);
    size_t start = 0;
    while (start <= name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        q.push_back(uint8_t(dot - start));
        q.insert(q.end(), name.begin() + long(start), name.begin() + long(dot));
        start = dot + 1;
    }
    q.push_back(0);
    put(q, 1, 2); put(q, 1, 2);
    return q;
}
} // namespace

TEST_CASE("pcap: inner handshake rule on flight sizes") {
    CHECK_FALSE(inner_handshake_match({{560}, {250, 3100}, {64}}).empty());
    CHECK_FALSE(inner_handshake_match({{300, 1400}, {1300}, {80, 400}}).empty());
    CHECK(inner_handshake_match({{560}, {3100}, {65}}).empty());     // not a finished size
    CHECK(inner_handshake_match({{200}, {3100}, {64}}).empty());     // first flight too small for a hello
    CHECK(inner_handshake_match({{560}, {400}, {64}}).empty());      // no certificate flight
    CHECK(inner_handshake_match({{560}, {3100}, {}}).empty());       // too short
    CHECK(inner_server_outcome(2, 2) == Outcome::Positive);
    CHECK(inner_server_outcome(5, 2) == Outcome::Positive);
    CHECK(inner_server_outcome(3, 1) == Outcome::Inconclusive);
    CHECK(inner_server_outcome(2, 0) == Outcome::Negative);
    CHECK(inner_server_outcome(1, 0) == Outcome::Inconclusive);
}

TEST_CASE("pcap: addresses, locality, doh names") {
    CHECK(capture_address("203.0.113.5") == "203.0.113.5");
    CHECK(capture_address("2001:db8::1") == "[2001:db8:0:0:0:0:0:1]");
    CHECK(capture_address("[::1]") == "[0:0:0:0:0:0:0:1]");
    CHECK(capture_address("fe80::") == "[fe80:0:0:0:0:0:0:0]");
    CHECK(capture_address("1.2.3").empty());
    CHECK(capture_address("1.2.3.256").empty());
    CHECK(capture_address("1:2:3:4:5:6:7:8:9").empty());
    CHECK(capture_address("1::2::3").empty());
    CHECK(capture_address("node.example").empty());
    CHECK(peer_is_local("192.168.1.1"));
    CHECK(peer_is_local("172.31.0.9"));
    CHECK_FALSE(peer_is_local("172.32.0.9"));
    CHECK(peer_is_local("224.0.0.251"));
    CHECK_FALSE(peer_is_local("8.8.8.8"));
    CHECK(peer_is_local("[fe80:0:0:0:0:0:0:1]"));
    CHECK(peer_is_local("[fd00:0:0:0:0:0:0:1]"));
    CHECK(peer_is_local("[ff02:0:0:0:0:0:0:fb]"));
    CHECK_FALSE(peer_is_local("[2001:db8:0:0:0:0:0:1]"));
    CHECK(doh_name("dns.google"));
    CHECK(doh_name("abc123.dns.nextdns.io"));
    CHECK_FALSE(doh_name("dns.nextdns.io.example"));
    CHECK_FALSE(doh_name("www.example.com"));
}

TEST_CASE("pcap: tls flows, inner handshake per server, dns and traffic beside the node") {
    Cap cap;
    tls_flow(cap, 50001, 560, 3100, 64);
    tls_flow(cap, 50002, 1500, 4000, 80, true);
    tls_flow(cap, 50003, 400, 5000, 9);
    const uint8_t router[4] = {192, 168, 1, 1}, other[4] = {198, 51, 100, 7};
    cap.packet(v4(CLIENT, router, 17, udp(53001, 53, dns_query("Example.COM", 1))));
    cap.packet(v4(CLIENT, router, 17, udp(53002, 53, dns_query("node.example.net", 2))));
    Bytes answer = dns_query("example.com", 1);
    answer[2] |= 0x80;
    cap.packet(v4(CLIENT, router, 17, udp(53001, 53, answer)));   // qr set: not a query
    cap.packet(v4(CLIENT, other, 17, udp(40000, 123, Bytes(48, 0x23))));
    cap.packet(v4(other, CLIENT, 17, udp(123, 40000, Bytes(48, 0x24))));

    PcapReport r = pcap_analyze(cap.b);
    REQUIRE(r.ok);
    CHECK(r.skipped == 0);
    REQUIRE(r.tls.size() == 3);
    for (const auto& t : r.tls) {
        CHECK(t.sni == "www.example.com");
        CHECK(t.ja4.rfind("t13d", 0) == 0);
        CHECK(t.grease);
        CHECK(t.version == "1.3");
        CHECK(t.server == "203.0.113.5:443");
    }
    size_t match = 0, nomatch = 0;
    for (const auto& t : r.tls) {
        if (t.inner == InnerState::Match) ++match;
        if (t.inner == InnerState::NoMatch) ++nomatch;
    }
    CHECK(match == 2);
    CHECK(nomatch == 1);
    REQUIRE(r.inner.size() == 1);
    CHECK(r.inner[0].outcome == Outcome::Positive);
    CHECK(r.inner[0].matched == 2);

    REQUIRE(r.dns.size() == 2);
    CHECK(r.dns[0].name == "example.com");
    CHECK(r.dns[0].resolver == "192.168.1.1:53");
    CHECK(r.dns[0].qtype == 1);

    LeakView none = pcap_leaks(r, "");
    CHECK(none.dns == Outcome::Positive);
    CHECK(none.outside == Outcome::NotApplicable);
    LeakView v = pcap_leaks(r, "203.0.113.5");
    CHECK(v.outside == Outcome::Positive);
    CHECK(v.outside_peers == 1);
    CHECK(v.outside_packets == 2);
    LeakView gone = pcap_leaks(r, "203.0.113.99");
    CHECK(gone.outside == Outcome::Inconclusive);

    std::string json = pcap_report_json(r, v);
    CHECK(json.find("\"check\": \"pcap\"") != std::string::npos);
    CHECK(json.find("\"inner\": \"match\"") != std::string::npos);
    CHECK(json.find("\"outcome\": \"positive\"") != std::string::npos);
}

TEST_CASE("pcap: plain https flows and no dns stay negative") {
    Cap cap;
    for (uint16_t p = 0; p < 4; ++p) tls_flow(cap, uint16_t(51000 + p), 420, 6000, 9 + p);
    PcapReport r = pcap_analyze(cap.b);
    REQUIRE(r.ok);
    REQUIRE(r.inner.size() == 1);
    CHECK(r.inner[0].outcome == Outcome::Negative);
    LeakView v = pcap_leaks(r, "203.0.113.5");
    CHECK(v.dns == Outcome::Negative);
    CHECK(v.outside == Outcome::Negative);
}

TEST_CASE("pcap: pcapng, ethernet, ipv6 and a v6 node") {
    auto block = [](Bytes& b, uint32_t type, Bytes body) {
        while (body.size() % 4) body.push_back(0);
        put_le(b, type); put_le(b, uint32_t(body.size() + 12));
        b.insert(b.end(), body.begin(), body.end());
        put_le(b, uint32_t(body.size() + 12));
    };
    auto frame = [](bool up, uint32_t seq, uint8_t flags, const Bytes& payload) {
        Bytes f(12, 0x02);
        f.push_back(0x86); f.push_back(0xdd);
        Bytes t = tcp(up ? 50100 : 443, up ? 443 : 50100, seq, flags, payload);
        Bytes c = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a};
        Bytes n = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05};
        for (uint8_t v : {0x60, 0, 0, 0}) f.push_back(v);
        put(f, uint32_t(t.size()), 2);
        f.push_back(6); f.push_back(64);
        for (uint8_t v : up ? c : n) f.push_back(v);
        for (uint8_t v : up ? n : c) f.push_back(v);
        for (uint8_t v : t) f.push_back(v);
        return f;
    };
    Bytes b, shb, idb = {1, 0, 0, 0};
    put_le(shb, 0x1a2b3c4d); shb.insert(shb.end(), {1, 0, 0, 0});
    put_le(shb, 0xffffffff); put_le(shb, 0xffffffff);
    block(b, 0x0a0d0d0a, shb);
    put_le(idb, 0);
    block(b, 1, idb);
    const std::vector<Bytes> frames = {frame(true, 10, 0x02, {}), frame(false, 500, 0x12, {}),
                                       frame(true, 11, 0x18, build_chromelike_clienthello("v6.example.net"))};
    uint32_t ts = 0;
    for (const auto& f : frames) {
        Bytes e;
        put_le(e, 0); put_le(e, 0); put_le(e, ts += 1000);
        put_le(e, uint32_t(f.size())); put_le(e, uint32_t(f.size()));
        e.insert(e.end(), f.begin(), f.end());
        block(b, 6, e);
    }
    PcapReport r = pcap_analyze(b);
    REQUIRE(r.ok);
    REQUIRE(r.tls.size() == 1);
    CHECK(r.tls[0].server == "[2001:db8:0:0:0:0:0:5]:443");
    CHECK(r.tls[0].sni == "v6.example.net");
    CHECK(r.tls[0].inner == InnerState::TooShort);
    REQUIRE(r.peers.size() == 1);
    CHECK(r.peers[0].v6);
    CHECK_FALSE(r.peers[0].local);
    CHECK(pcap_leaks(r, "203.0.113.5").outside == Outcome::Inconclusive);
    CHECK(pcap_leaks(r, "2001:db8::5").outside == Outcome::Negative);
}

TEST_CASE("pcap: quic initial hello and a bad container") {
    Bytes rec = build_chromelike_clienthello("cdn.example.org");
    Bytes hello(rec.begin() + 5, rec.end());
    Bytes dcid = {1, 2, 3, 4, 5, 6, 7, 8}, scid = {9, 9, 9, 9};
    Bytes dg = quic_build_client_initial(dcid, scid, hello, 0, 1);
    REQUIRE(dg.size() >= 1200);
    Cap cap;
    cap.packet(v4(CLIENT, NODE, 17, udp(50555, 443, dg)));
    PcapReport r = pcap_analyze(cap.b);
    REQUIRE(r.ok);
    REQUIRE(r.tls.size() == 1);
    CHECK(r.tls[0].quic);
    CHECK(r.tls[0].sni == "cdn.example.org");
    CHECK(r.tls[0].ja4.rfind("q13d", 0) == 0);
    CHECK(r.inner.empty());

    PcapReport bad = pcap_analyze(Bytes{1, 2, 3, 4, 5, 6, 7, 8});
    CHECK_FALSE(bad.ok);
    CHECK_FALSE(bad.error.empty());
}
