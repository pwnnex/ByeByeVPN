// SPDX-License-Identifier: GPL-3.0-or-later
#include "pcap_analysis.h"

#include "capture.h"
#include "ja4.h"
#include "quic.h"
#include "../common/json.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <iterator>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>

namespace {

constexpr size_t STREAM_CAP   = size_t(64) * 1024;   // first bytes kept per direction
constexpr size_t PENDING_MAX  = 512;         // out-of-order segments held per direction
constexpr size_t FLOWS_MAX    = 50000;
constexpr size_t RECORDS_KEPT = 12;
constexpr size_t DNS_KEPT     = 5000;
constexpr size_t QUIC_MAX     = 4096;

// inner handshake rule, docs/SIGNALS.md tls-in-tls
constexpr uint64_t INNER_HELLO_MIN  = 280;   // inner clienthello plus a proxy header
constexpr uint64_t INNER_SERVER_MIN = 600;   // inner server flight with a certificate
const uint32_t INNER_FINISHED[] = {58, 64, 74, 80};   // finished alone or after ccs, sha-256 or sha-384

struct Chunk { size_t end; uint64_t ns; };

// one tcp direction rebuilt from sequence numbers, first STREAM_CAP bytes
struct Stream {
    bool based = false;
    uint32_t base = 0;
    std::vector<uint8_t> data;
    std::vector<Chunk> chunks;
    std::map<uint32_t, std::pair<std::vector<uint8_t>, uint64_t>> pending;

    void syn(uint32_t seq) {
        if (!based) { based = true; base = seq + 1; }
    }
    void add(uint32_t seq, const std::vector<uint8_t>& p, uint64_t ns) {
        if (p.empty()) return;
        if (!based) { based = true; base = seq; }
        uint32_t rel = seq - base;
        if (rel >= STREAM_CAP) return;   // before the start or past the cap
        if (rel > data.size()) {
            if (pending.size() < PENDING_MAX) pending.emplace(rel, std::make_pair(p, ns));
            return;
        }
        append(rel, p, ns);
        for (auto it = pending.begin(); it != pending.end() && it->first <= data.size();) {
            append(it->first, it->second.first, it->second.second);
            it = pending.erase(it);
        }
    }
    void append(size_t at, const std::vector<uint8_t>& p, uint64_t ns) {
        if (at + p.size() <= data.size() || data.size() >= STREAM_CAP) return;   // retransmit
        size_t skip = data.size() - at;
        size_t take = std::min(p.size() - skip, STREAM_CAP - data.size());
        auto from = p.begin() + static_cast<std::ptrdiff_t>(skip);
        data.insert(data.end(), from, from + static_cast<std::ptrdiff_t>(take));
        chunks.push_back({data.size(), ns});
    }
    // time of the segment that brought byte end-1
    uint64_t time_at(size_t end) const {
        auto it = std::lower_bound(chunks.begin(), chunks.end(), end,
                                   [](const Chunk& c, size_t e) { return c.end < e; });
        if (it != chunks.end()) return it->ns;
        return chunks.empty() ? 0 : chunks.back().ns;
    }
};

struct Flow {
    std::string a, b;               // ip:port, a sent the first packet seen
    std::string a_addr, b_addr;
    uint16_t a_port = 0, b_port = 0;
    uint8_t  proto = 0;
    int      syn_from = 0;          // 1 a, 2 b
    Stream   ab, ba;
    uint64_t ab_bytes = 0, ba_bytes = 0, packets = 0, first_ns = 0, last_ns = 0;
};

struct QuicHello {
    std::string client, server;
    uint64_t first_ns = 0;
    size_t   bytes = 0;
    std::map<uint64_t, std::vector<uint8_t>> pieces;
};

struct Rec { uint8_t type; uint32_t len; uint64_t ns; };

std::string endpoint(const std::string& addr, uint16_t port) { return addr + ":" + std::to_string(port); }

bool starts_hello(const Stream& s) {
    return s.data.size() >= 6 && s.data[0] == 22 && s.data[1] == 3 && s.data[5] == 1;
}

// records from the start of a stream; hs gets the cleartext handshake bytes
void tls_records(const Stream& s, std::vector<Rec>& recs, std::vector<uint8_t>& hs) {
    const auto& d = s.data;
    size_t pos = 0;
    bool clear = true;
    while (d.size() - pos >= 5 && recs.size() < 512) {
        uint8_t t = d[pos];
        uint32_t len = (uint32_t(d[pos + 3]) << 8) | d[pos + 4];
        if (t < 20 || t > 23 || d[pos + 1] != 3 || d[pos + 2] > 4 || len == 0 || len > 18432) break;
        if (d.size() - pos - 5 < len) break;
        if (t == 20) clear = false;
        auto body = d.begin() + static_cast<std::ptrdiff_t>(pos + 5);
        if (t == 22 && clear && hs.size() < 65536) hs.insert(hs.end(), body, body + len);
        recs.push_back({t, len, s.time_at(pos + 5 + len)});
        pos += 5 + len;
    }
}

const char* version_name(int v) {
    switch (v) {
        case 0x0304: return "1.3";
        case 0x0303: return "1.2";
        case 0x0302: return "1.1";
        case 0x0301: return "1.0";
        default:     return "";
    }
}

// bytes a data record adds to its plaintext; 0 when unknown
uint32_t record_overhead(int version, uint16_t cipher) {
    if (version == 0x0304) return 17;                            // content type and tag
    if (version != 0x0303) return 0;
    if (cipher >= 0xcca8 && cipher <= 0xccae) return 16;         // chacha20-poly1305
    static const uint16_t GCM[] = {0x009c, 0x009d, 0x009e, 0x009f, 0x00a2, 0x00a3, 0x00a4, 0x00a5,
                                   0x00a6, 0x00a7, 0xc02b, 0xc02c, 0xc02d, 0xc02e, 0xc02f, 0xc030,
                                   0xc031, 0xc032};
    for (auto g : GCM)
        if (g == cipher) return 24;                              // explicit nonce and tag
    return 0;
}

void hello_fields(const ClientHelloFp& ch, TlsFlow& f) {
    f.sni = ch.sni;
    f.ja4 = ja4_client(ch);
    f.alpn = ch.alpn_first;
    f.grease = ch.has_grease;
    f.ech = std::find(ch.extensions.begin(), ch.extensions.end(), 0xfe0d) != ch.extensions.end();
    for (auto g : ch.groups)
        if (g == 0x11eb || g == 0x11ec || g == 0x11ed || g == 0x6399) f.pq = true;
}

// data records after the outer handshake, cut into the first three flights
bool data_flights(const std::vector<Rec>& c, const std::vector<Rec>& s, bool v13, uint32_t overhead,
                  Flights& out, TlsFlow& t, std::string& why) {
    struct Ev { uint64_t ns; bool client; uint32_t len; };
    std::vector<Ev> ev;
    uint64_t fin = 0;
    bool fin_seen = !v13;
    for (const auto& r : c) {
        if (r.type != 23) continue;
        if (!fin_seen) {
            // tls 1.3 client finished: 32 or 48 byte mac, header, type, tag
            if (r.len != 53 && r.len != 69) { why = "outer client finished not where expected"; return false; }
            fin_seen = true;
            fin = r.ns;
            continue;
        }
        ev.push_back({r.ns, true, r.len});
    }
    if (!fin_seen) { why = "no client finished in the capture"; return false; }
    for (const auto& r : s) {
        if (r.type != 23) continue;
        if (v13 && r.ns <= fin) continue;   // the server's encrypted handshake flight
        ev.push_back({r.ns, false, r.len});
    }
    std::stable_sort(ev.begin(), ev.end(), [](const Ev& x, const Ev& y) { return x.ns < y.ns; });
    for (const auto& e : ev) {
        auto& v = e.client ? t.c2s : t.s2c;
        if (v.size() < RECORDS_KEPT) v.push_back(e.len);
    }
    size_t i = 0;
    // tickets and server-first bytes come before any client data
    while (i < ev.size() && !ev[i].client) ++i;
    auto take = [&](bool client, std::vector<uint32_t>& f) {
        for (; i < ev.size() && ev[i].client == client; ++i)
            f.push_back(ev[i].len > overhead ? ev[i].len - overhead : 0);
    };
    take(true, out.f1);
    take(false, out.f2);
    take(true, out.f3);
    return true;
}

bool dns_question(const uint8_t* p, size_t n, std::string& name, uint16_t& qtype) {
    if (n < 17) return false;
    if (p[2] & 0x80) return false;                    // a response
    if ((p[2] >> 3) & 0x0f) return false;             // not a standard query
    unsigned qd = (unsigned(p[4]) << 8) | p[5];
    if (qd == 0 || qd > 4) return false;
    size_t pos = 12;
    name.clear();
    for (;;) {
        if (pos >= n) return false;
        size_t l = p[pos++];
        if (l == 0) break;
        if (l > 63 || n - pos < l || name.size() + l + 1 > 255) return false;
        if (!name.empty()) name += '.';
        for (size_t k = 0; k < l; ++k) {
            unsigned char ch = p[pos + k];
            name += (ch > 0x20 && ch < 0x7f) ? static_cast<char>(std::tolower(ch)) : '?';
        }
        pos += l;
    }
    if (n - pos < 4) return false;
    qtype = static_cast<uint16_t>((unsigned(p[pos]) << 8) | p[pos + 1]);
    if (name.empty()) name = ".";
    return true;
}

std::string jstr(const std::string& s) { return "\"" + json_escape_string(s) + "\""; }

std::string jnums(const std::vector<uint32_t>& v) {
    std::string o = "[";
    for (size_t i = 0; i < v.size(); ++i) o += (i ? "," : "") + std::to_string(v[i]);
    return o + "]";
}

const char* inner_name(InnerState s) {
    switch (s) {
        case InnerState::Match:    return "match";
        case InnerState::NoMatch:  return "no match";
        case InnerState::TooShort: return "too short";
        default:                   return "not checked";
    }
}

bool parse_v4(const std::string& s, unsigned out[4]) {
    size_t pos = 0;
    for (int i = 0; i < 4; ++i) {
        if (i) {
            if (pos >= s.size() || s[pos] != '.') return false;
            ++pos;
        }
        size_t start = pos;
        unsigned v = 0;
        while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos])) && pos - start < 3)
            v = v * 10 + unsigned(s[pos++] - '0');
        if (pos == start || v > 255) return false;
        out[i] = v;
    }
    return pos == s.size();
}

bool parse_v6(std::string s, unsigned out[8]) {
    if (s.size() > 2 && s.front() == '[' && s.back() == ']') s = s.substr(1, s.size() - 2);
    if (s.empty() || s.size() > 45) return false;
    std::vector<unsigned> head, tail;
    bool gap = false;
    size_t pos = 0;
    if (s.compare(0, 2, "::") == 0) { gap = true; pos = 2; }
    while (pos < s.size()) {
        size_t start = pos;
        unsigned v = 0;
        while (pos < s.size() && std::isxdigit(static_cast<unsigned char>(s[pos])) && pos - start < 4) {
            char c = static_cast<char>(std::tolower(static_cast<unsigned char>(s[pos++])));
            v = v * 16 + unsigned(c <= '9' ? c - '0' : c - 'a' + 10);
        }
        if (pos == start) return false;
        (gap ? tail : head).push_back(v);
        if (pos == s.size()) break;
        if (s[pos] != ':') return false;
        ++pos;
        if (pos < s.size() && s[pos] == ':') {
            if (gap) return false;
            gap = true;
            ++pos;
        } else if (pos == s.size()) {
            return false;
        }
    }
    size_t n = head.size() + tail.size();
    if (gap ? n > 7 : n != 8) return false;
    for (int i = 0; i < 8; ++i) out[i] = 0;
    for (size_t i = 0; i < head.size(); ++i) out[i] = head[i];
    for (size_t i = 0; i < tail.size(); ++i) out[8 - tail.size() + i] = tail[i];
    return true;
}

} // namespace

std::string capture_address(const std::string& text) {
    unsigned v4[4];
    if (parse_v4(text, v4))
        return std::to_string(v4[0]) + "." + std::to_string(v4[1]) + "." + std::to_string(v4[2]) + "." +
               std::to_string(v4[3]);
    unsigned v6[8];
    if (!parse_v6(text, v6)) return {};
    std::string o = "[";
    char buf[8];
    for (int i = 0; i < 8; ++i) {
        std::snprintf(buf, sizeof(buf), "%x", v6[i]);
        if (i) o += ':';
        o += buf;
    }
    return o + "]";
}

bool peer_is_local(const std::string& addr) {
    unsigned v4[4];
    if (parse_v4(addr, v4)) {
        unsigned a = v4[0], b = v4[1];
        return a == 0 || a == 10 || a == 127 || a >= 224 || (a == 169 && b == 254) ||
               (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168);
    }
    unsigned v6[8];
    if (!parse_v6(addr, v6)) return false;
    bool zero_prefix = v6[0] == 0 && v6[1] == 0 && v6[2] == 0 && v6[3] == 0 && v6[4] == 0 && v6[5] == 0;
    return (v6[0] & 0xffc0) == 0xfe80 || (v6[0] & 0xff00) == 0xff00 || (v6[0] & 0xfe00) == 0xfc00 ||
           (zero_prefix && v6[6] == 0 && v6[7] <= 1);
}

bool doh_name(const std::string& sni) {
    static const std::set<std::string> NAMES = {
        "dns.google", "dns.google.com", "dns64.dns.google", "cloudflare-dns.com", "one.one.one.one",
        "1dot1dot1dot1.cloudflare-dns.com", "mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
        "security.cloudflare-dns.com", "family.cloudflare-dns.com", "dns.quad9.net", "dns9.quad9.net",
        "dns10.quad9.net", "dns11.quad9.net", "doh.opendns.com", "dns.adguard.com", "dns.adguard-dns.com",
        "unfiltered.adguard-dns.com", "family.adguard-dns.com", "dns.nextdns.io", "doh.cleanbrowsing.org",
        "common.dot.dns.yandex.net", "safe.dot.dns.yandex.net", "family.dot.dns.yandex.net",
        "doh.mullvad.net", "dns.mullvad.net", "freedns.controld.com", "dns.controld.com"};
    if (NAMES.count(sni)) return true;
    const std::string nd = ".dns.nextdns.io";
    return sni.size() > nd.size() && sni.compare(sni.size() - nd.size(), nd.size(), nd) == 0;
}

std::string inner_handshake_match(const Flights& f) {
    if (f.f1.empty() || f.f2.empty() || f.f3.empty()) return {};
    uint64_t c1 = 0, s1 = 0;
    for (auto v : f.f1) c1 += v;
    for (auto v : f.f2) s1 += v;
    const uint32_t c2 = f.f3.front();
    if (c1 < INNER_HELLO_MIN || s1 < INNER_SERVER_MIN) return {};
    if (std::find(std::begin(INNER_FINISHED), std::end(INNER_FINISHED), c2) == std::end(INNER_FINISHED)) return {};
    return "client " + std::to_string(c1) + " B, server " + std::to_string(s1) + " B, then client " +
           std::to_string(c2) + " B: the size of a tls 1.3 finished";
}

Outcome inner_server_outcome(size_t checked, size_t matched) {
    // flows carry different content, so a flow without the pattern does
    // not contradict one with it; two matching flows are two observations
    if (matched >= 2) return Outcome::Positive;
    if (matched == 0 && checked >= 2) return Outcome::Negative;
    return Outcome::Inconclusive;
}

PcapReport pcap_analyze(const std::vector<uint8_t>& bytes) {
    PcapReport r;
    std::map<std::string, Flow> flows;
    std::map<std::vector<uint8_t>, QuicHello> quic;
    try {
        capture_walk(bytes, [&](const uint8_t* p, size_t n, uint32_t link, uint64_t ns, const std::string&) {
            Decoded d;
            if (!capture_decode(p, n, link, d)) { ++r.skipped; return; }
            if (d.proto == 6) ++r.tcp_segments; else ++r.udp_datagrams;
            const std::string sa = endpoint(d.src, d.sport), da = endpoint(d.dst, d.dport);
            const std::string key = std::to_string(d.proto) + "|" + (sa < da ? sa + "|" + da : da + "|" + sa);
            auto it = flows.find(key);
            if (it == flows.end()) {
                if (flows.size() >= FLOWS_MAX) { ++r.skipped; return; }
                Flow f;
                f.a = sa; f.b = da;
                f.a_addr = d.src; f.b_addr = d.dst;
                f.a_port = d.sport; f.b_port = d.dport;
                f.proto = d.proto;
                f.first_ns = ns;
                it = flows.emplace(key, std::move(f)).first;
            }
            Flow& f = it->second;
            const bool from_a = sa == f.a;
            ++f.packets;
            f.last_ns = std::max(f.last_ns, ns);
            (from_a ? f.ab_bytes : f.ba_bytes) += d.payload.size();
            if (d.proto == 6) {
                Stream& st = from_a ? f.ab : f.ba;
                const bool syn = d.flags & 0x02, ack = d.flags & 0x10;
                if (syn) {
                    st.syn(d.seq);
                    if (!ack && !f.syn_from) f.syn_from = from_a ? 1 : 2;
                }
                st.add(syn ? d.seq + 1 : d.seq, d.payload, ns);
                return;
            }
            if (d.dport == 53 && r.dns.size() < DNS_KEPT) {
                DnsQuery q;
                if (dns_question(d.payload.data(), d.payload.size(), q.name, q.qtype)) {
                    q.resolver = da;
                    r.dns.push_back(q);
                }
            }
            if (d.payload.size() >= 1200 && (d.payload[0] & 0xf0) == 0xc0) {
                std::vector<uint8_t> dcid;
                std::vector<QuicCryptoPiece> pieces;
                if (!quic_client_initial_crypto(d.payload, dcid, pieces)) return;
                auto q = quic.find(dcid);
                if (q == quic.end()) {
                    if (quic.size() >= QUIC_MAX) return;
                    q = quic.emplace(dcid, QuicHello{}).first;
                    q->second.client = sa;
                    q->second.server = da;
                    q->second.first_ns = ns;
                }
                for (auto& pc : pieces) {
                    if (q->second.bytes + pc.data.size() > 65536) break;
                    q->second.bytes += pc.data.size();
                    q->second.pieces.emplace(pc.offset, std::move(pc.data));
                }
            }
        }, r.records, r.skipped);
    } catch (const std::exception& e) {
        r.error = e.what();
        return r;
    }

    for (auto& kv : flows) {
        Flow& f = kv.second;
        if (f.proto != 6) continue;
        int client = f.syn_from;
        if (!client) client = starts_hello(f.ab) ? 1 : starts_hello(f.ba) ? 2 : 0;
        if (!client) continue;
        const Stream& cs = client == 1 ? f.ab : f.ba;
        const Stream& ss = client == 1 ? f.ba : f.ab;
        const std::string& srv = client == 1 ? f.b : f.a;
        const uint16_t sport = client == 1 ? f.b_port : f.a_port;
        if (sport == 53) {
            // dns over tcp: two-byte length, then the message
            size_t pos = 0;
            while (cs.data.size() - pos >= 2 && r.dns.size() < DNS_KEPT) {
                size_t len = (size_t(cs.data[pos]) << 8) | cs.data[pos + 1];
                if (!len || cs.data.size() - pos - 2 < len) break;
                DnsQuery q;
                if (dns_question(cs.data.data() + pos + 2, len, q.name, q.qtype)) {
                    q.resolver = srv;
                    q.tcp = true;
                    r.dns.push_back(q);
                }
                pos += 2 + len;
            }
            continue;
        }
        if (!starts_hello(cs)) continue;
        std::vector<Rec> crec, srec;
        std::vector<uint8_t> chs, shs;
        tls_records(cs, crec, chs);
        tls_records(ss, srec, shs);
        ClientHelloFp ch;
        if (!parse_client_hello(chs.data(), chs.size(), ch)) continue;
        TlsFlow t;
        t.client = client == 1 ? f.a : f.b;
        t.server = srv;
        hello_fields(ch, t);
        t.c2s_bytes = client == 1 ? f.ab_bytes : f.ba_bytes;
        t.s2c_bytes = client == 1 ? f.ba_bytes : f.ab_bytes;
        t.seconds = static_cast<double>(f.last_ns - f.first_ns) / 1e9;
        ServerHelloFp sh;
        if (shs.empty() || !parse_server_hello(shs.data(), shs.size(), sh)) {
            t.inner = InnerState::TooShort;
            t.inner_detail = "no server hello in the capture";
        } else {
            t.ja4s = ja4s_server(sh);
            t.version = version_name(sh.real_version);
            const uint32_t oh = record_overhead(sh.real_version, sh.cipher);
            Flights fl;
            std::string why;
            if (!oh) {
                t.inner_detail = "record overhead unknown for this version and cipher";
            } else if (!data_flights(crec, srec, sh.real_version == 0x0304, oh, fl, t, why)) {
                t.inner_detail = why;
            } else if (fl.f1.empty() || fl.f2.empty() || fl.f3.empty()) {
                t.inner = InnerState::TooShort;
                t.inner_detail = "fewer than three data flights after the handshake";
            } else {
                t.inner_detail = inner_handshake_match(fl);
                t.inner = t.inner_detail.empty() ? InnerState::NoMatch : InnerState::Match;
                if (t.inner == InnerState::NoMatch) {
                    uint64_t c1 = 0, s1 = 0;
                    for (auto v : fl.f1) c1 += v;
                    for (auto v : fl.f2) s1 += v;
                    t.inner_detail = "client " + std::to_string(c1) + " B, server " + std::to_string(s1) +
                                     " B, then client " + std::to_string(fl.f3.front()) + " B";
                }
            }
        }
        r.tls.push_back(std::move(t));
    }

    for (auto& kv : quic) {
        QuicHello& h = kv.second;
        std::vector<uint8_t> buf;
        for (const auto& pc : h.pieces) {
            if (pc.first > buf.size()) break;
            if (pc.first + pc.second.size() > buf.size())
                buf.insert(buf.end(), pc.second.begin() + static_cast<std::ptrdiff_t>(buf.size() - pc.first), pc.second.end());
        }
        ClientHelloFp ch;
        if (!parse_client_hello(buf.data(), buf.size(), ch)) continue;
        TlsFlow t;
        t.client = h.client;
        t.server = h.server;
        t.quic = true;
        hello_fields(ch, t);
        if (!t.ja4.empty()) t.ja4[0] = 'q';
        t.version = "quic";
        t.inner_detail = "quic: record sizes are not visible";
        r.tls.push_back(std::move(t));
    }
    std::stable_sort(r.tls.begin(), r.tls.end(), [](const TlsFlow& x, const TlsFlow& y) {
        return x.c2s_bytes + x.s2c_bytes > y.c2s_bytes + y.s2c_bytes;
    });

    std::map<std::string, InnerSummary> by;
    for (const auto& t : r.tls) {
        if (t.quic) continue;
        InnerSummary& s = by[t.server];
        s.server = t.server;
        ++s.flows;
        if (t.inner == InnerState::Match || t.inner == InnerState::NoMatch) ++s.checked;
        if (t.inner == InnerState::Match) ++s.matched;
    }
    for (auto& kv : by) {
        InnerSummary& s = kv.second;
        s.outcome = inner_server_outcome(s.checked, s.matched);
        if (s.outcome == Outcome::Positive)
            s.reason = std::to_string(s.matched) + " of " + std::to_string(s.flows) +
                       " flows carry the sizes of a tls handshake inside the tunnel";
        else if (s.outcome == Outcome::Negative)
            s.reason = "none of " + std::to_string(s.checked) + " checked flows has the sizes of an inner handshake";
        else if (s.matched == 1)
            s.reason = "one flow matches; a second is needed";
        else
            s.reason = "fewer than two flows long enough to check";
        r.inner.push_back(s);
    }
    std::stable_sort(r.inner.begin(), r.inner.end(), [](const InnerSummary& x, const InnerSummary& y) {
        if ((x.outcome == Outcome::Positive) != (y.outcome == Outcome::Positive)) return x.outcome == Outcome::Positive;
        return x.flows > y.flows;
    });

    std::map<std::string, Peer> peers;
    for (const auto& kv : flows) {
        const Flow& f = kv.second;
        bool b_server = f.syn_from != 2;
        if (!f.syn_from && f.a_port < 1024 && f.b_port >= 1024) b_server = false;
        Peer p;
        p.addr = b_server ? f.b_addr : f.a_addr;
        p.port = b_server ? f.b_port : f.a_port;
        p.proto = f.proto;
        p.v6 = !p.addr.empty() && p.addr[0] == '[';
        p.local = peer_is_local(p.addr);
        Peer& q = peers.emplace(std::to_string(p.proto) + "|" + endpoint(p.addr, p.port), p).first->second;
        ++q.flows;
        q.packets += f.packets;
        q.bytes += f.ab_bytes + f.ba_bytes;
    }
    for (auto& kv : peers) r.peers.push_back(kv.second);
    std::stable_sort(r.peers.begin(), r.peers.end(), [](const Peer& x, const Peer& y) {
        return x.bytes != y.bytes ? x.bytes > y.bytes : x.packets > y.packets;
    });
    r.ok = true;
    return r;
}

LeakView pcap_leaks(const PcapReport& r, const std::string& node) {
    LeakView v;
    const size_t packets = r.tcp_segments + r.udp_datagrams;
    std::set<std::string> resolvers;
    for (const auto& q : r.dns) resolvers.insert(q.resolver);
    if (r.dns.size() >= 2) {
        v.dns = Outcome::Positive;
        v.dns_reason = std::to_string(r.dns.size()) + " queries in the clear to " + std::to_string(resolvers.size()) +
                       (resolvers.size() == 1 ? " resolver" : " resolvers") + "; a box on the path reads every name";
    } else if (r.dns.size() == 1) {
        v.dns = Outcome::Inconclusive;
        v.dns_reason = "one query in the clear; a second is needed";
    } else if (packets >= 20) {
        v.dns = Outcome::Negative;
        v.dns_reason = "no port 53 query among " + std::to_string(packets) + " packets";
    } else {
        v.dns = Outcome::Inconclusive;
        v.dns_reason = "capture too short to say";
    }

    if (node.empty()) {
        v.outside_reason = "give --node with the node address to split traffic into tunnel and outside";
        return v;
    }
    v.node = capture_address(node);
    if (v.node.empty()) {
        v.outside = Outcome::Inconclusive;
        v.outside_reason = "--node is not an address";
        return v;
    }
    uint64_t node_packets = 0;
    for (const auto& p : r.peers) {
        if (p.addr == v.node) { node_packets += p.packets; continue; }
        if (p.local) continue;
        ++v.outside_peers;
        if (p.v6) ++v.outside_v6;
        v.outside_packets += p.packets;
        v.outside_bytes += p.bytes;
    }
    if (!node_packets) {
        v.outside = Outcome::Inconclusive;
        v.outside_reason = "the node does not appear in this capture";
    } else if (v.outside_packets >= 2) {
        v.outside = Outcome::Positive;
        v.outside_reason = std::to_string(v.outside_peers) + " addresses beside the node, " +
                           std::to_string(v.outside_packets) + " packets" +
                           (v.outside_v6 ? ", " + std::to_string(v.outside_v6) + " of them over ipv6" : "");
    } else if (v.outside_packets == 1) {
        v.outside = Outcome::Inconclusive;
        v.outside_reason = "one packet beside the node; a second is needed";
    } else {
        v.outside = Outcome::Negative;
        v.outside_reason = "all public traffic goes to the node";
    }
    return v;
}

std::string pcap_report_json(const PcapReport& r, const LeakView& v) {
    std::string o = "{\n  \"check\": \"pcap\",\n";
    o += "  \"records\": " + std::to_string(r.records) + ",\n  \"skipped\": " + std::to_string(r.skipped) +
         ",\n  \"tcp_segments\": " + std::to_string(r.tcp_segments) +
         ",\n  \"udp_datagrams\": " + std::to_string(r.udp_datagrams) + ",\n";
    o += "  \"node\": " + (v.node.empty() ? std::string("null") : jstr(v.node)) + ",\n";
    o += "  \"tls\": [";
    for (size_t i = 0; i < r.tls.size(); ++i) {
        const TlsFlow& t = r.tls[i];
        char secs[32];
        std::snprintf(secs, sizeof(secs), "%.3f", t.seconds);
        o += std::string(i ? "," : "") + "\n    { \"client\": " + jstr(t.client) + ", \"server\": " + jstr(t.server) +
             ", \"quic\": " + (t.quic ? "true" : "false") + ", \"sni\": " + jstr(t.sni) +
             ", \"ja4\": " + jstr(t.ja4) + ", \"ja4s\": " + jstr(t.ja4s) + ", \"version\": " + jstr(t.version) +
             ", \"alpn\": " + jstr(t.alpn) + ", \"grease\": " + (t.grease ? "true" : "false") +
             ", \"ech\": " + (t.ech ? "true" : "false") + ", \"pq\": " + (t.pq ? "true" : "false") +
             ", \"doh\": " + (doh_name(t.sni) ? "true" : "false") +
             ", \"c2s\": " + jnums(t.c2s) + ", \"s2c\": " + jnums(t.s2c) +
             ", \"c2s_bytes\": " + std::to_string(t.c2s_bytes) + ", \"s2c_bytes\": " + std::to_string(t.s2c_bytes) +
             ", \"seconds\": " + secs + ", \"inner\": " + jstr(inner_name(t.inner)) +
             ", \"inner_detail\": " + jstr(t.inner_detail) + " }";
    }
    o += r.tls.empty() ? "],\n" : "\n  ],\n";
    o += "  \"inner_handshake\": [";
    for (size_t i = 0; i < r.inner.size(); ++i) {
        const InnerSummary& s = r.inner[i];
        o += std::string(i ? "," : "") + "\n    { \"server\": " + jstr(s.server) + ", \"flows\": " + std::to_string(s.flows) +
             ", \"checked\": " + std::to_string(s.checked) + ", \"matched\": " + std::to_string(s.matched) +
             ", \"outcome\": " + jstr(outcome_name(s.outcome)) + ", \"reason\": " + jstr(s.reason) + " }";
    }
    o += r.inner.empty() ? "],\n" : "\n  ],\n";
    std::map<std::string, std::vector<const DnsQuery*>> per;
    for (const auto& q : r.dns) per[q.resolver].push_back(&q);
    o += "  \"dns\": { \"outcome\": " + jstr(outcome_name(v.dns)) + ", \"reason\": " + jstr(v.dns_reason) +
         ", \"queries\": " + std::to_string(r.dns.size()) + ", \"resolvers\": [";
    size_t k = 0;
    for (const auto& kv : per) {
        const std::string addr = kv.first.substr(0, kv.first.rfind(':'));
        std::set<std::string> names;
        for (auto* q : kv.second) names.insert(q->name);
        o += std::string(k++ ? "," : "") + "\n    { \"resolver\": " + jstr(kv.first) +
             ", \"local\": " + (peer_is_local(addr) ? "true" : "false") +
             ", \"queries\": " + std::to_string(kv.second.size()) + ", \"names\": [";
        size_t j = 0;
        for (const auto& n : names) o += std::string(j++ ? ", " : "") + jstr(n);
        o += "] }";
    }
    o += per.empty() ? "] },\n" : "\n  ] },\n";
    o += "  \"outside_node\": { \"outcome\": " + jstr(outcome_name(v.outside)) + ", \"reason\": " +
         jstr(v.outside_reason) + ", \"peers\": " + std::to_string(v.outside_peers) +
         ", \"ipv6_peers\": " + std::to_string(v.outside_v6) + ", \"packets\": " + std::to_string(v.outside_packets) +
         ", \"bytes\": " + std::to_string(v.outside_bytes) + " },\n";
    o += "  \"peers\": [";
    for (size_t i = 0; i < r.peers.size(); ++i) {
        const Peer& p = r.peers[i];
        o += std::string(i ? "," : "") + "\n    { \"proto\": \"" + (p.proto == 6 ? "tcp" : "udp") +
             "\", \"addr\": " + jstr(p.addr) + ", \"port\": " + std::to_string(p.port) +
             ", \"local\": " + (p.local ? "true" : "false") + ", \"node\": " + (p.addr == v.node ? "true" : "false") +
             ", \"flows\": " + std::to_string(p.flows) + ", \"packets\": " + std::to_string(p.packets) +
             ", \"bytes\": " + std::to_string(p.bytes) + " }";
    }
    o += r.peers.empty() ? "]\n}\n" : "\n  ]\n}\n";
    return o;
}
