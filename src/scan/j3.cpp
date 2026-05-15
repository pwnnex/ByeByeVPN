// SPDX-License-Identifier: GPL-3.0-or-later
#include "j3.h"
#include "../common/winhdr.h"
#include "../common/util.h"
#include "../common/config.h"
#include "../net/tcp.h"

#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <vector>

using std::string;
using std::vector;

namespace {

// probe identifiers. the order in this enum is the order they were sent in
// pre-v2.7.0; that fixed order itself was a tool fingerprint. since v2.7.0
// j3_probes() shuffles them per scan and may keep only a subset, so the
// scanner-shaped 8-in-fixed-order signature no longer goes on the wire.
enum ProbeKind {
    P_EMPTY,
    P_HTTP_GET,
    P_HTTP_CONNECT,
    P_SSH_BANNER,
    P_RANDOM_512,
    P_TLS_INVALID_SNI,
    P_HTTP_ABSURI,
    P_FF128,
    P_COUNT
};

J3Result send_simple(const string& host, int port, const string& name,
                     const void* data, int dlen, bool close_after_send = false) {
    J3Result r; r.name = name;
    auto t0 = std::chrono::steady_clock::now();
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) return r;
    if (dlen > 0) tcp_send_all(s, data, dlen);
    if (close_after_send) { closesocket(s); return r; }
    char buf[1024]; int n = tcp_recv_to(s, buf, sizeof(buf) - 1, 1200);
    closesocket(s);
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    if (n > 0) {
        r.responded = true; r.bytes = n;
        string raw(buf, n);
        size_t nl = raw.find('\n');
        r.first_line = trim(raw.substr(0, nl == string::npos ? raw.size() : nl));
        r.hex_head = hex_s((unsigned char*)buf, std::min(16, n), true);
    }
    return r;
}

J3Result run_one(ProbeKind kind, const string& host, int port) {
    switch (kind) {
    case P_EMPTY: {
        string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
        J3Result r; r.name = "empty/close";
        if (s != INVALID_SOCKET) {
            char buf[128]; int n = tcp_recv_to(s, buf, sizeof(buf) - 1, 800);
            if (n > 0) {
                r.responded = true; r.bytes = n;
                r.first_line = printable_prefix(string(buf, n));
                r.hex_head = hex_s((unsigned char*)buf, std::min(16, n), true);
            }
            closesocket(s);
        }
        return r;
    }
    case P_HTTP_GET: {
        string req = "GET / HTTP/1.1\r\nHost: " + host
                   + "\r\nUser-Agent: curl/8.4.0\r\nAccept: */*\r\n\r\n";
        return send_simple(host, port, "HTTP GET /", req.data(), (int)req.size());
    }
    case P_HTTP_CONNECT: {
        string req = "CONNECT 1.2.3.4:443 HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n";
        return send_simple(host, port, "HTTP CONNECT", req.data(), (int)req.size());
    }
    case P_SSH_BANNER: {
        string req = "SSH-2.0-OpenSSH_8.9p1\r\n";
        return send_simple(host, port, "SSH banner", req.data(), (int)req.size());
    }
    case P_RANDOM_512: {
        unsigned char buf[512]; RAND_bytes(buf, 512);
        return send_simple(host, port, "random 512B", buf, 512);
    }
    case P_TLS_INVALID_SNI: {
        unsigned char hello[] = {
            0x16,0x03,0x01,0x00,0x70,
            0x01,0x00,0x00,0x6c,
            0x03,0x03,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0x00,
            0x00,0x02,
            0x13,0x02,
            0x01,0x00,
            0x00,0x41,
            0x00,0x00,0x00,0x10, 0x00,0x0e, 0x00,0x00,0x0b, 0,0,0,'.','i','n','v','a','l','i','d',
            0x00,0x10,0x00,0x0b, 0x00,0x09, 0x08,'h','t','t','p','/','1','.','1',
            0x00,0x0b,0x00,0x02, 0x01,0x00,
            0x00,0x0a,0x00,0x04, 0x00,0x02,0x00,0x1d,
            0x00,0x0d,0x00,0x0a, 0x00,0x08, 0x04,0x01, 0x05,0x01, 0x08,0x07, 0x08,0x08,
            0x00,0x2b,0x00,0x03, 0x02,0x03,0x04,
            0x00,0x33,0x00,0x02, 0x00,0x00
        };
        RAND_bytes(hello + 11, 32);
        for (size_t i = 11 + 32; i + 11 <= sizeof(hello); ++i) {
            if (hello[i]   == '.' && hello[i+1] == 'i' && hello[i+2] == 'n' &&
                hello[i+3] == 'v' && hello[i+4] == 'a' && hello[i+5] == 'l' &&
                hello[i+6] == 'i' && hello[i+7] == 'd' && i >= 3) {
                unsigned char rnd[3]; RAND_bytes(rnd, 3);
                hello[i-3] = 'a' + (rnd[0] % 26);
                hello[i-2] = 'a' + (rnd[1] % 26);
                hello[i-1] = 'a' + (rnd[2] % 26);
                break;
            }
        }
        return send_simple(host, port, "TLS CH invalid-SNI", hello, (int)sizeof(hello));
    }
    case P_HTTP_ABSURI: {
        string req = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        return send_simple(host, port, "HTTP abs-URI (proxy-style)",
                           req.data(), (int)req.size());
    }
    case P_FF128: {
        unsigned char garb[128]; std::memset(garb, 0xFF, sizeof(garb));
        return send_simple(host, port, "0xFF x128", garb, sizeof(garb));
    }
    default: return J3Result{};
    }
}

} // namespace

vector<J3Result> j3_probes(const string& host, int port) {
    // build the full kind list then shuffle with a CSPRNG so the on-wire
    // probe ORDER is randomized per scan. before v2.7.0 these eight probes
    // always went out in the same order; that ordering was itself the most
    // distinctive byebyevpn fingerprint at the network layer.
    vector<int> kinds;
    kinds.reserve(P_COUNT);
    for (int i = 0; i < P_COUNT; ++i) kinds.push_back(i);
    crypto_shuffle(kinds);

    // optional scope cut: take only N out of the eight. --j3-subset=4 cuts
    // the count in half so the per-port pattern is even less identifiable.
    if (g_j3_subset > 0 && g_j3_subset < (int)kinds.size()) {
        kinds.resize((size_t)g_j3_subset);
    }

    vector<J3Result> out;
    out.reserve(kinds.size());
    for (size_t i = 0; i < kinds.size(); ++i) {
        // inter-probe timing jitter under --stealth: 250-1500ms between
        // probes so the burst doesn't smell like an automated scan. NO-OP
        // when stealth is off.
        if (i > 0) stealth_sleep_ms(250, 1500);
        out.push_back(run_one((ProbeKind)kinds[i], host, port));
    }
    return out;
}

static bool looks_like_http_line(const string& first_line, bool* bad_version_out = nullptr) {
    if (first_line.size() < 9) return false;
    if (first_line.compare(0, 5, "HTTP/") != 0) return false;
    char x = first_line[5];
    char dot = first_line.size() > 6 ? first_line[6] : 0;
    char y   = first_line.size() > 7 ? first_line[7] : 0;
    if (dot != '.') return false;
    bool good_version = ((x == '1' && (y == '0' || y == '1')) || (x == '2' && y == '0'));
    if (!good_version && bad_version_out) *bad_version_out = true;
    return true;
}

J3Analysis j3_analyze(const vector<J3Result>& probes) {
    J3Analysis a;
    struct KeyEntry { string line; int bytes; const char* name; };
    vector<KeyEntry> keys;
    for (auto& p: probes) {
        if (p.responded) {
            ++a.resp;
            keys.push_back({p.first_line, p.bytes, p.name.c_str()});
            bool bad_v = false;
            bool is_http = looks_like_http_line(p.first_line, &bad_v);
            if (is_http && !bad_v)      ++a.http_real;
            else if (is_http && bad_v)  ++a.http_bad_version;
            else                        ++a.raw_non_http;
        } else {
            ++a.silent;
        }
    }
    auto is_valid_http_probe = [](const char* n) {
        if (!n) return false;
        return std::strstr(n, "HTTP GET /") != nullptr ||
               std::strstr(n, "HTTP abs-URI") != nullptr;
    };
    for (size_t i = 0; i < keys.size(); ++i) {
        int count = 0;
        bool has_valid_http = false;
        for (size_t j = 0; j < keys.size(); ++j) {
            if (keys[i].line == keys[j].line && keys[i].bytes == keys[j].bytes) {
                ++count;
                if (is_valid_http_probe(keys[j].name)) has_valid_http = true;
            }
        }
        if (count >= 2 && keys[i].line.size() > 3 && has_valid_http) {
            a.canned_identical = count;
            a.canned_line      = keys[i].line;
            a.canned_bytes     = keys[i].bytes;
            break;
        }
    }
    return a;
}

Ja3Info our_openssl_ja3_signature() {
    Ja3Info j;
    j.version    = "771";
    j.ciphers    = "4865,4866,4867,49195,49199,49196,49200,52393,52392,49171,49172,156,157,47,53";
    j.extensions = "0,11,10,35,22,23,13,43,45,51";
    j.groups     = "29,23,30,25,24";
    j.ec_formats = "0";
    j.ja3_hash   = "0cce74b0d9b7f8528fb2181588d23793";
    return j;
}
