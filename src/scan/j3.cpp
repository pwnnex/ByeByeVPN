// SPDX-License-Identifier: GPL-3.0-or-later
#include "j3.h"
#include "chrome_ch.h"
#include "../common/platform.h"
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
    if (close_after_send) { closesocket(s); r.end = ReadEnd::Held; return r; }
    char buf[1024]; int n = tcp_recv_to(s, buf, sizeof(buf) - 1, 1200);
    r.end = classify_recv(n, n < 0 ? WSAGetLastError() : 0);
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
        r.client_first = false;
        if (s != INVALID_SOCKET) {
            char buf[128]; int n = tcp_recv_to(s, buf, sizeof(buf) - 1, 800);
            r.end = classify_recv(n, n < 0 ? WSAGetLastError() : 0);
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
        // was a hand-typed array, lengths drifted by 11 bytes
        unsigned char rnd[3]; RAND_bytes(rnd, 3);
        string sni = "aaa.invalid";
        for (int i = 0; i < 3; ++i) sni[i] = (char)('a' + rnd[i] % 26);
        const auto hello = build_minimal_clienthello(sni);
        return send_simple(host, port, "TLS CH invalid-SNI", hello.data(), (int)hello.size());
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
    // build the full kind list then shuffle with a csprng so the on-wire
    // probe order is randomized per scan. before v2.7.0 these eight probes
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
        // probes so the burst doesn't smell like an automated scan. no-op
        // when stealth is off.
        if (i > 0) stealth_sleep_ms(250, 1500);
        out.push_back(run_one((ProbeKind)kinds[i], host, port));
    }
    return out;
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
