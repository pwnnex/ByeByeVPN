// SPDX-License-Identifier: GPL-3.0-or-later
#include "dpi_probe.h"
#include "chrome_ch.h"
#include "../common/winhdr.h"
#include "../net/tcp.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using std::string;
using std::vector;

namespace {

struct ChResult {
    bool progressed = false;   // got a TLS response (ServerHello / alert)
    bool reset      = false;   // connection reset / closed before any TLS reply
    int  reset_ms   = -1;
};

// open one TLS connection, send a real ClientHello carrying `sni`, and observe
// whether the handshake gets a TLS response or an early RST. if `fragment`, the
// ClientHello is split across two TCP segments inside the SNI string so a
// stateless SNI-matcher can't see the whole hostname in one packet.
ChResult send_ch(const string& ip, int port, const string& sni, bool fragment, int to_ms) {
    ChResult r;
    string err;
    SOCKET s = tcp_connect(ip, port, to_ms, err);
    if (s == INVALID_SOCKET) return r;        // couldn't even connect

    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&one, sizeof(one));

    vector<uint8_t> rec = build_chrome131_clienthello(sni);
    auto t0 = std::chrono::steady_clock::now();

    if (fragment && rec.size() > 10) {
        size_t split = rec.size() / 2;
        if (!sni.empty()) {
            for (size_t i = 0; i + sni.size() <= rec.size(); ++i)
                if (std::memcmp(rec.data() + i, sni.data(), sni.size()) == 0) {
                    split = i + (sni.size() + 1) / 2;   // straddle (round up so 1+ byte stays in seg 1)
                    break;
                }
        }
        if (split < 1) split = 1;
        if (split >= rec.size()) split = rec.size() - 1;
        send(s, (const char*)rec.data(), (int)split, 0);
        Sleep(18);                              // force a distinct TCP segment
        send(s, (const char*)rec.data() + split, (int)(rec.size() - split), 0);
    } else {
        send(s, (const char*)rec.data(), (int)rec.size(), 0);
    }

    DWORD tv = (DWORD)to_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    char buf[512];
    int n = recv(s, buf, sizeof(buf), 0);
    int dt = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::steady_clock::now() - t0).count();

    if (n > 0) {
        r.progressed = true;                    // a TLS reply means no SNI-RST
    } else if (n == 0) {
        r.reset = true; r.reset_ms = dt;        // clean close with no TLS reply
    } else {
        int werr = WSAGetLastError();
        if (werr == WSAECONNRESET) { r.reset = true; r.reset_ms = dt; }
        // WSAETIMEDOUT / other: no reply and no reset -> leave both false
    }
    closesocket(s);
    return r;
}

// a resolved address in a fake-IP / tunnel range means a VPN with fake-IP DNS
// is active locally: traffic to it goes through the tunnel, not the raw ISP
// path, so an SNI-RST test is meaningless. ranges: 198.18.0.0/15 (RFC 2544,
// the sing-box / xray fake-IP default), 100.64.0.0/10 (CGNAT), 240.0.0.0/4.
bool looks_like_fake_ip(const string& ip) {
    unsigned a = 0, b = 0;
    if (std::sscanf(ip.c_str(), "%u.%u", &a, &b) != 2) return false;
    if (a == 198 && (b == 18 || b == 19)) return true;
    if (a == 100 && b >= 64 && b <= 127)  return true;
    if (a >= 240)                          return true;
    return false;
}

} // namespace

DpiProbe dpi_probe(const string& ip, int port, const string& sni, int to_ms) {
    DpiProbe r;
    r.ran = true;

    if (looks_like_fake_ip(ip)) {
        r.tunneled = true;
        r.note = "resolved IP " + ip + " is a fake-IP/tunnel address (198.18.x / CGNAT / class-E) "
                 "- a VPN with fake-IP DNS is active, so this probe is measuring the tunnel, not "
                 "your raw ISP path. disable the VPN and re-run for a real SNI-RST test.";
        return r;
    }

    // baseline: a SNI that is never on a blocklist. its only job is to prove
    // the IP:port itself accepts TLS, so any difference is SNI-specific.
    ChResult base = send_ch(ip, port, "www.example.com", false, to_ms);
    r.benign_reset = base.reset; r.benign_progressed = base.progressed;

    ChResult tgt = send_ch(ip, port, sni, false, to_ms);
    r.target_reset = tgt.reset; r.target_progressed = tgt.progressed; r.target_reset_ms = tgt.reset_ms;

    if (tgt.reset && base.progressed) {
        r.sni_blocked = true;
        ChResult fr = send_ch(ip, port, sni, true, to_ms);
        r.frag_tested = true;
        r.frag_evades = fr.progressed && !fr.reset;
    } else if (tgt.reset && base.reset) {
        r.ip_blocked = true;
    }

    if (r.sni_blocked) {
        r.note = "SNI '" + sni + "' is RST on your path ~" +
                 std::to_string(tgt.reset_ms) + "ms after the ClientHello, but a benign SNI to "
                 "the same IP completes a TLS reply. that's active SNI-based filtering between "
                 "you and the host (ISP / TSPU), not the host being down.";
        if (r.frag_tested)
            r.note += r.frag_evades
                ? " fragmenting the ClientHello (split inside the hostname) EVADES it here — a "
                  "Zapret / GoodbyeDPI style fragmentor, or a transport that fragments, gets you through."
                : " fragmenting the ClientHello did NOT help (this DPI reassembles segments, or the "
                  "host itself is resetting).";
    } else if (r.ip_blocked) {
        r.note = "both the target and a benign SNI reset to this IP — looks like an IP-level block "
                 "or a dead host, not SNI-specific filtering.";
    } else if (!tgt.progressed && !base.progressed) {
        r.note = "no TLS reply to either SNI (filtered / no route / timeout) — inconclusive.";
    } else {
        r.note = "no SNI-based RST on your path for '" + sni +
                 "' (the ClientHello reached the host and got a TLS reply).";
    }
    return r;
}
