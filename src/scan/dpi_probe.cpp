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
    bool connected  = false;
    bool progressed = false;   // got a tls response (serverhello / alert)
    bool reset      = false;   // connection reset / closed before any tls reply
    bool silent     = false;   // no bytes, no reset, timed out
    int  reset_ms   = -1;
};

// open one tls connection, send a real clienthello carrying `sni`, and observe
// whether the handshake gets a tls response or an early RST. if `fragment`, the
// clienthello is split across two tcp segments inside the sni string so a
// stateless sni-matcher can't see the whole hostname in one packet.
ChResult send_ch(const string& ip, int port, const string& sni, bool fragment, int to_ms) {
    ChResult r;
    string err;
    SOCKET s = tcp_connect(ip, port, to_ms, err);
    if (s == INVALID_SOCKET) return r;        // couldn't even connect
    r.connected = true;

    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&one, sizeof(one));

    vector<uint8_t> rec = build_chromelike_clienthello(sni);
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
        Sleep(18);                              // force a distinct tcp segment
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
        r.progressed = true;                    // a tls reply means no sni-RST
    } else if (n == 0) {
        r.reset = true; r.reset_ms = dt;        // clean close with no tls reply
    } else {
        int werr = WSAGetLastError();
        if (werr == WSAECONNRESET) { r.reset = true; r.reset_ms = dt; }
        else if (werr == WSAETIMEDOUT) r.silent = true;
    }
    closesocket(s);
    return r;
}

// a resolved address in a fake-ip / tunnel range means a vpn with fake-ip dns
// is active locally: traffic to it goes through the tunnel, not the raw isp
// path, so an sni-RST test is meaningless. ranges: 198.18.0.0/15 (rfc 2544,
// the sing-box / xray fake-ip default), 100.64.0.0/10 (cgnat), 240.0.0.0/4.
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

    // baseline: a sni that is never on a blocklist. its only job is to prove
    // the ip:port itself accepts tls, so any difference is sni-specific.
    ChResult base = send_ch(ip, port, "www.example.com", false, to_ms);
    r.benign_connected = base.connected; r.benign_reset = base.reset;
    r.benign_silent = base.silent; r.benign_progressed = base.progressed;

    ChResult tgt = send_ch(ip, port, sni, false, to_ms);
    r.target_connected = tgt.connected; r.target_reset = tgt.reset;
    r.target_silent = tgt.silent; r.target_progressed = tgt.progressed;
    r.target_reset_ms = tgt.reset_ms;

    if (tgt.reset && base.progressed) {
        r.sni_blocked = true;
        ChResult fr = send_ch(ip, port, sni, true, to_ms);
        r.frag_tested = true;
        r.frag_evades = fr.progressed && !fr.reset;
    } else if (tgt.silent && base.progressed) {
        r.sni_dropped = true;
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
                ? " a ClientHello split inside the hostname got through here."
                : " a ClientHello split inside the hostname was reset too (this DPI reassembles "
                  "segments, or the host itself is resetting).";
    } else if (r.sni_dropped) {
        r.note = "SNI '" + sni + "': no reply and no reset within " + std::to_string(to_ms) +
                 "ms after the ClientHello, while a benign SNI to the same IP:port got a TLS reply. "
                 "the failure is SNI-specific: a silent drop on your path (ISP / TSPU), or a "
                 "server that ignores this name.";
    } else if (r.ip_blocked) {
        r.note = "both the target and a benign SNI reset to this IP: an IP-level block "
                 "or a dead host, not SNI-specific filtering.";
    } else if (tgt.progressed) {
        r.note = "SNI '" + sni + "' got a TLS reply: no SNI-specific RST or drop on the first "
                 "flight. throttling or a freeze later in the connection is not measured.";
    } else if (!tgt.connected) {
        r.note = "TCP connect to " + ip + ":" + std::to_string(port) +
                 " failed: IP or port level, the SNI was not tested. inconclusive.";
    } else {
        r.note = "no TLS reply to the target SNI and no working benign baseline. inconclusive.";
    }
    return r;
}

ChEnd dpi_clienthello(const string& ip, int port, const string& sni, int to_ms) {
    const ChResult r = send_ch(ip, port, sni, false, to_ms);
    if (!r.connected) return ChEnd::NoTcp;
    if (r.progressed) return ChEnd::Reply;
    if (r.reset) return ChEnd::Reset;
    if (r.silent) return ChEnd::Silent;
    return ChEnd::Other;
}

int dpi_exit_code(const DpiProbe& d) {
    if (d.tunneled) return 64;
    if (d.sni_blocked || d.sni_dropped) return 2;
    if (d.target_progressed) return 0;
    return 4;
}
