// SPDX-License-Identifier: GPL-3.0-or-later
// active path-DPI probe: detect SNI-based RST injection on the LOCAL path
// (your ISP / TSPU), as opposed to the target server's own detectability.
//
// method: open two TLS connections to the same target IP:port and send a real
// ClientHello on each, one carrying the target SNI and one a benign SNI. if the
// target-SNI connection is reset shortly after the ClientHello but the benign
// one progresses, the path is doing SNI-based blocking. if SNI-RST is seen, a
// best-effort follow-up splits the ClientHello across TCP segments (the classic
// Zapret/GoodbyeDPI evasion) to see whether fragmentation defeats it.
//
// this measures interference between YOU and the host, not the host itself.
#pragma once

#include <string>

struct DpiProbe {
    bool        ran = false;
    bool        tunneled = false;       // resolved IP is a fake-IP/tunnel addr (VPN on)
    bool        target_reset = false;   // CH with the target SNI got an early RST
    bool        target_progressed = false;
    int         target_reset_ms = -1;
    bool        benign_reset = false;   // CH with a benign SNI got an early RST
    bool        benign_progressed = false;
    bool        sni_blocked = false;    // target reset AND benign progressed
    bool        ip_blocked = false;     // both reset / both dead -> not SNI-specific
    bool        frag_tested = false;
    bool        frag_evades = false;    // fragmented CH progressed where whole was reset
    std::string note;
    std::string err;
};

DpiProbe dpi_probe(const std::string& ip, int port, const std::string& sni, int to_ms = 2500);
