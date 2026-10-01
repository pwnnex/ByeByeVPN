// SPDX-License-Identifier: GPL-3.0-or-later
// active path-dpi probe: detect sni-based interference (RST or silent drop)
// on the local path (your isp / tspu), as opposed to the target server's own
// detectability.
//
// method: open two tls connections to the same target ip:port and send a real
// clienthello on each, one carrying the target sni and one a benign sni. if the
// target-sni connection is reset or goes silent after the clienthello but the
// benign one gets a reply, the failure is sni-specific. a silent target can
// also be a server that ignores that name; the probe can't split the two. if
// sni-RST is seen, a
// best-effort follow-up splits the clienthello across tcp segments (the classic
// zapret/goodbyedpi evasion) to see whether fragmentation defeats it.
//
// this measures interference between you and the host, not the host itself.
#pragma once

#include "../common/outcome.h"

#include <string>

// tspu-docs 10.1.5: send_RST off, drop is the norm
struct DpiProbe {
    bool        ran = false;
    bool        tunneled = false;       // resolved ip is a fake-ip/tunnel addr (vpn on)
    bool        target_connected = false;
    bool        target_reset = false;   // ch with the target sni got an early RST
    bool        target_silent = false;  // connected, no bytes, no reset until timeout
    bool        target_progressed = false;
    int         target_reset_ms = -1;
    bool        benign_connected = false;
    bool        benign_reset = false;   // ch with a benign sni got an early RST
    bool        benign_silent = false;
    bool        benign_progressed = false;
    bool        sni_blocked = false;    // target reset and benign progressed
    bool        sni_dropped = false;    // target silent and benign progressed
    bool        ip_blocked = false;     // both reset / both dead -> not sni-specific
    bool        frag_tested = false;
    bool        frag_evades = false;    // fragmented ch progressed where whole was reset
    std::string note;
    std::string err;
};

DpiProbe dpi_probe(const std::string& ip, int port, const std::string& sni, int to_ms = 2500);

// 0 reply, 2 sni-specific failure, 4 inconclusive, 64 tunneled
int dpi_exit_code(const DpiProbe& d);

// the shared four outcomes; positive = an sni-specific failure on this path
inline Outcome dpi_outcome(const DpiProbe& d) {
    if (d.tunneled) return Outcome::NotApplicable;
    if (d.sni_blocked || d.sni_dropped) return Outcome::Positive;
    if (d.target_progressed) return Outcome::Negative;
    return Outcome::Inconclusive;
}
