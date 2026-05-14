// SPDX-License-Identifier: GPL-3.0-or-later
// AmneziaWG deep-probe: junk-prefix size sweep.
//
// AmneziaWG is WireGuard plus an obfuscation layer with these knobs:
//   Jc          junk packet count sent before the handshake
//   Jmin/Jmax   junk packet size band
//   S1          junk bytes prepended to the handshake-initiation packet
//   S2          junk bytes prepended to the handshake-response packet
//   H1..H4      custom 4-byte values replacing WG's 1/2/3/4 message types
//
// vanilla WireGuard puts the message-type byte 0x01 at offset 0 of the
// initiation packet. AmneziaWG with S1=N shifts the real WG packet N bytes
// to the right behind N random junk bytes, so a vanilla-WG listener drops
// it (type byte not at offset 0) and only a listener configured with the
// matching S1 accepts it.
//
// S1 is the one obfuscation param a remote observer can actually recover:
// sweep the prefix size, and whichever size gets a handshake response is
// the server's configured S1. (H1..H4 are a 4-byte custom value each, too
// large to brute-force, so this probe does not attempt them. Jc/Jmin/Jmax
// affect packets we do not send, so they are out of scope here.)
//
// the sweep is cheap: a handful of single UDP datagrams. it only runs when
// the basic AmneziaWG probe already suggested an obfuscated listener, or
// on the default WG port where it is highest-value.
#pragma once

#include <string>
#include <utility>
#include <vector>

struct AmneziaSweep {
    bool ok = false;
    bool any_responded       = false;
    bool vanilla_wg_responds = false;   // S1 = 0 (plain WG type byte) answered
    int  detected_s1         = -1;      // junk-prefix size that answered, -1 = none
    // (s1_size, responded) for every sweep step, in probe order
    std::vector<std::pair<int, bool>> sweep;
    std::string summary;
};

// sweep the AmneziaWG S1 junk-prefix size against host:port.
AmneziaSweep amnezia_deep_probe(const std::string& host, int port);
