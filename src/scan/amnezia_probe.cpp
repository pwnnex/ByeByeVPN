// SPDX-License-Identifier: GPL-3.0-or-later
#include "amnezia_probe.h"
#include "../net/udp.h"

#include <openssl/rand.h>

#include <vector>

using std::string;
using std::vector;

namespace {

// build a WireGuard MessageInitiation packet with `s1` random junk bytes
// prepended. layout: [s1 junk][0x01 type][3 reserved zero][144 WG body].
// every byte that is not structural is randomized so the datagram is
// indistinguishable from a real obfuscated client's first packet.
vector<unsigned char> build_s1_packet(int s1) {
    vector<unsigned char> pkt((size_t)s1 + 148, 0);
    if (s1 > 0) RAND_bytes(pkt.data(), s1);
    pkt[s1] = 0x01;                          // WG handshake-initiation type
    RAND_bytes(pkt.data() + s1 + 4, 144);    // sender idx + ephemeral + ...
    return pkt;
}

// S1 sizes to sweep. 0 = vanilla WireGuard. the rest are the prefix sizes
// AmneziaWG configs commonly land on (presets and the official client's
// generated ranges cluster around small-to-mid values). kept short so the
// whole sweep is a dozen single datagrams.
const int S1_SWEEP[] = { 0, 4, 8, 12, 16, 24, 32, 48, 64, 96, 128, 150 };
constexpr int S1_SWEEP_N = (int)(sizeof(S1_SWEEP) / sizeof(S1_SWEEP[0]));

} // namespace

AmneziaSweep amnezia_deep_probe(const string& host, int port) {
    AmneziaSweep r;
    for (int i = 0; i < S1_SWEEP_N; ++i) {
        int s1 = S1_SWEEP[i];
        vector<unsigned char> pkt = build_s1_packet(s1);
        UdpResult u = udp_probe(host, port, pkt.data(), (int)pkt.size(), 1200);
        r.sweep.push_back({s1, u.responded});
        if (u.responded) {
            r.any_responded = true;
            if (s1 == 0) r.vanilla_wg_responds = true;
            // record the first non-zero S1 that answers as the detected
            // obfuscation prefix. if only S1=0 answers, that is plain WG.
            if (r.detected_s1 < 0 && s1 > 0) r.detected_s1 = s1;
        }
    }

    if (!r.any_responded) {
        r.summary = "no S1 prefix size in the sweep got a handshake response "
                    "(port closed/filtered, or an S1 outside the swept range)";
    } else if (r.vanilla_wg_responds && r.detected_s1 < 0) {
        r.summary = "only S1=0 answered: this is plain WireGuard, not AmneziaWG";
    } else if (r.detected_s1 >= 0 && !r.vanilla_wg_responds) {
        r.summary = "AmneziaWG detected: vanilla-WG (S1=0) was dropped, S1=" +
                    std::to_string(r.detected_s1) +
                    " junk-prefix got a handshake response. that prefix size "
                    "is the server's configured S1 obfuscation parameter";
    } else if (r.detected_s1 >= 0 && r.vanilla_wg_responds) {
        r.summary = "ambiguous: both S1=0 and S1=" + std::to_string(r.detected_s1) +
                    " answered. the listener may accept a junk prefix without "
                    "rejecting plain WG, or a middlebox is reflecting UDP";
    }
    r.ok = true;
    return r;
}
