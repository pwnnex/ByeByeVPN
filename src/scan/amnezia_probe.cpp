// SPDX-License-Identifier: GPL-3.0-or-later
#include "amnezia_probe.h"
#include "../net/udp.h"
#include "../common/util.h"

#include <openssl/rand.h>

#include <vector>

using std::string;
using std::vector;

namespace {

// build a WireGuard messageinitiation packet with `s1` random junk bytes
// prepended. layout: [s1 junk][0x01 type][3 reserved zero][144 wg body].
// every byte that isn't structural is randomized so the datagram is
// indistinguishable from a real obfuscated client's first packet.
vector<unsigned char> build_s1_packet(int s1) {
    vector<unsigned char> pkt((size_t)s1 + 148, 0);
    if (s1 > 0) RAND_bytes(pkt.data(), s1);
    pkt[s1] = 0x01;                          // wg handshake-initiation type
    RAND_bytes(pkt.data() + s1 + 4, 144);    // sender idx + ephemeral + ...
    return pkt;
}

// s1 sizes to sweep. 0 = vanilla WireGuard. the rest are the prefix sizes
// amneziawg configs commonly land on (presets and the official client's
// generated ranges cluster around small-to-mid values). kept short so the
// whole sweep is a dozen single datagrams.
const int S1_SWEEP[] = { 0, 4, 8, 12, 16, 24, 32, 48, 64, 96, 128, 150 };
constexpr int S1_SWEEP_N = (int)(sizeof(S1_SWEEP) / sizeof(S1_SWEEP[0]));

} // namespace

AmneziaSweep amnezia_deep_probe(const string& host, int port) {
    AmneziaSweep r;
    for (int i = 0; i < S1_SWEEP_N; ++i) {
        // a 12-datagram sweep on the same wg port is the most obvious
        // amneziawg-detector pattern. under --stealth, jitter 150-900ms
        // between datagrams to smear it. no-op without --stealth.
        if (i > 0) stealth_sleep_ms(150, 900);
        int s1 = S1_SWEEP[i];
        vector<unsigned char> pkt = build_s1_packet(s1);
        UdpResult u = udp_probe(host, port, pkt.data(), (int)pkt.size(), 1200);
        r.sweep.push_back({s1, u.responded});
        if (u.responded) {
            r.any_responded = true;
            if (s1 == 0) r.vanilla_wg_responds = true;
            // keep response observations, not an inferred protocol or s1.
        }
    }

    r.detected_s1 = -1; // unauthenticated replies can't identify s1.
    r.summary = r.any_responded ? "UDP response observed; protocol and S1 unconfirmed" : "No UDP response; protocol unknown";
    r.ok = true;
    return r;
}
