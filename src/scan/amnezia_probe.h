// SPDX-License-Identifier: GPL-3.0-or-later
// legacy unauthenticated udp prefix experiment. A response can't identify
// amneziawg or recover s1. use awg-entropy on real outer traffic for passive
// entropy/sequence evidence; see docs/amneziawg_analysis.md.
#pragma once

#include <string>
#include <utility>
#include <vector>

struct AmneziaSweep {
    bool ok = false;
    bool any_responded       = false;
    bool vanilla_wg_responds = false;   // s1 = 0 (plain wg type byte) answered
    int  detected_s1         = -1;      // reserved; always -1 (s1 not authenticated)
    // (s1_size, responded) for every sweep step, in probe order
    std::vector<std::pair<int, bool>> sweep;
    std::string summary;
};

// sweep the amneziawg s1 junk-prefix size against host:port.
AmneziaSweep amnezia_deep_probe(const std::string& host, int port);
