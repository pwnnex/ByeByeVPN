// SPDX-License-Identifier: GPL-3.0-or-later
#include "signals.h"

const std::vector<SignalSpec>& signal_registry() {
    // weights: docs/SIGNALS.md, section per id
    static const std::vector<SignalSpec> r = {
        {"wg-family", "a WireGuard-family responder answered our handshake initiation", 'A', 15, false, "wg"},
        // same fact as wg-family, proven with the owner's key
        {"wg-keyed",  "the node completes a WireGuard handshake with the owner's peer key", 'A', 15, false, "wg"},
        {"socks5",    "the port negotiates SOCKS5 methods",                             'A', 20, false, "socks5"},
        {"sstp",      "the TLS service accepts an SSTP setup request",                  'A', 18, false, "sstp"},
        // reference only, printed but never scored
        {"geoip-tags",  "third-party databases tag the address",                        'R', 0, true, "geoip-tags"},
        {"junk-probes", "how the port reacts to malformed first flights",               'R', 0, true, "junk-probes"},
        {"tcp-stack",   "peer tcp window and handshake timing",                         'R', 0, true, "tcp-stack"},
        {"ja4s-family", "server hello shape against a small seed table",                'R', 0, true, "ja4s-family"},
        {"cert-brand",  "certificate names a large brand",                              'R', 0, true, "cert-brand"},
    };
    return r;
}

const SignalSpec* signal_spec(const std::string& id) {
    for (const auto& s : signal_registry())
        if (id == s.id) return &s;
    return nullptr;
}

std::string signal_passport(const std::string& id) {
    return "docs/SIGNALS.md#" + id;
}
