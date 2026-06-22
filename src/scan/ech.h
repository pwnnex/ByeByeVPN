// SPDX-License-Identifier: GPL-3.0-or-later
// ECH / DNS HTTPS-RR probe. fetches the DNS HTTPS resource record (type 65) for
// a domain via DoH and reports what it advertises: ALPN (HTTP/3?), IP hints, and
// crucially the `ech` SvcParam (the ECHConfigList) - Encrypted ClientHello.
//
// ECH hides the SNI from on-path DPI, so an ECH-advertising domain is harder to
// SNI-filter; conversely TSPU has been observed RST-ing ECH-carrying handshakes,
// which makes "does this domain advertise ECH" a real signal. the presentation
// parser (ech_parse) is pure and unit-tested; ech_query does the DoH fetch.
#pragma once

#include <string>

struct EchInfo {
    bool        has_https_rr = false;   // a type-65 HTTPS RR exists
    bool        has_ech = false;        // it carries an `ech` (ECHConfigList) param
    std::string alpn;                   // e.g. "h3,h2"
    std::string ipv4hint;
    std::string ipv6hint;
    int         ech_len = 0;            // approx decoded ECHConfigList length (bytes)
    std::string ech_b64;               // the raw ech= value (base64)
    std::string raw;                    // the full HTTPS-RR presentation string
    std::string err;
};

// parse a DNS HTTPS-RR presentation string ("1 . alpn=... ipv4hint=... ech=...").
// pure: no network, unit-tested.
EchInfo ech_parse(const std::string& https_rr_presentation);

// query the domain's HTTPS RR over DoH (Google) and parse it. on a network or
// JSON error returns an EchInfo with err set and has_https_rr false.
EchInfo ech_query(const std::string& domain);
