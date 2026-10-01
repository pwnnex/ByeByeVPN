// SPDX-License-Identifier: GPL-3.0-or-later
// ech / dns https-rr probe. fetches the dns https resource record (type 65) for
// a domain via doh and reports what it advertises: alpn (http/3?), ip hints, and
// crucially the `ech` svcparam (the echconfiglist) - encrypted clienthello.
//
// ech hides the sni from on-path dpi, so an ech-advertising domain is harder to
// sni-filter; conversely tspu has been observed RST-ing ech-carrying handshakes,
// which makes "does this domain advertise ECH" a real signal. the presentation
// parser (ech_parse) is pure and unit-tested; ech_query does the doh fetch.
#pragma once

#include <string>

struct EchInfo {
    bool        has_https_rr = false;   // a type-65 https rr exists
    bool        has_ech = false;        // it carries an `ech` (echconfiglist) param
    std::string alpn;                   // e.g. "h3,h2"
    std::string ipv4hint;
    std::string ipv6hint;
    int         ech_len = 0;            // approx decoded echconfiglist length (bytes)
    std::string ech_b64;               // the raw ech= value (base64)
    std::string raw;                    // the full https-rr presentation string
    std::string err;
    // a resolver answered noerror; without it "no rr" is unknown, not absent
    bool        lookup_complete = false;
    bool        bad_input = false;
};

// parse a dns https-rr presentation string ("1 . alpn=... ipv4hint=... ech=...").
// pure: no network, unit-tested.
EchInfo ech_parse(const std::string& https_rr_presentation);

// query the domain's https rr over doh (google) and parse it. on a network or
// json error returns an EchInfo with err set and has_https_rr false.
EchInfo ech_query(const std::string& domain);
