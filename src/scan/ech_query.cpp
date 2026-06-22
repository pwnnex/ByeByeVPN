// SPDX-License-Identifier: GPL-3.0-or-later
// networking half of the ECH probe: fetch the HTTPS RR over DoH, parse via the
// pure ech_parse. kept separate from ech.cpp so ech_parse stays in the
// platform-agnostic unit-test build.
//
// two resolvers are tried so the verdict survives a censored network: Google DoH
// first (bare GET, presentation form), then Cloudflare DoH (needs an Accept
// header and may answer in RFC 3597 generic form — ech_parse handles both). the
// fallback fires only when Google is unreachable or replies with junk, not when
// it gives a clean "this domain has no HTTPS RR".
#include "ech.h"
#include "../net/http.h"
#include "../common/json.h"

#include <cctype>
#include <string>

using std::string;

namespace {

// an HTTPS RR is keyed on a hostname, so a bare IP literal can never carry one.
// catch that early to give a useful error instead of a confused empty answer.
bool looks_like_ip(const string& d) {
    if (d.find(':') != string::npos) return true;        // any colon => IPv6 literal
    bool has_digit = false, only_v4_chars = true;
    for (unsigned char c : d) {
        if (std::isdigit(c)) has_digit = true;
        else if (c != '.')   only_v4_chars = false;
    }
    return has_digit && only_v4_chars;                   // all [0-9.] => IPv4 literal
}

// scan a DoH JSON body for the first type-65 (HTTPS) answer.
//   1  = found an HTTPS RR (out is filled, has_https_rr set)
//   0  = NOERROR (DNS Status 0) with no HTTPS RR — an authoritative negative
//  -1  = not valid JSON, OR a resolver-side failure (SERVFAIL etc.) -> fall back
int parse_doh_json(const string& body, EchInfo& out) {
    bool ok = false;
    JsonValue root = json_parse(body, &ok);
    if (!ok) return -1;
    const JsonValue& ans = root["Answer"];
    for (size_t i = 0; i < ans.size(); ++i) {
        if (ans.at(i)["type"].as_int() == 65) {          // HTTPS RR
            out = ech_parse(ans.at(i)["data"].as_str());
            out.has_https_rr = true;
            return 1;
        }
    }
    // only a NOERROR (Status==0) reply with no type-65 record is an authoritative
    // "no HTTPS RR". a SERVFAIL (Status==2) or a body with no Status is a
    // resolver-side failure — report -1 so the caller tries the other resolver.
    return root["Status"].as_int(-1) == 0 ? 0 : -1;
}

} // namespace

EchInfo ech_query(const string& domain) {
    EchInfo e;
    if (domain.empty()) { e.err = "empty domain"; return e; }
    if (looks_like_ip(domain)) {
        e.err = "an HTTPS RR is keyed on a hostname — give a domain, not an IP";
        return e;
    }

    EchInfo parsed;
    const string no_rr = "no HTTPS RR (type 65) published for " + domain;

    // primary: Google DoH. presentation form, accepts a bare GET. &do=1 asks for
    // DNSSEC-validated data where available.
    HttpResp g = http_get(
        "https://dns.google/resolve?name=" + domain + "&type=HTTPS&do=1", 6000);
    if (g.ok()) {
        int rc = parse_doh_json(g.body, parsed);
        if (rc == 1) return parsed;
        if (rc == 0) { e.err = no_rr; return e; }        // trust a working resolver
        e.err = "Google DoH: no usable answer (SERVFAIL/junk)"; // rc == -1 -> fall back
    } else {
        e.err = "Google DoH: http " + std::to_string(g.status) +
                (g.err.empty() ? "" : " " + g.err);
    }

    // fallback: Cloudflare DoH. requires Accept: application/dns-json and may
    // return the RFC 3597 generic form (ech_parse handles it). reached only when
    // Google is unreachable/blocked or replied with non-JSON.
    HttpResp cf = http_get(
        "https://cloudflare-dns.com/dns-query?name=" + domain + "&type=HTTPS&do=1",
        6000, "application/dns-json");
    if (cf.ok()) {
        int rc = parse_doh_json(cf.body, parsed);
        if (rc == 1) return parsed;
        if (rc == 0) { e.err = no_rr; return e; }
        e.err += "; Cloudflare DoH: no usable answer (SERVFAIL/junk)";
        return e;
    }
    e.err += "; Cloudflare DoH: http " + std::to_string(cf.status) +
             (cf.err.empty() ? "" : " " + cf.err);
    return e;
}
