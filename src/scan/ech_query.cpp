// SPDX-License-Identifier: GPL-3.0-or-later
// networking half of the ech probe: fetch the https rr over doh, parse via the
// pure ech_parse. kept separate from ech.cpp so ech_parse stays in the
// platform-agnostic unit-test build.
//
// two resolvers are tried so the verdict survives a censored network: google doh
// first (bare get, presentation form), then cloudflare doh (needs an accept
// header and may answer in rfc 3597 generic form - ech_parse handles both). the
// fallback fires only when google is unreachable or replies with junk, not when
// it gives a clean "this domain has no HTTPS RR".
#include "ech.h"
#include "../net/http.h"
#include "../common/json.h"

#include <cctype>
#include <string>

using std::string;

namespace {

// an https rr is keyed on a hostname, so a bare ip literal can never carry one.
// catch that early to give a useful error instead of a confused empty answer.
bool looks_like_ip(const string& d) {
    if (d.find(':') != string::npos) return true;        // any colon => ipv6 literal
    bool has_digit = false, only_v4_chars = true;
    for (unsigned char c : d) {
        if (std::isdigit(c)) has_digit = true;
        else if (c != '.')   only_v4_chars = false;
    }
    return has_digit && only_v4_chars;                   // all [0-9.] => ipv4 literal
}

// domain goes into the doh query string
// reject url delimiters so they can't inject extra params
bool is_hostname_charset(const string& d) {
    if (d.size() > 253) return false;
    for (unsigned char c : d) {
        bool okc = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
        if (!okc) return false;
    }
    return true;
}

// scan a doh json body for the first type-65 (https) answer.
//   1  = found an https rr (out is filled, has_https_rr set)
//   0  = noerror (dns Status 0) with no https rr - an authoritative negative
//  -1  = not valid json, or a resolver-side failure (servfail etc.) -> fall back
int parse_doh_json(const string& body, EchInfo& out) {
    bool ok = false;
    JsonValue root = json_parse(body, &ok);
    if (!ok) return -1;
    const JsonValue& ans = root["Answer"];
    for (size_t i = 0; i < ans.size(); ++i) {
        if (ans.at(i)["type"].as_int() == 65) {          // https rr
            out = ech_parse(ans.at(i)["data"].as_str());
            out.has_https_rr = true;
            return 1;
        }
    }
    // only a noerror (Status==0) reply with no type-65 record is an authoritative
    // "no HTTPS RR". a servfail (Status==2) or a body with no Status is a
    // resolver-side failure - report -1 so the caller tries the other resolver.
    return root["Status"].as_int(-1) == 0 ? 0 : -1;
}

} // namespace

EchInfo ech_query(const string& domain) {
    EchInfo e;
    e.bad_input = true;
    if (domain.empty()) { e.err = "empty domain"; return e; }
    if (looks_like_ip(domain)) {
        e.err = "an HTTPS RR is keyed on a hostname; give a domain, not an IP";
        return e;
    }
    if (!is_hostname_charset(domain)) {
        e.err = "not a valid hostname (letters, digits, '.', '-', '_' only, max 253 chars)";
        return e;
    }
    e.bad_input = false;

    EchInfo parsed;
    const string no_rr = "no HTTPS RR (type 65) published for " + domain;

    // primary: google doh. presentation form, accepts a bare get. &do=1 asks for
    // dnssec-validated data where available.
    HttpResp g = http_get(
        "https://dns.google/resolve?name=" + domain + "&type=HTTPS&do=1", 6000);
    if (g.ok()) {
        int rc = parse_doh_json(g.body, parsed);
        if (rc == 1) { parsed.lookup_complete = true; return parsed; }
        if (rc == 0) { e.err = no_rr; e.lookup_complete = true; return e; }
        e.err = "Google DoH: no usable answer (SERVFAIL/junk)"; // rc == -1 -> fall back
    } else {
        e.err = "Google DoH: http " + std::to_string(g.status) +
                (g.err.empty() ? "" : " " + g.err);
    }

    // fallback: cloudflare doh. requires accept: application/dns-json and may
    // return the rfc 3597 generic form (ech_parse handles it). reached only when
    // google is unreachable/blocked or replied with non-json.
    HttpResp cf = http_get(
        "https://cloudflare-dns.com/dns-query?name=" + domain + "&type=HTTPS&do=1",
        6000, "application/dns-json");
    if (cf.ok()) {
        int rc = parse_doh_json(cf.body, parsed);
        if (rc == 1) { parsed.lookup_complete = true; return parsed; }
        if (rc == 0) { e.err = no_rr; e.lookup_complete = true; return e; }
        e.err += "; Cloudflare DoH: no usable answer (SERVFAIL/junk)";
        return e;
    }
    e.err += "; Cloudflare DoH: http " + std::to_string(cf.status) +
             (cf.err.empty() ? "" : " " + cf.err);
    return e;
}
