// SPDX-License-Identifier: GPL-3.0-or-later
// pure HTTPS-RR parser (no network). compiled into the unit-test build; the DoH
// fetch lives in ech_query.cpp.
//
// resolvers hand back the type-65 RDATA in one of two shapes and we handle both:
//   1. presentation form  -> "1 . alpn=\"h3,h2\" ipv4hint=1.2.3.4 ech=AED+..."
//      (dns.google, and Cloudflare when it knows the SVCB type)
//   2. RFC 3597 generic    -> "\\# 63 00010000010003026832...0005004bfe0d..."
//      (older resolvers / any resolver that treats HTTPS as an unknown type)
// keeping both paths means the ech verdict is provider-agnostic — a fallback
// resolver that only speaks generic format still yields a correct answer.
#include "ech.h"

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using std::string;
using std::vector;

namespace {

// ---- presentation-format helpers ------------------------------------------

// extract a SvcParam value from a presentation string: `key` is e.g. "ech=".
// handles quoted ("...") and bare (up-to-space) values. returns "" if absent.
string svcparam(const string& s, const string& key) {
    // match key only at a token boundary (start or after whitespace) so
    // "ipv4hint=" can't be found inside another token.
    size_t p = 0;
    for (;;) {
        p = s.find(key, p);
        if (p == string::npos) return {};
        if (p == 0 || s[p - 1] == ' ' || s[p - 1] == '\t') break;
        p += 1;
    }
    p += key.size();
    if (p < s.size() && s[p] == '"') {
        size_t e = s.find('"', p + 1);
        return s.substr(p + 1, e == string::npos ? string::npos : e - (p + 1));
    }
    size_t e = p;
    while (e < s.size() && s[e] != ' ' && s[e] != '\t') ++e;
    return s.substr(p, e - p);
}

// exact length of the bytes a base64 string decodes to. counts only the
// significant (non-'=', non-whitespace) symbols, so it is correct for both
// padded and unpadded input: floor(sig * 3 / 4).
int b64_decoded_len(const string& b) {
    size_t sig = 0;
    for (unsigned char c : b)
        if (c != '=' && !std::isspace(c)) ++sig;
    return (int)(sig * 3 / 4);
}

// ---- generic (RFC 3597) wire-format helpers -------------------------------

// decode an ASCII hex string (whitespace tolerated) into bytes. returns false
// on an odd number of nibbles or a stray non-hex symbol.
bool hex_to_bytes(const string& hex, vector<uint8_t>& out) {
    int hi = -1;
    for (unsigned char c : hex) {
        int d;
        if      (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else if (std::isspace(c))      continue;     // separators are fine
        else                           return false; // anything else is junk
        if (hi < 0) hi = d;
        else { out.push_back((uint8_t)((hi << 4) | d)); hi = -1; }
    }
    return hi < 0;   // a dangling nibble means malformed input
}

uint16_t rd16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }

// parse binary SVCB/HTTPS RDATA (RFC 9460): SvcPriority(2) + TargetName +
// SvcParams[(key:2, len:2, value:len)...]. fills the EchInfo fields we report.
EchInfo parse_wire(const vector<uint8_t>& b) {
    EchInfo e;
    size_t p = 0;
    if (b.size() < 3) return e;          // priority(2) + at least the root label
    p += 2;                              // skip SvcPriority
    // skip the TargetName: a sequence of length-prefixed labels ending in 0x00.
    // SVCB RDATA forbids name compression, so a 0xC0-style pointer is malformed.
    while (p < b.size()) {
        uint8_t l = b[p];
        if (l == 0) { ++p; break; }
        if ((l & 0xC0) != 0) return e;   // compression pointer => bail
        p += 1 + (size_t)l;
    }
    // walk the SvcParams
    while (p + 4 <= b.size()) {
        uint16_t key = rd16(&b[p]);
        uint16_t vl  = rd16(&b[p + 2]);
        p += 4;
        if (p + vl > b.size()) break;    // truncated value => stop
        const uint8_t* v = b.data() + p;
        switch (key) {
            case 1: {                    // alpn: [u8 len][bytes]...
                string alpns;
                size_t q = 0;
                while (q < vl) {
                    uint8_t al = v[q++];
                    if (q + al > vl) break;
                    if (!alpns.empty()) alpns += ",";
                    alpns.append((const char*)v + q, al);
                    q += al;
                }
                e.alpn = alpns;
                break;
            }
            case 4: {                    // ipv4hint: n * 4 bytes
                string s;
                for (size_t q = 0; q + 4 <= vl; q += 4) {
                    char buf[20];
                    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                                  (unsigned)v[q],     (unsigned)v[q + 1],
                                  (unsigned)v[q + 2], (unsigned)v[q + 3]);
                    if (!s.empty()) s += ",";
                    s += buf;
                }
                e.ipv4hint = s;
                break;
            }
            case 6: {                    // ipv6hint: n * 16 bytes
                string s;
                for (size_t q = 0; q + 16 <= vl; q += 16) {
                    char buf[48];
                    std::snprintf(buf, sizeof(buf),
                                  "%x:%x:%x:%x:%x:%x:%x:%x",
                                  (unsigned)rd16(v + q),      (unsigned)rd16(v + q + 2),
                                  (unsigned)rd16(v + q + 4),  (unsigned)rd16(v + q + 6),
                                  (unsigned)rd16(v + q + 8),  (unsigned)rd16(v + q + 10),
                                  (unsigned)rd16(v + q + 12), (unsigned)rd16(v + q + 14));
                    if (!s.empty()) s += ",";
                    s += buf;
                }
                e.ipv6hint = s;
                break;
            }
            case 5: {                    // ech: opaque ECHConfigList
                e.has_ech = vl > 0;
                e.ech_len = vl;
                break;
            }
            default: break;              // mandatory / port / no-default-alpn: ignored
        }
        p += vl;
    }
    return e;
}

} // namespace

EchInfo ech_parse(const string& data) {
    EchInfo e;
    e.raw = data;
    if (data.empty()) return e;

    // skip leading whitespace, then sniff the format.
    size_t s = 0;
    while (s < data.size() && std::isspace((unsigned char)data[s])) ++s;

    // RFC 3597 generic form: "\# <rdlen> <hex...>"
    if (s + 1 < data.size() && data[s] == '\\' && data[s + 1] == '#') {
        size_t p = s + 2;
        while (p < data.size() && std::isspace((unsigned char)data[p])) ++p;
        while (p < data.size() && std::isdigit((unsigned char)data[p])) ++p; // rdlen
        vector<uint8_t> bytes;
        if (hex_to_bytes(data.substr(p), bytes))
            return parse_wire(bytes);
        return e;                        // malformed generic record
    }

    // presentation form.
    e.alpn     = svcparam(data, "alpn=");
    e.ipv4hint = svcparam(data, "ipv4hint=");
    e.ipv6hint = svcparam(data, "ipv6hint=");
    e.ech_b64  = svcparam(data, "ech=");
    // some resolvers print an empty/placeholder ech; treat a real base64 of
    // non-trivial length as present.
    e.has_ech  = e.ech_b64.size() >= 8;
    if (e.has_ech) e.ech_len = b64_decoded_len(e.ech_b64);
    return e;
}
