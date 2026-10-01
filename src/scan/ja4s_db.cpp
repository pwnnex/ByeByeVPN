// SPDX-License-Identifier: GPL-3.0-or-later
#include "ja4s_db.h"

#include <cstdlib>
#include <cstring>

using std::string;

namespace {

// seed table. each entry is a (matcher, family, note) triple.
//   match_kind 'f' = full ja4s string equality
//   match_kind 'C' = ja4s_c (ext-hash) equality, cipher/alpn-agnostic
//
// only values actually observed by this project are listed. extend via
// community-submitted scans, don't add guesses.
struct SeedEntry {
    char        kind;     // 'f' or 'C'
    const char* key;      // full ja4s string, or just the ext-hash
    const char* family;
    const char* note;
};

// wire order, re-observed 2026-09-30 with tools/groundtruth/sh_order.py.
// the old seeds were sorted hashes and never matched a wire-order ja4s.
const SeedEntry SEED[] = {
    // 002b,0033: github, caddyserver.com, www.microsoft.com, openssl 3.5
    {'C', "a56c5b993250", "tls13-generic-serverhello",
        "TLS 1.3 ServerHello, supported_versions then key_share; ALPN rides in "
        "EncryptedExtensions. identifies no specific stack; observed on GitHub, "
        "Caddy, Microsoft and OpenSSL 3.5"},

    // 0033,002b: www.cloudflare.com; one operator, not a family
    {'C', "234ea6891581", "tls13-generic-serverhello",
        "TLS 1.3 ServerHello, key_share then supported_versions. identifies no "
        "specific stack; observed on Cloudflare"},

    // ff01,0000,000b,0023,0010,0017: nginx.org and mail.ru over tls 1.2
    {'C', "17136cd5846b", "tls12-openssl-family",
        "TLS 1.2 ServerHello with the 6-extension OpenSSL/nginx set in OpenSSL "
        "order (observed on nginx.org, mail.ru); a family, not one product"},
};
constexpr size_t SEED_N = sizeof(SEED) / sizeof(SEED[0]);

int decode_version(const string& v2) {
    if (v2 == "13") return 0x0304;
    if (v2 == "12") return 0x0303;
    if (v2 == "11") return 0x0302;
    if (v2 == "10") return 0x0301;
    if (v2 == "s3") return 0x0300;
    return 0;
}

const char* version_text(int v) {
    switch (v) {
        case 0x0304: return "TLS 1.3";
        case 0x0303: return "TLS 1.2";
        case 0x0302: return "TLS 1.1";
        case 0x0301: return "TLS 1.0";
        case 0x0300: return "SSL 3.0";
        default:     return "unknown-version";
    }
}

// coarse family guess from the structural fields when there is no exact
// table hit. vague: this is a family band, not a stack name.
//
// the serverhello extension count is the main lever:
//   * a tls 1.3 serverhello carries supported_versions + key_share as a
//     hard minimum (2). a 3rd extension is almost always alpn.
//   * <= 3 exts with no exotic entries is the common shape for both
//     openssl-family servers (nginx/haproxy) and go crypto/tls servers
//     (caddy / xray / sing-box). ja4s alone can't split those two
//     without the reference ext-hash, so we say so honestly.
//   * 4+ exts on a tls 1.3 serverhello is unusual and worth a note.
string structural_family(int ver, int ext_count, const string& alpn) {
    if (ver == 0x0304) {
        if (ext_count <= 3) return "tls13-generic";
        return "tls13-rich-exts";
    }
    if (ver == 0x0303) return (ext_count >= 5) ? "tls12-multi-ext" : "tls12-generic";
    if (ver == 0) return "unknown";
    (void)alpn;
    return "legacy-tls";
}

string structural_note(int ver, int ext_count, const string& alpn,
                        const string& cipher_hex) {
    string n = version_text(ver);
    n += ", " + std::to_string(ext_count) + " ServerHello ext";
    if (ext_count != 1) n += "s";
    if (!alpn.empty()) n += ", ALPN=" + alpn;
    else               n += ", no ALPN";
    if (!cipher_hex.empty()) n += ", cipher 0x" + cipher_hex;
    if (ver == 0x0304 && ext_count <= 3) {
        n += ". note: a TLS 1.3 ServerHello only exposes supported_versions + "
             "key_share in the clear (ALPN and the rest move into "
             "EncryptedExtensions), so this generic shape cannot split "
             "OpenSSL-family (nginx/haproxy) from Go crypto/tls "
             "(caddy/xray/sing-box) without a reference ext-hash";
    } else if (ver == 0x0304 && ext_count >= 4) {
        n += ". more ServerHello extensions than a plain TLS 1.3 server "
             "usually sends, worth a closer look";
    } else if (ver == 0x0303) {
        n += (ext_count >= 5)
             ? ". a multi-extension TLS 1.2 ServerHello, characteristic of an "
               "OpenSSL-family terminator (nginx / HAProxy / stock OpenSSL)"
             : ". a sparse TLS 1.2 ServerHello";
    }
    return n;
}

} // namespace

Ja4sInfo ja4s_classify(const string& ja4s) {
    Ja4sInfo info;
    info.ja4s = ja4s;
    if (ja4s.empty()) {
        info.confidence = "unknown";
        info.family     = "unknown";
        info.note       = "no JA4S string (ServerHello not captured)";
        return info;
    }

    // split on '_' into a / b / c
    size_t u1 = ja4s.find('_');
    size_t u2 = (u1 == string::npos) ? string::npos : ja4s.find('_', u1 + 1);
    if (u1 == string::npos || u2 == string::npos) {
        info.confidence = "unknown";
        info.family     = "unknown";
        info.note       = "malformed JA4S string";
        return info;
    }
    string a = ja4s.substr(0, u1);
    info.cipher_hex = ja4s.substr(u1 + 1, u2 - u1 - 1);
    info.ext_hash   = ja4s.substr(u2 + 1);

    // a-part: t + ver(2) + extcount(2) + alpn(2)
    if (a.size() >= 7 && a[0] == 't') {
        info.tls_version = decode_version(a.substr(1, 2));
        info.ext_count   = std::atoi(a.substr(3, 2).c_str());
        string al = a.substr(5, 2);
        if (al != "00") info.alpn = al;
    }

    // tier 1: exact table lookup
    for (size_t i = 0; i < SEED_N; ++i) {
        const SeedEntry& e = SEED[i];
        bool hit = (e.kind == 'F' && ja4s == e.key) ||
                   (e.kind == 'C' && info.ext_hash == e.key);
        if (hit) {
            info.ok         = true;
            info.family     = e.family;
            info.confidence = "exact";
            info.note       = e.note;
            return info;
        }
    }

    // tier 2: structural family guess
    info.ok         = true;
    info.family     = structural_family(info.tls_version, info.ext_count, info.alpn);
    info.confidence = "structural";
    info.note       = structural_note(info.tls_version, info.ext_count,
                                      info.alpn, info.cipher_hex);
    return info;
}
