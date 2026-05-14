// SPDX-License-Identifier: GPL-3.0-or-later
// JA4S classifier: turn a server-hello JA4S hash into a backend-stack guess.
//
// JA4S string layout (FoxIO spec, see ja4.h):
//   <a>_<b>_<c>
//   a = t + ver(2) + extcount(2) + alpn(2)   e.g. "t130203h2"
//   b = negotiated cipher hex                e.g. "1301"
//   c = sha256(sorted ServerHello exts)[:12] e.g. "a56c5b993250"
//
// classification has two tiers:
//   * exact:      the full JA4S string (or its ext-hash) is in the seed
//                 table below. high confidence, names a specific stack.
//   * structural: not in the table, so we decode the <a> part and the
//                 cipher and emit a coarse family guess (TLS version,
//                 extension-count band, ALPN). low confidence, never a
//                 hard verdict signal on its own.
//
// the seed table is intentionally small and honest: it only contains
// values this project has actually observed. it is meant to grow from
// community-submitted scans, not to ship guesses. an unknown JA4S is
// reported as unknown, not force-fit to a label.
#pragma once

#include <string>

struct Ja4sInfo {
    bool        ok = false;
    std::string ja4s;            // echoed input
    int         tls_version = 0; // decoded (0x0304 = TLS 1.3, etc.)
    int         ext_count   = 0; // ServerHello extension count
    std::string alpn;            // negotiated ALPN ("h2", "") from the <a> part
    std::string cipher_hex;      // JA4S_b
    std::string ext_hash;        // JA4S_c
    std::string family;          // "cloudflare-edge" / "openssl-tls13" / etc.
    std::string confidence;      // "exact" / "structural" / "unknown"
    std::string note;            // human-readable one-liner
};

Ja4sInfo ja4s_classify(const std::string& ja4s);
