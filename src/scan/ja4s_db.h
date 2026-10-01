// SPDX-License-Identifier: GPL-3.0-or-later
// ja4s classifier: turn a server-hello ja4s hash into a backend-stack guess.
//
// ja4s string layout (foxio spec, see ja4.h):
//   <a>_<b>_<c>
//   a = t + ver(2) + extcount(2) + alpn(2)   e.g. "t130203h2"
//   b = negotiated cipher hex                e.g. "1301"
//   c = sha256(serverhello exts in wire order)[:12] e.g. "a56c5b993250"
//
// classification has two tiers:
//   * exact:      the full ja4s string (or its ext-hash) is in the seed
//                 table below. high confidence, names a specific stack.
//   * structural: not in the table, so we decode the <a> part and the
//                 cipher and emit a coarse family guess (tls version,
//                 extension-count band, alpn). low confidence, never a
//                 hard verdict signal on its own.
//
// the seed table is small and honest: it only contains
// values this project has actually observed. it is meant to grow from
// community-submitted scans, not to ship guesses. an unknown ja4s is
// reported as unknown, not force-fit to a label.
#pragma once

#include <string>

struct Ja4sInfo {
    bool        ok = false;
    std::string ja4s;            // echoed input
    int         tls_version = 0; // decoded (0x0304 = tls 1.3, etc.)
    int         ext_count   = 0; // serverhello extension count
    std::string alpn;            // negotiated alpn ("h2", "") from the <a> part
    std::string cipher_hex;      // ja4s_b
    std::string ext_hash;        // ja4s_c
    std::string family;          // "cloudflare-edge" / "openssl-tls13" / etc.
    std::string confidence;      // "exact" / "structural" / "unknown"
    std::string note;            // human-readable one-liner
};

Ja4sInfo ja4s_classify(const std::string& ja4s);
