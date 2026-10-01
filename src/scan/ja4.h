// SPDX-License-Identifier: GPL-3.0-or-later
// ja4 family fingerprint primitives. spec: https://github.com/FoxIO-LLC/ja4
//
// ja4 = ja4_a + "_" + ja4_b + "_" + ja4_c
//   ja4_a (10 chars): proto(1) + tls_version(2) + sni_flag(1) + cipher_count(2)
//                     + ext_count(2) + alpn first+last char(2)
//   ja4_b (12 hex):   first 12 hex chars of sha256(sorted_ciphers_csv)
//   ja4_c (12 hex):   first 12 hex chars of sha256(sorted_exts_csv [+ "_" + sigalgs_csv])
//
// ja4s (server hello): same shape but ja4s_a is (proto+ver+exts_count+alpn2),
//                      ja4s_b is the single negotiated cipher hex (no sort),
//                      ja4s_c is sha256(extension list in wire order)[:12].
//
// GREASE values match (val & 0x0f0f) == 0x0a0a and are stripped before
// counting / sorting / hashing per spec.
//
// version mapping:
//   0x0304 -> "13"
//   0x0303 -> "12"
//   0x0302 -> "11"
//   0x0301 -> "10"
//   0x0300 -> "s3"
//   else   -> "00"
//
// the parser reads handshake-message bytes (no tls record header) as captured
// by SSL_set_msg_callback when content_type == SSL3_RT_HANDSHAKE. msg layout:
//   [1] handshaketype (1=clienthello, 2=serverhello)
//   [3] length (uint24 be)
//   [N] body (struct clienthello / serverhello as defined in rfc 8446)
#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct ClientHelloFp {
    bool                  ok = false;
    int                   legacy_version  = 0;   // clienthello.legacy_version (uint16)
    int                   real_version    = 0;   // from supported_versions ext if present
    std::vector<uint16_t> ciphers;               // GREASE-stripped, in original order
    std::vector<uint16_t> extensions;            // GREASE-stripped, in original order
    std::vector<uint16_t> sigalgs;               // sigalgs ext (0x000d), in original order
    std::vector<uint16_t> groups;                // supported_groups (0x000a), in original order
    std::string           alpn_first;            // first alpn proto (full string)
    bool                  has_sni    = false;
    std::string           sni;                   // captured for diagnostics, never logged on wire
    bool                  has_grease = false;
};

struct ServerHelloFp {
    bool                  ok = false;
    int                   legacy_version = 0;
    int                   real_version   = 0;   // from supported_versions ext if present
    uint16_t              cipher = 0;
    std::vector<uint16_t> extensions;            // in serverhello (GREASE-stripped)
    std::string           alpn_negotiated;       // empty if no alpn extension
};

bool parse_client_hello(const uint8_t* data, size_t len, ClientHelloFp& out);
bool parse_server_hello(const uint8_t* data, size_t len, ServerHelloFp& out);

// ja4 builders. each returns the canonical "tNNd1516h2_xxxxxxxxxxxx_yyyyyyyyyyyy"
// shape. on parse failure they return "" so callers can detect.
std::string ja4_client(const ClientHelloFp& ch);
std::string ja4s_server(const ServerHelloFp& sh);

// ja4h of an http/1.1 request. method (>=2 chars), version (http/1.1 = 11),
// cookie+referer flags, accept-language 4 chars. cookie hashes optional.
struct Ja4hInput {
    std::string method;          // "GET", "POST", ...
    std::string http_version;    // "1.1", "2.0"
    std::vector<std::string> header_names_in_order;  // case folded, with x-prefixes excluded
    std::vector<std::string> cookie_names;
    std::vector<std::pair<std::string,std::string>> cookies_kv;  // name=value pairs
    std::string accept_language;
    bool        has_referer = false;
    bool        has_cookie  = false;
};

std::string ja4h(const Ja4hInput& in);

// helper: sha256(input)[:12 hex chars] used by all ja4 family hashes
std::string sha256_12(const std::string& input);

// expose the GREASE check for callers that build hashes themselves
bool ja4_is_grease(uint16_t v);