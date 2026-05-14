// SPDX-License-Identifier: GPL-3.0-or-later
// dual-flavored TLS handshake probe.
//
// per port the orchestrator runs TWO TLS handshakes:
//   * "chrome-flavored": SSL_CTX customized to mimic Chrome 13x ClientHello as
//     close as OpenSSL 3.x permits (cipher list, supported groups, sigalgs,
//     ALPN, TLS 1.3 only). still NOT byte-identical to a real Chrome hello
//     (extension order is OpenSSL's, no GREASE injection by us, no PSK
//     resumption). good enough to differ from default OpenSSL JA3 by at least
//     the cipher hash and the group order.
//   * "openssl-default": the same ctx the rest of the tool uses
//     (TLS_client_method, no extra options).
//
// for each handshake we capture the raw ClientHello bytes (what we sent)
// and ServerHello bytes (what the server returned) via SSL_set_msg_callback,
// then feed them through ja4.h to produce JA4 and JA4S.
//
// the diff is the diagnostic:
//   * different JA4S between the two flavors -> server adapts its ServerHello
//     to client JA3 -> reality / utls-aware steering.
//   * different cert sha256 between the two -> server returns different cert
//     for chrome-class clients vs default-openssl clients -> hard reality
//     enforcement.
//   * one handshake fails (alert/RST), other succeeds -> server filters by
//     client fingerprint -> strict utls enforcement.
#pragma once

#include "ja4.h"

#include <cstdint>
#include <string>
#include <vector>

struct UtlsProbeResult {
    bool        ok = false;
    bool        handshake_completed = false;
    std::string err;
    std::string flavor;                 // "chrome" or "openssl"
    int         tls_version = 0;        // negotiated, decoded from real_version
    std::string cipher;                 // negotiated (text, e.g. TLS_AES_128_GCM_SHA256)
    std::string alpn;                   // negotiated ALPN
    std::string cert_sha256;
    long long   handshake_ms = 0;

    // raw bytes of CH/SH first message captured by msg_callback
    std::vector<uint8_t> ch_bytes;
    std::vector<uint8_t> sh_bytes;

    // parsed forms + JA4 strings (filled if parse succeeds)
    ClientHelloFp ch_fp;
    ServerHelloFp sh_fp;
    std::string   ja4;
    std::string   ja4s;
};

UtlsProbeResult utls_probe_chrome (const std::string& ip, int port,
                                   const std::string& sni,
                                   int to_ms = 5000);

UtlsProbeResult utls_probe_openssl(const std::string& ip, int port,
                                   const std::string& sni,
                                   int to_ms = 5000);

struct UtlsDualProbe {
    UtlsProbeResult chrome;
    UtlsProbeResult openssl;
    bool        both_completed   = false;
    bool        ja4s_differs     = false;   // server SH differs between flavors
    bool        cert_differs     = false;   // cert sha256 differs between flavors
    bool        only_chrome_ok   = false;   // chrome handshake passed, openssl rejected
    bool        only_openssl_ok  = false;   // openssl passed, chrome rejected
    std::string verdict;                    // short human-readable conclusion
};

UtlsDualProbe utls_dual_probe(const std::string& ip, int port,
                              const std::string& sni);