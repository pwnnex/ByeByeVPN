// SPDX-License-Identifier: GPL-3.0-or-later
// compare two clienthello profiles; tls negotiation differences aren't protocol proof
// raw chrome stops at serverhello; openssl attempts a full handshake
#pragma once

#include "ja4.h"

#include <cstdint>
#include <string>
#include <vector>

struct UtlsProbeResult {
    bool        ok = false;
    bool        handshake_completed = false;
    bool        server_hello_received = false;
    std::string err;
    std::string flavor;                 // "chrome" or "openssl"
    int         tls_version = 0;        // negotiated, decoded from real_version
    std::string cipher;                 // negotiated (text, e.g. tls_aes_128_gcm_sha256)
    std::string alpn;                   // negotiated alpn
    std::string cert_sha256;
    long long   handshake_ms = 0;

    // raw bytes of ch/sh first message captured by msg_callback
    std::vector<uint8_t> ch_bytes;
    std::vector<uint8_t> sh_bytes;

    // parsed forms + ja4 strings (filled if parse succeeds)
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
    bool        both_responded   = false;
    bool        ja4s_differs     = false;   // server sh differs between flavors
    bool        cert_differs     = false;   // cert sha256 differs between flavors
    bool        only_chrome_ok   = false;   // only chrome got a usable serverhello
    bool        only_openssl_ok  = false;   // only openssl got a usable serverhello
    std::string verdict;                    // short human-readable conclusion
};

UtlsDualProbe utls_dual_probe(const std::string& ip, int port,
                              const std::string& sni);
UtlsDualProbe compare_utls_probes(UtlsProbeResult chrome, UtlsProbeResult openssl);
