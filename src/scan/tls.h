// SPDX-License-Identifier: GPL-3.0-or-later
// tls handshake probe: version / cipher / alpn / group / cert intel.
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <ctime>
#include <openssl/types.h>

struct CertificateInfo {
    std::string cert_subject;
    std::string cert_issuer;
    std::string cert_sha256;
    std::vector<std::string> san;

    // observations only; the probe does not validate the trust chain.
    std::string subject_cn;
    std::string issuer_cn;
    int         age_days  = 0;
    int         days_left = 0;
    int         total_validity_days = 0;
    int64_t     total_validity_seconds = 0;
    bool        certificate_present = false;
    bool        certificate_times_valid = false;
    bool        certificate_expired = false;
    bool        certificate_not_yet_valid = false;
    bool        self_issued = false;
    bool        self_signature_checked = false;
    bool        self_signed   = false;
    bool        is_letsencrypt = false;
    bool        is_wildcard    = false;
    int         san_count      = 0;
};

struct TlsProbe : CertificateInfo {
    bool        ok = false;
    std::string err;
    std::string version;
    std::string cipher;
    std::string alpn;
    std::string group;
    int64_t     handshake_ms = 0;
};

// metadata extraction without networking. now is explicit for reproducible checks.
void inspect_certificate(X509* cert, CertificateInfo& result, std::time_t now);

TlsProbe tls_probe(const std::string& ip, int port, const std::string& sni,
                   const std::string& alpn = "h2,http/1.1",
                   int to_ms = 5000);
