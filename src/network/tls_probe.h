#ifndef NETWORK_TLS_PROBE_H
#define NETWORK_TLS_PROBE_H

#include <string>
#include <vector>
#include <cstdint>

struct TlsProbe {
    bool   ok = false;
    std::string err;
    std::string version;
    std::string cipher;
    std::string alpn;
    std::string group;
    std::string cert_subject;
    std::string cert_issuer;
    std::string cert_sha256;
    std::vector<std::string> san;
    int64_t handshake_ms = 0;
    std::string  subject_cn;
    std::string  issuer_cn;
    int     age_days = 0;
    int     days_left = 0;
    int     total_validity_days = 0;
    bool    self_signed = false;
    bool    is_letsencrypt = false;
    bool    is_wildcard = false;
    int     san_count = 0;
};

TlsProbe tls_probe(const std::string& ip, int port, const std::string& sni,
                   const std::string& alpn = "h2,http/1.1", int to_ms = 5000);

#endif // NETWORK_TLS_PROBE_H