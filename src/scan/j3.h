// J3-style active probing: 8 distinct probes per TLS port (empty/close,
// HTTP GET, CONNECT, SSH banner, random bytes, TLS-CH-invalid-SNI,
// abs-URI proxy GET, 0xFF junk).
//
// the response analysis bucket-classifies replies into:
// real HTTP / canned-fallback / non-HTTP / version-anomaly / silent.
#pragma once

#include <string>
#include <vector>
#include <cstdint>

struct J3Result {
    std::string name;
    bool        responded = false;
    int         bytes     = 0;
    std::string first_line;
    std::string hex_head;
    int64_t     ms        = 0;
};

struct J3Analysis {
    int silent              = 0;
    int resp                = 0;
    int http_real           = 0;
    int http_bad_version    = 0;
    int raw_non_http        = 0;
    int canned_identical    = 0;
    std::string canned_line;
    int canned_bytes        = 0;
};

std::vector<J3Result> j3_probes(const std::string& host, int port);
J3Analysis            j3_analyze(const std::vector<J3Result>& probes);

// our-OpenSSL JA3 fingerprint metadata for the verdict advisory.
struct Ja3Info {
    std::string version;
    std::string ciphers;
    std::string extensions;
    std::string groups;
    std::string ec_formats;
    std::string ja3_hash;
};
Ja3Info our_openssl_ja3_signature();
