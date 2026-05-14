// SPDX-License-Identifier: GPL-3.0-or-later
// SNI consistency probe + Reality discriminator.
//
// Reality is identified by: same cert returned for every SNI AND that cert
// is valid for at least one of the foreign SNIs we probed. plain TLS server
// with one default cert behaves identically on the first half but the cert
// covers no foreign SNI.
#pragma once

#include <string>
#include <vector>

struct SniConsistency {
    std::string base_sni;
    std::string base_sha;
    std::string base_subject;
    std::vector<std::string> base_san;

    struct Entry {
        std::string sni;
        bool        ok = false;
        std::string sha;
        std::string subject;
    };
    std::vector<Entry> entries;

    bool        same_cert_always   = false;
    bool        reality_like       = false;
    bool        default_cert_only  = false;
    std::string matched_foreign_sni;

    // brand impersonation
    std::string brand_claimed;
    bool        cert_impersonation = false;
    bool        passthrough_mode   = false;

    int distinct_certs = 0;
};

// run a base + 10 foreign-SNI probes, classify the cert behaviour.
SniConsistency sni_consistency(const std::string& ip, int port, const std::string& base_sni);