// SPDX-License-Identifier: GPL-3.0-or-later
// observed certificate routing; sni behaviour alone does not identify reality.
#pragma once

#include <string>
#include <vector>
#include "tls.h"

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
        std::string err;
    };
    std::vector<Entry> entries;
    bool base_ok = false;
    int compared = 0;
    int failed = 0;
    int same_as_base = 0;
    std::string pattern = "insufficient-data";
    std::string err;

    bool        same_cert_always   = false;
    bool        reality_like       = false;
    bool        default_cert_only  = false;
    std::string matched_foreign_sni;

    // legacy attribution fields remain false; brand is only a name observation.
    std::string brand_claimed;
    bool        cert_impersonation = false;
    bool        passthrough_mode   = false;

    int distinct_certs = 0;
};

// run a base + 10 foreign-sni probes, classify the cert behaviour.
SniConsistency sni_consistency(const std::string& ip, int port, const std::string& base_sni);
SniConsistency analyze_sni(const std::string& base_sni, const TlsProbe& base,
                           const std::vector<SniConsistency::Entry>& entries);
