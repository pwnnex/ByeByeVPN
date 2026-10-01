// SPDX-License-Identifier: GPL-3.0-or-later
// naming hints only; no protocol confirmation or score impact.
#pragma once

#include <string>
#include <vector>
#include "hostname_input.h"
#include "public_suffix.h"

struct HostnameMark {
    enum class Tier {
        Strong,     // distinctive software or protocol name
        Moderate,   // suggestive, with unrelated uses too
        Weak,       // broad or ambiguous association
    };

    std::string token;
    std::string label;
    std::string decoded_label;
    std::string host;
    bool        in_subdomain = false;
    Tier        tier = Tier::Weak;
    std::string why;
    std::string kind = "token"; // token, provider_domain, provider_node, hosting_domain
    std::vector<std::string> sources; // target, cert_cn[:port], cert_san[:port]
};

struct HostnameAnalysis {
    std::vector<HostnameMark> marks;
    int strong = 0, moderate = 0, weak = 0;

    bool any() const { return !marks.empty(); }
};

// returns no labels for invalid names or ip literals.
std::vector<std::string> hostname_labels(const std::string& host);

HostnameAnalysis analyze_hostname(const std::string& host);

struct ObservedHostname {
    std::string name;
    std::string source;
};

// canonical names are deduplicated; all observation sources are retained.
HostnameAnalysis analyze_host_names(const std::vector<ObservedHostname>& names);
HostnameAnalysis analyze_host_names(const std::string& scanned_host,
                                    const std::string& subject_cn,
                                    const std::vector<std::string>& san);

const char* hostname_tier_name(HostnameMark::Tier t);
std::string hostname_marks_json(const HostnameAnalysis& analysis);
std::string hostname_report_json(const std::vector<std::string>& names);
