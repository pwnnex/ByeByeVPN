#ifndef ANALYSIS_SNI_CONSISTENCY_H
#define ANALYSIS_SNI_CONSISTENCY_H

#include <string>
#include <vector>

struct SniConsistency {
    std::string base_sni;
    std::string base_sha;
    std::string base_subject;
    std::vector<std::string> base_san;
    struct Entry { std::string sni; bool ok; std::string sha; std::string subject; };
    std::vector<Entry> entries;
    bool same_cert_always = false;
    bool reality_like = false;
    bool default_cert_only = false;
    std::string matched_foreign_sni;
    std::string brand_claimed;
    bool   cert_impersonation = false;
    bool   passthrough_mode = false;
    int    distinct_certs = 0;
};

SniConsistency sni_consistency(const std::string& ip, int port, const std::string& base_sni);

#endif // ANALYSIS_SNI_CONSISTENCY_H