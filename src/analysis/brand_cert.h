#ifndef ANALYSIS_BRAND_CERT_H
#define ANALYSIS_BRAND_CERT_H

#include <string>
#include <vector>

std::string cert_claims_brand(const std::string& subject_cn, const std::vector<std::string>& san);
bool asn_owns_brand(const std::string& brand_domain, const std::vector<std::string>& asn_orgs);
std::string server_header_brand(const std::string& server_hdr);

#endif // ANALYSIS_BRAND_CERT_H