// SPDX-License-Identifier: GPL-3.0-or-later
// brand-impersonation detector. given a TLS cert + the host's GeoIP ASN,
// flag setups where a famous-brand cert (amazon/microsoft/yandex/etc.) is
// served by an ASN that doesn't belong to that brand — the Reality-static
// "dest=www.brand.com" profile.
#pragma once

#include <string>
#include <vector>

// returns the brand domain the cert vouches for, or "" on no match.
// checks subject CN + every SAN entry against the curated brand list.
std::string cert_claims_brand(const std::string& subject_cn,
                              const std::vector<std::string>& san);

// true iff any of asn_orgs contain a marker associated with this brand.
bool asn_owns_brand(const std::string& brand_domain,
                    const std::vector<std::string>& asn_orgs);

// HTTP Server: header -> brand domain (CloudFront, gws, Microsoft-IIS, ...)
// only returns a domain for headers a real web server can never forge by
// accident (no nginx/apache/caddy mappings).
std::string server_header_brand(const std::string& server_hdr);