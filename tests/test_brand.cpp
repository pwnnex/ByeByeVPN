// SPDX-License-Identifier: GPL-3.0-or-later
// unit tests for src/scan/brand.cpp (brand-impersonation helpers).
#include "doctest.h"
#include "../src/scan/brand.h"

#include <string>
#include <vector>

TEST_CASE("cert_claims_brand matches CN and SAN against the brand table") {
    std::vector<std::string> no_san;
    CHECK(cert_claims_brand("www.amazon.com", no_san) == "amazon.com");
    CHECK(cert_claims_brand("amazon.com", no_san)     == "amazon.com");
    CHECK(cert_claims_brand("yandex.ru", no_san)      == "yandex.ru");
    // wildcard CN strips the "*." before matching
    CHECK(cert_claims_brand("*.cloudflare.com", no_san) == "cloudflare.com");
    // not a brand at all
    CHECK(cert_claims_brand("my-random-vps.example", no_san) == "");
    // brand found via SAN even if CN is unrelated
    std::vector<std::string> san = {"node1.internal", "www.microsoft.com"};
    CHECK(cert_claims_brand("internal-name", san) == "microsoft.com");
}

TEST_CASE("asn_owns_brand cross-checks brand against ASN-org strings") {
    // amazon.com is legitimately served from Amazon / AWS ASNs
    std::vector<std::string> aws = {"AMAZON-02", "Amazon Technologies Inc."};
    CHECK(asn_owns_brand("amazon.com", aws));
    // ... but not from a random hosting ASN
    std::vector<std::string> hostkey = {"HOSTKEY B.V."};
    CHECK_FALSE(asn_owns_brand("amazon.com", hostkey));
    // yandex.ru on a Yandex ASN is legit
    std::vector<std::string> yandex = {"YANDEX LLC"};
    CHECK(asn_owns_brand("yandex.ru", yandex));
    CHECK_FALSE(asn_owns_brand("yandex.ru", hostkey));
    // empty inputs never claim ownership
    CHECK_FALSE(asn_owns_brand("", aws));
    CHECK_FALSE(asn_owns_brand("amazon.com", {}));
}

TEST_CASE("server_header_brand maps unforgeable Server banners") {
    CHECK(server_header_brand("cloudflare")        == "cloudflare.com");
    CHECK(server_header_brand("AmazonS3")          == "amazon.com");
    CHECK(server_header_brand("gws")               == "google.com");
    CHECK(server_header_brand("Microsoft-IIS/10.0")== "microsoft.com");
    // a generic banner is not brand-bound
    CHECK(server_header_brand("nginx/1.24.0") == "");
    CHECK(server_header_brand("Apache")       == "");
    CHECK(server_header_brand("")             == "");
}
