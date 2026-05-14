// SPDX-License-Identifier: GPL-3.0-or-later
// unit tests for src/common/tspu.cpp (mgmt-subnet + redirect recognisers).
#include "doctest.h"
#include "../src/common/tspu.h"

TEST_CASE("looks_like_tspu_hop matches the mgmt-subnet last-octet bands") {
    // 10.X.Y.Z with Z in [131..235] / [241..245] / 254 is the tspu layout.
    CHECK(looks_like_tspu_hop("10.1.2.131"));
    CHECK(looks_like_tspu_hop("10.1.2.235"));
    CHECK(looks_like_tspu_hop("10.99.99.241"));
    CHECK(looks_like_tspu_hop("10.0.0.245"));
    CHECK(looks_like_tspu_hop("10.5.5.254"));
}

TEST_CASE("looks_like_tspu_hop rejects out-of-band and non-10.* hops") {
    CHECK_FALSE(looks_like_tspu_hop("10.1.2.130"));   // just below band
    CHECK_FALSE(looks_like_tspu_hop("10.1.2.236"));   // gap between bands
    CHECK_FALSE(looks_like_tspu_hop("10.1.2.240"));   // gap
    CHECK_FALSE(looks_like_tspu_hop("10.1.2.246"));   // just above band
    CHECK_FALSE(looks_like_tspu_hop("10.1.2.1"));     // low octet
    CHECK_FALSE(looks_like_tspu_hop("192.168.1.131"));// not 10.*
    CHECK_FALSE(looks_like_tspu_hop("100.64.0.131")); // CGNAT, not 10.*
    CHECK_FALSE(looks_like_tspu_hop(""));
    CHECK_FALSE(looks_like_tspu_hop("not-an-ip"));
    CHECK_FALSE(looks_like_tspu_hop("10.1.2.999"));   // octet overflow
}

TEST_CASE("looks_like_tspu_redirect matches operator warning markers") {
    const char* m1 = looks_like_tspu_redirect("https://rkn.gov.ru/blocked");
    REQUIRE(m1 != nullptr);
    CHECK(std::string(m1) == "rkn.gov.ru");

    const char* m2 = looks_like_tspu_redirect("http://WARNING.RT.RU/page");
    REQUIRE(m2 != nullptr);          // match is case-insensitive
    CHECK(std::string(m2) == "warning.rt.ru");

    const char* m3 = looks_like_tspu_redirect("http://185.76.180.75/");
    REQUIRE(m3 != nullptr);
}

TEST_CASE("looks_like_tspu_redirect rejects normal redirects") {
    CHECK(looks_like_tspu_redirect("https://example.com/login") == nullptr);
    CHECK(looks_like_tspu_redirect("") == nullptr);
    // oversized Location values are rejected outright
    std::string huge(600, 'a');
    CHECK(looks_like_tspu_redirect(huge) == nullptr);
}
