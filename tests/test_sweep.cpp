// SPDX-License-Identifier: GPL-3.0-or-later
// unit tests for the pure CIDR + clustering logic in src/app/sweep_core.cpp.
#include "doctest.h"
#include "../src/app/sweep.h"

#include <string>
#include <vector>

TEST_CASE("parse_cidr expands a /24") {
    std::vector<std::string> ips;
    std::string err;
    REQUIRE(parse_cidr("1.2.3.0/24", ips, 1024, err));
    CHECK(ips.size() == 256);
    CHECK(ips.front() == "1.2.3.0");
    CHECK(ips.back() == "1.2.3.255");
}

TEST_CASE("parse_cidr aligns to the network address") {
    std::vector<std::string> ips;
    std::string err;
    REQUIRE(parse_cidr("10.0.0.130/30", ips, 1024, err));   // .130 -> network .128
    CHECK(ips.size() == 4);
    CHECK(ips[0] == "10.0.0.128");
    CHECK(ips[3] == "10.0.0.131");
}

TEST_CASE("parse_cidr: bare IP is a single /32 host") {
    std::vector<std::string> ips;
    std::string err;
    REQUIRE(parse_cidr("8.8.8.8", ips, 1024, err));
    CHECK(ips.size() == 1);
    CHECK(ips[0] == "8.8.8.8");
}

TEST_CASE("parse_cidr rejects oversized ranges and bad input") {
    std::vector<std::string> ips;
    std::string err;
    CHECK_FALSE(parse_cidr("10.0.0.0/8", ips, 1024, err));   // 16M hosts > cap
    CHECK_FALSE(err.empty());
    CHECK_FALSE(parse_cidr("1.2.3.4/33", ips, 1024, err));   // prefix out of range
    CHECK_FALSE(parse_cidr("999.1.1.1/24", ips, 1024, err)); // bad octet
    CHECK_FALSE(parse_cidr("1.2.3.4.5", ips, 1024, err));    // too many octets
    CHECK_FALSE(parse_cidr("not-an-ip", ips, 1024, err));
}

static SweepHost mk(const std::string& ip, bool open, bool tls,
                    const std::string& ja4s, const std::string& issuer,
                    const std::string& sha16) {
    SweepHost h; h.ip = ip; h.open443 = open; h.tls_ok = tls;
    h.ja4s = ja4s; h.issuer_cn = issuer; h.cert_sha16 = sha16;
    return h;
}

TEST_CASE("sweep_cluster_key separates down / no-tls / tls hosts") {
    CHECK(sweep_cluster_key(mk("1.1.1.1", false, false, "", "", "")) == "down");
    CHECK(sweep_cluster_key(mk("1.1.1.2", true, false, "", "", "")) == "open443-no-tls");
    std::string k = sweep_cluster_key(
        mk("1.1.1.3", true, true, "t130200_1301_a56c5b993250", "R10", "abcdef0123456789"));
    CHECK(k.find("ja4s:a56c5b993250") != std::string::npos);
    CHECK(k.find("issuer=R10") != std::string::npos);
    CHECK(k.find("cert=abcdef0123456789") != std::string::npos);
}

TEST_CASE("cluster_hosts groups identical fingerprints and sorts by size") {
    std::vector<SweepHost> hosts = {
        mk("1.0.0.1", true, true, "t130200_1301_aaaa", "RealityCo", "1111111111111111"),
        mk("1.0.0.2", true, true, "t130200_1301_aaaa", "RealityCo", "1111111111111111"),
        mk("1.0.0.3", true, true, "t130200_1301_aaaa", "RealityCo", "1111111111111111"),
        mk("1.0.0.4", true, true, "t130200_1301_bbbb", "Let's Encrypt", "2222222222222222"),
        mk("1.0.0.5", false, false, "", "", ""),
    };
    auto groups = cluster_hosts(hosts);
    REQUIRE(groups.size() == 3);          // the aaaa cluster, the bbbb host, the down host
    // largest cluster first
    CHECK(groups[0].second.size() == 3);
    CHECK(groups[0].first.find("aaaa") != std::string::npos);
}
