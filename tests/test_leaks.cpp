// SPDX-License-Identifier: GPL-3.0-or-later
#include "doctest.h"
#include "../src/local/leaks.h"

namespace {
LeakAdapter wifi(std::vector<std::string> v6 = {}, std::vector<std::string> dns = {"192.168.1.1"}) {
    LeakAdapter a;
    a.name = "Wi-Fi"; a.index = 7; a.metric = 35; a.up = true; a.gateway = true;
    a.v6 = std::move(v6); a.dns = std::move(dns);
    return a;
}
LeakAdapter tun(std::vector<std::string> dns = {"172.19.0.2"}) {
    LeakAdapter a;
    a.name = "tun0"; a.index = 21; a.metric = 5; a.up = true; a.tunnel = true;
    a.v6 = {"fdfe:dcba:9876::1"}; a.dns = std::move(dns);
    return a;
}
V6Probe v6(V6Seen s) { V6Probe p; p.target = "2606:4700:4700::1111"; p.seen = s; return p; }
DnsProbe asked(std::vector<DnsSeen> seen) { DnsProbe p; p.server = "192.168.1.1"; p.adapter = "Wi-Fi"; p.seen = std::move(seen); return p; }
} // namespace

TEST_CASE("leaks: global ipv6 addresses") {
    CHECK(v6_global("2a02:6b8::1"));
    CHECK(v6_global("2001:db8::5"));
    CHECK(v6_global("3fff::1"));
    CHECK_FALSE(v6_global("fe80::1%12"));
    CHECK_FALSE(v6_global("fd00::1"));
    CHECK_FALSE(v6_global("fec0:0:0:ffff::1"));
    CHECK_FALSE(v6_global("::1"));
    CHECK_FALSE(v6_global("ff02::fb"));
    CHECK_FALSE(v6_global(""));
    CHECK_FALSE(v6_global("12345::"));
}

TEST_CASE("leaks: ipv6 beside the tunnel") {
    // no tunnel: nothing to leak from
    CHECK(ipv6_leak({wifi({"2a02:6b8::10"})}, {}).outcome == Outcome::NotApplicable);
    // tunnel up, no global v6 outside: proof without packets
    CHECK(ipv6_leak({wifi({"fe80::2"}), tun()}, {}).outcome == Outcome::Negative);
    std::vector<LeakAdapter> ads = {wifi({"fe80::2", "2a02:6b8::10"}), tun()};
    CHECK(ipv6_leak(ads, {v6(V6Seen::Outside), v6(V6Seen::Outside)}).outcome == Outcome::Positive);
    CHECK(ipv6_leak(ads, {v6(V6Seen::Tunnel), v6(V6Seen::Tunnel)}).outcome == Outcome::Negative);
    CHECK(ipv6_leak(ads, {v6(V6Seen::NoPath), v6(V6Seen::NoPath)}).outcome == Outcome::Negative);
    // one look is not two, silence is not proof, a split is unstable
    CHECK(ipv6_leak(ads, {v6(V6Seen::Outside), v6(V6Seen::Silent)}).outcome == Outcome::Inconclusive);
    CHECK(ipv6_leak(ads, {v6(V6Seen::Silent), v6(V6Seen::Silent)}).outcome == Outcome::Inconclusive);
    CHECK(ipv6_leak(ads, {v6(V6Seen::Outside), v6(V6Seen::Tunnel)}).outcome == Outcome::Inconclusive);
    CHECK(ipv6_leak(ads, {}).outcome == Outcome::Inconclusive);
}

TEST_CASE("leaks: dns beside the tunnel") {
    CHECK(dns_leak({wifi()}, true, {}).outcome == Outcome::NotApplicable);
    std::vector<LeakAdapter> ads = {wifi(), tun()};
    REQUIRE(dns_outside(ads, true).size() == 1);
    CHECK(dns_leak(ads, true, {asked({DnsSeen::Answer, DnsSeen::Answer})}).outcome == Outcome::Positive);
    CHECK(dns_leak(ads, true, {asked({DnsSeen::Blocked, DnsSeen::Blocked})}).outcome == Outcome::Negative);
    CHECK(dns_leak(ads, true, {asked({DnsSeen::Answer, DnsSeen::Silent})}).outcome == Outcome::Inconclusive);
    CHECK(dns_leak(ads, true, {asked({DnsSeen::Silent, DnsSeen::Silent})}).outcome == Outcome::Inconclusive);
    CHECK(dns_leak(ads, true, {}).outcome == Outcome::Inconclusive);
    // parallel queries off and the tunnel's resolver first: not asked beside it
    CHECK(dns_outside(ads, false).empty());
    CHECK(dns_leak(ads, false, {}).outcome == Outcome::Negative);
    // parallel queries off but the tunnel has no resolver: the outside one is used
    std::vector<LeakAdapter> bare = {wifi(), tun({})};
    CHECK(dns_outside(bare, false).size() == 1);
    // only the placeholder site-local resolvers outside
    std::vector<LeakAdapter> none = {wifi({}, {"fec0:0:0:ffff::1", "fec0:0:0:ffff::2"}), tun()};
    CHECK(dns_outside(none, true).empty());
    CHECK(dns_leak(none, true, {}).outcome == Outcome::Negative);
    // an adapter that is down does not count
    LeakAdapter down = wifi();
    down.up = false;
    CHECK(dns_outside({down, tun()}, true).empty());
}
