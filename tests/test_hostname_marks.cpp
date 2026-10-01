// SPDX-License-Identifier: GPL-3.0-or-later
// parsing, suffix boundaries, source attribution and false-positive regressions.
#include "doctest.h"
#include "../src/scan/hostname_marks.h"
#include "../src/common/json.h"

#include <algorithm>
#include <string>
#include <vector>

namespace {

bool has_token(const HostnameAnalysis& a, const std::string& t) {
    return std::any_of(a.marks.begin(), a.marks.end(),
                       [&](const HostnameMark& m) { return m.token == t; });
}

const HostnameMark* find_token(const HostnameAnalysis& a, const std::string& t) {
    for (const auto& m : a.marks) if (m.token == t) return &m;
    return nullptr;
}

} // namespace

TEST_CASE("hostname_labels lowercases and strips the root dot") {
    auto l = hostname_labels("SUB.Example.COM.");
    REQUIRE(l.size() == 3);
    CHECK(l[0] == "sub");
    CHECK(l[1] == "example");
    CHECK(l[2] == "com");
}

TEST_CASE("hostname_labels drops a wildcard san label") {
    auto l = hostname_labels("*.example.com");
    REQUIRE(l.size() == 2);
    CHECK(l[0] == "example");
    CHECK(l[1] == "com");
}

TEST_CASE("hostname_labels rejects ip literals") {
    // an ip is not a naming choice, so it can carry no naming tell
    CHECK(hostname_labels("203.0.113.189").empty());
    CHECK(hostname_labels("1.1.1.1").empty());
    CHECK(hostname_labels("2606:4700::1111").empty());
    CHECK(hostname_labels("").empty());
    CHECK(hostname_labels(".").empty());
}

TEST_CASE("registrable_domain_start: plain two-label domain has no subdomains") {
    CHECK(registrable_domain_start({"example", "com"}) == 0);
    CHECK(registrable_domain_start({"com"}) == 0);
    CHECK(registrable_domain_start({}) == 0);
}

TEST_CASE("registrable_domain_start counts operator-created labels") {
    CHECK(registrable_domain_start({"sub", "example", "com"}) == 1);
    CHECK(registrable_domain_start({"a", "b", "example", "ru"}) == 2);
}

TEST_CASE("registrable_domain_start handles second-level registries") {
    // example.co.uk is the registrable domain, so "vpn" is the only subdomain
    CHECK(registrable_domain_start({"vpn", "example", "co", "uk"}) == 1);
    CHECK(registrable_domain_start({"example", "co", "uk"}) == 0);
    CHECK(registrable_domain_start({"node1", "shop", "com", "ua"}) == 1);
}

TEST_CASE("a token in a subdomain is marked as operator-created") {
    HostnameAnalysis a = analyze_hostname("vless.example.com");
    const HostnameMark* m = find_token(a, "vless");
    REQUIRE(m != nullptr);
    CHECK(m->in_subdomain == true);
    CHECK(m->label == "vless");
    CHECK(m->tier == HostnameMark::Tier::Strong);
}

TEST_CASE("a token in the registrable domain is not a subdomain mark") {
    // buying vless.com is a different act from naming a subdomain vless.
    HostnameAnalysis a = analyze_hostname("vless.com");
    const HostnameMark* m = find_token(a, "vless");
    REQUIRE(m != nullptr);
    CHECK(m->in_subdomain == false);
}

TEST_CASE("tokens are matched as whole words, never as substrings") {
    // the substring trap: these must NOT fire
    CHECK_FALSE(has_token(analyze_hostname("vpnews.example.com"), "vpn"));
    CHECK_FALSE(has_token(analyze_hostname("subaru.example.com"), "sub"));
    CHECK_FALSE(has_token(analyze_hostname("subtle.example.com"), "sub"));
}

TEST_CASE("hyphen and underscore split a label into matchable words") {
    CHECK(has_token(analyze_hostname("vless-de1.example.com"), "vless"));
    CHECK(has_token(analyze_hostname("de1-vless.example.com"), "vless"));
    CHECK(has_token(analyze_hostname("my_vpn_gw.example.com"), "vpn"));
}

TEST_CASE("a clean hostname produces no marks at all") {
    HostnameAnalysis a = analyze_hostname("www.wikipedia.org");
    CHECK(a.marks.empty());
    CHECK_FALSE(a.any());
    CHECK(a.strong == 0);
    CHECK(a.moderate == 0);
}

TEST_CASE("tier counters agree with the marks list") {
    HostnameAnalysis a = analyze_hostname("vless.sub.example.com");
    CHECK((int)a.marks.size() == a.strong + a.moderate + a.weak);
    CHECK(a.strong >= 1);     // vless
    CHECK(a.moderate >= 1);   // sub
}

TEST_CASE("analyze_host_names sweeps scanned host, cn and every san") {
    HostnameAnalysis a = analyze_host_names(
        "plain.example.com", "cn.example.com",
        {"vless.example.com", "other.example.com"});
    CHECK(has_token(a, "vless"));
}

TEST_CASE("analyze_host_names reports a repeated name once") {
    // the same name routinely appears as both the cn and the first san
    HostnameAnalysis dup = analyze_host_names(
        "vless.example.com", "vless.example.com", {"vless.example.com"});
    HostnameAnalysis one = analyze_hostname("vless.example.com");
    CHECK(dup.marks.size() == one.marks.size());
}

TEST_CASE("analyze_host_names is case-insensitive when deduping") {
    HostnameAnalysis a = analyze_host_names(
        "VLESS.Example.COM", "vless.example.com", {"Vless.Example.Com"});
    HostnameAnalysis one = analyze_hostname("vless.example.com");
    CHECK(a.marks.size() == one.marks.size());
}

TEST_CASE("analyze_host_names tolerates empty inputs") {
    HostnameAnalysis a = analyze_host_names("", "", {});
    CHECK(a.marks.empty());
    HostnameAnalysis b = analyze_host_names("203.0.113.189", "", {});
    CHECK(b.marks.empty());
}

TEST_CASE("hostname_tier_name covers every tier") {
    CHECK(std::string(hostname_tier_name(HostnameMark::Tier::Strong))   == "strong");
    CHECK(std::string(hostname_tier_name(HostnameMark::Tier::Moderate)) == "moderate");
    CHECK(std::string(hostname_tier_name(HostnameMark::Tier::Weak))     == "weak");
}

TEST_CASE("coined names match inside a run-together label") {
    // distinctive tokens can occur in combined names.
    CHECK(has_token(analyze_hostname("v2rayshare.com"), "v2ray"));
    CHECK(has_token(analyze_hostname("shadowsocksfree.example.com"), "shadowsocks"));
    CHECK(has_token(analyze_hostname("myhiddifypanel.example.com"), "hiddify"));
}

TEST_CASE("generic tokens still refuse to match as substrings") {
    // the whole point of keeping two matching modes: these must stay silent
    CHECK_FALSE(has_token(analyze_hostname("hanvpn.biz"), "vpn"));
    CHECK_FALSE(has_token(analyze_hostname("vpnews.example.com"), "vpn"));
    CHECK_FALSE(has_token(analyze_hostname("subaru.example.com"), "sub"));
    CHECK_FALSE(has_token(analyze_hostname("xraymedical.example.com"), "xray"));
    CHECK_FALSE(has_token(analyze_hostname("clashroyale.example.com"), "clash"));
}

TEST_CASE("a trailing digit run no longer hides an enumerated host") {
    CHECK(has_token(analyze_hostname("vless001.example.com"), "vless"));
    CHECK(has_token(analyze_hostname("wireguard01.example.com"), "wireguard"));
    CHECK(has_token(analyze_hostname("ovpn1.example.com"), "ovpn"));
    CHECK(has_token(analyze_hostname("sub2.example.com"), "sub"));
    CHECK(has_token(analyze_hostname("node3.example.com"), "node"));
}

TEST_CASE("digit stripping refuses to manufacture two-character words") {
    // s1 must not become "s"; hy2 must not become "hy"
    HostnameAnalysis s1 = analyze_hostname("s1.example.com");
    CHECK(s1.marks.empty());
    // hy2 is carried as its own token instead of being stripped
    CHECK(has_token(analyze_hostname("hy2.example.com"), "hy2"));
}

TEST_CASE("a token is not double-counted via its own digit stem") {
    // socks5 must produce exactly one mark, not socks5 AND socks
    HostnameAnalysis a = analyze_hostname("socks5.example.com");
    int n = 0;
    for (const auto& m : a.marks) if (m.label == "socks5") ++n;
    CHECK(n == 1);
}

TEST_CASE("a repeated token in one label is marked once") {
    HostnameAnalysis a = analyze_hostname("vless-vless.example.com");
    int n = 0;
    for (const auto& m : a.marks) if (m.token == "vless") ++n;
    CHECK(n == 1);
}

TEST_CASE("common infrastructure labels are not vpn tokens") {
    // ordinary service names carry no useful protocol hint.
    for (const char* h : {"mail.example.com", "dev.example.com", "api.example.com",
                          "cdn.example.com", "portal.example.com", "cloud.example.com",
                          "web.example.com", "app.example.com", "staging.example.com",
                          "my.example.com", "secure.example.com", "www.example.com",
                          "net.example.com", "access.example.com", "user.example.com",
                          "edge.example.com", "client.example.com", "private.example.com",
                          "key.example.com", "prod.example.com", "srv1.example.com",
                          "vps1.example.com", "relay1.example.com", "de1.example.com"}) {
        CAPTURE(h);
        CHECK(analyze_hostname(h).marks.empty());
    }
}

TEST_CASE("the tool's own focus protocol is covered") {
    // both the full name and common abbreviations are covered.
    CHECK(has_token(analyze_hostname("amneziawg.example.com"), "amneziawg"));
    CHECK(has_token(analyze_hostname("awg.example.com"), "awg"));
    CHECK(has_token(analyze_hostname("amnezia.example.com"), "amnezia"));
}

TEST_CASE("corporate remote-access names stay at the weak tier") {
    // ipsec / anyconnect / tailscale are ordinary enterprise infrastructure.
    // they may be recorded, but they must never be able to move a score.
    for (const char* t : {"ipsec", "anyconnect", "tailscale", "l2tp", "pptp"}) {
        HostnameAnalysis a = analyze_hostname(std::string(t) + ".corp.example.com");
        CAPTURE(t);
        REQUIRE_FALSE(a.marks.empty());
        CHECK(a.strong == 0);
        CHECK(a.moderate == 0);
    }
}

TEST_CASE("strong tier is reserved for coined names only") {
    // a scan of a boring corporate vpn gateway must not produce a strong mark
    HostnameAnalysis corp = analyze_hostname("vpn.bigcorp.com");
    CHECK(corp.strong == 0);
    // while a host that names the protocol does
    HostnameAnalysis prox = analyze_hostname("vless.shop.xyz");
    CHECK(prox.strong >= 1);
}

TEST_CASE("invalid names are not repaired into convincing matches") {
    for (const auto& name : std::vector<std::string>{
            "vless..example.com", ".vless.example", "vless.example.com..",
            "https://vless.example.com/", "vless.example/path", "vless.example:443",
            "vless.*.example.com", "**.vless.example", "vless@somewhere.example",
            "-vless.example", "vless-.example", "vless example.com", "vless\n.example",
            std::string("vless\0.example", 14), std::string(64, 'a') + ".vless.example",
            "999.0.0.1", "2001:::1", "xn--a.example", "xn--abc-.example",
            "xn--" + std::string(58, 'z') + ".example"}) {
        CAPTURE(name);
        CHECK(parse_hostname(name).status == HostnameInput::Status::Invalid);
        CHECK(analyze_hostname(name).marks.empty());
    }
    CHECK(parse_hostname("203.0.113.189").status == HostnameInput::Status::IpLiteral);
    CHECK(parse_hostname("[2001:db8::1]").status == HostnameInput::Status::IpLiteral);
    CHECK(parse_hostname("2001:db8::1").status == HostnameInput::Status::IpLiteral);
}

TEST_CASE("dns name length includes the wildcard label") {
    const auto longest = std::string(63, 'a') + "." + std::string(63, 'b') + "." +
                         std::string(63, 'c') + "." + std::string(61, 'd');
    REQUIRE(longest.size() == 253);
    CHECK(parse_hostname(longest + '.').status == HostnameInput::Status::Hostname);
    CHECK(parse_hostname("*." + longest).status == HostnameInput::Status::Invalid);
}

TEST_CASE("psl handles private suffixes wildcards and exceptions") {
    CHECK(registrable_domain_start({"vpn", "net", "example"}) == 1);
    CHECK(registrable_domain_start({"vpn", "github", "io"}) == 0);
    CHECK(registrable_domain_start({"vless", "site", "github", "io"}) == 1);
    CHECK(registrable_domain_start({"vpn", "site", "workers", "dev"}) == 1);
    CHECK(registrable_domain_start({"vpn", "account", "appspot", "com"}) == 1);
    CHECK(public_suffix_start({"x", "b", "ck"}) == 1);
    CHECK(public_suffix_start({"www", "ck"}) == 1);
    CHECK(registrable_domain_start({"vpn", "www", "ck"}) == 1);
    CHECK(registrable_domain_start({"vpn", "city", "kawasaki", "jp"}) == 1);
    CHECK(registrable_domain_start({"vpn", "a", "kawasaki", "jp"}) == 0);
    CHECK(registrable_domain_start({"vpn", "site", "xn--p1ai"}) == 1);
}

TEST_CASE("public suffix words are not attributed to the operator") {
    CHECK_FALSE(has_token(analyze_hostname("www.example.free"), "free"));
    CHECK_FALSE(has_token(analyze_hostname("www.example.tor"), "tor"));
    CHECK(has_token(analyze_hostname("site.xray.app"), "xray"));
    CHECK_FALSE(has_token(analyze_hostname("site.vpnplus.to"), "vpn"));
    auto a = analyze_hostname("vless.github.io");
    REQUIRE(find_token(a, "vless"));
    CHECK_FALSE(find_token(a, "vless")->in_subdomain);
}

TEST_CASE("punycode is decoded before matching") {
    auto parsed = parse_hostname("xn--bcher-kva.example");
    REQUIRE(parsed.status == HostnameInput::Status::Hostname);
    CHECK(parsed.decoded_labels[0] == "bücher");
    CHECK_FALSE(analyze_hostname("xn--bcher-kva.example").any());
    auto a = analyze_hostname("xn--b1awf.example");
    REQUIRE(has_token(a, "впн"));
    CHECK(find_token(a, "впн")->decoded_label == "впн");
    CHECK(has_token(analyze_hostname("xn--80ahmirfcr.example"), "подписка"));
    CHECK(has_token(analyze_hostname("xn--vless-k1e.example"), "vless"));
    CHECK(has_token(analyze_hostname("xn--2-ctb7ah.example"), "впн"));
    CHECK(parse_hostname("впн.example").status == HostnameInput::Status::Invalid);
}

TEST_CASE("known short and numeric tokens keep numbered nodes visible") {
    CHECK(has_token(analyze_hostname("wg01.example.com"), "wg"));
    CHECK(has_token(analyze_hostname("awg2.example.com"), "awg"));
    auto a = analyze_hostname("socks5001.example.com");
    CHECK(has_token(a, "socks5"));
    CHECK_FALSE(has_token(a, "socks"));
    CHECK(has_token(analyze_hostname("hy201.example.com"), "hy2"));
    CHECK_FALSE(analyze_hostname("s1.example.com").any());
}

TEST_CASE("canonical duplicates retain every source including later ports") {
    auto a = analyze_host_names(std::vector<ObservedHostname>{
        {"VLESS.EXAMPLE.COM.", "target"}, {"vless.example.com", "cert_cn:443"},
        {"vless.example.com.", "cert_san:443"}, {"vless.example.com", "cert_san:443"},
        {"amneziawg.example.com", "cert_cn:8443"}});
    REQUIRE(a.marks.size() == 2);
    REQUIRE(find_token(a, "vless"));
    CHECK(find_token(a, "vless")->host == "vless.example.com");
    CHECK(find_token(a, "vless")->sources == std::vector<std::string>{"target", "cert_cn:443", "cert_san:443"});
    CHECK(find_token(a, "amneziawg")->sources == std::vector<std::string>{"cert_cn:8443"});
    auto cert = analyze_host_names("www.example.com", "vless.cover.example", {});
    REQUIRE(find_token(cert, "vless"));
    CHECK(find_token(cert, "vless")->sources == std::vector<std::string>{"cert_cn"});
}

TEST_CASE("wildcard observations remain distinct from apex names") {
    auto a = analyze_host_names("vless.example.com", "*.vless.example.com", {"*.VLESS.example.com."});
    REQUIRE(a.marks.size() == 2);
    CHECK(a.marks[0].host != a.marks[1].host);
    CHECK(a.marks[1].sources.size() == 2);
}

TEST_CASE("provider domains require an exact suffix boundary") {
    auto provider = [](const HostnameAnalysis& a, const std::string& kind) {
        return std::any_of(a.marks.begin(), a.marks.end(), [&](const auto& m) { return m.kind == kind; });
    };
    CHECK(provider(analyze_hostname("cloudflareclient.com"), "provider_domain"));
    CHECK(provider(analyze_hostname("engage.cloudflareclient.com"), "provider_domain"));
    CHECK(provider(analyze_hostname("us8360.nordvpn.com"), "provider_node"));
    CHECK(provider(analyze_hostname("ua.wg.ivpn.net"), "provider_node"));
    CHECK(provider(analyze_hostname("se-mma-wg-004.relays.mullvad.net"), "provider_node"));
    for (const char* name : {"notnordvpn.com", "de1.nordvpn.com.example", "ivpn.net.example",
                             "fakecloudflareclient.com", "relays.mullvad.net.example"}) {
        CAPTURE(name);
        CHECK_FALSE(provider(analyze_hostname(name), "provider_domain"));
        CHECK_FALSE(provider(analyze_hostname(name), "provider_node"));
    }
    CHECK_FALSE(provider(analyze_hostname("www.nordvpn.com"), "provider_node"));
    CHECK_FALSE(provider(analyze_hostname("*.de1.nordvpn.com"), "provider_node"));
    auto hosting = analyze_hostname("site.account.workers.dev");
    CHECK(provider(hosting, "hosting_domain"));
    CHECK_FALSE(provider(hosting, "provider_domain"));
    CHECK(hosting.strong == 0);
    CHECK(hosting.moderate == 0);
}

TEST_CASE("offline name json distinguishes errors hints and IP inputs") {
    bool ok = false;
    auto j = json_parse(hostname_report_json({"VLESS.example.com.", "sub..example", "203.0.113.189", "bad\nname"}), &ok);
    REQUIRE(ok);
    CHECK_FALSE(j["protocol_confirmed"].as_bool(true));
    CHECK_FALSE(j["network_checked"].as_bool(true));
    CHECK(j["score_impact"].as_int(-1) == 0);
    CHECK(j["results"].at(0)["normalized_host"].as_str() == "vless.example.com");
    CHECK(j["results"].at(0)["marks"].at(0)["sources"].at(0).as_str() == "target");
    CHECK(j["results"].at(1)["status"].as_str() == "invalid");
    CHECK(j["results"].at(2)["status"].as_str() == "ip_literal");
    CHECK(j["results"].at(3)["input"].as_str() == "bad\nname");
    CHECK_FALSE(json_parse(hostname_report_json({}))["error"].is_null());
}
