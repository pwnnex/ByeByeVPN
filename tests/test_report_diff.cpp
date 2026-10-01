// SPDX-License-Identifier: GPL-3.0-or-later
#include "doctest.h"
#include "../src/app/report_diff.h"

#include <string>

namespace {
// the fields diff reads, in the shape json_report writes them
std::string report(const std::string& label, const std::string& ports, const std::string& cert,
                   const std::string& check = "negative", const std::string& geo_vpn = "false",
                   const std::string& score = "12") {
    return std::string("{ \"tool\": \"byebyevpn\", \"target\": \"node.example\", \"resolved_ip\": \"203.0.113.5\",") +
           "\"score\": " + score + ", \"label\": \"" + label + "\", \"unreliable\": false," +
           "\"tspu\": { \"tier\": \"PASS\" }," +
           "\"checks\": [ { \"id\": \"wg-family\", \"port\": 51820, \"outcome\": \"" + check + "\" } ]," +
           "\"signals\": { \"scored\": [] }," +
           "\"geo\": [ { \"source\": \"ipinfo.io\", \"is_vpn\": " + geo_vpn + ", \"is_proxy\": false, \"is_tor\": false," +
           " \"is_hosting\": true, \"err\": \"\" } ]," +
           "\"open_tcp\": [" + ports + "]," +
           "\"udp\": [ { \"port\": 51820, \"kind\": \"wg\", \"responded\": false } ]," +
           "\"tls_ports\": [ { \"port\": 443, \"cert_sha256\": \"" + cert + "\", \"cert_cn\": \"node.example\"," +
           " \"cert_issuer\": \"R11\", \"tls_version\": \"TLSv1.3\", \"alpn\": \"h2\", \"utls\": null } ] }";
}
const std::string P443 = "{ \"port\": 443 }";
const std::string P443_8443 = "{ \"port\": 443 }, { \"port\": 8443 }";
} // namespace

TEST_CASE("diff: identical reports") {
    ReportDiff d = diff_reports(report("CLEAN", P443, "aa"), report("CLEAN", P443, "aa"));
    REQUIRE(d.ok);
    CHECK(d.items.empty());
    CHECK(diff_exit_code(d) == 0);
    CHECK(d.target_a == "node.example");
}

TEST_CASE("diff: surface and context changes keep the verdict class apart") {
    ReportDiff d = diff_reports(report("CLEAN", P443, "aa", "negative", "false", "12"),
                                report("CLEAN", P443_8443, "bb", "negative", "true", "15"));
    REQUIRE(d.ok);
    CHECK(diff_exit_code(d) == 1);
    bool port = false, cert = false, geo = false, score = false;
    for (const auto& i : d.items) {
        CHECK(i.cls != "verdict");
        if (i.what == "tcp 8443") { port = true; CHECK(i.from.empty()); CHECK(i.to == "open"); }
        if (i.what == "tls 443 certificate") { cert = true; CHECK(i.from == "aa"); CHECK(i.to == "bb"); }
        if (i.what == "geoip ipinfo.io") { geo = true; CHECK(i.from == "hosting"); CHECK(i.to == "vpn,hosting"); }
        if (i.what == "score") { score = true; CHECK(i.cls == "context"); }
    }
    CHECK(port);
    CHECK(cert);
    CHECK(geo);
    CHECK(score);
}

TEST_CASE("diff: a verdict change ranks first and exits 2") {
    ReportDiff d = diff_reports(report("CLEAN", P443, "aa"), report("NOISY", "", "aa", "positive"));
    REQUIRE(d.ok);
    CHECK(diff_exit_code(d) == 2);
    REQUIRE_FALSE(d.items.empty());
    CHECK(d.items.front().cls == "verdict");
    bool label = false, check = false, gone = false;
    for (const auto& i : d.items) {
        if (i.what == "label") { label = true; CHECK(i.from == "CLEAN"); CHECK(i.to == "NOISY"); }
        if (i.what == "check wg-family :51820") { check = true; CHECK(i.to == "positive"); }
        if (i.what == "tcp 443") { gone = true; CHECK(i.to.empty()); }
    }
    CHECK(label);
    CHECK(check);
    CHECK(gone);
}

TEST_CASE("diff: refuses what is not a scan report") {
    CHECK_FALSE(diff_reports("{}", report("CLEAN", P443, "aa")).ok);
    CHECK_FALSE(diff_reports(report("CLEAN", P443, "aa"), "not json").ok);
    CHECK_FALSE(diff_reports("{ \"check\": \"pcap\" }", "{ \"check\": \"pcap\" }").ok);
    ReportDiff bad = diff_reports("[]", "[]");
    CHECK(diff_exit_code(bad) == 64);
    CHECK_FALSE(bad.error.empty());
    std::string j = diff_json({{"a.json", diff_reports(report("CLEAN", P443, "aa"), report("NOISY", P443, "aa"))}});
    CHECK(j.find("\"check\": \"diff\"") != std::string::npos);
    CHECK(j.find("\"to\": \"NOISY\"") != std::string::npos);
}
