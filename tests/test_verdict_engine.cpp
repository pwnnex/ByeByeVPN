// SPDX-License-Identifier: GPL-3.0-or-later
// verdict engine rules from the false-positive work: three-valued outcomes,
// repeats, coverage, preflight, ack-all. cases mirror docs/GROUNDTRUTH.md.
#include "doctest.h"
#include "../src/app/verdict.h"
#include "../src/app/preflight.h"
#include "../src/common/outcome.h"
#include "../src/common/util.h"
#include "../src/scan/chrome_ch.h"
#include "../src/scan/fingerprint.h"
#include "../src/scan/udp_validate.h"

#include <algorithm>
#include <cstring>
#include <initializer_list>
#include <utility>

namespace {

FullReport web() {
    FullReport r;
    r.completed = true;
    r.open_tcp = {{443, 1, "", ""}};
    r.fps.emplace_back();
    r.fps.back().port = 443;
    r.fps.back().tls = TlsProbe{};
    r.fps.back().tls->ok = true;
    r.fps.back().https = parse_https_response("HTTP/1.1 200 OK\r\n\r\n");
    return r;
}

UdpResult wg_reply(const std::vector<uint8_t>& receiver, bool match) {
    UdpResult u;
    u.responded = true;
    u.bytes = 92;
    u.reply.assign(92, 0x5a);
    u.reply[0] = 2; u.reply[1] = u.reply[2] = u.reply[3] = 0;
    for (int i = 0; i < 4; ++i) u.reply[8 + i] = match ? receiver[i] : uint8_t(receiver[i] ^ 0xff);
    u.expect_receiver = receiver;
    return u;
}

bool has_reason(const FullReport& r, const char* part) {
    for (const auto& x : r.failed_reasons) if (x.find(part) != std::string::npos) return true;
    return false;
}

} // namespace

TEST_CASE("inconclusive never becomes negative") {
    using O = Outcome;
    CHECK(combine_observations({}) == O::Inconclusive);
    CHECK(combine_observations({O::Positive}) == O::Inconclusive);
    CHECK(combine_observations({O::Negative}) == O::Inconclusive);
    CHECK(combine_observations({O::Positive, O::Positive}) == O::Positive);
    CHECK(combine_observations({O::Negative, O::Negative}) == O::Negative);
    CHECK(combine_observations({O::Positive, O::Negative, O::Positive}) == O::Inconclusive);
    CHECK(combine_observations({O::Inconclusive, O::Inconclusive, O::Inconclusive}) == O::Inconclusive);
    CHECK(combine_observations({O::Positive, O::Inconclusive, O::Positive}) == O::Positive);
    CHECK(combine_observations({O::NotApplicable}) == O::NotApplicable);
    CHECK(combine_observations({O::NotApplicable, O::Negative}) == O::Inconclusive);
}

TEST_CASE("repeat series stop once the answer cannot change") {
    using O = Outcome;
    CHECK_FALSE(observations_settled({}));
    CHECK_FALSE(observations_settled({O::Positive}));
    CHECK(observations_settled({O::Positive, O::Positive}));
    CHECK(observations_settled({O::Positive, O::Negative}));
    CHECK_FALSE(observations_settled({O::Inconclusive}));
    CHECK(observations_settled({O::Inconclusive, O::Inconclusive}));
    CHECK(observations_settled({O::Positive, O::Inconclusive, O::Inconclusive}));
}

// stand K: 92 B type-2 garbage unrelated to the probe scored IMMEDIATE BLOCK
TEST_CASE("a wireguard response must be addressed to our sender index") {
    const std::vector<uint8_t> idx = {1, 2, 3, 4};
    CHECK(wg_response_valid(wg_reply(idx, true)));
    CHECK_FALSE(wg_response_valid(wg_reply(idx, false)));
    FullReport r; r.completed = true;
    r.udp_probes = {{51820, "wg", wg_reply(idx, false)}, {51820, "wg", wg_reply(idx, false)}};
    evaluate_report(r);
    CHECK(r.scored.empty());
    REQUIRE(r.checks.size() == 1);
    CHECK(r.checks[0].outcome == Outcome::Negative);
}

TEST_CASE("one wireguard-shaped reply is not a signal") {
    const std::vector<uint8_t> idx = {9, 9, 9, 9};
    FullReport r = web();
    r.udp_probes = {{51820, "wg", wg_reply(idx, true)}};
    evaluate_report(r);
    CHECK(r.scored.empty());
    CHECK(r.checks[0].outcome == Outcome::Inconclusive);
    CHECK(r.checks[0].reason.find("second") != std::string::npos);
}

TEST_CASE("silent udp ports are not applicable, not negative") {
    FullReport r = web();
    UdpResult silent; silent.err = "no-reply / filtered";
    r.udp_probes = {{51820, "wg", silent}, {51820, "amnezia", silent}};
    evaluate_report(r);
    REQUIRE(r.checks.size() == 1);
    CHECK(r.checks[0].outcome == Outcome::NotApplicable);
    CHECK(r.checks_applicable == 0);
    CHECK(r.label == "CLEAN");
}

TEST_CASE("wireguard and amneziawg positives collapse into one signal") {
    const std::vector<uint8_t> idx = {5, 6, 7, 8};
    FullReport r = web();
    auto wg = wg_reply(idx, true);
    UdpResult awg = wg; awg.reply.insert(awg.reply.begin(), 16, 0xee); awg.bytes = (int)awg.reply.size();
    r.udp_probes = {{51820, "wg", wg}, {51820, "wg", wg}, {51820, "amnezia", awg}, {51820, "amnezia", awg},
                    {55555, "amnezia", awg}, {55555, "amnezia", awg}};
    evaluate_report(r);
    CHECK(r.scored.size() == 1);
    CHECK(r.score == 69);
}

TEST_CASE("too many inconclusive checks give no verdict") {
    FullReport r = web();
    FpResult t; t.outcome = Outcome::Inconclusive;
    r.sstp_obs = {t, t};
    evaluate_report(r);
    CHECK_FALSE(r.score_available);
    CHECK(r.label == "INCONCLUSIVE");
    CHECK(has_reason(r, "inconclusive"));
    CHECK(report_exit_code(r) == 4);
    FpResult n; n.outcome = Outcome::Negative;
    r.sstp_obs = {n, n};
    evaluate_report(r);
    CHECK(r.label == "CLEAN");
    CHECK(r.checks_conclusive == 1);
}

TEST_CASE("sstp needs two agreeing setup answers") {
    FullReport r = web();
    FpResult p; p.outcome = Outcome::Positive;
    FpResult n; n.outcome = Outcome::Negative;
    r.sstp_obs = {p, n, p};
    evaluate_report(r);
    CHECK(r.scored.empty());
    r.sstp_obs = {p, p};
    evaluate_report(r);
    REQUIRE(r.scored.size() == 1);
    CHECK(r.scored[0].id == "sstp");
    CHECK(r.label == "SUSPICIOUS");
}

TEST_CASE("threshold boundaries and the empty signal set") {
    FullReport r = web();
    evaluate_report(r);
    CHECK(r.score == 100); CHECK(r.label == "CLEAN"); CHECK(r.tspu_tier == "PASS / ALLOW");
    CHECK(report_exit_code(r) == 0);
    // score is only lowered by registry weights; check the cut points directly
    for (auto [score, code] : std::initializer_list<std::pair<int, int>>{{85, 0}, {84, 1}, {70, 1}, {69, 2}, {50, 2}, {49, 3}}) {
        FullReport x = r; x.score = score;
        CHECK(report_exit_code(x) == code);
    }
}

TEST_CASE("every scored id has a registry entry and a passport") {
    for (const auto& s : signal_registry()) {
        CHECK(signal_passport(s.id).find("docs/SIGNALS.md#") == 0);
        if (s.tier == 'R') CHECK(s.weight == 0);
        else CHECK(s.weight > 0);
    }
    CHECK(signal_spec("geo-vpn") == nullptr);
    CHECK(signal_spec("wireguard") == nullptr);
    CHECK(signal_spec("wg-family") != nullptr);
}

TEST_CASE("preflight blocks on a tunnel route, an ack-all stack, rewriters and fake ips") {
    PreflightFacts f;
    f.target_ip = "203.0.113.5";
    f.ack_all_checked = true;
    CHECK_FALSE(preflight_decide(f, false).blocked);
    auto tunnel = f; tunnel.target_iface = "sing-tun"; tunnel.target_iface_is_tunnel = true;
    CHECK(preflight_decide(tunnel, false).blocked);
    auto ack = f; ack.local_ack_all = true;
    CHECK(preflight_decide(ack, false).blocked);
    auto rw = f; rw.rewriters = {"zapret (winws)"};
    CHECK(preflight_decide(rw, false).blocked);
    auto fake = f; fake.fake_ip_target = true;
    CHECK(preflight_decide(fake, false).blocked);
    auto ip = f; ip.expect_ip = "198.51.100.7"; ip.external_ips = {"198.51.100.9", "198.51.100.9", ""};
    CHECK(preflight_decide(ip, false).blocked);
    ip.external_ips = {"198.51.100.7", "198.51.100.7", ""};
    CHECK_FALSE(preflight_decide(ip, false).blocked);
    // tunnel up but not on the target route: warn only
    auto side = f; side.tunnels_up = {"sing-tun"};
    auto d = preflight_decide(side, false);
    CHECK_FALSE(d.blocked); CHECK_FALSE(d.warnings.empty());
    auto o = preflight_decide(tunnel, true);
    CHECK(o.blocked); CHECK(o.overridden);
}

TEST_CASE("failed preflight makes the whole report unreliable unless overridden") {
    FullReport r = web();
    PreflightFacts f; f.target_ip = "203.0.113.5"; f.local_ack_all = true; f.ack_all_checked = true;
    r.preflight = preflight_decide(f, false);
    r.preflight_ran = true;
    evaluate_report(r);
    CHECK(r.label == "UNRELIABLE"); CHECK_FALSE(r.score_available); CHECK(report_exit_code(r) == 5);
    r.preflight = preflight_decide(f, true);
    evaluate_report(r);
    CHECK(r.label == "CLEAN"); CHECK(r.overridden); CHECK(report_exit_code(r) == 0);
}

TEST_CASE("an ack-all path voids the verdict") {
    FullReport r = web();
    r.ack_all_control_tried = 3; r.ack_all_control_open = 2;
    evaluate_report(r);
    CHECK(r.label == "INCONCLUSIVE");
    CHECK(has_reason(r, "control ports"));
    r.ack_all_control_open = 0; r.ack_all_heuristic = true;
    evaluate_report(r);
    CHECK(r.label == "CLEAN");
    r.ack_all_control_open = 1;
    evaluate_report(r);
    CHECK(r.label == "INCONCLUSIVE");
}

TEST_CASE("path loss makes silence inconclusive and blocks the verdict at half") {
    auto q = assess_channel(443, 10, {1, 1, 1, 1, 1, 1, 1, 1, 1});
    CHECK_FALSE(q.degraded);
    q = assess_channel(443, 10, {1, 1, 1, 1, 1, 1, 1, 1});
    CHECK(q.degraded); CHECK_FALSE(q.unusable);
    q = assess_channel(443, 10, {1, 1, 1, 1, 1});
    CHECK(q.unusable);
    CHECK_FALSE(assess_channel(443, 0, {}).measured);
    FullReport r = web();
    r.channel = q;
    evaluate_report(r);
    CHECK(r.label == "INCONCLUSIVE");
}

TEST_CASE("socks5 reply rules follow rfc 1928") {
    const unsigned char noauth[] = {5, 0}, userpass[] = {5, 2}, none[] = {5, 0xff}, http[] = {'H', 'T'};
    CHECK(socks5_reply_outcome(noauth, 2, ReadEnd::Data) == Outcome::Positive);
    CHECK(socks5_reply_outcome(userpass, 2, ReadEnd::Data) == Outcome::Positive);
    CHECK(socks5_reply_outcome(none, 2, ReadEnd::Data) == Outcome::Positive);
    CHECK(socks5_reply_outcome(http, 2, ReadEnd::Data) == Outcome::Negative);
    CHECK(socks5_reply_outcome(noauth, 0, ReadEnd::Held) == Outcome::Inconclusive);
    CHECK(socks5_reply_outcome(noauth, 0, ReadEnd::Fin) == Outcome::Inconclusive);
}

TEST_CASE("sstp setup request carries a fresh correlation id, not zeros") {
    unsigned char g[16];
    for (int i = 0; i < 16; ++i) g[i] = (unsigned char)(0xa0 + i);
    const auto req = sstp_setup_request("vpn.example.com", g);
    CHECK(req.find("{A0A1A2A3-A4A5-A6A7-A8A9-AAABACADAEAF}") != std::string::npos);
    CHECK(req.find("00000000-0000") == std::string::npos);
    CHECK(req.find("Host: vpn.example.com\r\n") != std::string::npos);
    CHECK(sstp_response(parse_https_response("HTTP/1.1 405 Not Allowed\r\n\r\n")).outcome == Outcome::Negative);
    CHECK(sstp_response(parse_https_response("HTTP/1.1 200\r\nContent-Length: 18446744073709551615\r\n\r\n")).outcome == Outcome::Positive);
    CHECK(sstp_response(HttpsProbe{}).outcome == Outcome::Inconclusive);
}

TEST_CASE("ip literals never go into an sni") {
    CHECK(is_ip_literal("127.0.1.1"));
    CHECK(is_ip_literal("2001:db8::1"));
    CHECK_FALSE(is_ip_literal("example.com"));
    CHECK_FALSE(is_ip_literal("1.2.3"));
    CHECK_FALSE(is_ip_literal("1.2.3.4.example"));
    CHECK_FALSE(is_ip_literal(""));
    const auto with = build_chromelike_clienthello("example.com");
    const auto ip = build_chromelike_clienthello("203.0.113.5");
    const std::string needle = "203.0.113.5", name = "example.com";
    CHECK(std::search(ip.begin(), ip.end(), needle.begin(), needle.end()) == ip.end());
    CHECK(std::search(with.begin(), with.end(), name.begin(), name.end()) != with.end());
}
