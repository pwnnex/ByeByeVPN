// SPDX-License-Identifier: GPL-3.0-or-later
#include "doctest.h"
#include "../src/scan/transport_probe.h"
#include "../src/scan/fingerprint.h"
#include "../src/scan/sni.h"
#include "../src/scan/grpc.h"
#include "../src/scan/udp_validate.h"
#include "../src/app/verdict.h"
#include "../src/common/tspu.h"

namespace {
const std::string key = "dGhlIHNhbXBsZSBub25jZQ==";
const std::string expected_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
const std::string upgrade = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: " + expected_accept + "\r\n";
std::vector<uint8_t> frame(uint8_t type, uint8_t flags, uint32_t stream, std::vector<uint8_t> payload = {}) {
    const auto len = payload.size();
    std::vector<uint8_t> out{uint8_t(len >> 16), uint8_t(len >> 8), uint8_t(len), type, flags,
        uint8_t(stream >> 24), uint8_t(stream >> 16), uint8_t(stream >> 8), uint8_t(stream)};
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}
std::vector<uint8_t> after_settings(const std::vector<uint8_t>& tail) {
    auto out = frame(4, 0, 0);
    out.insert(out.end(), tail.begin(), tail.end());
    return out;
}
FullReport web_report() {
    FullReport r;
    r.completed = true;
    r.open_tcp = {{443, 1, "", ""}};
    r.fps.emplace_back();
    auto& p = r.fps.back();
    p.port = 443;
    p.tls = TlsProbe{};
    p.tls->ok = true;
    p.tls->version = "TLSv1.3";
    p.https = parse_https_response("HTTP/1.1 200 OK\r\n\r\n");
    return r;
}
}

TEST_CASE("websocket requires the matching accept challenge and upgrade headers") {
    CHECK(websocket_accept(key) == expected_accept);
    CHECK(websocket_upgrade_valid(parse_https_response(upgrade + "\r\n"), key));
    CHECK_FALSE(websocket_upgrade_valid(parse_https_response(upgrade + "\r\n"), "different nonce"));
    for (const auto& text : {"HTTP/1.1 101 Switching Protocols\r\n\r\n", "HTTP/1.1 101garbage\r\n\r\n",
                           "HTTP/1.1 200 OK\r\n\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="})
        CHECK_FALSE(websocket_upgrade_valid(parse_https_response(text), key));
    for (const auto& header : {"Sec-WebSocket-Extensions: permessage-deflate", "Sec-WebSocket-Protocol: chat",
                              "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="})
        CHECK_FALSE(websocket_upgrade_valid(parse_https_response(upgrade + header + "\r\n\r\n"), key));
    CHECK_FALSE(websocket_upgrade_valid(parse_https_response("HTTP/1.1 101 OK\r\nSec-WebSocket-Accept:\r\n" + upgrade.substr(upgrade.find("Upgrade:")) + "\r\n"), key));
    CHECK_FALSE(websocket_upgrade_valid(parse_https_response("HTTP/1.1 101 OK\r\nUpgrade: notwebsocket\r\nConnection: upgradex\r\nSec-WebSocket-Accept: " + expected_accept + "\r\n\r\n"), key));
}

TEST_CASE("HTTP setup fingerprints use complete final headers") {
    auto connect = http_fingerprint_response(parse_https_response("HTTP/1.1 200 OK\r\n\r\n"), true);
    CHECK(connect.connect_accepted);
    CHECK_FALSE(connect.is_vpn_like);
    CHECK(connect.service == "HTTP");
    for (const auto& text : {"HTTP/1.1 200garbage\r\n\r\n", "HTTP/2.0 200 OK\r\n\r\n", "HTTP/1.1 200 OK\r\nX: partial", "HTTP/1.1 407 Auth\r\n\r\n"})
        CHECK_FALSE(http_fingerprint_response(parse_https_response(text), true).connect_accepted);
    CHECK(http_fingerprint_response(parse_https_response("SSH-2.0-test\r\n\r\n")).service == "HTTP?");
    CHECK(sstp_response(parse_https_response("HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n")).is_vpn_like);
    for (const auto& text : {"HTTP/1.1 500 SSTP unsupported\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nSSTP 18446744073709551615",
        "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615x\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\nTransfer-Encoding: chunked\r\n\r\n"})
        CHECK_FALSE(sstp_response(parse_https_response(text)).is_vpn_like);
}

TEST_CASE("redirect recognition uses a redirect status and bounded hostname") {
    for (const auto& location : {"https://rkn.gov.ru.evil.example/", "https://evil.example/?next=https://rkn.gov.ru/",
        "https://warning.rt.ru@evil.example/", "https://evil.example/rkn.gov.ru", "/rkn.gov.ru",
        "https://evilwarning.rt.ru/", "https://warning.rt.ru:bogus/", "https://warning.rt.ru:99999/",
        "https://warning.rt.ru\\@evil.example/", "https://185.76.180.75.evil.example/"})
        CHECK(looks_like_tspu_redirect(location) == nullptr);
    CHECK(looks_like_tspu_redirect("//warning.rt.ru:443/page") != nullptr);
    CHECK(looks_like_tspu_redirect("https://WARNING.RT.RU./page") != nullptr);
    CHECK_FALSE(http_fingerprint_response(parse_https_response("HTTP/1.1 200 OK\r\nLocation: https://warning.rt.ru/\r\n\r\n")).tspu_redirect);
    CHECK(http_fingerprint_response(parse_https_response("HTTP/1.1 302 Found\r\nLocation: https://warning.rt.ru/\r\n\r\n")).tspu_redirect);
}

TEST_CASE("SNI routing never establishes Reality or certificate impersonation") {
    TlsProbe base;
    base.ok = true; base.cert_sha256 = "base"; base.subject_cn = "www.google.com";
    std::vector<SniConsistency::Entry> entries{{"one.example", true, "base", "", ""},
        {"two.example", true, "base", "", ""}, {"three.example", true, "base", "", ""}};
    auto r = analyze_sni("my.example", base, entries);
    CHECK(r.same_cert_always);
    CHECK(r.brand_claimed == "google.com");
    CHECK_FALSE(r.reality_like);
    CHECK_FALSE(r.cert_impersonation);
    entries[1].sha = "other";
    r = analyze_sni("my.example", base, entries);
    CHECK(r.pattern == "mixed-certificates");
    CHECK_FALSE(r.passthrough_mode);
    entries[0].sha.clear(); entries[1].ok = false;
    r = analyze_sni("my.example", base, entries);
    CHECK(r.pattern == "insufficient-data"); CHECK(r.failed == 2);
    entries = {{"my.example", true, "base", "", ""}, {"ONE.example", true, "base", "", ""}, {"one.example", true, "base", "", ""}};
    CHECK(analyze_sni("my.example", base, entries).compared == 1);
    base.ok = false;
    CHECK_FALSE(analyze_sni("my.example", base, entries).base_ok);
}

TEST_CASE("HPACK literal lengths survive the 127 byte boundary") {
    for (size_t size : {size_t(126), size_t(127), size_t(128), size_t(255), size_t(300)}) {
        const auto h = grpc_request_headers(std::string(size, 'a'), "/test");
        REQUIRE(h.size() > size);
        size_t pos = 3;
        size_t length = h[pos++] & 127;
        if (length == 127) {
            unsigned shift = 0;
            while (true) { const auto b = h[pos++]; length += size_t(b & 127) << shift; if (!(b & 128)) break; shift += 7; }
        }
        CHECK(length == size);
        CHECK(std::string(h.begin() + pos, h.begin() + pos + length) == std::string(size, 'a'));
        CHECK(h[pos + length] == 0x44);
    }
    CHECK(http_authority("::1", 8443) == "[::1]:8443");
    CHECK(http_authority("example.com", 443) == "example.com");
    CHECK(http_authority("bad\r\nhost", 443).empty());
}

TEST_CASE("HTTP2 requires complete frames and valid stream and continuation structure") {
    GrpcProbe r;
    analyze_h2_response(after_settings(frame(3, 0, 1, {0,0,0,7})), r);
    CHECK(r.h2_frames); CHECK(r.stream_reset); CHECK(r.err.empty());
    auto cut = after_settings(frame(3, 0, 1, {0,0,0,7})); cut.pop_back();
    analyze_h2_response(cut, r); CHECK_FALSE(r.stream_reset); CHECK_FALSE(r.err.empty());
    for (const auto& malformed : {frame(3, 0, 0, {0,0,0,7}), frame(3, 0, 1), frame(7, 0, 0), frame(6, 0, 1, std::vector<uint8_t>(8)), frame(9, 4, 1)}) {
        analyze_h2_response(after_settings(malformed), r);
        CHECK_FALSE(r.err.empty()); CHECK_FALSE(r.stream_reset); CHECK_FALSE(r.goaway);
    }
    auto headers = after_settings(frame(1, 0, 1, {0x88}));
    analyze_h2_response(headers, r); CHECK_FALSE(r.headers_resp); CHECK_FALSE(r.err.empty());
    auto continuation = frame(9, 4, 1);
    headers.insert(headers.end(), continuation.begin(), continuation.end());
    analyze_h2_response(headers, r); CHECK(r.headers_resp); CHECK(r.err.empty());
    analyze_h2_response(after_settings(frame(0, 0, 1, {'g','r','p','c'})), r);
    CHECK_FALSE(r.grpc_marker);
    analyze_h2_response(frame(3, 0, 1, {0,0,0,7}), r); CHECK_FALSE(r.h2_frames);
    analyze_h2_response(frame(4, 1, 0), r); CHECK_FALSE(r.h2_frames);
}

TEST_CASE("ordinary web features and preset ports do not lower VPN score") {
    auto r = web_report();
    for (int port : {2053,2083,8443,10808,3389,25000}) r.open_tcp.push_back({port, 1, "", ""});
    GeoInfo g; g.source = "provider"; g.is_hosting = true; g.asn_org = "unrelated hosting"; r.geos.push_back(g);
    auto& p = r.fps[0];
    p.sni = SniConsistency{}; p.sni->reality_like = p.sni->cert_impersonation = true; p.sni->brand_claimed = "google.com";
    p.websocket = WsProbe{}; p.websocket->ws_upgrade = true; p.websocket->path_hit = "/vmess";
    p.grpc = GrpcProbe{}; p.grpc->alpn_h2 = p.grpc->stream_reset = true;
    p.tls->certificate_present = p.tls->certificate_times_valid = p.tls->self_signed = true;
    p.tls->total_validity_seconds = 160 * 3600;
    p.ct = parse_ct_response("[]");
    p.fp.tspu_redirect = true; p.fp.redirect_marker = "warning.rt.ru";
    evaluate_report(r);
    CHECK(r.score == 100); CHECK(r.score_available);
    CHECK(r.tspu_a_hits == 0); CHECK(r.tspu_b_hits == 0);
    CHECK(r.signals_major.empty()); CHECK(report_exit_code(r) == 0);
    const auto count = r.notes.size(); evaluate_report(r); CHECK(r.notes.size() == count);
}

TEST_CASE("failed or incomplete scans do not yield CLEAN or operator-block claims") {
    FullReport r; r.completed = true; r.scan_stats.scanned = r.scan_stats.timeouts = 1000;
    r.bgp_blackhole_likely = true;
    evaluate_report(r);
    CHECK(r.tcp_timeout_pattern); CHECK_FALSE(r.bgp_blackhole_likely);
    CHECK_FALSE(r.score_available); CHECK(r.label == "INCONCLUSIVE");
    CHECK(report_exit_code(r) == 4); CHECK(r.tspu_tier == "UNKNOWN"); CHECK(r.tspu_a_hits == 0);
    r = web_report(); r.scan_stats.skipped = true; evaluate_report(r);
    CHECK_FALSE(r.score_available); CHECK(report_exit_code(r) == 4);
    r.completed = false; evaluate_report(r); CHECK(report_exit_code(r) == 64);
}

// ipapi.is and friends tag every hosting address; geo lost 18 points on clean nodes
TEST_CASE("geoip tags never reach the score") {
    auto r = web_report();
    GeoInfo g; g.source = "provider"; g.is_vpn = g.is_proxy = g.is_tor = true;
    r.geos = {g};
    g.source = "other"; r.geos.push_back(g);
    g.source = "third"; r.geos.push_back(g);
    evaluate_report(r);
    CHECK(r.score == 100); CHECK(r.tspu_b_hits == 0); CHECK(r.label == "CLEAN");
    bool noted = false;
    for (const auto& [tag, text] : r.notes) noted |= tag == "geoip-tags" && text.find("not scored") != std::string::npos;
    CHECK(noted);
}

TEST_CASE("validated protocol shapes retain their signal without duplicate penalties") {
    FullReport r; r.completed = true;
    UdpResult u; u.responded = true; u.bytes = 92; u.reply.assign(92, 0); u.reply[0] = 2;
    r.udp_probes = {{51820, "wg", u}, {51820, "wg", u}, {55555, "wg", u}, {55555, "wg", u}};
    evaluate_report(r);
    CHECK(r.score_available); CHECK(r.score == 69); CHECK(r.tspu_a_hits == 1);
    CHECK(r.port_observations.size() == 2);
    CHECK(r.scored.size() == 1);
    u.reply.resize(4); CHECK_FALSE(wg_response_valid(u));
    u.reply.assign(64, 0); u.reply[0] = 3; u.bytes = 64; CHECK(wg_response_valid(u));
    u.reply.resize(4); CHECK_FALSE(wg_response_valid(u));
}


// one wg layout gave 85 CLEAN next to IMMEDIATE BLOCK
TEST_CASE("a tier-A hit never yields CLEAN or NOISY") {
    UdpResult wg; wg.responded = true; wg.bytes = 92; wg.reply.assign(92, 0); wg.reply[0] = 2;
    UdpResult awg; awg.responded = true; awg.bytes = 100; awg.reply.assign(100, 0xee);
    awg.reply[8] = 2; awg.reply[9] = awg.reply[10] = awg.reply[11] = 0;
    for (const auto& rec : {UdpProbeRec{51820, "wg", wg}, UdpProbeRec{51820, "amnezia", awg}}) {
        FullReport r; r.completed = true;
        r.udp_probes = {rec, rec};
        evaluate_report(r);
        REQUIRE(r.score_available);
        CHECK(r.tspu_tier == "IMMEDIATE BLOCK");
        CHECK(r.score <= 69);
        CHECK(r.label != "CLEAN"); CHECK(r.label != "NOISY");
        CHECK(report_exit_code(r) >= 2);
    }
    auto r = web_report();
    FpResult s; s.service = "SOCKS5"; s.is_vpn_like = true; s.outcome = Outcome::Positive;
    r.fps[0].socks5_obs = {s, s};
    evaluate_report(r);
    CHECK(r.tspu_a_hits == 1); CHECK(r.label == "SUSPICIOUS"); CHECK(report_exit_code(r) == 2);
}

TEST_CASE("QUIC structure alone cannot establish a clean service observation") {
    for (const auto& bytes : {std::vector<uint8_t>{0xc0,0,0,0,1,0,0},
                             std::vector<uint8_t>{0x80,0,0,0,0,0,0,0,0,0,1}}) {
        FullReport r;
        r.completed = true;
        UdpResult u;
        u.responded = true;
        u.reply = bytes;
        u.bytes = (int)bytes.size();
        r.udp_probes.push_back({443,"hysteria2",u});
        evaluate_report(r);
        CHECK_FALSE(r.score_available);
        CHECK(r.label == "INCONCLUSIVE");
        CHECK(report_exit_code(r) == 4);
    }
}
