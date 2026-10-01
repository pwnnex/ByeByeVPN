// SPDX-License-Identifier: GPL-3.0-or-later
// unit tests for src/app/config_audit.cpp (the pre-deploy config advisor).
#include "doctest.h"
#include "../src/app/config_audit.h"

#include <string>

static bool has_tag(const ConfigAudit& a, const std::string& tag) {
    for (auto& f : a.findings) if (f.tag == tag) return true;
    return false;
}

TEST_CASE("xray VLESS+Reality with brand dest is flagged and blocks") {
    const char* cfg = R"({
      "inbounds": [{
        "protocol": "vless",
        "port": 443,
        "settings": { "decryption": "none", "clients": [{ "id": "x", "flow": "" }] },
        "streamSettings": {
          "network": "tcp",
          "security": "reality",
          "realitySettings": {
            "show": true,
            "dest": "www.microsoft.com:443",
            "serverNames": ["www.microsoft.com"],
            "shortIds": [""]
          }
        }
      }]
    })";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(a.format == "xray");
    CHECK(a.inbound_count == 1);
    CHECK(has_tag(a, "reality-dest-brand"));   // famous-brand dest
    CHECK(has_tag(a, "reality-shortid-empty")); // only "" shortid
    CHECK(has_tag(a, "reality-show"));          // debug logging on
    CHECK(has_tag(a, "no-vision-flow"));        // flow not vision
    CHECK_FALSE(has_tag(a, "no-fallback")); // reality handles unauthenticated fallback itself
    // a High soft signal (brand dest) -> accumulative block, no named A-tier
    CHECK(a.a_hits == 0);
    CHECK(a.tspu_tier == "BLOCK (accumulative)");
}

static std::string category_of(const ConfigAudit& a, const std::string& tag) {
    for (auto& f : a.findings) if (f.tag == tag) return f.category;
    return {};
}

TEST_CASE("one port twice on one layer cannot bind; tcp and udp can share it") {
    const char* both_tcp = R"({"inbounds":[
      {"protocol":"trojan","port":443,"settings":{"clients":[{"password":"a"}]},
       "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{}}},
      {"protocol":"vmess","port":443,"settings":{"clients":[{"id":"x"}]}}]})";
    ConfigAudit a = audit_config_text(both_tcp);
    REQUIRE(a.ok);
    CHECK(has_tag(a, "duplicate-listener"));
    CHECK(a.tspu_tier == "UNKNOWN");
    const char* tcp_udp = R"({"inbounds":[
      {"protocol":"vmess","port":443,"settings":{"clients":[{"id":"x"}]}},
      {"protocol":"hysteria","port":443,"settings":{"version":2},"streamSettings":{"network":"hysteria","security":"tls"}}]})";
    CHECK_FALSE(has_tag(audit_config_text(tcp_udp), "duplicate-listener"));
    const char* two_addrs = R"({"inbounds":[
      {"protocol":"vmess","port":8080,"listen":"127.0.0.1","settings":{"clients":[{"id":"x"}]}},
      {"protocol":"vmess","port":8080,"listen":"10.0.0.2","settings":{"clients":[{"id":"y"}]}}]})";
    CHECK_FALSE(has_tag(audit_config_text(two_addrs), "duplicate-listener"));
    const char* wildcard = R"({"inbounds":[
      {"protocol":"vmess","port":8080,"listen":"127.0.0.1","settings":{"clients":[{"id":"x"}]}},
      {"protocol":"vmess","port":8080,"settings":{"clients":[{"id":"y"}]}}]})";
    CHECK(has_tag(audit_config_text(wildcard), "duplicate-listener"));
}

TEST_CASE("sing-box reality with tls off is plaintext, not reality") {
    // before: the brand rule fired on a handshake server sing-box never uses
    const char* cfg = R"({"inbounds":[{"type":"vless","listen_port":443,"users":[{"uuid":"x"}],
      "tls":{"enabled":false,"reality":{"enabled":true,"handshake":{"server":"www.microsoft.com","server_port":443},
      "short_id":["ab"]}}}]})";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(has_tag(a, "plaintext-proto"));
    CHECK(has_tag(a, "settings-ignored"));
    CHECK_FALSE(has_tag(a, "reality-dest-brand"));
}

TEST_CASE("hygiene findings print apart and never move the tier") {
    const char* cfg = R"({"log":{"loglevel":"debug"},"inbounds":[{"protocol":"vless","port":443,
      "settings":{"decryption":"none","clients":[{"id":"x","flow":"xtls-rprx-vision"},{"id":"x","flow":"xtls-rprx-vision"}],
                  "fallbacks":[{"dest":80}]},
      "streamSettings":{"network":"tcp","security":"reality","wsSettings":{"path":"/a"},
        "realitySettings":{"show":true,"target":"example.com:443","serverNames":["example.com"],"shortIds":["ab"]}}}]})";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    for (const char* t : {"debug-log", "duplicate-user", "settings-ignored", "reality-show"})
        CHECK(category_of(a, t) == "hygiene");
    CHECK(a.b_hits == 0);
    CHECK(a.tspu_tier == "PASS / ALLOW");
}

TEST_CASE("control apis on public addresses are exposure, on loopback nothing") {
    const char* pub = R"({"api":{"tag":"api"},"inbounds":[{"protocol":"dokodemo-door","port":10085,"tag":"api",
      "settings":{"address":"127.0.0.1"}}]})";
    CHECK(has_tag(audit_config_text(pub), "api-public"));
    const char* loc = R"({"api":{"tag":"api"},"inbounds":[{"protocol":"dokodemo-door","port":10085,"tag":"api",
      "listen":"127.0.0.1","settings":{"address":"127.0.0.1"}}]})";
    CHECK_FALSE(has_tag(audit_config_text(loc), "api-public"));
    const char* clash = R"({"experimental":{"clash_api":{"external_controller":":9090"}},
      "inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":2080}]})";
    CHECK(has_tag(audit_config_text(clash), "api-public"));
    const char* clash_loc = R"({"experimental":{"clash_api":{"external_controller":"127.0.0.1:9090"}},
      "inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":2080}]})";
    CHECK_FALSE(has_tag(audit_config_text(clash_loc), "api-public"));
}

TEST_CASE("clean Reality config passes") {
    const char* cfg = R"({
      "inbounds": [{
        "protocol": "vless",
        "port": 443,
        "settings": {
          "decryption": "none",
          "clients": [{ "id": "x", "flow": "xtls-rprx-vision" }],
          "fallbacks": [{ "dest": 8080 }]
        },
        "streamSettings": {
          "network": "tcp",
          "security": "reality",
          "realitySettings": {
            "show": false,
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "shortIds": ["0123abcd"]
          }
        }
      }]
    })";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(a.findings.empty());
    CHECK(a.tspu_tier == "PASS / ALLOW");
}

TEST_CASE("shadowsocks default port alone has no detection score") {
    const char* cfg = R"({"inbounds":[{"protocol":"shadowsocks","port":8388,
        "settings":{"method":"aes-256-gcm"}}]})";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(has_tag(a, "shadowsocks-default-port"));
    CHECK(a.a_hits == 0);
    CHECK(a.tspu_tier == "PASS / ALLOW");
}

TEST_CASE("plaintext vless warns about encryption without claiming a network observation") {
    const char* cfg = R"({"inbounds":[{"protocol":"vless","port":80,"settings":{"decryption":"none"},
        "streamSettings":{"network":"tcp","security":"none"}}]})";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(has_tag(a, "plaintext-proto"));
    CHECK(a.tspu_tier == "BLOCK (accumulative)");
}

TEST_CASE("sing-box hysteria2 inbound is a soft anomaly, not a named signature") {
    // a config label must not become a confirmed network signature
    const char* cfg = R"({
      "inbounds": [{ "type": "hysteria2", "listen_port": 36712 }]
    })";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(a.format == "sing-box");
    CHECK(has_tag(a, "hysteria2"));
    CHECK(a.a_hits == 0);
    CHECK(a.b_hits >= 1);
    CHECK(a.tspu_tier != "IMMEDIATE BLOCK");
}

TEST_CASE("sing-box reality with brand handshake server is flagged") {
    const char* cfg = R"({
      "inbounds": [{
        "type": "vless",
        "listen_port": 443,
        "users": [{ "uuid": "x", "flow": "xtls-rprx-vision" }],
        "tls": {
          "enabled": true,
          "server_name": "www.apple.com",
          "reality": {
            "enabled": true,
            "handshake": { "server": "www.apple.com", "server_port": 443 },
            "short_id": ["00aabb"]
          }
        }
      }]
    })";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(a.format == "sing-box");
    CHECK(has_tag(a, "reality-dest-brand"));
    CHECK(a.tspu_tier == "BLOCK (accumulative)");
}

TEST_CASE("panel-port cluster across inbounds is flagged") {
    const char* cfg = R"({"inbounds":[
        {"protocol":"vless","port":2083,"streamSettings":{"security":"reality",
         "realitySettings":{"dest":"example.com:443","serverNames":["example.com"],
         "shortIds":["aa"]}}},
        {"protocol":"trojan","port":8443,"streamSettings":{"security":"tls"}}
    ]})";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(has_tag(a, "panel-cluster"));
}

TEST_CASE("malformed config returns ok=false") {
    ConfigAudit a = audit_config_text(R"({"inbounds":)");
    CHECK_FALSE(a.ok);
    CHECK_FALSE(a.err.empty());
}

TEST_CASE("non-config json reports no inbounds") {
    ConfigAudit a = audit_config_text(R"({"hello":"world"})");
    CHECK_FALSE(a.ok);
}

TEST_CASE("deprecated XTLS flow is flagged High") {
    const char* cfg = R"({"inbounds":[{"protocol":"vless","port":443,
        "settings":{"decryption":"none","clients":[{"id":"x","flow":"xtls-rprx-direct"}]},
        "streamSettings":{"network":"tcp","security":"reality",
          "realitySettings":{"dest":"example.com:443","serverNames":["example.com"],
          "shortIds":["aa11"]}}}]})";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(has_tag(a, "deprecated-flow"));
    CHECK_FALSE(has_tag(a, "no-vision-flow"));   // deprecated takes precedence
    CHECK(a.compatibility_errors > 0);
    CHECK(a.tspu_tier == "UNKNOWN");
}

TEST_CASE("TLS 1.2 minimum still allows Vision to negotiate 1.3") {
    const char* cfg = R"({"inbounds":[{"protocol":"vless","port":443,
        "settings":{"decryption":"none","clients":[{"id":"x","flow":"xtls-rprx-vision"}]},
        "streamSettings":{"network":"tcp","security":"tls",
          "tlsSettings":{"minVersion":"1.2"}}}]})";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK_FALSE(has_tag(a, "tls-min-version"));
}

TEST_CASE("multi-port Reality across inbounds is flagged") {
    const char* cfg = R"({"inbounds":[
      {"protocol":"vless","port":443,
       "settings":{"decryption":"none","clients":[{"id":"x","flow":"xtls-rprx-vision"}],"fallbacks":[{"dest":8080}]},
       "streamSettings":{"network":"tcp","security":"reality",
         "realitySettings":{"dest":"a.example.com:443","serverNames":["a.example.com"],"shortIds":["aa11"]}}},
      {"protocol":"vless","port":8444,
       "settings":{"decryption":"none","clients":[{"id":"y","flow":"xtls-rprx-vision"}],"fallbacks":[{"dest":8081}]},
       "streamSettings":{"network":"tcp","security":"reality",
         "realitySettings":{"dest":"b.example.com:443","serverNames":["b.example.com"],"shortIds":["bb22"]}}}
    ]})";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(has_tag(a, "reality-multiport"));
}

TEST_CASE("WireGuard .conf on default port is a named immediate-block") {
    const char* cfg =
        "[Interface]\n"
        "PrivateKey = aaaa\n"
        "Address = 10.0.0.1/24\n"
        "ListenPort = 51820\n"
        "[Peer]\n"
        "PublicKey = bbbb\n";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(a.format == "wireguard");
    CHECK(has_tag(a, "wireguard-default-port"));
    CHECK(a.tspu_tier == "IMMEDIATE BLOCK");
}

TEST_CASE("AmneziaWG .conf is recognised by its obfuscation params") {
    const char* cfg =
        "[Interface]\n"
        "PrivateKey = aaaa\n"
        "ListenPort = 51820\n"
        "Jc = 4\n"
        "Jmin = 40\n"
        "Jmax = 70\n"
        "S1 = 86\n"
        "S2 = 574\n"
        "H1 = 1\n"
        "[Peer]\n"
        "PublicKey = bbbb\n";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(a.format == "wireguard");
    CHECK(has_tag(a, "amneziawg-detected"));
    CHECK(has_tag(a, "amneziawg-default-port"));
    CHECK_FALSE(has_tag(a, "wireguard-default-port"));   // obfuscation present
}

TEST_CASE("config_audit_to_json emits a well-formed object") {
    const char* cfg = R"({"inbounds":[{"protocol":"shadowsocks","port":8388,
        "settings":{"method":"aes-256-gcm"}}]})";
    ConfigAudit a = audit_config_text(cfg);
    std::string j = config_audit_to_json(a);
    CHECK(j.find("\"ok\": true") != std::string::npos);
    CHECK(j.find("\"tspu_tier\": \"PASS / ALLOW\"") != std::string::npos);
    CHECK(j.find("\"tag\": \"shadowsocks-default-port\"") != std::string::npos);
    CHECK(j.find("\"named\": true") == std::string::npos);
}

TEST_CASE("config_audit_to_json reports parse errors") {
    ConfigAudit a = audit_config_text("not a config");
    std::string j = config_audit_to_json(a);
    CHECK(j.find("\"ok\": false") != std::string::npos);
    CHECK(j.find("\"error\"") != std::string::npos);
}

TEST_CASE("audit rejects unrecognized inbounds and invalid ports") {
    for (const auto& s : {
        R"({"inbounds":[{}]})",
        R"({"inbounds":[42]})",
        R"({"inbounds":[{"type":"unknown"}]})",
        R"({"inbounds":[{"protocol":"vless","port":1e50}]})",
        R"({"inbounds":[{"protocol":"vless","port":443.5}]})",
        R"({"inbounds":[{"protocol":"vless","port":"99999999999999999"}]})"
    }) {
        auto a = audit_config_text(s);
        CHECK_FALSE(a.ok);
        CHECK(a.tspu_tier == "UNKNOWN");
    }
}

static ConfigAudit xray_case(const std::string& settings, const std::string& stream,
                            const std::string& protocol = "vless", const std::string& listen = "0.0.0.0") {
    return audit_config_text("{\"protocol\":\"" + protocol + "\",\"port\":443,\"listen\":\"" + listen +
        "\",\"settings\":" + settings + ",\"streamSettings\":" + stream + "}");
}

TEST_CASE("current Xray aliases and inherited Vision flow match source precedence") {
    auto a = xray_case(R"({"decryption":"none","flow":"xtls-rprx-vision","users":[{"id":"a"},{"id":"b","flow":""}]})",
                      R"({"method":"raw","network":"quic","security":"tls"})");
    REQUIRE(a.ok);
    REQUIRE(a.protocols.size() == 1);
    CHECK(a.compatibility_errors == 0);
    CHECK(a.protocols[0].flow == "vision");
    CHECK(a.protocols[0].vision_users == 2);
    CHECK(a.protocols[0].transport == "raw");
    CHECK_FALSE(has_tag(a, "removed-transport"));
    CHECK_FALSE(has_tag(a, "no-vision-flow"));

    auto empty = xray_case(R"({"decryption":"none","clients":[],"users":[{"flow":"xtls-rprx-vision"}]})",
                          R"({"network":"tcp","security":"tls"})");
    CHECK(empty.protocols[0].flow == "no_users");
    auto null = xray_case(R"({"decryption":"none","clients":null,"users":[{"flow":"xtls-rprx-vision"}]})",
                         R"({"method":null,"network":"tcp","security":"tls"})");
    CHECK(null.protocols[0].vision_users == 1);
}

TEST_CASE("mixed VLESS accounts do not hide users without Vision") {
    auto a = xray_case(R"({"decryption":"none","clients":[{"flow":"xtls-rprx-vision"},{"flow":""},{}]})",
                      R"({"network":"tcp","security":"tls"})");
    REQUIRE(a.ok);
    CHECK(a.protocols[0].flow == "mixed");
    CHECK(a.protocols[0].vision_users == 1);
    CHECK(a.protocols[0].plain_users == 2);
    CHECK(has_tag(a, "no-vision-flow"));
    CHECK(a.b_hits == 0);
}

TEST_CASE("inbound Vision uses exact case-sensitive flow names") {
    for (auto flow : {"xtls-rprx-vision-udp443", "XTLS-RPRX-VISION", "fake-xtls-rprx-vision", "xtls-rprx-direct"}) {
        auto a = xray_case("{\"decryption\":\"none\",\"clients\":[{\"flow\":\"" + std::string(flow) + "\"}]}",
                          R"({"security":"tls"})");
        REQUIRE(a.ok);
        CHECK(a.compatibility_errors > 0);
        CHECK(a.protocols[0].vision_users == 0);
        CHECK(a.protocols[0].invalid_flow_users == 1);
        CHECK(a.protocols[0].flow == "invalid");
        CHECK(a.tspu_tier == "UNKNOWN");
        CHECK(a.a_hits == 0);
        CHECK(a.b_hits == 0);
    }
}

TEST_CASE("removed Xray modes are errors while supported deprecations are advisory") {
    for (auto net : {"http", "h2", "h3", "quic"}) {
        auto a = xray_case(R"({"decryption":"none"})", "{\"network\":\"" + std::string(net) + "\",\"security\":\"tls\"}");
        CHECK(has_tag(a, "removed-transport"));
        CHECK(a.compatibility_errors > 0);
        CHECK(a.b_hits == 0);
    }
    for (auto net : {"ws", "websocket", "grpc", "httpupgrade"}) {
        auto a = xray_case(R"({"decryption":"none"})", "{\"method\":\"" + std::string(net) + "\",\"security\":\"tls\"}");
        CHECK(has_tag(a, "deprecated-transport"));
        CHECK(a.compatibility_errors == 0);
        CHECK(a.b_hits == 0);
    }
    auto old = xray_case(R"({"decryption":"none"})", R"({"security":"xtls"})");
    CHECK(has_tag(old, "removed-xtls-security"));
}

TEST_CASE("Vision transport constraints account for VLESS Encryption") {
    auto st = R"({"decryption":"none","users":[{"flow":"xtls-rprx-vision"}]})";
    auto ws = xray_case(st, R"({"method":"ws","security":"tls"})");
    CHECK(has_tag(ws, "vision-transport"));
    auto plain = xray_case(st, R"({"method":"raw","security":"none"})");
    CHECK(has_tag(plain, "vision-transport"));
    auto capped = xray_case(st, R"({"security":"tls","tlsSettings":{"maxVersion":"1.2"}})");
    CHECK(has_tag(capped, "vision-tls-version"));
    auto enc = xray_case(R"({"decryption":"mlkem768x25519plus.native.600s.REDACTED","users":[{"flow":"xtls-rprx-vision"}]})",
                         R"({"method":"xhttp"})");
    CHECK(has_tag(enc, "vless-encryption"));
    CHECK_FALSE(has_tag(enc, "vision-transport"));
    CHECK_FALSE(has_tag(enc, "plaintext-proto"));
    CHECK(enc.protocols[0].encryption == "vless-encryption-unverified");
    auto conflict = xray_case(R"({"decryption":"mlkem768x25519plus.native.600s.REDACTED","fallbacks":[]})", "{}");
    CHECK(has_tag(conflict, "vless-encryption-fallback"));
    CHECK(has_tag(xray_case("{}", "{}"), "vless-decryption-missing"));
    CHECK(has_tag(xray_case(R"({"decryption":"typo"})", "{}"), "vless-decryption-unknown"));
}

TEST_CASE("VMess encryption and legacy alterId are separate from outer TLS") {
    auto a = xray_case(R"({"clients":[{"id":"example","alterId":64}]})", "{}", "vmess");
    REQUIRE(a.ok);
    CHECK(has_tag(a, "vmess-legacy-alterid"));
    CHECK(has_tag(a, "vmess-no-outer-tls"));
    CHECK_FALSE(has_tag(a, "plaintext-proto"));
    CHECK(a.compatibility_errors == 0);
    CHECK(a.b_hits == 0);
    auto current = xray_case(R"({"users":[{"alterId":0}]})", "{}", "vmess");
    CHECK_FALSE(has_tag(current, "vmess-legacy-alterid"));
}

TEST_CASE("Shadowsocks methods are checked per effective account") {
    auto old = xray_case(R"({"method":"aes-256-cfb"})", "{}", "shadowsocks");
    CHECK(has_tag(old, "shadowsocks-cipher"));
    CHECK(old.compatibility_errors == 1);
    auto modern = xray_case(R"({"method":"2022-blake3-aes-128-gcm"})", "{}", "shadowsocks");
    CHECK_FALSE(has_tag(modern, "shadowsocks-cipher"));
    CHECK(modern.protocols[0].encryption == "shadowsocks-2022");
    auto users = xray_case(R"({"method":"aes-256-gcm","users":[{"method":"rc4-md5"}]})", "{}", "shadowsocks");
    CHECK(has_tag(users, "shadowsocks-cipher"));
}

TEST_CASE("REALITY fallback and short IDs follow server configuration semantics") {
    auto st = R"({"decryption":"none","users":[{"flow":"xtls-rprx-vision"}]})";
    auto a = xray_case(st, R"({"security":"reality","realitySettings":{"target":"example.com:443","dest":"www.microsoft.com:443","serverNames":["example.com"],"shortIds":["","aabb"]}})");
    CHECK(a.compatibility_errors == 0);
    CHECK(has_tag(a, "reality-shortid-empty"));
    CHECK_FALSE(has_tag(a, "reality-dest-brand"));
    CHECK_FALSE(has_tag(a, "no-fallback"));
    CHECK(a.b_hits == 0);
    for (auto ids : {"[]", "[\"aaa\"]", "[\"zz\"]", "[42]", "[\"001122334455667788\"]"}) {
        auto bad = xray_case(st, "{\"security\":\"reality\",\"realitySettings\":{\"target\":\"example.com:443\",\"serverNames\":[\"example.com\"],\"shortIds\":" + std::string(ids) + "}}");
        CHECK(bad.compatibility_errors > 0);
    }
    auto badnet = xray_case(st, R"({"method":"ws","security":"reality"})");
    CHECK(has_tag(badnet, "reality-transport"));
    auto nulltarget = xray_case(st, R"({"security":"reality","realitySettings":{"target":null,"dest":"www.microsoft.com:443","serverNames":["example.com"],"shortIds":["aa"]}})");
    CHECK(has_tag(nulltarget, "reality-target-missing"));
    CHECK_FALSE(has_tag(nulltarget, "reality-dest-brand"));
}

TEST_CASE("proxy auth warnings respect loopback listeners and alias precedence") {
    for (auto proto : {"http", "socks", "mixed"}) {
        CHECK(has_tag(xray_case("{}", "{}", proto), "proxy-no-auth"));
        for (auto host : {"127.0.0.1", "127.12.0.9", "::1", "localhost", "/run/proxy.sock", "@proxy"})
            CHECK_FALSE(has_tag(xray_case("{}", "{}", proto, host), "proxy-no-auth"));
        CHECK(has_tag(xray_case("{}", "{}", proto, "127.999.0.1"), "proxy-no-auth"));
    }
    CHECK_FALSE(has_tag(xray_case(R"({"users":[{"user":"a","pass":"secret"}]})", "{}", "http"), "proxy-no-auth"));
    CHECK(has_tag(xray_case(R"({"accounts":[],"users":[{"user":"a","pass":"secret"}]})", "{}", "http"), "proxy-no-auth"));
    CHECK_FALSE(has_tag(xray_case(R"({"auth":"password","accounts":[{"user":"a","pass":"secret"}]})", "{}", "socks"), "proxy-no-auth"));
}

TEST_CASE("malformed Xray profile fields fail without partial detection") {
    for (auto cfg : {
        R"({"protocol":"vless","settings":{"clients":42}})",
        R"({"protocol":"vless","settings":{"users":[null]}})",
        R"({"protocol":"vless","settings":{"users":[{"flow":42}]}})",
        R"({"protocol":"vless","streamSettings":{"method":[]}})",
        R"({"protocol":"vless","streamSettings":{"realitySettings":[]}})",
        R"({"inbounds":[{"protocol":"vless"},{"type":"vless"}]})",
        R"({"protocol":"hysteria2"})"}) {
        auto a = audit_config_text(cfg);
        CHECK_FALSE(a.ok);
        CHECK(a.protocols.empty());
        CHECK(a.tspu_tier == "UNKNOWN");
    }
}

TEST_CASE("audit JSON distinguishes configuration evidence and omits credentials") {
    auto a = xray_case(R"({"decryption":"none","users":[{"id":"SECRET_UUID","flow":"xtls-rprx-vision","password":"SECRET_PASSWORD"}]})",
                      R"({"security":"reality","realitySettings":{"target":"example.com:443","serverNames":["example.com"],"shortIds":["aa"],"privateKey":"SECRET_KEY"}})");
    std::string out = config_audit_to_json(a);
    bool ok = false;
    auto doc = json_parse(out, &ok);
    REQUIRE(ok);
    CHECK(doc["evidence_source"].as_str() == "configuration");
    CHECK_FALSE(doc["network_confirmed"].as_bool(true));
    CHECK_FALSE(doc["runtime_validated"].as_bool(true));
    CHECK(doc["protocols"].at(0)["flow"].as_str() == "vision");
    CHECK(out.find("SECRET_") == std::string::npos);
}


TEST_CASE("duplicate configuration keys never produce a pass") {
    for (const auto* security : {R"("tls","security":"none")", R"("none","security":"tls")"}) {
        auto a = audit_config_text(std::string(R"({"protocol":"trojan","port":443,"streamSettings":{"security":)") + security + "}}");
        CHECK_FALSE(a.ok);
        CHECK_FALSE(a.err.empty());
    }
}

TEST_CASE("sing-box loopback listeners do not imply public exposure") {
    for (const auto* host : {"127.0.0.1", "127.99.0.2", "::1"}) {
        auto a = audit_config_text(std::string(R"({"type":"trojan","listen_port":12345,"listen":")") + host + R"("})");
        REQUIRE(a.ok);
        CHECK_FALSE(has_tag(a, "plaintext-proto"));
        CHECK(a.a_hits == 0);
        CHECK(has_tag(a, "local-listener"));
    }
    for (const auto* host : {"0.0.0.0", "::", "203.0.113.7"}) {
        auto a = audit_config_text(std::string(R"({"type":"trojan","listen_port":12345,"listen":")") + host + R"("})");
        REQUIRE(a.ok);
        CHECK(has_tag(a, "plaintext-proto"));
    }
    auto a = audit_config_text(R"({"inbounds":[{"type":"trojan","listen":"127.0.0.1","listen_port":2083},
        {"type":"trojan","listen":"::1","listen_port":8443}]})");
    CHECK_FALSE(has_tag(a, "panel-cluster"));
}

TEST_CASE("AWG parameter names cannot establish effective obfuscation") {
    for (const auto* params : {"Jc=0\n", "S1=0\nS2=0\n", "Jc=4\n", "H1=1\n", "Jc=garbage\n",
                             "H1=100-200\n", "Jc=\n", "S1=86\nS2=574\nH1=123\n"}) {
        auto a = audit_config_text(std::string("[Interface]\nListenPort=12345\n") + params);
        REQUIRE(a.ok);
        CHECK(a.tspu_tier == "UNKNOWN");
        CHECK(has_tag(a, "amneziawg-unverified"));
    }
}
