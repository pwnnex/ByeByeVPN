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
        "settings": { "clients": [{ "id": "x", "flow": "" }] },
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
    CHECK(has_tag(a, "reality-shortid-empty")); // only "" shortId
    CHECK(has_tag(a, "reality-show"));          // debug logging on
    CHECK(has_tag(a, "no-vision-flow"));        // flow not vision
    CHECK(has_tag(a, "no-fallback"));           // silent-on-junk risk
    // a High soft signal (brand dest) -> accumulative block, no named A-tier
    CHECK(a.a_hits == 0);
    CHECK(a.tspu_tier == "BLOCK (accumulative)");
}

TEST_CASE("clean Reality config passes") {
    const char* cfg = R"({
      "inbounds": [{
        "protocol": "vless",
        "port": 443,
        "settings": {
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

TEST_CASE("shadowsocks default port is a named immediate-block") {
    const char* cfg = R"({"inbounds":[{"protocol":"shadowsocks","port":8388,
        "settings":{"method":"aes-256-gcm"}}]})";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(has_tag(a, "shadowsocks-default-port"));
    CHECK(a.a_hits >= 1);
    CHECK(a.tspu_tier == "IMMEDIATE BLOCK");
}

TEST_CASE("plaintext vless (security=none) is a named immediate-block") {
    const char* cfg = R"({"inbounds":[{"protocol":"vless","port":80,
        "streamSettings":{"network":"tcp","security":"none"}}]})";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(has_tag(a, "plaintext-proto"));
    CHECK(a.tspu_tier == "IMMEDIATE BLOCK");
}

TEST_CASE("sing-box hysteria2 inbound detected and named") {
    const char* cfg = R"({
      "inbounds": [{ "type": "hysteria2", "listen_port": 36712 }]
    })";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(a.format == "sing-box");
    CHECK(has_tag(a, "hysteria2"));
    CHECK(a.a_hits >= 1);
    CHECK(a.tspu_tier == "IMMEDIATE BLOCK");
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
        "settings":{"clients":[{"id":"x","flow":"xtls-rprx-direct"}]},
        "streamSettings":{"network":"tcp","security":"reality",
          "realitySettings":{"dest":"example.com:443","serverNames":["example.com"],
          "shortIds":["aa11"]}}}]})";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(has_tag(a, "deprecated-flow"));
    CHECK_FALSE(has_tag(a, "no-vision-flow"));   // deprecated takes precedence
    CHECK(a.tspu_tier == "BLOCK (accumulative)");
}

TEST_CASE("TLS minVersion below 1.3 is flagged") {
    const char* cfg = R"({"inbounds":[{"protocol":"vless","port":443,
        "settings":{"clients":[{"id":"x","flow":"xtls-rprx-vision"}]},
        "streamSettings":{"network":"tcp","security":"tls",
          "tlsSettings":{"minVersion":"1.2"}}}]})";
    ConfigAudit a = audit_config_text(cfg);
    REQUIRE(a.ok);
    CHECK(has_tag(a, "tls-min-version"));
}

TEST_CASE("multi-port Reality across inbounds is flagged") {
    const char* cfg = R"({"inbounds":[
      {"protocol":"vless","port":443,
       "settings":{"clients":[{"id":"x","flow":"xtls-rprx-vision"}],"fallbacks":[{"dest":8080}]},
       "streamSettings":{"network":"tcp","security":"reality",
         "realitySettings":{"dest":"a.example.com:443","serverNames":["a.example.com"],"shortIds":["aa11"]}}},
      {"protocol":"vless","port":8444,
       "settings":{"clients":[{"id":"y","flow":"xtls-rprx-vision"}],"fallbacks":[{"dest":8081}]},
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
    CHECK(j.find("\"tspu_tier\": \"IMMEDIATE BLOCK\"") != std::string::npos);
    CHECK(j.find("\"tag\": \"shadowsocks-default-port\"") != std::string::npos);
    CHECK(j.find("\"named\": true") != std::string::npos);
}

TEST_CASE("config_audit_to_json reports parse errors") {
    ConfigAudit a = audit_config_text("not a config");
    std::string j = config_audit_to_json(a);
    CHECK(j.find("\"ok\": false") != std::string::npos);
    CHECK(j.find("\"error\"") != std::string::npos);
}
