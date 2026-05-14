// SPDX-License-Identifier: GPL-3.0-or-later
// unit tests for src/scan/ports.cpp (port-list builder + hint lookup).
#include "doctest.h"
#include "../src/scan/ports.h"
#include "../src/common/config.h"

#include <algorithm>

TEST_CASE("build_tcp_ports FULL covers 1..65535") {
    g_port_mode = PortMode::FULL;
    auto p = build_tcp_ports();
    REQUIRE(p.size() == 65535);
    CHECK(p.front() == 1);
    CHECK(p.back() == 65535);
}

TEST_CASE("build_tcp_ports FAST is the curated list") {
    g_port_mode = PortMode::FAST;
    auto p = build_tcp_ports();
    CHECK(p.size() == TCP_FAST_PORTS.size());
    CHECK(p.size() > 100);
    // the curated list must contain the obvious TLS / proxy ports
    CHECK(std::find(p.begin(), p.end(), 443)   != p.end());
    CHECK(std::find(p.begin(), p.end(), 8443)  != p.end());
    CHECK(std::find(p.begin(), p.end(), 51820) != p.end());
}

TEST_CASE("build_tcp_ports RANGE is inclusive and clamped") {
    g_port_mode = PortMode::RANGE;
    g_range_lo = 1000;
    g_range_hi = 1010;
    auto p = build_tcp_ports();
    REQUIRE(p.size() == 11);
    CHECK(p.front() == 1000);
    CHECK(p.back() == 1010);

    // out-of-bounds lo/hi get clamped into 1..65535
    g_range_lo = -50;
    g_range_hi = 70000;
    auto q = build_tcp_ports();
    CHECK(q.front() == 1);
    CHECK(q.back() == 65535);
}

TEST_CASE("build_tcp_ports LIST echoes the explicit list") {
    g_port_mode = PortMode::LIST;
    g_port_list = {80, 443, 8443};
    auto p = build_tcp_ports();
    REQUIRE(p.size() == 3);
    CHECK(p[0] == 80); CHECK(p[1] == 443); CHECK(p[2] == 8443);
    // restore default so later test files are not affected
    g_port_mode = PortMode::FULL;
}

TEST_CASE("port_hint names well-known ports") {
    CHECK(std::string(port_hint(22))  == "SSH");
    CHECK(std::string(port_hint(443)).find("HTTPS") != std::string::npos);
    CHECK(std::string(port_hint(51820)) == "WireGuard");
    // unknown port returns empty string, never nullptr
    const char* h = port_hint(12345);
    REQUIRE(h != nullptr);
    CHECK(std::string(h) == "");
    // the heuristic alt-TLS band
    CHECK(std::string(port_hint(10810)).find("v2ray") != std::string::npos);
}
