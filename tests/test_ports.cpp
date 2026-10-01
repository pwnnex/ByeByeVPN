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
    // the curated list must contain the obvious tls / proxy ports
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

TEST_CASE("build_tcp_ports RANGE survives an inverted range") {
    g_port_mode = PortMode::RANGE;
    // reversed by the user: (hi - lo + 1) went negative and reserve() threw.
    g_range_lo = 9000;
    g_range_hi = 8000;
    auto p = build_tcp_ports();
    REQUIRE(p.size() == 1001);
    CHECK(p.front() == 8000);
    CHECK(p.back() == 9000);

    // entirely above the port space: no valid port, so an empty list - not a
    // silent fallback to 65535 and not a length_error.
    g_range_lo = 70000;
    g_range_hi = 80000;
    auto q = build_tcp_ports();
    CHECK(q.empty());

    g_port_mode = PortMode::FULL;
}

TEST_CASE("build_tcp_ports LIST drops out-of-range entries") {
    g_port_mode = PortMode::LIST;
    // atoi() turns "--ports 80,,http,443,99999" into these.
    g_port_list = {80, 0, 0, 443, 99999, -1};
    auto p = build_tcp_ports();
    REQUIRE(p.size() == 2);
    CHECK(p[0] == 80);
    CHECK(p[1] == 443);
    g_port_list.clear();
    g_port_mode = PortMode::FULL;
}

TEST_CASE("build_tcp_ports LIST echoes the explicit list") {
    g_port_mode = PortMode::LIST;
    g_port_list = {80, 443, 8443};
    auto p = build_tcp_ports();
    REQUIRE(p.size() == 3);
    CHECK(p[0] == 80); CHECK(p[1] == 443); CHECK(p[2] == 8443);
    // restore default so later test files aren't affected
    g_port_mode = PortMode::FULL;
}

TEST_CASE("port_hint names well-known ports") {
    CHECK(std::string(port_hint(22))  == "SSH");
    CHECK(std::string(port_hint(443)).find("HTTPS") != std::string::npos);
    CHECK(std::string(port_hint(51820)) == "WireGuard default");
    // unknown port returns empty string, never nullptr
    const char* h = port_hint(12345);
    REQUIRE(h != nullptr);
    CHECK(std::string(h) == "");
}

TEST_CASE("port_hint never guesses a tunnel from a port number") {
    // every https host got "XTLS / Reality" and k8s got "possible VPN"
    for (int p : {443, 4433, 4443, 8443, 6443, 10810, 10815})
        CHECK(std::string(port_hint(p)).find("Reality") == std::string::npos);
    CHECK(std::string(port_hint(443)) == "HTTPS");
    CHECK(std::string(port_hint(6443)).find("VPN") == std::string::npos);
    CHECK(std::string(port_hint(10815)) == "");
}
