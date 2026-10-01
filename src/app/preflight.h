// SPDX-License-Identifier: GPL-3.0-or-later
// preflight: is our own stack fit to measure anything. a tunnel on the path
// to the target, a packet rewriter or a local ack-all stack turns every
// probe result into a statement about this machine, not the target.
#pragma once

#include <string>
#include <vector>

struct PreflightFacts {
    std::string target_ip;
    std::vector<std::string> tunnels_up;       // adapter names
    std::string target_iface;                  // adapter windows picks for the target
    bool        target_iface_is_tunnel = false;
    bool        target_is_loopback = false;
    bool        fake_ip_target = false;        // 198.18/15, cgnat, class e
    std::vector<std::string> rewriters;        // windivert tools
    std::vector<std::string> proxy_clients;
    std::string system_proxy;                  // wininet proxy or pac url
    std::vector<std::string> proxy_env;        // env var names only
    bool        local_ack_all = false;         // rfc 5737 address accepted tcp
    bool        ack_all_checked = false;
    std::vector<std::string> external_ips;     // one per source, "" on failure
    std::string expect_ip;
};

struct PreflightReport {
    PreflightFacts facts;
    std::vector<std::string> blockers;   // report is unreliable
    std::vector<std::string> warnings;   // side lookups affected
    bool blocked = false;
    bool overridden = false;
};

// pure decision, unit tested
PreflightReport preflight_decide(const PreflightFacts& f, bool override_flag);

// gathers facts on this machine; external ip lookup only when allowed
PreflightFacts preflight_gather(const std::string& target_ip, bool third_party_ok,
                                const std::string& expect_ip);

void print_preflight(const PreflightReport& p);

// local-only snapshot for the interactive status bar; sends nothing
struct LocalHealth {
    std::string public_iface;              // what 1.1.1.1 would leave through
    bool        public_via_tunnel = false;
    std::vector<std::string> tunnels_up;
    std::vector<std::string> proxy_clients;
    std::vector<std::string> rewriters;
    std::string system_proxy;
};
LocalHealth local_health();

// rfc 5737 test-net-1 address, routed nowhere on a clean host
extern const char* const PREFLIGHT_DEAD_ADDRESS;
