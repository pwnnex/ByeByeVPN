// SPDX-License-Identifier: GPL-3.0-or-later
// local-machine analysis: list adapters, routes, running vpn processes,
// installed vpn config dirs, and print a split-tunnel summary.
#pragma once

#include <string>
#include <vector>

struct LocalAdapter {
    std::string  friendly;
    std::string  description;
    std::string  mac;
    std::vector<std::string> ipv4;
    std::vector<std::string> ipv6;
    std::vector<std::string> gateways;
    std::vector<std::string> dns;      // configured resolvers
    unsigned long metric   = 0;        // ipv4 interface metric
    unsigned long mtu      = 0;
    unsigned long if_index = 0;
    unsigned long if_type  = 0;
    bool          is_vpn   = false;
    bool          is_up    = false;
};

// decides from IfType plus exact driver tokens, not substrings
bool adapter_is_tunnel(unsigned long if_type, const std::string& desc, const std::string& name);

struct LocalRoute {
    std::string  prefix;
    std::string  nexthop;
    unsigned long if_index = 0;
    unsigned long metric   = 0;
    std::string  via_adapter;
    bool         via_vpn = false;
};

enum class ProcKind { Vpn, Proxy, Rewriter };

struct LocalProcess {
    unsigned long pid = 0;
    std::string  name;
    std::string  exe_path;
    std::string  category;
    ProcKind     kind = ProcKind::Vpn;   // rewriter edits our packets in flight
};

struct ConfigHit { std::string tool; std::string path; };

std::vector<LocalAdapter> list_local_adapters();
std::vector<LocalRoute>   list_local_routes();
std::vector<LocalProcess> list_vpn_processes();
std::vector<ConfigHit>    find_known_configs();

// default route covers everything: 0/0, or the 0/1 + 128/1 pair
bool routes_cover_default(const std::vector<std::string>& prefixes_v4);

// interface windows would use to reach ip, 0 when unknown
unsigned long best_interface_for(const std::string& ip);

// pretty-print the whole local report. 2 when ipv6 or dns leaves beside
// the tunnel, 0 otherwise.
int run_local_analysis();