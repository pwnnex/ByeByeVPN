// SPDX-License-Identifier: GPL-3.0-or-later
// local-machine analysis: list adapters, routes, running VPN processes,
// installed VPN config dirs, and print a split-tunnel summary.
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
    unsigned long mtu      = 0;
    unsigned long if_index = 0;
    bool          is_vpn   = false;
    bool          is_up    = false;
};

struct LocalRoute {
    std::string  prefix;
    std::string  nexthop;
    unsigned long if_index = 0;
    unsigned long metric   = 0;
    std::string  via_adapter;
    bool         via_vpn = false;
};

struct LocalProcess {
    unsigned long pid = 0;
    std::string  name;
    std::string  exe_path;
    std::string  category;
};

struct ConfigHit { std::string tool; std::string path; };

std::vector<LocalAdapter> list_local_adapters();
std::vector<LocalRoute>   list_local_routes();
std::vector<LocalProcess> list_vpn_processes();
std::vector<ConfigHit>    find_known_configs();

// pretty-print the whole local report.
void run_local_analysis();