// SPDX-License-Identifier: GPL-3.0-or-later
// port-list builder + per-port reference hint string.
#pragma once

#include "../common/config.h"
#include <string>
#include <vector>

// curated 205-port "fast" list: VPN/proxy/TLS/admin/tor/xray defaults.
extern const std::vector<int> TCP_FAST_PORTS;

// 35 UDP ports we sweep when in udp scan mode.
extern const std::vector<int> UDP_SCAN_PORTS;

// returns the active TCP scan list given g_port_mode / g_range_* / g_port_list.
std::vector<int> build_tcp_ports();

// short reference label for a well-known port (e.g. 443 -> "HTTPS / XTLS / Reality").
// returns "" if not in the table.
const char* port_hint(int p);