// SPDX-License-Identifier: GPL-3.0-or-later
// global config knobs. set by main() from the cli, read everywhere.
// keep this header tiny: only what really needs to be globally visible.
#pragma once

#include <vector>
#include <string>
#include <cstdio>

// port-scan mode (driven by --full / --fast / --range / --ports)
enum class PortMode { FULL, FAST, RANGE, LIST };

// runtime tuning
extern bool g_no_color;
extern bool g_verbose;
extern int  g_threads;
extern int  g_tcp_to;
extern int  g_udp_to;

// stealth / privacy opt-outs (default off = full scanner behaviour).
// the v2.7.0 stealth pack is about removing scanner-shaped patterns from
// the wire: shuffle probe order so the 8-J3 sequence isn't a signature,
// add timing jitter so port-bursts and back-to-back handshakes smear out,
// and offer probe-set scope cuts.
extern bool g_stealth;     // master toggle: implies no-geoip + no-ct + udp-jitter
                           // and turns on inter-probe timing jitter everywhere
extern bool g_no_geoip;    // skip all 3rd-party GeoIP services
extern bool g_no_ct;       // skip crt.sh CT lookups
extern bool g_udp_jitter;  // 50-300ms random delay between UDP probes
extern int  g_j3_subset;   // 0 = all 8 J3 probes; 1..7 = a random subset of N
extern bool g_passive;     // minimal-probe mode: skips J3, uTLS dual-probe,
                           // SNI consistency loop and AmneziaWG sweep entirely

// --save: tee scan output to a file (ANSI stripped)
extern bool        g_save_requested;
extern FILE*       g_save_fp;
extern std::string g_save_path;

// --json: emit a machine-readable JSON report on stdout. when set, the
// human-readable scan output is redirected to stderr so stdout carries
// only the JSON object (pipe-friendly).
extern bool g_json;

// port-scan selection
extern PortMode         g_port_mode;
extern int              g_range_lo;
extern int              g_range_hi;
extern std::vector<int> g_port_list;