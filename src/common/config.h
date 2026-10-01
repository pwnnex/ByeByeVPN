// SPDX-License-Identifier: GPL-3.0-or-later
// global config knobs. set by main() from the cli, read everywhere.
// keep this header tiny: only what really needs to be globally visible.
#pragma once

#include <vector>
#include <string>
#include <cstdio>

// version shared by the banner, json and saved reports
// keep `VERSION` in `Makefile` in sync
#define SCANNER_VERSION "v3.0.0"

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
// the wire: shuffle probe order so the 8-j3 sequence isn't a signature,
// add timing jitter so port-bursts and back-to-back handshakes smear out,
// and offer probe-set scope cuts.
extern bool g_stealth;     // master toggle: implies no-geoip + no-ct + udp-jitter
                           // and turns on inter-probe timing jitter everywhere
extern bool g_no_geoip;    // skip all 3rd-party geoip services
extern bool g_no_ct;       // skip crt.sh ct lookups
extern bool g_udp_jitter;  // 50-300ms random delay between udp probes
extern int  g_j3_subset;   // 0 = all 8 j3 probes; 1..7 = a random subset of N
extern bool g_passive;     // minimal-probe mode: skips j3, utls dual-probe,
                           // sni consistency loop and amneziawg sweep entirely

// --save: tee scan output to a file (ansi stripped)
extern bool        g_save_requested;
extern FILE*       g_save_fp;
extern std::string g_save_path;

// preflight: --i-know-what-i-am-doing gives a verdict on a failed preflight,
// marked as overridden. --expect-ip is the address lookup services must see.
extern bool        g_override_preflight;
extern std::string g_expect_ip;

// wireguard owner self-check. pubkey is key text or a path, key and psk are
// paths only; the keys themselves are read at use time and wiped after.
extern std::string g_wg_pubkey;
extern std::string g_wg_key;
extern std::string g_wg_psk;
extern int         g_wg_port;

// dpi --volume <path> [--control host[:port]/path]: client-side volume check
extern std::string g_volume_path;
extern std::string g_volume_control;

// dpi --sni NAME --real IP|auto: the same name to the node and to its own address
extern std::string g_dpi_sni;
extern std::string g_dpi_real;

// names --ct [--ct-file F] [--resolve] [--node IP]
extern bool        g_names_ct;
extern std::string g_ct_file;
extern bool        g_resolve;
extern std::string g_node_ip;

// --json: emit a machine-readable json report on stdout. when set, the
// human-readable scan output is redirected to stderr so stdout carries
// only the json object (pipe-friendly).
extern bool g_json;

// port-scan selection
extern PortMode         g_port_mode;
extern int              g_range_lo;
extern int              g_range_hi;
extern std::vector<int> g_port_list;
