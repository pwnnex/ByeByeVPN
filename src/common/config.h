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

// stealth / privacy opt-outs (default off = full scanner behaviour)
extern bool g_stealth;     // master toggle: implies no-geoip + no-ct + udp-jitter
extern bool g_no_geoip;    // skip all 3rd-party GeoIP services
extern bool g_no_ct;       // skip crt.sh CT lookups
extern bool g_udp_jitter;  // 50-300ms random delay between UDP probes

// --save: tee scan output to a file (ANSI stripped)
extern bool        g_save_requested;
extern FILE*       g_save_fp;
extern std::string g_save_path;

// port-scan selection
extern PortMode         g_port_mode;
extern int              g_range_lo;
extern int              g_range_hi;
extern std::vector<int> g_port_list;
