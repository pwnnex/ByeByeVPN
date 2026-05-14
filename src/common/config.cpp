// SPDX-License-Identifier: GPL-3.0-or-later
#include "config.h"

bool g_no_color = false;
bool g_verbose  = false;
int  g_threads  = 500;
int  g_tcp_to   = 800;
int  g_udp_to   = 900;

bool g_stealth    = false;
bool g_no_geoip   = false;
bool g_no_ct      = false;
bool g_udp_jitter = false;

bool        g_save_requested = false;
FILE*       g_save_fp        = nullptr;
std::string g_save_path;

bool g_json = false;

PortMode         g_port_mode = PortMode::FULL;
int              g_range_lo  = 1;
int              g_range_hi  = 65535;
std::vector<int> g_port_list;