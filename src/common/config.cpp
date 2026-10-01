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
int  g_j3_subset  = 0;
bool g_passive    = false;

bool        g_save_requested = false;
FILE*       g_save_fp        = nullptr;
std::string g_save_path;

bool g_json = false;

bool        g_override_preflight = false;
std::string g_expect_ip;

std::string g_wg_pubkey;
std::string g_wg_key;
std::string g_wg_psk;
int         g_wg_port = 51820;

std::string g_volume_path;
std::string g_volume_control;

PortMode         g_port_mode = PortMode::FULL;
int              g_range_lo  = 1;
int              g_range_hi  = 65535;
std::vector<int> g_port_list;