// SPDX-License-Identifier: GPL-3.0-or-later
// cli entry points: help text + interactive menu.
#pragma once

#include <string>
#include <vector>

void help();
void interactive();

// dispatch one command line (main.cpp); same codes as the process exit
int run_command(const std::vector<std::string>& pos);

// --save around a run; save_begin picks <target>.md unless a path was given
void save_begin(const std::vector<std::string>& pos);
void save_end();

// read a config file, run the static detectability audit, print it colored.
// returns an exit code mirroring the scan verdict tiers:
//   0 pass, 1 throttle, 2 block, 3 immediate block, 64 on file/parse error.
int run_config_audit(const std::string& path);
int run_config_pair(const std::string& server_path, const std::string& client_path);

// offline packet-capture analysis. 0 completed, 64 input/read error.
int run_awg_analysis(const std::string& path);

// pcap: client hellos, inner handshakes, cleartext dns, traffic beside
// --node. 2 when a box can read something listed, 0 otherwise, 64 input error.
int run_pcap_analysis(const std::string& path);

// batch: full scan per line of a file, --out DIR keeps each --json report.
// exit is the worst target's verdict code.
int run_batch(const std::string& list);

// diff two reports or two --out directories: 2 verdict changed, 1 surface
// or context changed, 0 same, 64 unreadable input.
int run_diff(const std::string& a, const std::string& b);

// offline names: 3 strong, 2 moderate, 0 weak/none/ip, 64 invalid input.
int run_hostname_analysis(const std::vector<std::string>& names);
