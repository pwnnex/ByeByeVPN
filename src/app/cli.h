// SPDX-License-Identifier: GPL-3.0-or-later
// CLI entry points: help text + interactive menu.
#pragma once

#include <string>

void help();
void interactive();

// read a config file, run the static detectability audit, print it colored.
// returns an exit code mirroring the scan verdict tiers:
//   0 PASS, 1 THROTTLE, 2 BLOCK, 3 IMMEDIATE BLOCK, 64 on file/parse error.
int run_config_audit(const std::string& path);