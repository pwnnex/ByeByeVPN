// SPDX-License-Identifier: GPL-3.0-or-later
// diff: what changed between two --json scan reports of a node, or two
// directories of them (batch --out). offline, reads files only.
#pragma once

#include <string>
#include <vector>

struct DiffItem {
    std::string cls;      // verdict, surface, context
    std::string what;     // "label", "tcp 8443", "tls 443 cert", ...
    std::string from, to; // "" when absent on that side
};

struct ReportDiff {
    bool        ok = false;
    std::string error;
    std::string target_a, target_b;
    std::vector<DiffItem> items;
};

ReportDiff diff_reports(const std::string& a_json, const std::string& b_json);

// 2 verdict changed, 1 only surface or context changed, 0 same
int diff_exit_code(const ReportDiff& d);

std::string diff_json(const std::vector<std::pair<std::string, ReportDiff>>& pairs);
