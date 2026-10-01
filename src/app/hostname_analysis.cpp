// SPDX-License-Identifier: GPL-3.0-or-later
#include "cli.h"
#include "../common/config.h"
#include "../common/console.h"
#include "../common/util.h"
#include "../scan/hostname_marks.h"

#include <algorithm>
#include <cstdio>

int run_hostname_analysis(const std::vector<std::string>& names) {
    bool invalid = names.empty();
    int worst = 0;
    if (g_json) std::fputs(hostname_report_json(names).c_str(), stdout);
    else if (names.empty()) printf("need at least one hostname\n");
    for (const auto& name : names) {
        const auto parsed = parse_hostname(name);
        const auto a = analyze_hostname(name);
        if (parsed.status == HostnameInput::Status::Invalid) invalid = true;
        worst = std::max(worst, a.strong ? 3 : a.moderate ? 2 : 0);
        if (g_json) continue;
        printf("\n  %s\n", printable_prefix(name, 256).c_str());
        if (parsed.status == HostnameInput::Status::Invalid) {
            printf("    error: %s\n", parsed.error.c_str());
            continue;
        }
        if (parsed.status == HostnameInput::Status::IpLiteral) {
            printf("    IP literal: hostname analysis is not applicable\n");
            continue;
        }
        if (!a.any()) printf("    no naming markers found\n");
        for (const auto& m : a.marks)
            printf("    [%-8s] %s (%s), label '%s'%s: %s\n",
                   hostname_tier_name(m.tier), m.token.c_str(), m.kind.c_str(), m.decoded_label.c_str(),
                   m.in_subdomain ? "" : " (domain/suffix)", m.why.c_str());
    }
    if (!g_json && !names.empty())
        printf("\n  Naming heuristics only. No DNS lookup, protocol confirmation, or scan score impact.\n"
               "  Exit 0 includes weak findings and IP inputs; it does not mean the server is clean.\n");
    return invalid ? 64 : worst;
}
