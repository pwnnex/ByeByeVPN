// SPDX-License-Identifier: GPL-3.0-or-later
#include "cli.h"
#include "../common/config.h"
#include "../common/console.h"
#include "../common/util.h"
#include "../scan/hostname_marks.h"
#include "../scan/ct.h"
#include "../scan/ct_names.h"
#include "../net/dns.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <iterator>

namespace {

bool read_file(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return !f.bad() && out.size() <= 16u * 1024u * 1024u;
}

int ct_one(const std::string& domain) {
    std::string body, err;
    if (!g_ct_file.empty()) {
        if (!read_file(g_ct_file, body)) err = "cannot read " + g_ct_file + " (missing or over 16 MiB)";
    } else {
        if (g_no_ct) { printf("  --ct contacts crt.sh, and --no-ct forbids it; save the JSON and use --ct-file\n"); return 64; }
        body = ct_names_fetch(domain, err);
    }
    CtNames ct;
    if (err.empty()) ct = parse_ct_names(body, domain);
    else { ct.domain = domain; ct.err = err; }
    if (!ct.err.empty() && ct.err == "not a domain name") {
        if (!g_json) printf("\n  %s\n    error: not a domain name\n", printable_prefix(domain, 256).c_str());
        else std::fputs(ct_names_json(ct, {}).c_str(), stdout);
        return 64;
    }

    std::vector<std::pair<std::string, std::vector<std::string>>> resolved;
    if (ct.lookup_complete && g_resolve) {
        // dns asks for each name; cap so a big domain stays quick
        int asked = 0;
        for (const auto& n : ct.names) {
            if (asked++ >= 64) break;
            const Resolved r = resolve_host(n.name);
            if (r.err.empty() && !r.ips.empty()) resolved.emplace_back(n.name, r.ips);
        }
    }
    const auto shared = ct_shared_addresses(ct, resolved, g_node_ip);
    if (g_json) {
        std::fputs(ct_names_json(ct, shared).c_str(), stdout);
    } else {
        printf("\n  %s%s%s", col(C::BOLD), ct.domain.c_str(), col(C::RST));
        if (!ct.lookup_complete) {
            printf("   %sCT lookup failed: %s%s\n", col(C::YEL), ct.err.c_str(), col(C::RST));
            printf("  an unknown answer is not an empty one; nothing is concluded\n");
            return 4;
        }
        printf("   %d names in CT logs, %d certificates\n", (int)ct.names.size(), ct.certificates);
        int plain = 0;
        for (const auto& n : ct.names) {
            if (!n.marks.any()) { ++plain; continue; }
            const auto& m = n.marks.marks.front();
            const char* c = m.tier == HostnameMark::Tier::Strong ? C::RED : m.tier == HostnameMark::Tier::Moderate ? C::YEL : C::DIM;
            printf("    %s[%-8s]%s %s%s  %s%s: %s%s", col(c), hostname_tier_name(m.tier), col(C::RST), n.wildcard ? "*." : "",
                   n.name.c_str(), col(C::DIM), m.token.c_str(), m.why.c_str(), col(C::RST));
            if (!n.first_seen.empty()) printf("  %s(since %s)%s", col(C::DIM), n.first_seen.c_str(), col(C::RST));
            printf("\n");
        }
        if (plain) printf("    %s+ %d names without markers (--json lists all)%s\n", col(C::DIM), plain, col(C::RST));
        if (g_resolve) {
            printf("\n  %sShared addresses%s (DNS from this machine, %zu names resolved)\n", col(C::BOLD), col(C::RST), resolved.size());
            if (shared.empty()) printf("    no address carries two of these names\n");
            for (const auto& s : shared) {
                std::string list;
                for (const auto& n : s.names) list += (list.empty() ? "" : ", ") + n;
                printf("    %s%-15s%s %s%s%s %s\n", col(s.marked ? C::YEL : C::DIM), s.ip.c_str(), col(C::RST),
                       s.node ? col(C::ACC) : "", s.node ? "your node " : "", col(C::RST), list.c_str());
            }
            printf("  %sBehind a CDN every name shares the CDN's addresses; a shared address means nothing there.%s\n",
                   col(C::DIM), col(C::RST));
        }
        printf("  %sCT logs are public: anyone can list these names without sending a packet to your node.%s\n",
               col(C::DIM), col(C::RST));
    }
    if (!ct.lookup_complete) return 4;
    int worst = 0;
    for (const auto& n : ct.names) worst = std::max(worst, n.marks.strong ? 3 : n.marks.moderate ? 2 : 0);
    return worst;
}

} // namespace

int run_ct_names(const std::vector<std::string>& domains) {
    if (domains.empty()) { printf("need a domain, e.g. names --ct example.com\n"); return 64; }
    int rc = 0;
    for (const auto& d : domains) {
        const int r = ct_one(d);
        // usage errors win, then failed lookups, then the strongest marker
        if (r == 64 || rc == 64) rc = 64;
        else if (r == 4 || rc == 4) rc = 4;
        else rc = std::max(rc, r);
    }
    return rc;
}

int run_hostname_analysis(const std::vector<std::string>& names) {
    if (g_names_ct) return run_ct_names(names);
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
