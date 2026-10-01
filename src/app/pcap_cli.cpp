// SPDX-License-Identifier: GPL-3.0-or-later
#include <cstdio>
#include "cli.h"
#include "../common/config.h"
#include "../common/console.h"
#include "../common/json.h"
#include "../scan/capture.h"
#include "../scan/pcap_analysis.h"

#include <map>
#include <set>
#include <string>

namespace {

constexpr size_t FLOWS_SHOWN = 10;
constexpr size_t SERVERS_SHOWN = 8;
constexpr size_t NAMES_SHOWN = 6;

const char* outcome_color(Outcome o) {
    return o == Outcome::Positive ? C::RED : o == Outcome::Negative ? C::GRN : o == Outcome::Inconclusive ? C::YEL : C::DIM;
}

std::string sizes(const std::vector<uint32_t>& v) {
    std::string s;
    for (auto n : v) s += (s.empty() ? "" : " ") + std::to_string(n);
    return s.empty() ? "-" : s;
}

std::string kb(uint64_t b) {
    char buf[32];
    if (b < 10 * 1024) std::snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(b));
    else std::snprintf(buf, sizeof(buf), "%.1f KB", static_cast<double>(b) / 1024.0);
    return buf;
}

void verdict_line(const char* what, Outcome o, const std::string& reason) {
    printf("  %s=>%s %s: %s%s%s. %s\n", col(C::ACC), col(C::RST), what, col(outcome_color(o)), outcome_name(o),
           col(C::RST), reason.c_str());
}

void print_flow(const TlsFlow& t, const std::string& node, size_t same) {
    const bool to_node = !node.empty() && t.server.compare(0, node.size() + 1, node + ":") == 0;
    const std::string times = same > 1 ? "  x" + std::to_string(same) : "";
    printf("    %s%s%s  %s%s%s  %s%s%s%s\n", col(C::BOLD), t.server.c_str(), col(C::RST),
           col(C::CYN), t.sni.empty() ? "(no sni)" : t.sni.c_str(), col(C::RST),
           t.quic ? "quic" : ("tls " + (t.version.empty() ? std::string("?") : t.version)).c_str(),
           t.alpn.empty() ? "" : ("  " + t.alpn).c_str(), to_node ? "  [node]" : "", times.c_str());
    // the ech extension alone: chromium sends a grease one with the real name
    printf("      ja4 %s   grease %s  ech-ext %s  pq %s%s\n", t.ja4.c_str(), t.grease ? "yes" : "no",
           t.ech ? "yes" : "no", t.pq ? "yes" : "no", doh_name(t.sni) ? "  dns-over-https" : "");
    if (t.quic) return;
    printf("      %sfirst records%s  c>s %s   s>c %s\n", col(C::DIM), col(C::RST), sizes(t.c2s).c_str(),
           sizes(t.s2c).c_str());
    const char* c = t.inner == InnerState::Match ? C::RED : t.inner == InnerState::NoMatch ? C::GRN : C::DIM;
    const char* name = t.inner == InnerState::Match ? "match" : t.inner == InnerState::NoMatch ? "no match"
                     : t.inner == InnerState::TooShort ? "too short" : "not checked";
    printf("      inner handshake %s%s%s  %s%s%s\n", col(c), name, col(C::RST), col(C::DIM), t.inner_detail.c_str(),
           col(C::RST));
}

} // namespace

int run_pcap_analysis(const std::string& path) {
    std::vector<uint8_t> bytes;
    std::string err;
    PcapReport r;
    if (!capture_read_file(path, bytes, err)) r.error = err;
    else r = pcap_analyze(bytes);
    if (!r.ok) {
        if (g_json) std::fputs(("{\n  \"check\": \"pcap\",\n  \"error\": \"" + json_escape_string(r.error) + "\"\n}\n").c_str(), stdout);
        else printf("  pcap: %s\n", r.error.c_str());
        return 64;
    }
    const LeakView v = pcap_leaks(r, g_node_ip);
    bool positive = v.dns == Outcome::Positive || v.outside == Outcome::Positive;
    for (const auto& s : r.inner) positive = positive || s.outcome == Outcome::Positive;
    if (g_json) {
        std::fputs(pcap_report_json(r, v).c_str(), stdout);
        return positive ? 2 : 0;
    }

    section(1, 4, "Client hellos", std::to_string(r.records) + " records, " + std::to_string(r.skipped) + " skipped");
    printf("  %zu tcp segments, %zu udp datagrams; what a box on this link reads before any key\n",
           r.tcp_segments, r.udp_datagrams);
    if (r.tls.empty()) printf("  no tls or quic client hello in this capture\n");
    // same server, hello and result print once; sizes shown are the first flow's
    std::vector<std::pair<const TlsFlow*, size_t>> groups;
    std::map<std::string, size_t> index;
    for (const auto& t : r.tls) {
        const std::string key = t.server + "|" + t.sni + "|" + t.ja4 + "|" + t.version + "|" + t.alpn + "|" +
                                std::to_string(int(t.inner));
        auto it = index.find(key);
        if (it != index.end()) { ++groups[it->second].second; continue; }
        index[key] = groups.size();
        groups.emplace_back(&t, 1);
    }
    for (size_t i = 0; i < groups.size() && i < FLOWS_SHOWN; ++i) print_flow(*groups[i].first, v.node, groups[i].second);
    if (groups.size() > FLOWS_SHOWN)
        printf("  %s%zu more in --json%s\n", col(C::DIM), groups.size() - FLOWS_SHOWN, col(C::RST));

    section(2, 4, "Handshake inside the tunnel", "reference rule on record sizes");
    if (r.inner.empty()) printf("  no tcp tls flow to check\n");
    size_t shown = 0;
    for (const auto& s : r.inner) {
        const bool node = !v.node.empty() && s.server.compare(0, v.node.size() + 1, v.node + ":") == 0;
        if (shown >= SERVERS_SHOWN && !node && s.matched == 0) continue;
        ++shown;
        printf("    %-28s %s%-12s%s %s%s\n", s.server.c_str(), col(outcome_color(s.outcome)), outcome_name(s.outcome),
               col(C::RST), s.reason.c_str(), node ? "  [node]" : "");
    }
    if (shown < r.inner.size())
        printf("  %s%zu more servers in --json%s\n", col(C::DIM), r.inner.size() - shown, col(C::RST));

    section(3, 4, "DNS", "port 53 in the clear");
    std::map<std::string, std::set<std::string>> per;
    std::map<std::string, size_t> count;
    for (const auto& q : r.dns) { per[q.resolver].insert(q.name); ++count[q.resolver]; }
    for (const auto& kv : per) {
        const std::string addr = kv.first.substr(0, kv.first.rfind(':'));
        std::string names;
        size_t n = 0;
        for (const auto& name : kv.second) {
            if (n++ == NAMES_SHOWN) { names += ", ..."; break; }
            names += (names.empty() ? "" : ", ") + name;
        }
        const bool fake = addr.compare(0, 7, "198.18.") == 0 || addr.compare(0, 7, "198.19.") == 0;
        printf("    %-24s %s%5zu %-7s  %s\n", kv.first.c_str(), peer_is_local(addr) ? "lan " : "    ",
               count[kv.first], count[kv.first] == 1 ? "query" : "queries", names.c_str());
        if (fake) printf("      %s198.18.0.0/15 is the fake-ip range of tunnel clients; was this captured inside the tunnel?%s\n",
                         col(C::DIM), col(C::RST));
    }
    for (const auto& t : r.tls)
        if (doh_name(t.sni))
            printf("    %s dns-over-https to %s (%s): names hidden, the resolver's name is not%s\n", col(C::DIM),
                   t.sni.c_str(), t.server.c_str(), col(C::RST));
    verdict_line("dns in the clear", v.dns, v.dns_reason);

    section(4, 4, "Traffic beside the node", v.node.empty() ? std::string("no --node") : v.node);
    if (!v.node.empty()) {
        size_t n = 0;
        for (const auto& p : r.peers) {
            if (p.local || p.addr == v.node) continue;
            if (n++ == SERVERS_SHOWN) { printf("    %s...%s\n", col(C::DIM), col(C::RST)); break; }
            printf("    %s %-30s %6llu packets  %s\n", p.proto == 6 ? "tcp" : "udp",
                   (p.addr + ":" + std::to_string(p.port)).c_str(), static_cast<unsigned long long>(p.packets),
                   kb(p.bytes).c_str());
        }
    } else if (!r.peers.empty()) {
        const Peer& top = r.peers.front();
        printf("    busiest peer %s:%u (%s, %s); pass it as --node if it is your node\n", top.addr.c_str(), top.port,
               top.proto == 6 ? "tcp" : "udp", kb(top.bytes).c_str());
    }
    verdict_line("traffic beside the node", v.outside, v.outside_reason);

    printf("\n");
    card(positive ? C::ORG : C::GRN, positive ? "READABLE" : "QUIET",
         positive ? "a box on this link reads something listed above" : "nothing listed above stood out");
    printf("  %scapture on the physical interface, not inside the tunnel; the file never leaves this machine%s\n",
           col(C::DIM), col(C::RST));
    return positive ? 2 : 0;
}
