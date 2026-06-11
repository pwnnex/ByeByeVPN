// SPDX-License-Identifier: GPL-3.0-or-later
// pure CIDR + clustering logic for the subnet sweep. no networking, no Win32 —
// compiled into the Linux unit-test build.
#include "sweep.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>

using std::string;
using std::vector;

namespace {

// parse "a.b.c.d" into a host-order uint32. false on malformed input.
bool parse_ipv4(const string& s, uint32_t& out) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    char extra = 0;
    // %c catches trailing junk like "1.2.3.4.5".
    int n = std::sscanf(s.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra);
    if (n != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    out = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

string ipv4_to_str(uint32_t v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  (v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff);
    return buf;
}

} // namespace

bool parse_cidr(const string& cidr, vector<string>& out, int max_hosts, string& err) {
    out.clear();
    err.clear();
    string ip = cidr;
    int prefix = 32;
    size_t slash = cidr.find('/');
    if (slash != string::npos) {
        ip = cidr.substr(0, slash);
        string ps = cidr.substr(slash + 1);
        if (ps.empty()) { err = "missing prefix length after '/'"; return false; }
        for (char ch : ps) if (ch < '0' || ch > '9') { err = "non-numeric prefix"; return false; }
        prefix = std::atoi(ps.c_str());
    }
    if (prefix < 0 || prefix > 32) { err = "prefix must be 0..32"; return false; }

    uint32_t base = 0;
    if (!parse_ipv4(ip, base)) { err = "malformed IPv4 address"; return false; }

    uint64_t count = (uint64_t)1 << (32 - prefix);
    if (count > (uint64_t)max_hosts) {
        err = "range too large (" + std::to_string(count) + " hosts, cap " +
              std::to_string(max_hosts) + ") — use a longer prefix";
        return false;
    }
    uint32_t mask    = (prefix == 0) ? 0u : (0xffffffffu << (32 - prefix));
    uint32_t network = base & mask;
    out.reserve((size_t)count);
    for (uint64_t i = 0; i < count; ++i)
        out.push_back(ipv4_to_str(network + (uint32_t)i));
    return true;
}

string sweep_cluster_key(const SweepHost& h) {
    if (!h.open443) return "down";
    if (!h.tls_ok)  return "open443-no-tls";
    // JA4S ext-hash is the part after the last '_'.
    string exthash = h.ja4s;
    size_t u = h.ja4s.rfind('_');
    if (u != string::npos) exthash = h.ja4s.substr(u + 1);
    if (exthash.empty()) exthash = "?";
    string key = "ja4s:" + exthash;
    key += " | issuer=" + (h.issuer_cn.empty() ? "(none)" : h.issuer_cn);
    if (!h.cert_sha16.empty()) key += " | cert=" + h.cert_sha16;
    return key;
}

vector<std::pair<string, vector<SweepHost>>>
cluster_hosts(const vector<SweepHost>& hosts) {
    // preserve first-seen order of keys, then sort by descending size.
    std::map<string, size_t> index;
    vector<std::pair<string, vector<SweepHost>>> groups;
    for (const auto& h : hosts) {
        string k = sweep_cluster_key(h);
        auto it = index.find(k);
        if (it == index.end()) {
            index[k] = groups.size();
            groups.push_back({k, {h}});
        } else {
            groups[it->second].second.push_back(h);
        }
    }
    std::stable_sort(groups.begin(), groups.end(),
                     [](const auto& a, const auto& b) {
                         return a.second.size() > b.second.size();
                     });
    return groups;
}
