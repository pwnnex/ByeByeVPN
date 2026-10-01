// SPDX-License-Identifier: GPL-3.0-or-later
#include "ct_names.h"
#include "hostname_input.h"
#include "../common/json.h"
#include "../common/util.h"

#include <algorithm>
#include <cmath>
#include <map>
#include <set>

namespace {

int rank(const CtName& n) { return n.marks.strong ? 0 : n.marks.moderate ? 1 : n.marks.weak ? 2 : 3; }

std::string jstr(const std::string& s) { return "\"" + json_escape_string(s) + "\""; }

} // namespace

CtNames parse_ct_names(const std::string& body, const std::string& domain_in) {
    CtNames r;
    const HostnameInput d = parse_hostname(domain_in);
    if (d.status != HostnameInput::Status::Hostname || d.wildcard) {
        r.err = "not a domain name";
        return r;
    }
    r.domain = d.canonical;
    bool ok = false;
    const auto root = json_parse(trim(body), &ok);
    if (!ok || !root.is_arr()) { r.err = "invalid crt.sh JSON array"; return r; }

    struct Acc { bool wildcard = false; std::set<double> ids; std::string first; };
    std::map<std::string, Acc> acc;
    std::set<double> all_ids;
    for (const auto& row : root.arr) {
        const auto& id = row["id"];
        if (!row.is_obj() || !id.is_num() || !std::isfinite(id.num) || id.num < 1 || std::floor(id.num) != id.num) {
            r.err = "invalid crt.sh record";
            return r;
        }
        all_ids.insert(id.num);
        const std::string seen = row["not_before"].as_str().substr(0, 10);
        std::vector<std::string> values = split(row["name_value"].as_str(), '\n');
        values.push_back(row["common_name"].as_str());
        for (std::string v : values) {
            v = tolower_s(trim(v));
            bool wild = false;
            if (v.rfind("*.", 0) == 0) { wild = true; v = v.substr(2); }
            while (!v.empty() && v.back() == '.') v.pop_back();
            // mail addresses, ip literals and names under another domain drop out here
            const HostnameInput h = parse_hostname(v);
            if (h.status != HostnameInput::Status::Hostname || h.wildcard) continue;
            const std::string& c = h.canonical;
            if (c != r.domain && (c.size() <= r.domain.size() + 1 ||
                                  c.compare(c.size() - r.domain.size() - 1, std::string::npos, "." + r.domain) != 0))
                continue;
            Acc& a = acc[c];
            a.wildcard |= wild;
            a.ids.insert(id.num);
            if (!seen.empty() && (a.first.empty() || seen < a.first)) a.first = seen;
        }
    }
    for (const auto& [name, a] : acc) {
        CtName n;
        n.name = name;
        n.wildcard = a.wildcard;
        n.certificates = (int)a.ids.size();
        n.first_seen = a.first;
        n.marks = analyze_hostname(name);
        r.names.push_back(std::move(n));
    }
    std::stable_sort(r.names.begin(), r.names.end(),
                     [](const CtName& x, const CtName& y) { return rank(x) < rank(y); });
    r.certificates = (int)all_ids.size();
    r.lookup_complete = true;
    return r;
}

std::vector<SharedAddress> ct_shared_addresses(const CtNames& ct,
                                               const std::vector<std::pair<std::string, std::vector<std::string>>>& resolved,
                                               const std::string& node_ip) {
    std::map<std::string, std::set<std::string>> by_ip;
    for (const auto& [name, ips] : resolved)
        for (const auto& ip : ips) by_ip[ip].insert(name);
    std::map<std::string, const CtName*> index;
    for (const auto& n : ct.names) index[n.name] = &n;
    std::vector<SharedAddress> out;
    for (const auto& [ip, names] : by_ip) {
        SharedAddress s;
        s.ip = ip;
        s.node = !node_ip.empty() && ip == node_ip;
        if (names.size() < 2 && !s.node) continue;
        for (const auto& n : names) {
            s.names.push_back(n);
            auto it = index.find(n);
            if (it != index.end() && (it->second->marks.strong || it->second->marks.moderate)) s.marked = true;
        }
        out.push_back(std::move(s));
    }
    // the node first, then marked groups
    std::stable_sort(out.begin(), out.end(), [](const SharedAddress& a, const SharedAddress& b) {
        return (a.node ? 0 : a.marked ? 1 : 2) < (b.node ? 0 : b.marked ? 1 : 2);
    });
    return out;
}

std::string ct_names_json(const CtNames& ct, const std::vector<SharedAddress>& shared) {
    std::string o = "{\n  \"domain\": " + jstr(ct.domain) + ",\n";
    o += "  \"lookup_complete\": " + std::string(ct.lookup_complete ? "true" : "false") + ",\n";
    o += "  \"error\": " + (ct.err.empty() ? std::string("null") : jstr(ct.err)) + ",\n";
    o += "  \"certificates\": " + std::to_string(ct.certificates) + ",\n  \"names\": [";
    for (size_t i = 0; i < ct.names.size(); ++i) {
        const auto& n = ct.names[i];
        o += std::string(i ? "," : "") + "\n    { \"name\": " + jstr(n.name) +
             ", \"wildcard\": " + (n.wildcard ? "true" : "false") +
             ", \"certificates\": " + std::to_string(n.certificates) +
             ", \"first_seen\": " + jstr(n.first_seen) + ", \"marks\": [";
        for (size_t j = 0; j < n.marks.marks.size(); ++j)
            o += std::string(j ? ", " : "") + "{ \"token\": " + jstr(n.marks.marks[j].token) +
                 ", \"tier\": " + jstr(hostname_tier_name(n.marks.marks[j].tier)) + " }";
        o += "] }";
    }
    o += ct.names.empty() ? "],\n" : "\n  ],\n";
    o += "  \"shared_addresses\": [";
    for (size_t i = 0; i < shared.size(); ++i) {
        const auto& s = shared[i];
        o += std::string(i ? "," : "") + "\n    { \"ip\": " + jstr(s.ip) + ", \"node\": " + (s.node ? "true" : "false") +
             ", \"marked\": " + (s.marked ? "true" : "false") + ", \"names\": [";
        for (size_t j = 0; j < s.names.size(); ++j) o += std::string(j ? ", " : "") + jstr(s.names[j]);
        o += "] }";
    }
    o += shared.empty() ? "]\n}\n" : "\n  ]\n}\n";
    return o;
}
