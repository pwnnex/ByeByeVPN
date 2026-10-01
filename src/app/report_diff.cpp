// SPDX-License-Identifier: GPL-3.0-or-later
#include "report_diff.h"

#include "../common/json.h"

#include <algorithm>
#include <map>
#include <set>

namespace {

using Fields = std::map<std::string, std::string>;

std::string text(const JsonValue& v) {
    if (v.is_str()) return v.as_str();
    if (v.is_num()) return std::to_string(v.as_int());
    if (v.is_bool()) return v.as_bool() ? "true" : "false";
    return "";
}

std::string keyed(const JsonValue& o, const char* id) {
    const int port = o["port"].as_int();
    return o[id].as_str() + (port ? " :" + std::to_string(port) : "");
}

// every comparable field of one report, flattened to "class|name" -> value
Fields flatten(const JsonValue& r) {
    Fields f;
    f["verdict|label"] = r["label"].as_str();
    f["verdict|tier"] = r["tspu"]["tier"].as_str();
    for (size_t i = 0; i < r["checks"].size(); ++i) {
        const JsonValue& c = r["checks"].at(i);
        f["verdict|check " + keyed(c, "id")] = c["outcome"].as_str();
    }
    for (size_t i = 0; i < r["signals"]["scored"].size(); ++i)
        f["verdict|signal " + keyed(r["signals"]["scored"].at(i), "id")] = "fired";

    f["surface|address"] = r["resolved_ip"].as_str();
    for (size_t i = 0; i < r["open_tcp"].size(); ++i)
        f["surface|tcp " + std::to_string(r["open_tcp"].at(i)["port"].as_int())] = "open";
    for (size_t i = 0; i < r["udp"].size(); ++i) {
        const JsonValue& u = r["udp"].at(i);
        if (u["responded"].as_bool())
            f["surface|udp " + std::to_string(u["port"].as_int()) + " " + u["kind"].as_str()] = "answers";
    }
    for (size_t i = 0; i < r["tls_ports"].size(); ++i) {
        const JsonValue& t = r["tls_ports"].at(i);
        const std::string p = "surface|tls " + std::to_string(t["port"].as_int()) + " ";
        f[p + "certificate"] = t["cert_sha256"].as_str();
        f[p + "subject"] = t["cert_cn"].as_str();
        f[p + "issuer"] = t["cert_issuer"].as_str();
        f[p + "version"] = t["tls_version"].as_str();
        f[p + "alpn"] = t["alpn"].as_str();
        f[p + "ja4s"] = t["utls"]["ja4s_openssl"].as_str();
    }

    f["context|score"] = text(r["score"]);
    f["context|unreliable"] = text(r["unreliable"]);
    for (size_t i = 0; i < r["geo"].size(); ++i) {
        const JsonValue& g = r["geo"].at(i);
        std::string tags;
        for (const char* k : {"is_vpn", "is_proxy", "is_tor", "is_hosting"})
            if (g[k].as_bool()) tags += (tags.empty() ? "" : ",") + std::string(k + 3);
        if (g["err"].as_str().empty()) f["context|geoip " + g["source"].as_str()] = tags.empty() ? "none" : tags;
    }
    // empty values say nothing; keep the map to what each report states
    for (auto it = f.begin(); it != f.end();) it = it->second.empty() ? f.erase(it) : std::next(it);
    return f;
}

int rank(const std::string& cls) { return cls == "verdict" ? 0 : cls == "surface" ? 1 : 2; }

} // namespace

ReportDiff diff_reports(const std::string& a_json, const std::string& b_json) {
    ReportDiff d;
    bool oka = false, okb = false;
    const JsonValue a = json_parse(a_json, &oka), b = json_parse(b_json, &okb);
    auto valid = [](bool ok, const JsonValue& v) {
        return ok && v.is_obj() && v["tool"].as_str() == "byebyevpn" && v.has("label") && v.has("checks");
    };
    if (!valid(oka, a) || !valid(okb, b)) {
        d.error = !valid(oka, a) ? "first file is not a byebyevpn scan report (--json)"
                                 : "second file is not a byebyevpn scan report (--json)";
        return d;
    }
    d.target_a = a["target"].as_str();
    d.target_b = b["target"].as_str();
    const Fields fa = flatten(a), fb = flatten(b);
    std::set<std::string> keys;
    for (const auto& kv : fa) keys.insert(kv.first);
    for (const auto& kv : fb) keys.insert(kv.first);
    for (const auto& k : keys) {
        auto ia = fa.find(k), ib = fb.find(k);
        const std::string va = ia == fa.end() ? "" : ia->second, vb = ib == fb.end() ? "" : ib->second;
        if (va == vb) continue;
        const size_t bar = k.find('|');
        d.items.push_back({k.substr(0, bar), k.substr(bar + 1), va, vb});
    }
    std::stable_sort(d.items.begin(), d.items.end(),
                     [](const DiffItem& x, const DiffItem& y) { return rank(x.cls) < rank(y.cls); });
    d.ok = true;
    return d;
}

int diff_exit_code(const ReportDiff& d) {
    if (!d.ok) return 64;
    int rc = 0;
    for (const auto& i : d.items) rc = std::max(rc, i.cls == "verdict" ? 2 : 1);
    return rc;
}

std::string diff_json(const std::vector<std::pair<std::string, ReportDiff>>& pairs) {
    auto q = [](const std::string& s) { return "\"" + json_escape_string(s) + "\""; };
    std::string o = "{\n  \"check\": \"diff\",\n  \"pairs\": [";
    for (size_t p = 0; p < pairs.size(); ++p) {
        const ReportDiff& d = pairs[p].second;
        o += std::string(p ? "," : "") + "\n    { \"name\": " + q(pairs[p].first) +
             ", \"ok\": " + (d.ok ? "true" : "false") + ", \"error\": " + q(d.error) +
             ", \"target_a\": " + q(d.target_a) + ", \"target_b\": " + q(d.target_b) +
             ", \"exit\": " + std::to_string(diff_exit_code(d)) + ", \"changes\": [";
        for (size_t i = 0; i < d.items.size(); ++i) {
            const DiffItem& it = d.items[i];
            o += std::string(i ? "," : "") + "\n      { \"class\": " + q(it.cls) + ", \"what\": " + q(it.what) +
                 ", \"from\": " + q(it.from) + ", \"to\": " + q(it.to) + " }";
        }
        o += d.items.empty() ? "] }" : "\n    ] }";
    }
    o += pairs.empty() ? "]\n}\n" : "\n  ]\n}\n";
    return o;
}
