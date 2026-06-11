// SPDX-License-Identifier: GPL-3.0-or-later
#include "config_audit.h"
#include "../common/util.h"
#include "../scan/brand.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <vector>

using std::string;
using std::vector;

namespace {

// the 3x-ui / x-ui / Marzban panel-installer TLS-port cluster — the same set
// the live scanner flags. two or more of these open is an installer
// fingerprint.
bool is_panel_port(int p) {
    switch (p) {
        case 2053: case 2083: case 2087: case 2096:
        case 8443: case 8880: case 6443: case 7443: case 9443:
            return true;
        default: return false;
    }
}

// read a port out of a JSON value that may be a number ("port": 443) or a
// string ("listen_port": "443", or even "0.0.0.0:443"). -1 if absent.
int json_port(const JsonValue& v) {
    if (v.is_num()) return (int)v.as_num();
    if (v.is_str()) {
        string s = v.as_str();
        if (s.empty()) return -1;
        size_t c = s.rfind(':');
        string ps = (c != string::npos) ? s.substr(c + 1) : s;
        if (ps.empty()) return -1;
        for (char ch : ps) if (!std::isdigit((unsigned char)ch)) return -1;
        return std::atoi(ps.c_str());
    }
    return -1;
}

// split a Reality dest like "www.example.com:443" into host + port. a bare
// host leaves port = -1. IPv6 literals (rare in dest=) are left intact.
void split_host_port(const string& dest, string& host, int& port) {
    host = dest;
    port = -1;
    if (dest.find(']') != string::npos) return;   // looks like [v6]:p — skip
    size_t c = dest.rfind(':');
    if (c == string::npos || c + 1 >= dest.size()) return;
    string ps = dest.substr(c + 1);
    for (char ch : ps) if (!std::isdigit((unsigned char)ch)) return;
    host = dest.substr(0, c);
    port = std::atoi(ps.c_str());
}

// does any user/client entry carry the xtls-rprx-vision flow? vision padding
// is what hides the VLESS packet-length fingerprint, so its absence on a
// reality/tls VLESS inbound is a soft tell.
bool clients_have_vision(const JsonValue& clients) {
    if (!clients.is_arr()) return false;
    for (size_t i = 0; i < clients.size(); ++i) {
        string fl = tolower_s(clients.at(i)["flow"].as_str());
        if (fl.find("xtls-rprx-vision") != string::npos) return true;
    }
    return false;
}

// a deprecated XTLS flow (direct/origin/splice) is both removed from modern
// Xray and a recognisable older-deployment tell. returns the offending flow.
bool clients_flow_deprecated(const JsonValue& clients, string& which) {
    if (!clients.is_arr()) return false;
    for (size_t i = 0; i < clients.size(); ++i) {
        string fl = tolower_s(clients.at(i)["flow"].as_str());
        if (fl.find("xtls-rprx-direct") != string::npos ||
            fl.find("xtls-rprx-origin") != string::npos ||
            fl.find("xtls-rprx-splice") != string::npos) { which = fl; return true; }
    }
    return false;
}

// true iff a short-id list has at least one non-empty entry. an all-empty (or
// missing) list lets clients connect with no shortId, which both weakens the
// auth and is itself a recognisable default.
bool has_nonempty_shortid(const JsonValue& sid) {
    if (!sid.is_arr()) return false;
    for (size_t i = 0; i < sid.size(); ++i)
        if (!sid.at(i).as_str().empty()) return true;
    return false;
}

struct Auditor {
    ConfigAudit& A;
    std::set<int> panel_hits;
    int reality_inbounds = 0;

    explicit Auditor(ConfigAudit& a) : A(a) {}

    void add(AuditFinding::Sev sev, bool named, const string& tag,
             const string& where, const string& title, const string& fix) {
        AuditFinding f;
        f.sev = sev; f.named = named; f.tag = tag;
        f.where = where; f.title = title; f.fix = fix;
        A.findings.push_back(std::move(f));
    }

    void reality_dest_brand(const string& host, const string& where) {
        if (host.empty()) return;
        string brand = cert_claims_brand(host, {});
        if (brand.empty()) return;
        add(AuditFinding::Sev::High, false, "reality-dest-brand", where,
            "Reality dest/handshake target is the major brand '" + brand +
            "'. The endpoint will serve that brand's cert on your VPS ASN, "
            "which does not own the brand — the cheapest cert-impersonation "
            "tell (matches the scanner's brand-on-non-owning-ASN signal).",
            "Point dest= at a real site hosted on the SAME ASN/CDN netblock as "
            "your VPS (e.g. a small regional site on the same provider), or — "
            "safer — a domain you actually own with a full LE chain. Never "
            "amazon/apple/microsoft/google/cloudflare on a rented VPS.");
    }

    void reality_common(const string& host, int dport, bool has_shortid,
                        const string& where) {
        reality_dest_brand(host, where);
        if (dport > 0 && dport != 443)
            add(AuditFinding::Sev::Medium, false, "reality-dest-port", where,
                "Reality handshake target port is " + std::to_string(dport) +
                ", not 443. A real browser only speaks TLS to :443; a non-443 "
                "steering target is anomalous.",
                "Use a :443 handshake target.");
        if (!has_shortid)
            add(AuditFinding::Sev::Medium, false, "reality-shortid-empty", where,
                "Reality shortId list is empty or missing — clients can connect "
                "with no shortId, which is a recognisable lazy-default.",
                "Generate at least one non-empty shortId (e.g. `openssl rand "
                "-hex 8`) and remove the empty \"\" entry.");
    }

    // ---- Xray / v2ray-core inbound ------------------------------------
    void xray_inbound(const JsonValue& in, int idx) {
        string proto = tolower_s(in["protocol"].as_str());
        const JsonValue& ss = in["streamSettings"];
        string sec = tolower_s(ss["security"].as_str());
        string net = tolower_s(ss["network"].as_str("tcp"));
        int port = json_port(in["port"]);
        string where = "inbound[" + std::to_string(idx) + "] " + proto +
                       (port > 0 ? " :" + std::to_string(port) : "");

        if (port > 0 && is_panel_port(port)) panel_hits.insert(port);

        bool has_tls = (sec == "tls" || sec == "reality" || sec == "xtls");

        if (proto == "shadowsocks" && (port == 8388 || port == 8488))
            add(AuditFinding::Sev::High, true, "shadowsocks-default-port", where,
                "Shadowsocks on its default port. Trivially probed by the AEAD "
                "length oracle and a named TSPU signature.",
                "Wrap it in VLESS+Reality, or at minimum move off 8388/8488.");

        if (proto == "wireguard" && port == 51820)
            add(AuditFinding::Sev::High, true, "wireguard-default-port", where,
                "WireGuard inbound on UDP/51820. The MessageInitiation layout is "
                "a fixed-offset signature TSPU fingerprints directly.",
                "Use AmneziaWG (obfuscated WG) and move off the default port.");

        if ((proto == "vless" || proto == "vmess" || proto == "trojan") && !has_tls)
            add(AuditFinding::Sev::High, true, "plaintext-proto", where,
                proto + " inbound with security=none — the protocol framing is "
                "in cleartext on the wire and reads directly to any DPI.",
                "Set security=reality (preferred) or tls with a real cert.");

        if ((net == "ws" || net == "grpc" || net == "httpupgrade" ||
             net == "h2" || net == "http") && !has_tls)
            add(AuditFinding::Sev::High, false, "plaintext-transport", where,
                net + " transport without TLS — the inner protocol is exposed "
                "and the transport header pattern is itself fingerprintable.",
                "Always run ws/grpc/httpupgrade under TLS.");

        if (sec == "reality") {
            ++reality_inbounds;
            const JsonValue& rs = ss["realitySettings"];
            string dest = rs["dest"].as_str();
            if (dest.empty()) dest = rs["target"].as_str();
            string host; int dport; split_host_port(dest, host, dport);
            reality_common(host, dport, has_nonempty_shortid(rs["shortIds"]), where);

            if (rs["show"].as_bool())
                add(AuditFinding::Sev::Medium, false, "reality-show", where,
                    "realitySettings.show is true — debug handshake logging is "
                    "on. Harmless on the wire but leaks operationally.",
                    "Set show=false in production.");

            const JsonValue& sn = rs["serverNames"];
            if (!sn.is_arr() || sn.size() == 0)
                add(AuditFinding::Sev::Medium, false, "reality-no-servernames", where,
                    "Reality serverNames is empty — the SNI clients send won't "
                    "match the dest, breaking the cover story.",
                    "Set serverNames to the dest's real hostname.");

            const JsonValue& fb = in["settings"]["fallbacks"];
            if (proto == "vless" && net == "tcp" && (!fb.is_arr() || fb.size() == 0))
                add(AuditFinding::Sev::Info, false, "no-fallback", where,
                    "No fallbacks configured. Non-handshake / junk bytes get no "
                    "real HTTP reply — the exact silent-on-junk pattern the "
                    "scanner's J3 phase flags.",
                    "Add a fallback to a real nginx so unrecognised bytes return "
                    "a genuine HTTP 400/502 with a Server: header.");
        }

        if (proto == "vless" && (sec == "reality" || sec == "tls") && net == "tcp") {
            string depflow;
            if (clients_flow_deprecated(in["settings"]["clients"], depflow))
                add(AuditFinding::Sev::High, false, "deprecated-flow", where,
                    "VLESS uses the deprecated XTLS flow '" + depflow +
                    "' — removed from modern Xray and a recognisable legacy "
                    "fingerprint; xtls-rprx-vision replaced it.",
                    "Switch the flow to xtls-rprx-vision.");
            else if (!clients_have_vision(in["settings"]["clients"]))
                add(AuditFinding::Sev::Medium, false, "no-vision-flow", where,
                    "VLESS over TCP without xtls-rprx-vision flow — packet-length "
                    "padding is off, so the flow's length distribution is "
                    "more distinguishable.",
                    "Set flow to xtls-rprx-vision on the client entries.");
        }

        if (sec == "tls") {
            string mv = ss["tlsSettings"]["minVersion"].as_str();
            if (!mv.empty() && mv < "1.3")
                add(AuditFinding::Sev::Medium, false, "tls-min-version", where,
                    "tlsSettings.minVersion=" + mv + " (below 1.3) — modern clients "
                    "expect TLS 1.3; a lower floor widens the handshake fingerprint.",
                    "Set tlsSettings.minVersion to \"1.3\".");
        }
    }

    // ---- sing-box inbound ----------------------------------------------
    void singbox_inbound(const JsonValue& in, int idx) {
        string type = tolower_s(in["type"].as_str());
        int port = json_port(in["listen_port"]);
        string where = "inbound[" + std::to_string(idx) + "] " + type +
                       (port > 0 ? " :" + std::to_string(port) : "");

        if (port > 0 && is_panel_port(port)) panel_hits.insert(port);

        const JsonValue& tls = in["tls"];
        bool tls_en = tls["enabled"].as_bool();
        const JsonValue& reality = tls["reality"];
        bool reality_en = reality["enabled"].as_bool();

        if (type == "shadowsocks" && (port == 8388 || port == 8488))
            add(AuditFinding::Sev::High, true, "shadowsocks-default-port", where,
                "Shadowsocks on its default port — named TSPU signature + AEAD "
                "length-oracle probeable.",
                "Move off 8388/8488 and prefer VLESS+Reality.");

        if (type == "wireguard" && port == 51820)
            add(AuditFinding::Sev::High, true, "wireguard-default-port", where,
                "WireGuard inbound on UDP/51820 — fixed-layout handshake "
                "signature on the default port.",
                "Use AmneziaWG and move off 51820.");

        if (type == "hysteria2")
            add(AuditFinding::Sev::Medium, true, "hysteria2", where,
                "Hysteria2 (QUIC) inbound — a QUIC v1 Initial to a hosting IP "
                "with no matching web presence is a named tunnel signature.",
                "Front it with a real HTTP/3 site on the same IP, or move off "
                "the default Hysteria2 port range.");

        if (type == "tuic")
            add(AuditFinding::Sev::Medium, true, "tuic", where,
                "TUIC (QUIC) inbound — QUIC-based tunnel signature on a hosting "
                "IP.",
                "Same as Hysteria2: co-host a real HTTP/3 origin or rotate ports.");

        if ((type == "vless" || type == "vmess" || type == "trojan") &&
            !tls_en && !reality_en)
            add(AuditFinding::Sev::High, true, "plaintext-proto", where,
                type + " inbound with TLS disabled and no Reality — cleartext "
                "framing on the wire.",
                "Enable tls.reality (preferred) or tls with a real cert.");

        if (reality_en) {
            ++reality_inbounds;
            const JsonValue& hs = reality["handshake"];
            string server = hs["server"].as_str();
            int sport = json_port(hs["server_port"]);
            reality_common(server, sport, has_nonempty_shortid(reality["short_id"]), where);
        }

        if (tls_en) {
            string mv = tls["min_version"].as_str();
            if (!mv.empty() && mv < "1.3")
                add(AuditFinding::Sev::Medium, false, "tls-min-version", where,
                    "tls.min_version=" + mv + " (below 1.3) — modern clients expect "
                    "TLS 1.3; a lower floor widens the handshake fingerprint.",
                    "Set tls.min_version to \"1.3\".");
        }

        if (type == "vless" && (tls_en || reality_en)) {
            string depflow;
            if (clients_flow_deprecated(in["users"], depflow))
                add(AuditFinding::Sev::High, false, "deprecated-flow", where,
                    "VLESS uses the deprecated XTLS flow '" + depflow +
                    "' — removed from modern cores; xtls-rprx-vision replaced it.",
                    "Switch the flow to xtls-rprx-vision.");
            else if (!clients_have_vision(in["users"]))
                add(AuditFinding::Sev::Medium, false, "no-vision-flow", where,
                    "VLESS without xtls-rprx-vision flow — length-padding off.",
                    "Set flow to xtls-rprx-vision on the user entries.");
        }
    }

    void finish() {
        if (panel_hits.size() >= 2) {
            string ports;
            for (int p : panel_hits) { if (!ports.empty()) ports += ","; ports += std::to_string(p); }
            add(AuditFinding::Sev::Medium, false, "panel-cluster", "config",
                std::to_string(panel_hits.size()) + " of the 3x-ui/x-ui/Marzban "
                "panel-installer TLS ports are used ({" + ports + "}) — that exact "
                "cluster is one of the strongest installer fingerprints DPI looks for.",
                "Keep ONE real inbound on :443; close/relocate the rest and "
                "firewall the panel UI to admin IPs only.");
        }
        if (reality_inbounds >= 2) {
            add(AuditFinding::Sev::Medium, false, "reality-multiport", "config",
                std::to_string(reality_inbounds) + " inbounds run Reality on this IP — "
                "multi-port TLS cert-steering is an ASN/port-sweep anomaly.",
                "Keep Reality on a single port; fill the other ports with real "
                "services or close them.");
        }
    }
};

// dedupe exact-duplicate findings (same tag + location), then tally severities
// and resolve the predicted TSPU tier. shared by the JSON and INI auditors.
void finalize_audit(ConfigAudit& A) {
    std::vector<AuditFinding> uniq;
    for (auto& f : A.findings) {
        bool dup = false;
        for (auto& g : uniq) if (g.tag == f.tag && g.where == f.where) { dup = true; break; }
        if (!dup) uniq.push_back(f);
    }
    A.findings.swap(uniq);

    int high_soft = 0, medium_soft = 0;
    A.high = A.medium = A.info = A.a_hits = A.b_hits = 0;
    for (auto& f : A.findings) {
        switch (f.sev) {
            case AuditFinding::Sev::High:   ++A.high; break;
            case AuditFinding::Sev::Medium: ++A.medium; break;
            case AuditFinding::Sev::Info:   ++A.info; break;
        }
        if (f.named) { ++A.a_hits; continue; }
        ++A.b_hits;
        if (f.sev == AuditFinding::Sev::High)   ++high_soft;
        if (f.sev == AuditFinding::Sev::Medium) ++medium_soft;
    }
    if (A.a_hits > 0) {
        A.tspu_tier = "IMMEDIATE BLOCK";
        A.verdict_line = "a named protocol signature is present in the config — "
                         "TSPU would drop this on first handshake inspection.";
    } else if (high_soft >= 1 || medium_soft >= 2) {
        A.tspu_tier = "BLOCK (accumulative)";
        A.verdict_line = "multiple soft anomalies accumulate past the classifier "
                         "threshold — this would be blocked over time.";
    } else if (medium_soft == 1) {
        A.tspu_tier = "THROTTLE / QoS";
        A.verdict_line = "one soft anomaly — flagged for monitoring / rate-limit, "
                         "not an instant block.";
    } else {
        A.tspu_tier = "PASS / ALLOW";
        A.verdict_line = "no detectability tell found in the config — looks like a "
                         "clean TLS origin to passive DPI.";
    }
}

// collect inbound objects from a root that may be a full config (with an
// "inbounds" array), a bare inbounds array, or a single inbound object.
vector<const JsonValue*> collect_inbounds(const JsonValue& root) {
    vector<const JsonValue*> out;
    const JsonValue& ib = root["inbounds"];
    if (ib.is_arr()) {
        for (size_t i = 0; i < ib.size(); ++i) out.push_back(&ib.at(i));
    } else if (root.is_arr()) {
        for (size_t i = 0; i < root.size(); ++i) out.push_back(&root.at(i));
    } else if (root.is_obj() && (root.has("protocol") || root.has("type"))) {
        out.push_back(&root);
    }
    return out;
}

} // namespace

ConfigAudit audit_config_json(const JsonValue& root) {
    ConfigAudit A;
    vector<const JsonValue*> inbounds = collect_inbounds(root);
    if (inbounds.empty()) {
        A.ok = false;
        A.err = "no inbounds found (not an Xray/sing-box config, or empty)";
        return A;
    }
    A.ok = true;
    A.inbound_count = (int)inbounds.size();

    // format: decide by the first inbound's discriminator key.
    if      (inbounds[0]->has("protocol")) A.format = "xray";
    else if (inbounds[0]->has("type"))     A.format = "sing-box";

    Auditor au{A};
    for (int i = 0; i < (int)inbounds.size(); ++i) {
        const JsonValue& in = *inbounds[i];
        if (in.has("protocol"))   au.xray_inbound(in, i);
        else if (in.has("type"))  au.singbox_inbound(in, i);
    }
    au.finish();

    finalize_audit(A);
    return A;
}

// ---- WireGuard / AmneziaWG .conf (INI) -------------------------------------

ConfigAudit audit_wireguard_ini(const string& text) {
    ConfigAudit A;
    A.ok = true;
    A.format = "wireguard";
    A.inbound_count = 1;

    // parse the [Interface] section into a lowercased key->value map.
    std::map<string, string> iface;
    string section;
    for (auto& rawln : split(text, '\n')) {
        string ln = trim(rawln);
        if (ln.empty() || ln[0] == '#' || ln[0] == ';') continue;
        if (ln[0] == '[') { section = tolower_s(ln); continue; }
        if (section.find("interface") == string::npos) continue;
        size_t eq = ln.find('=');
        if (eq == string::npos) continue;
        iface[tolower_s(trim(ln.substr(0, eq)))] = trim(ln.substr(eq + 1));
    }
    if (iface.empty()) {
        A.ok = false;
        A.err = "no [Interface] section found (not a WireGuard/AmneziaWG .conf)";
        return A;
    }

    int port = iface.count("listenport") ? std::atoi(iface["listenport"].c_str()) : -1;
    bool amnezia = iface.count("jc") || iface.count("jmin") || iface.count("jmax") ||
                   iface.count("s1") || iface.count("s2") || iface.count("h1") ||
                   iface.count("h2") || iface.count("h3") || iface.count("h4");
    string where = string("[Interface]") + (port > 0 ? " :" + std::to_string(port) : "");

    AuditFinding f;
    auto add = [&](AuditFinding::Sev sev, bool named, const string& tag,
                   const string& title, const string& fix) {
        AuditFinding x; x.sev = sev; x.named = named; x.tag = tag;
        x.where = where; x.title = title; x.fix = fix;
        A.findings.push_back(std::move(x));
    };

    if (!amnezia) {
        if (port == 51820)
            add(AuditFinding::Sev::High, true, "wireguard-default-port",
                "Plain WireGuard on UDP/51820 — the MessageInitiation layout is a "
                "fixed-offset signature TSPU fingerprints directly on the default port.",
                "Use AmneziaWG (set Jc/Jmin/Jmax/S1/S2/H1-H4) and move off 51820.");
        else
            add(AuditFinding::Sev::Medium, true, "wireguard-plain",
                "Plain WireGuard (no AmneziaWG obfuscation) — the handshake layout is a "
                "fixed signature regardless of port.",
                "Switch to AmneziaWG obfuscation parameters.");
    } else {
        if (port == 51820)
            add(AuditFinding::Sev::Medium, false, "amneziawg-default-port",
                "AmneziaWG on the default WG port :51820 — even obfuscated, a fixed "
                "junk-prefix on the canonical port is a coarse pattern.",
                "Move off 51820.");
        add(AuditFinding::Sev::Info, false, "amneziawg-detected",
            "AmneziaWG obfuscation parameters present (Jc/Jmin/Jmax/S1/S2/H1-H4). Good — "
            "but a FIXED parameter set reused across deployments is itself a fingerprint.",
            "Randomize Jc/Jmin/Jmax/S1/S2/H1-H4 per deployment and avoid preset defaults.");
    }

    finalize_audit(A);
    return A;
}

// ---- format auto-detect ----------------------------------------------------

ConfigAudit audit_config_text(const string& text) {
    // a WireGuard/AmneziaWG .conf carries an [Interface] section (which also
    // makes it start with '['), so check that BEFORE assuming a leading '['
    // means a JSON array.
    if (tolower_s(text).find("[interface]") != string::npos)
        return audit_wireguard_ini(text);

    bool ok = false;
    JsonValue root = json_parse(text, &ok);
    if (!ok) {
        ConfigAudit A;
        A.ok = false;
        A.err = "parse failed (not valid JSON, and not a WireGuard .conf)";
        return A;
    }
    return audit_config_json(root);
}

// ---- JSON serializer (for --json) ------------------------------------------

namespace {
string jesc(const string& s) {
    string o;
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if ((unsigned char)c < 0x20) { char b[8]; std::snprintf(b, sizeof(b), "\\u%04x", c); o += b; }
                else o += c;
        }
    }
    return o;
}
const char* sev_name(AuditFinding::Sev s) {
    switch (s) {
        case AuditFinding::Sev::High:   return "high";
        case AuditFinding::Sev::Medium: return "medium";
        default:                        return "info";
    }
}
} // namespace

string config_audit_to_json(const ConfigAudit& a) {
    string o = "{\n";
    o += "  \"ok\": " + string(a.ok ? "true" : "false") + ",\n";
    if (!a.ok) { o += "  \"error\": \"" + jesc(a.err) + "\"\n}\n"; return o; }
    o += "  \"format\": \"" + jesc(a.format) + "\",\n";
    o += "  \"inbounds\": " + std::to_string(a.inbound_count) + ",\n";
    o += "  \"tspu_tier\": \"" + jesc(a.tspu_tier) + "\",\n";
    o += "  \"a_hits\": " + std::to_string(a.a_hits) + ",\n";
    o += "  \"b_hits\": " + std::to_string(a.b_hits) + ",\n";
    o += "  \"counts\": { \"high\": " + std::to_string(a.high) +
         ", \"medium\": " + std::to_string(a.medium) +
         ", \"info\": " + std::to_string(a.info) + " },\n";
    o += "  \"verdict\": \"" + jesc(a.verdict_line) + "\",\n";
    o += "  \"findings\": [";
    for (size_t i = 0; i < a.findings.size(); ++i) {
        const AuditFinding& f = a.findings[i];
        o += (i ? ",\n" : "\n");
        o += "    { \"severity\": \"" + string(sev_name(f.sev)) + "\"";
        o += ", \"named\": " + string(f.named ? "true" : "false");
        o += ", \"tag\": \"" + jesc(f.tag) + "\"";
        o += ", \"where\": \"" + jesc(f.where) + "\"";
        o += ", \"title\": \"" + jesc(f.title) + "\"";
        o += ", \"fix\": \"" + jesc(f.fix) + "\" }";
    }
    o += (a.findings.empty() ? "]\n" : "\n  ]\n");
    o += "}\n";
    return o;
}
