// SPDX-License-Identifier: GPL-3.0-or-later
#include "config_audit.h"
#include "../common/util.h"
#include "../scan/brand.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

using std::string;
using std::vector;

namespace {

// the 3x-ui / x-ui / marzban panel-installer tls-port cluster - the same set
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

// read a port out of a json value that may be a number ("port": 443) or a
// string ("listen_port": "443", or even "0.0.0.0:443"). -1 if absent.
int parse_port(const string& s) {
    int n = -1;
    auto r = std::from_chars(s.data(), s.data() + s.size(), n);
    return r.ec == std::errc{} && r.ptr == s.data() + s.size() && n > 0 && n <= 65535 ? n : -1;
}

int json_port(const JsonValue& v) {
    if (v.is_num()) {
        int n = v.as_int(-1);
        return n > 0 && n <= 65535 && v.as_num() == n ? n : -1;
    }
    if (v.is_str()) {
        string s = v.as_str();
        if (s.empty()) return -1;
        size_t c = s.rfind(':');
        string ps = (c != string::npos) ? s.substr(c + 1) : s;
        if (ps.empty()) return -1;
        for (char ch : ps) if (!std::isdigit((unsigned char)ch)) return -1;
        return parse_port(ps);
    }
    return -1;
}

// split a reality dest like "www.example.com:443" into host + port. a bare
// host leaves port = -1. ipv6 literals (rare in dest=) are left intact.
void split_host_port(const string& dest, string& host, int& port) {
    host = dest;
    port = -1;
    if (dest.find(']') != string::npos) return;   // looks like [v6]:p - skip
    size_t c = dest.rfind(':');
    if (c == string::npos || c + 1 >= dest.size()) return;
    string ps = dest.substr(c + 1);
    for (char ch : ps) if (!std::isdigit((unsigned char)ch)) return;
    host = dest.substr(0, c);
    port = parse_port(ps);
}

// names follow the core's current aliases
string xray_transport(const JsonValue& ss) {
    string n = tolower_s((!ss["method"].is_null() ? ss["method"] : ss["network"]).as_str("raw"));
    if (n == "tcp") return "raw";
    if (n == "splithttp") return "xhttp";
    if (n == "kcp") return "mkcp";
    if (n == "ws") return "websocket";
    return n;
}

bool local_listener(const string& host) {
    if (host == "localhost" || host == "::1" || host == "[::1]" ||
        host.rfind("/", 0) == 0 || host.rfind("@", 0) == 0)
        return true;
    auto parts = split(host, '.');
    if (parts.size() != 4 || parts[0] != "127") return false;
    for (const auto& part : parts) {
        unsigned n = 0;
        auto r = std::from_chars(part.data(), part.data() + part.size(), n);
        if (r.ec != std::errc{} || r.ptr != part.data() + part.size() || n > 255) return false;
    }
    return true;
}

// check the exact inbound vision flow name
bool clients_have_vision(const JsonValue& clients) {
    if (!clients.is_arr()) return false;
    for (size_t i = 0; i < clients.size(); ++i) {
        string fl = tolower_s(clients.at(i)["flow"].as_str());
        if (fl == "xtls-rprx-vision") return true;
    }
    return false;
}

// legacy flow names used by the sing-box audit
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

// socket layers a listener binds; tcp and udp may share one port number
constexpr unsigned L_TCP = 1, L_UDP = 2;

unsigned layers_from_network(const string& network, unsigned dflt) {
    string n = tolower_s(network);
    if (n.empty()) return dflt;
    unsigned l = 0;
    if (n.find("tcp") != string::npos) l |= L_TCP;
    if (n.find("udp") != string::npos) l |= L_UDP;
    return l ? l : dflt;
}

bool wildcard_listen(const string& s) {
    return s.empty() || s == "0.0.0.0" || s == "::" || s == "[::]";
}

bool socket_path(const string& s) { return s.rfind("/", 0) == 0 || s.rfind("@", 0) == 0; }

// "1.0".."1.3" as 10..13, 0 when unset or unknown
int tls_version(const string& v) {
    if (v == "1.0") return 10;
    if (v == "1.1") return 11;
    if (v == "1.2") return 12;
    if (v == "1.3") return 13;
    return 0;
}

bool valid_short_id(const string& id) {
    return id.size() <= 16 && id.size() % 2 == 0 &&
           std::all_of(id.begin(), id.end(), [](unsigned char c) { return std::isxdigit(c); });
}

// host part of "host:port", "[v6]:port" or a bare host
string listen_host(const string& hp) {
    if (!hp.empty() && hp[0] == '[') {
        size_t e = hp.find(']');
        return e == string::npos ? hp : hp.substr(1, e - 1);
    }
    size_t c = hp.rfind(':');
    if (c != string::npos && hp.find(':') == c) return hp.substr(0, c);
    return hp;
}

struct Listener {
    int      idx = 0;
    int      port = -1;
    string   listen;
    unsigned layers = L_TCP;
    string   where;
};

struct Auditor {
    ConfigAudit& A;
    std::set<int> panel_hits;
    int reality_inbounds = 0;
    vector<Listener> listeners;
    std::map<string, int> xray_tags;   // inbound tag -> first index

    explicit Auditor(ConfigAudit& a) : A(a) {}

    void listener(int idx, int port, const string& listen, unsigned layers, const string& where) {
        if (port > 0 && !socket_path(listen)) listeners.push_back({idx, port, listen, layers, where});
    }

    // no effect on what an observer sees; printed in its own section
    void hygiene(const string& tag, const string& where, const string& title, const string& fix) {
        add(AuditFinding::Sev::Info, false, tag, where, title, fix);
        A.findings.back().category = "hygiene";
    }

    // the same identity twice in one inbound; the core keeps one of them
    void duplicate_users(const JsonValue& users, const char* key, const string& what, const string& where) {
        if (!users.is_arr()) return;
        std::set<string> seen;
        for (size_t i = 0; i < users.size(); ++i) {
            string v = users.at(i)[key].as_str();
            if (v.empty()) continue;
            if (!seen.insert(v).second) {
                hygiene("duplicate-user", where,
                    "Two users in this inbound share one " + what + "; only one entry is effective, "
                    "so traffic accounting and revoking that user are ambiguous.",
                    "Give every user its own " + what + ".");
                return;
            }
        }
    }

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
            "'. Your VPS will hand out that brand's cert from an ASN the brand "
            "does not own, a cheap cert-impersonation tell.",
            "Point dest at a real site on the same ASN/CDN as the VPS, or at a "
            "domain you own with a full chain. Not amazon/apple/microsoft/google/"
            "cloudflare on a rented VPS.");
    }

    // same checks for xray and sing-box, one deployment one verdict
    void reality_common(const string& host, int dport, bool empty_id, const string& where) {
        reality_dest_brand(host, where);
        if (dport > 0 && dport != 443)
            add(AuditFinding::Sev::Info, false, "reality-dest-port", where,
                "REALITY handshake target port is " + std::to_string(dport) +
                ". Observers see your listener port, not this one; unauthenticated "
                "probes get forwarded there.",
                "Keep it only if the target really serves TLS on that port.");
        if (empty_id)
            add(AuditFinding::Sev::Info, false, "reality-shortid-empty", where,
                "The shortIds list permits an empty ID. REALITY authentication still applies.",
                "Keep this entry only if clients need it.");
    }

    void plaintext(const string& proto, const string& where) {
        add(AuditFinding::Sev::High, false, "plaintext-proto", where,
            proto + " has neither outer TLS/REALITY nor protocol encryption on this listener.",
            "Verify upstream TLS termination or enable transport security before public exposure.");
    }

    void ss_default_port(int port, const string& where) {
        if (port == 8388 || port == 8488)
            add(AuditFinding::Sev::Info, false, "shadowsocks-default-port", where,
                "A common Shadowsocks port is configured; the number alone is not a protocol signature.",
                "Review actual exposure and authentication.");
    }

    // plain wg handshake has a fixed layout on any port, same rule as the .conf auditor
    void wireguard_listener(int port, const string& where) {
        if (port == 51820)
            add(AuditFinding::Sev::High, true, "wireguard-default-port", where,
                "Plain WireGuard on UDP/51820. The MessageInitiation layout is a "
                "fixed-offset signature, on the default port on top.",
                "Use AmneziaWG or a masked transport and move off 51820.");
        else
            add(AuditFinding::Sev::Medium, true, "wireguard-plain", where,
                "Plain WireGuard without obfuscation. The handshake layout is a "
                "fixed signature regardless of port.",
                "Use AmneziaWG obfuscation or a masked transport.");
    }

    void quic_tunnel(const string& tag, const string& name, const string& where) {
        add(AuditFinding::Sev::Medium, false, tag, where,
            name + " (QUIC) inbound. QUIC itself is normal web traffic with no tunnel "
            "handshake signature; the tell is a QUIC endpoint on a hosting IP with no "
            "matching web presence. Soft anomaly, not an instant block.",
            "Front it with a real HTTP/3 site on the same IP or move off the default ports.");
    }

    void local_note(const string& where) {
        add(AuditFinding::Sev::Info, false, "local-listener", where,
            "Listener is bound to loopback or a local socket; exposure depends on "
            "whatever sits in front of it.",
            "Audit the fronting proxy or terminator separately.");
    }

    void compat(AuditFinding::Sev sev, const string& tag, const string& where,
                const string& title, const string& fix) {
        add(sev, false, tag, where, title, fix);
        A.findings.back().category = "compatibility";
    }

    // mirrors alias precedence in infra/conf; empty arrays still override users
    void xray_inbound(const JsonValue& in, int idx) {
        using Sev = AuditFinding::Sev;
        const auto& st = in["settings"];
        const auto& ss = in["streamSettings"];
        const auto& users = !st["clients"].is_null() ? st["clients"] : st["users"];
        ConfigProtocol p;
        p.inbound = idx;
        p.protocol = tolower_s(in["protocol"].as_str());
        p.transport = xray_transport(ss);
        p.security = tolower_s(ss["security"].as_str("none"));
        if (p.security.empty()) p.security = "none";
        p.encryption = "protocol-native";
        const string& proto = p.protocol;
        const string& net = p.transport;
        const string& sec = p.security;
        int port = json_port(in["port"]);
        string where = "inbound[" + std::to_string(idx) + "] " + proto +
                       (port > 0 ? " :" + std::to_string(port) : "");
        bool local = local_listener(in["listen"].as_str());
        bool has_tls = sec == "tls" || sec == "reality";
        if (!local && port > 0 && is_panel_port(port)) panel_hits.insert(port);
        if (local) local_note(where);

        unsigned layers = L_TCP;
        if (proto == "wireguard" || proto == "hysteria" || net == "mkcp" || net == "hysteria") layers = L_UDP;
        else if (net == "xhttp") {
            // xhttp serves http/3 over quic when h3 is the only alpn
            const auto& alpn = ss["tlsSettings"]["alpn"];
            if (sec == "tls" && alpn.is_arr() && alpn.size() == 1 && alpn.at(0).as_str() == "h3") layers = L_UDP;
        } else if (proto == "shadowsocks" || proto == "dokodemo-door" || proto == "tunnel")
            layers = layers_from_network(st["network"].as_str(), L_TCP);
        if ((proto == "socks" || proto == "mixed") && st["udp"].as_bool()) layers |= L_UDP;
        listener(idx, port, in["listen"].as_str(), layers, where);

        string tag = in["tag"].as_str();
        if (!tag.empty()) {
            auto [it, fresh] = xray_tags.emplace(tag, idx);
            if (!fresh)
                compat(Sev::High, "duplicate-tag", where,
                    "Inbound tag '" + tag + "' is already used by inbound[" + std::to_string(it->second) +
                    "]; the core refuses to start.",
                    "Give every inbound a unique tag.");
        }
        // xray lowercases emails and refuses a repeat per inbound
        if (users.is_arr()) {
            std::set<string> emails;
            for (size_t i = 0; i < users.size(); ++i) {
                string e = tolower_s(users.at(i)["email"].as_str());
                if (!e.empty() && !emails.insert(e).second) {
                    compat(Sev::High, "duplicate-email", where,
                        "Two users share the email '" + users.at(i)["email"].as_str() +
                        "' (case-insensitive); the core refuses to start this inbound.",
                        "Use a unique email per user in each inbound.");
                    break;
                }
            }
        }
        if (proto == "vless" || proto == "vmess") duplicate_users(users, "id", "id", where);
        if (proto == "trojan" || proto == "shadowsocks") duplicate_users(users, "password", "password", where);

        const auto& tlss = ss["tlsSettings"];
        const int tmin = tls_version(tlss["minVersion"].as_str()), tmax = tls_version(tlss["maxVersion"].as_str());
        if (sec == "tls" && tmin && tmax && tmin > tmax)
            compat(Sev::High, "tls-version-range", where,
                "tlsSettings.minVersion is above maxVersion; no TLS version is left and every handshake fails.",
                "Set minVersion at or below maxVersion.");
        if (!tlss.is_null() && sec != "tls")
            hygiene("settings-ignored", where,
                "tlsSettings is present but security is '" + sec + "'; the core ignores it.",
                "Remove the block, or set security to tls if TLS was intended.");
        if (!ss["realitySettings"].is_null() && sec != "reality")
            hygiene("settings-ignored", where,
                "realitySettings is present but security is '" + sec + "'; the core ignores it.",
                "Remove the block, or set security to reality if REALITY was intended.");
        static const std::pair<const char*, const char*> transport_keys[] = {
            {"rawSettings", "raw"}, {"tcpSettings", "raw"}, {"xhttpSettings", "xhttp"},
            {"splithttpSettings", "xhttp"}, {"kcpSettings", "mkcp"}, {"grpcSettings", "grpc"},
            {"wsSettings", "websocket"}, {"httpupgradeSettings", "httpupgrade"}};
        for (const auto& [key, owner] : transport_keys)
            if (!ss[key].is_null() && net != owner)
                hygiene("settings-ignored", where,
                    string(key) + " is present but the transport is " + net + "; the core ignores it.",
                    "Remove the block, or switch the transport if " + string(owner) + " was intended.");

        static const std::set<string> transports = {
            "raw", "xhttp", "mkcp", "grpc", "websocket", "httpupgrade", "hysteria"};
        if (net == "h2" || net == "h3" || net == "http" || net == "quic")
            compat(Sev::High, "removed-transport", where,
                "This legacy transport was removed from the reviewed Xray core.",
                "Migrate both ends to a supported transport, then run xray run -test.");
        else if (!transports.count(net))
            compat(Sev::High, "unknown-transport", where,
                "The transport is not supported by the reviewed Xray core.",
                "Check streamSettings.method/network and the installed core version.");
        else if (net == "grpc" || net == "websocket" || net == "httpupgrade")
            compat(Sev::Info, "deprecated-transport", where,
                "Xray warns that this transport is deprecated, but still supports it.",
                "Review XHTTP migration; this warning does not identify remote traffic.");

        if (sec == "xtls")
            compat(Sev::High, "removed-xtls-security", where,
                "Legacy security=xtls was removed from Xray.",
                "Use TLS or REALITY with a supported VLESS flow on both ends.");
        else if (sec != "none" && !has_tls)
            compat(Sev::High, "unknown-security", where,
                "Unknown transport security mode.", "Check streamSettings.security.");
        if (sec == "reality" && net != "raw" && net != "xhttp" && net != "grpc")
            compat(Sev::High, "reality-transport", where,
                "REALITY supports RAW, XHTTP and gRPC in the reviewed core.",
                "Choose a supported combination on both ends.");

        if (proto == "vless") {
            string dec = st["decryption"].as_str();
            bool encrypted = dec.rfind("mlkem768x25519plus.", 0) == 0;
            p.encryption = encrypted ? "vless-encryption-unverified" : "none";
            if (dec.empty())
                compat(Sev::High, "vless-decryption-missing", where,
                    "VLESS requires an explicit settings.decryption value.",
                    "Set none for outer TLS/REALITY, or configure VLESS Encryption.");
            else if (dec != "none" && !encrypted) {
                p.encryption = "unrecognized";
                compat(Sev::High, "vless-decryption-unknown", where,
                    "Unrecognized VLESS decryption scheme.",
                    "Check the installed Xray version and run xray run -test.");
            }
            if (encrypted) {
                compat(Sev::Info, "vless-encryption", where,
                    "VLESS Encryption is configured. Key material and padding syntax were not validated.",
                    "Run xray run -test with the deployed version and check an authenticated connection.");
                if (!st["fallbacks"].is_null())
                    compat(Sev::High, "vless-encryption-fallback", where,
                        "VLESS Encryption cannot be combined with settings.fallbacks, even an empty list.",
                        "Remove settings.fallbacks when using VLESS Encryption.");
            }
            auto check_flow = [&](const string& flow, const string& at) {
                if (flow.empty() || flow == "xtls-rprx-vision") return true;
                bool old = flow == "xtls-rprx-direct" || flow == "xtls-rprx-origin" ||
                           flow == "xtls-rprx-splice";
                compat(Sev::High, old ? "deprecated-flow" : "invalid-flow", at,
                    old ? "Legacy XTLS flow is no longer supported." :
                          "Inbound flow must be empty or exactly xtls-rprx-vision.",
                    "Correct the server flow and match it on the client.");
                return false;
            };
            string default_flow = st["flow"].as_str();
            bool default_valid = check_flow(default_flow, where + " settings.flow");
            for (size_t i = 0; i < users.size(); ++i) {
                string flow = users.at(i)["flow"].as_str();
                if (flow.empty()) flow = default_flow;
                if (!check_flow(flow, where + " user[" + std::to_string(i) + "]"))
                    ++p.invalid_flow_users;
                else if (flow == "xtls-rprx-vision") ++p.vision_users;
                else ++p.plain_users;
            }
            p.flow = !default_valid || p.invalid_flow_users ? "invalid" :
                     users.size() == 0 ? "no_users" :
                     p.vision_users && p.plain_users ? "mixed" :
                     p.vision_users ? "vision" : "none";
            if (p.vision_users && !encrypted && (net != "raw" || !has_tls))
                compat(Sev::High, "vision-transport", where,
                    "Without VLESS Encryption, Vision requires RAW/TCP with TLS or REALITY.",
                    "Use a supported transport/security combination on both ends.");
            if (p.vision_users && !encrypted && sec == "tls") {
                string maxv = ss["tlsSettings"]["maxVersion"].as_str();
                if (maxv == "1.0" || maxv == "1.1" || maxv == "1.2")
                    compat(Sev::High, "vision-tls-version", where,
                        "Vision requires outer TLS 1.3; maxVersion prevents it.",
                        "Allow TLS 1.3 on this listener.");
            }
            if (default_valid && !p.invalid_flow_users && p.plain_users &&
                net == "raw" && has_tls)
                add(Sev::Info, false, "no-vision-flow", where,
                    std::to_string(p.plain_users) + " user(s) use standard VLESS without Vision padding.",
                    "Check whether this is intentional; it does not prove detectability.");
            if (!local && dec == "none" && sec == "none") plaintext("VLESS", where);
        }

        if (proto == "vmess" || proto == "shadowsocks")
            compat(Sev::Info, "deprecated-protocol", where,
                "The reviewed Xray core warns about this protocol but still supports it.",
                "Review the core's migration guidance; a deprecation warning is not a wire signature.");
        if (proto == "vmess") {
            for (size_t i = 0; i < users.size(); ++i) {
                const auto& aid = users.at(i)["alterId"];
                if (!aid.is_null() && !(aid.is_num() && aid.as_num() == 0))
                    compat(Sev::Medium, "vmess-legacy-alterid", where,
                        "A legacy alterId setting is present. Current Xray no longer reads this field.",
                        "Remove alterId and verify that the peer uses VMess AEAD.");
            }
            if (!has_tls)
                add(Sev::Info, false, "vmess-no-outer-tls", where,
                    "VMess has its own authentication and encryption; missing outer TLS is not plaintext.",
                    "Assess traffic camouflage separately from payload encryption.");
        }
        if (proto == "shadowsocks") {
            static const std::set<string> ciphers = {
                "aes-128-gcm", "aes-256-gcm", "aead_aes_128_gcm", "aead_aes_256_gcm",
                "chacha20-poly1305", "chacha20-ietf-poly1305", "aead_chacha20_poly1305",
                "xchacha20-poly1305", "xchacha20-ietf-poly1305", "aead_xchacha20_poly1305"};
            string method = st["method"].as_str();
            bool ss2022 = method == "2022-blake3-aes-128-gcm" ||
                          method == "2022-blake3-aes-256-gcm" ||
                          method == "2022-blake3-chacha20-poly1305";
            p.encryption = ss2022 ? "shadowsocks-2022" : "shadowsocks-aead";
            auto check_cipher = [&](const string& m, const string& at) {
                if (!ciphers.count(tolower_s(m))) {
                    p.encryption = "unrecognized";
                    compat(Sev::High, "shadowsocks-cipher", at,
                        "Missing or unsupported Shadowsocks cipher, including legacy stream ciphers.",
                        "Use an AEAD cipher supported by both peers; check 2022 key requirements separately.");
                }
            };
            if (!ss2022) {
                if (users.is_arr()) {
                    for (size_t i = 0; i < users.size(); ++i)
                        check_cipher(users.at(i)["method"].as_str(), where + " user[" + std::to_string(i) + "]");
                } else check_cipher(method, where);
            }
            if (!local) ss_default_port(port, where);
        }
        if (proto == "trojan") {
            p.encryption = "none";
            if (!local && sec == "none") plaintext("Trojan", where);
        }
        if (proto == "wireguard" && !local) {
            const auto& masks = ss["finalmask"]["udp"];
            if (masks.is_arr() && masks.size() > 0)
                add(Sev::Info, false, "wireguard-finalmask", where,
                    "WireGuard runs behind finalmask UDP masks. The wire shape depends on the "
                    "mask types and was not verified here.",
                    "Capture real traffic and check it with awg-entropy or a packet view.");
            else wireguard_listener(port, where);
        }
        if (proto == "hysteria" && !local) quic_tunnel("hysteria2", "Hysteria2", where);

        if (proto == "socks" || proto == "mixed" || proto == "http") {
            p.encryption = "none";
            const auto& accounts = !st["accounts"].is_null() ? st["accounts"] : st["users"];
            bool auth = proto == "http" ? accounts.size() > 0 : st["auth"].as_str() == "password";
            if (!local && !auth)
                add(Sev::High, false, "proxy-no-auth", where,
                    "Proxy authentication is disabled on a listener not restricted to loopback.",
                    "Bind locally or require authentication and restrict access. Firewall/routing were not checked.");
        }

        if (sec == "reality") {
            if (!local) ++reality_inbounds;
            const auto& rs = ss["realitySettings"];
            const auto& target = rs.has("target") ? rs["target"] : rs["dest"];
            string host; int dport;
            split_host_port(target.as_str(), host, dport);
            if (!local) reality_common(host, dport, false, where);
            if (target.is_null() || (target.is_str() && target.as_str().empty()))
                compat(Sev::High, "reality-target-missing", where,
                    "REALITY server target/dest is missing.", "Set a reachable target supported by the deployed core.");
            if (rs["show"].as_bool())
                hygiene("reality-show", where,
                    "REALITY handshake debug logging is enabled.", "Disable show when debug output is no longer needed.");
            if (!rs["serverNames"].is_arr() || rs["serverNames"].size() == 0)
                compat(Sev::High, "reality-no-servernames", where,
                    "REALITY requires a nonempty serverNames list.", "Use names accepted by the configured target.");
            const auto& ids = rs["shortIds"];
            if (!ids.is_arr() || ids.size() == 0)
                compat(Sev::High, "reality-shortids-missing", where,
                    "REALITY requires a nonempty shortIds list; an empty list is not the same as [\"\"].",
                    "Configure the short IDs expected by your clients.");
            else for (size_t i = 0; i < ids.size(); ++i) {
                string id = ids.at(i).as_str();
                if (!ids.at(i).is_str() || !valid_short_id(id))
                    compat(Sev::High, "reality-shortid-invalid", where,
                        "A shortId must have 0 to 16 hexadecimal characters and an even length.",
                        "Correct the value on both peers.");
                else if (id.empty())
                    add(Sev::Info, false, "reality-shortid-empty", where,
                        "The shortIds list explicitly permits an empty ID. REALITY authentication still applies.",
                        "Keep this entry only if clients need it.");
            }
        }
        if (has_tls && sec == "tls" && net == "raw" &&
            (proto == "vless" || proto == "trojan") &&
            (proto != "vless" || st["decryption"].as_str() == "none") &&
            (!st["fallbacks"].is_arr() || st["fallbacks"].size() == 0))
            add(Sev::Info, false, "no-fallback", where,
                "No application fallback is configured after TLS termination.",
                "Configure one if a website response is intended. Its absence does not prove a tunnel.");
        if (sec == "tls") {
            string minv = ss["tlsSettings"]["minVersion"].as_str();
            if (minv == "1.0" || minv == "1.1")
                add(Sev::Medium, false, "tls-min-version", where,
                    "Legacy TLS 1.0/1.1 is allowed.", "Require TLS 1.2 or newer; Vision needs TLS 1.3.");
        }
        A.protocols.push_back(std::move(p));
    }

    // sing-box inbound
    void singbox_inbound(const JsonValue& in, int idx) {
        string type = tolower_s(in["type"].as_str());
        int port = json_port(in["listen_port"]);
        string where = "inbound[" + std::to_string(idx) + "] " + type +
                       (port > 0 ? " :" + std::to_string(port) : "");

        // loopback backend behind a terminator isn't public, same as xray
        bool local = local_listener(in["listen"].as_str());
        if (!local && port > 0 && is_panel_port(port)) panel_hits.insert(port);
        if (local) local_note(where);

        const JsonValue& tls = in["tls"];
        bool tls_en = tls["enabled"].as_bool();
        const JsonValue& reality = tls["reality"];
        // reality lives inside tls; with tls off sing-box never reads it
        bool reality_en = tls_en && reality["enabled"].as_bool();
        if (!tls_en && reality["enabled"].as_bool())
            hygiene("settings-ignored", where,
                "tls.reality.enabled is true but tls.enabled is not; sing-box ignores the REALITY block "
                "and this listener runs without TLS.",
                "Set tls.enabled to true if REALITY was intended.");

        unsigned layers = L_TCP;
        if (type == "wireguard" || type == "hysteria" || type == "hysteria2" || type == "tuic") layers = L_UDP;
        else if (type == "shadowsocks") layers = layers_from_network(in["network"].as_str(), L_TCP | L_UDP);
        else if (type == "direct" || type == "tproxy") layers = layers_from_network(in["network"].as_str(), L_TCP | L_UDP);
        listener(idx, port, in["listen"].as_str(), layers, where);

        if (type == "vless" || type == "vmess" || type == "tuic") duplicate_users(in["users"], "uuid", "uuid", where);
        if (type == "trojan" || type == "hysteria2" || type == "shadowsocks")
            duplicate_users(in["users"], "password", "password", where);

        const int tmin = tls_version(tls["min_version"].as_str()), tmax = tls_version(tls["max_version"].as_str());
        if (tls_en && tmin && tmax && tmin > tmax)
            compat(AuditFinding::Sev::High, "tls-version-range", where,
                "tls.min_version is above max_version; no TLS version is left and every handshake fails.",
                "Set min_version at or below max_version.");

        if (type == "shadowsocks") {
            string method = tolower_s(in["method"].as_str());
            bool ok = method.rfind("2022-blake3-", 0) == 0 || method == "none" ||
                      method == "aes-128-gcm" || method == "aes-192-gcm" || method == "aes-256-gcm" ||
                      method == "chacha20-ietf-poly1305" || method == "xchacha20-ietf-poly1305";
            if (!ok)
                compat(AuditFinding::Sev::High, "shadowsocks-cipher", where,
                    "Missing or unsupported Shadowsocks method, including legacy stream ciphers.",
                    "Use an AEAD or 2022 method supported by both peers.");
            if (!local && method == "none") plaintext("Shadowsocks", where);
            if (!local) ss_default_port(port, where);
        }
        if (local) return;

        if (type == "wireguard") wireguard_listener(port, where);
        if (type == "hysteria2") quic_tunnel("hysteria2", "Hysteria2", where);
        if (type == "tuic") quic_tunnel("tuic", "TUIC", where);
        if (type == "hysteria") quic_tunnel("hysteria", "Hysteria", where);

        if ((type == "vless" || type == "trojan") && !tls_en && !reality_en)
            plaintext(type == "vless" ? "VLESS" : "Trojan", where);
        if (type == "vmess" && !tls_en && !reality_en)
            add(AuditFinding::Sev::Info, false, "vmess-no-outer-tls", where,
                "VMess has its own authentication and encryption; missing outer TLS is not plaintext.",
                "Assess traffic camouflage separately from payload encryption.");
        if (type == "socks" || type == "mixed" || type == "http") {
            const auto& users = in["users"];
            if (!users.is_arr() || users.size() == 0)
                add(AuditFinding::Sev::High, false, "proxy-no-auth", where,
                    "Proxy authentication is disabled on a listener not restricted to loopback.",
                    "Bind locally or require authentication and restrict access. Firewall/routing were not checked.");
        }

        if (reality_en) {
            ++reality_inbounds;
            const JsonValue& hs = reality["handshake"];
            const JsonValue& ids = reality["short_id"];
            bool empty_id = !ids.is_arr() || ids.size() == 0;
            bool bad_id = false;
            // sing-box also takes a single string here
            if (ids.is_str()) { empty_id = ids.as_str().empty(); bad_id = !valid_short_id(ids.as_str()); }
            for (size_t i = 0; ids.is_arr() && i < ids.size(); ++i) {
                if (ids.at(i).as_str().empty()) empty_id = true;
                if (!ids.at(i).is_str() || !valid_short_id(ids.at(i).as_str())) bad_id = true;
            }
            reality_common(hs["server"].as_str(), json_port(hs["server_port"]), empty_id, where);
            // parity with the xray checks of the same name
            if (hs["server"].as_str().empty())
                compat(AuditFinding::Sev::High, "reality-target-missing", where,
                    "REALITY handshake.server is missing.", "Set a reachable handshake server.");
            if (bad_id)
                compat(AuditFinding::Sev::High, "reality-shortid-invalid", where,
                    "A short_id must have 0 to 16 hexadecimal characters and an even length.",
                    "Correct the value on both peers.");
        }

        if (tls_en) {
            string mv = tls["min_version"].as_str();
            if (mv == "1.0" || mv == "1.1")
                add(AuditFinding::Sev::Medium, false, "tls-min-version", where,
                    "Legacy TLS 1.0/1.1 is allowed.", "Require TLS 1.2 or newer; Vision needs TLS 1.3.");
        }

        if (type == "vless" && (tls_en || reality_en)) {
            string depflow;
            if (clients_flow_deprecated(in["users"], depflow))
                compat(AuditFinding::Sev::High, "deprecated-flow", where,
                    "Legacy XTLS flow '" + depflow + "' is no longer supported.",
                    "Correct the server flow and match it on the client.");
            else if (!clients_have_vision(in["users"]))
                add(AuditFinding::Sev::Info, false, "no-vision-flow", where,
                    "VLESS users run without Vision padding.",
                    "Check whether this is intentional; it does not prove detectability.");
        }
    }

    // fields outside the inbounds: logging and control apis
    void root_checks(const JsonValue& root, bool xray) {
        using Sev = AuditFinding::Sev;
        string level = tolower_s(xray ? root["log"]["loglevel"].as_str() : root["log"]["level"].as_str());
        if (level == "debug" || level == "trace")
            hygiene("debug-log", "log", "Log level is " + level + "; client addresses and destinations are "
                    "written to the log on the node.", "Use warning or error once debugging is done.");
        auto api_public = [&](const string& where, const string& what) {
            add(Sev::High, false, "api-public", where,
                what + " listens on a non-loopback address. It answers anyone who connects, and an "
                "open control port is visible to any scan of the node.",
                "Bind it to 127.0.0.1 and reach it over SSH or the panel's own tunnel.");
        };
        if (xray) {
            const auto& api = root["api"];
            string listen = api["listen"].as_str();
            if (!listen.empty() && !local_listener(listen_host(listen)))
                api_public("api.listen", "The Xray gRPC API");
            string tag = api["tag"].as_str();
            const auto& ib = root["inbounds"];
            for (size_t i = 0; !tag.empty() && ib.is_arr() && i < ib.size(); ++i)
                if (ib.at(i)["tag"].as_str() == tag && !local_listener(ib.at(i)["listen"].as_str()))
                    api_public("inbound[" + std::to_string(i) + "] api", "The Xray gRPC API inbound");
        } else {
            const auto& ex = root["experimental"];
            string clash = ex["clash_api"]["external_controller"].as_str();
            if (!clash.empty() && !local_listener(listen_host(clash)))
                api_public("experimental.clash_api", "The Clash API controller");
            string v2 = ex["v2ray_api"]["listen"].as_str();
            if (!v2.empty() && !local_listener(listen_host(v2)))
                api_public("experimental.v2ray_api", "The V2Ray stats API");
        }
    }

    void duplicate_listeners() {
        for (size_t i = 0; i < listeners.size(); ++i)
            for (size_t j = i + 1; j < listeners.size(); ++j) {
                const Listener& a = listeners[i];
                const Listener& b = listeners[j];
                if (a.port != b.port || !(a.layers & b.layers)) continue;
                if (!wildcard_listen(a.listen) && !wildcard_listen(b.listen) &&
                    tolower_s(a.listen) != tolower_s(b.listen)) continue;
                const char* layer = (a.layers & b.layers & L_TCP) ? "TCP" : "UDP";
                compat(AuditFinding::Sev::High, "duplicate-listener", b.where,
                    string(layer) + " port " + std::to_string(b.port) + " is already bound by inbound[" +
                    std::to_string(a.idx) + "] on an overlapping address; the second listener fails to start.",
                    "Move one inbound to another port, or route both through one listener.");
            }
    }

    void finish() {
        duplicate_listeners();
        if (panel_hits.size() >= 2) {
            string ports;
            for (int p : panel_hits) { if (!ports.empty()) ports += ","; ports += std::to_string(p); }
            add(AuditFinding::Sev::Medium, false, "panel-cluster", "config",
                std::to_string(panel_hits.size()) + " of the 3x-ui/x-ui/Marzban "
                "panel-installer TLS ports are used ({" + ports + "}). That cluster "
                "is a well-known installer fingerprint.",
                "Keep ONE real inbound on :443; close/relocate the rest and "
                "firewall the panel UI to admin IPs only.");
        }
        if (reality_inbounds >= 2) {
            add(AuditFinding::Sev::Medium, false, "reality-multiport", "config",
                std::to_string(reality_inbounds) + " inbounds run Reality on this IP; "
                "multi-port TLS cert-steering is an ASN/port-sweep anomaly.",
                "Keep Reality on a single port; fill the other ports with real "
                "services or close them.");
        }
    }
};

// dedupe exact-duplicate findings (same tag + location), then tally severities
// and resolve the predicted tspu tier. shared by the json and ini auditors.
void finalize_audit(ConfigAudit& A) {
    std::vector<AuditFinding> uniq;
    for (auto& f : A.findings) {
        bool dup = false;
        for (auto& g : uniq) if (g.tag == f.tag && g.where == f.where) { dup = true; break; }
        if (!dup) uniq.push_back(f);
    }
    A.findings.swap(uniq);

    int high_soft = 0, medium_soft = 0;
    bool unverified = false;
    A.high = A.medium = A.info = A.a_hits = A.b_hits = A.compatibility_errors = 0;
    for (auto& f : A.findings) {
        switch (f.sev) {
            case AuditFinding::Sev::High:   ++A.high; break;
            case AuditFinding::Sev::Medium: ++A.medium; break;
            case AuditFinding::Sev::Info:   ++A.info; break;
        }
        if (f.category == "compatibility") {
            if (f.sev == AuditFinding::Sev::High) ++A.compatibility_errors;
            continue;
        }
        if (f.category == "unverified") { unverified = true; continue; }
        if (f.category == "hygiene") continue;
        if (f.named) { ++A.a_hits; continue; }
        if (f.sev != AuditFinding::Sev::Info) ++A.b_hits;
        if (f.sev == AuditFinding::Sev::High)   ++high_soft;
        if (f.sev == AuditFinding::Sev::Medium) ++medium_soft;
    }
    if (A.compatibility_errors) {
        A.tspu_tier = "UNKNOWN";
        A.verdict_line = "configuration compatibility errors found; no network verdict inferred.";
    } else if (unverified) {
        A.tspu_tier = "UNKNOWN";
        A.verdict_line = "the settings don't pin down the wire format; no verdict inferred.";
    } else if (A.a_hits > 0) {
        A.tspu_tier = "IMMEDIATE BLOCK";
        A.verdict_line = "high exposure under the legacy scoring rules; actual filtering was not measured.";
    } else if (high_soft >= 1 || medium_soft >= 2) {
        A.tspu_tier = "BLOCK (accumulative)";
        A.verdict_line = "configuration risks found; this heuristic does not predict an actual network block.";
    } else if (medium_soft == 1) {
        A.tspu_tier = "THROTTLE / QoS";
        A.verdict_line = "one exposure warning; actual throttling or filtering was not measured.";
    } else {
        A.tspu_tier = "PASS / ALLOW";
        A.verdict_line = "no scored exposure warnings in the checked settings; runtime security and reachability remain unverified.";
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
    for (const auto* in : inbounds) {
        if (!in->is_obj() ||
            (in->has("protocol") == in->has("type")) ||
            ((*in)["protocol"].as_str().empty() && (*in)["type"].as_str().empty())) {
            A.err = "invalid inbound: expected an object with one nonempty protocol/type";
            A.tspu_tier = "UNKNOWN";
            return A;
        }
        string proto = tolower_s((*in)[in->has("protocol") ? "protocol" : "type"].as_str());
        static const std::set<string> xray = {"vless", "vmess", "trojan", "shadowsocks", "wireguard",
            "socks", "mixed", "http", "tunnel", "dokodemo-door", "hysteria", "tun"};
        static const std::set<string> singbox = {"vless", "vmess", "trojan", "shadowsocks", "wireguard",
            "hysteria2", "tuic", "hysteria", "socks", "mixed", "http", "naive", "shadowtls", "anytls",
            "direct", "tun", "redirect", "tproxy"};
        const auto& supported = in->has("protocol") ? xray : singbox;
        if (!supported.count(proto)) {
            A.err = "unsupported inbound protocol: " + proto;
            return A;
        }
        if (in->has("protocol") != inbounds.front()->has("protocol")) {
            A.err = "mixed Xray and sing-box inbound formats";
            return A;
        }
        if (in->has("protocol")) {
            const auto& st = (*in)["settings"];
            const auto& ss = (*in)["streamSettings"];
            bool shape = (st.is_null() || st.is_obj()) && (ss.is_null() || ss.is_obj());
            for (const auto* key : {"method", "network", "security"})
                shape = shape && (ss[key].is_null() || ss[key].is_str());
            for (const auto* key : {"flow", "decryption"})
                shape = shape && (st[key].is_null() || st[key].is_str());
            for (const auto* key : {"users", "clients", "accounts"}) {
                const auto& list = st[key];
                shape = shape && (list.is_null() || list.is_arr());
                if (list.is_arr()) for (size_t i = 0; i < list.size(); ++i) {
                    const auto& u = list.at(i);
                    shape = shape && u.is_obj() && (u["flow"].is_null() || u["flow"].is_str());
                }
            }
            for (const auto* key : {"tlsSettings", "realitySettings"})
                shape = shape && (ss[key].is_null() || ss[key].is_obj());
            if (!shape) {
                A.err = "invalid Xray settings/streamSettings field types";
                return A;
            }
        }
        const char* port_key = in->has("protocol") ? "port" : "listen_port";
        if (in->has(port_key) && json_port((*in)[port_key]) < 0) {
            A.err = "invalid inbound port";
            return A;
        }
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
    if (root.is_obj()) au.root_checks(root, A.format == "xray");
    au.finish();

    finalize_audit(A);
    return A;
}

// WireGuard / amneziawg .conf (ini)

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
        if (section != "[interface]") continue;
        size_t eq = ln.find('=');
        if (eq == string::npos) continue;
        iface[tolower_s(trim(ln.substr(0, eq)))] = trim(ln.substr(eq + 1));
    }
    if (iface.empty()) {
        A.ok = false;
        A.err = "no [Interface] section found (not a WireGuard/AmneziaWG .conf)";
        return A;
    }

    int port = iface.count("listenport") ? parse_port(iface["listenport"]) : -1;
    static const char* AWG_KEYS[] = {"jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
        "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"};
    bool amnezia = false;
    for (const char* k : AWG_KEYS) amnezia = amnezia || iface.count(k);
    string where = string("[Interface]") + (port > 0 ? " :" + std::to_string(port) : "");

    auto add = [&](AuditFinding::Sev sev, bool named, const string& tag,
                   const string& title, const string& fix, const char* category = "exposure") {
        AuditFinding x; x.sev = sev; x.named = named; x.tag = tag;
        x.where = where; x.title = title; x.fix = fix; x.category = category;
        A.findings.push_back(std::move(x));
    };

    if (!amnezia) {
        if (port == 51820)
            add(AuditFinding::Sev::High, true, "wireguard-default-port",
                "Plain WireGuard on UDP/51820. The MessageInitiation layout is a "
                "fixed-offset signature, on the default port on top.",
                "Use AmneziaWG (set Jc/Jmin/Jmax/S1/S2/H1-H4) and move off 51820.");
        else
            add(AuditFinding::Sev::Medium, true, "wireguard-plain",
                "Plain WireGuard without AmneziaWG obfuscation. The handshake layout is a "
                "fixed signature regardless of port.",
                "Switch to AmneziaWG obfuscation parameters.");
        finalize_audit(A);
        return A;
    }

    // parse like awg-go uapi.go: jc/jmin/jmax u32, s1-s4 u16, h1-h4 "a" or "a-b" u32
    auto num = [&](const char* k, uint64_t max, uint64_t& out) {
        const string& s = iface[k];
        auto r = std::from_chars(s.data(), s.data() + s.size(), out);
        return !s.empty() && r.ec == std::errc{} && r.ptr == s.data() + s.size() && out <= max;
    };
    vector<string> bad;
    uint64_t jc = 0, jmin = 0, jmax = 0, s[4] = {0, 0, 0, 0};
    const char* snames[] = {"s1", "s2", "s3", "s4"};
    if (iface.count("jc") && !num("jc", 0xffffffffULL, jc)) bad.push_back("Jc");
    if (iface.count("jmin") && !num("jmin", 0xffffffffULL, jmin)) bad.push_back("Jmin");
    if (iface.count("jmax") && !num("jmax", 0xffffffffULL, jmax)) bad.push_back("Jmax");
    for (int i = 0; i < 4; ++i)
        if (iface.count(snames[i]) && !num(snames[i], 0xffff, s[i])) bad.push_back("S" + std::to_string(i + 1));
    // missing h means stock wg type 1..4
    uint64_t hlo[4] = {1, 2, 3, 4}, hhi[4] = {1, 2, 3, 4};
    for (int i = 0; i < 4; ++i) {
        string k = "h" + std::to_string(i + 1);
        if (!iface.count(k)) continue;
        const string& v = iface[k];
        size_t dash = v.find('-');
        string a = v.substr(0, dash), b = dash == string::npos ? a : v.substr(dash + 1);
        auto ra = std::from_chars(a.data(), a.data() + a.size(), hlo[i]);
        auto rb = std::from_chars(b.data(), b.data() + b.size(), hhi[i]);
        if (a.empty() || b.empty() || ra.ec != std::errc{} || rb.ec != std::errc{} ||
            ra.ptr != a.data() + a.size() || rb.ptr != b.data() + b.size() ||
            hlo[i] > 0xffffffffULL || hhi[i] > 0xffffffffULL || hhi[i] < hlo[i])
            bad.push_back("H" + std::to_string(i + 1));
    }
    // awg refuses overlapping header ranges
    for (int i = 0; i < 4 && bad.empty(); ++i)
        for (int j = i + 1; j < 4; ++j)
            if (hlo[i] <= hhi[j] && hlo[j] <= hhi[i]) { bad.push_back("H" + std::to_string(i + 1) + "/H" + std::to_string(j + 1) + " overlap"); break; }
    // jmax < jmin underflows min+rand(max-min) in awg-go
    if (jc > 0 && iface.count("jmin") && iface.count("jmax") && jmax < jmin) bad.push_back("Jmax < Jmin");

    if (!bad.empty()) {
        string list;
        for (const auto& x : bad) { if (!list.empty()) list += ", "; list += x; }
        add(AuditFinding::Sev::High, false, "amneziawg-invalid",
            "AmneziaWG rejects or misreads these values: " + list + ".",
            "Fix the values; awg-go parses them as unsigned integers or a-b ranges.", "compatibility");
        add(AuditFinding::Sev::Info, false, "amneziawg-unverified",
            "Invalid AmneziaWG settings; the resulting wire format is unknown.",
            "Fix the values and audit again.", "unverified");
        finalize_audit(A);
        return A;
    }

    bool junk = jc >= 1 && iface.count("jmin") && iface.count("jmax") && jmax > 0;
    bool sizes = s[0] > 0 || s[1] > 0;
    bool custom_h = true;
    for (int i = 0; i < 4; ++i)
        if (hlo[i] <= uint64_t(i + 1) && uint64_t(i + 1) <= hhi[i]) custom_h = false;

    // key names alone prove nothing, need padded sizes plus junk or new headers
    if (!sizes || (!junk && !custom_h)) {
        add(AuditFinding::Sev::Info, false, "amneziawg-unverified",
            "AmneziaWG keys are present, but the set doesn't change the handshake shape "
            "enough to call it obfuscated (need S1/S2 padding plus junk packets or custom H1-H4).",
            "Set S1/S2, Jc/Jmin/Jmax and H1-H4 per deployment, then audit again.", "unverified");
        finalize_audit(A);
        return A;
    }

    if (port == 51820)
        add(AuditFinding::Sev::Medium, false, "amneziawg-default-port",
            "AmneziaWG on the default WG port :51820. Even obfuscated, the canonical "
            "port is a coarse pattern.",
            "Move off 51820.");
    if (!custom_h)
        add(AuditFinding::Sev::Medium, false, "amneziawg-default-headers",
            "At least one of H1-H4 keeps the stock WireGuard message type, so those "
            "packets still start with the plain wg header (transport data is type 4).",
            "Set all four H1-H4 to distinct non-default values.");
    add(AuditFinding::Sev::Info, false, "amneziawg-detected",
        "AmneziaWG obfuscation parameters change the handshake shape. A fixed "
        "parameter set reused across deployments is itself a fingerprint.",
        "Randomize Jc/Jmin/Jmax/S1/S2/H1-H4 per deployment and avoid preset defaults.");

    finalize_audit(A);
    return A;
}

// format auto-detect

ConfigAudit audit_config_text(const string& text) {
    // a WireGuard/amneziawg .conf carries an [Interface] section (which also
    // makes it start with '['), so check that before assuming a leading '['
    // means a json array.
    if (tolower_s(text).find("[interface]") != string::npos)
        return audit_wireguard_ini(text);

    bool ok = false;
    JsonValue root = json_parse(text, &ok);
    if (!ok) {
        ConfigAudit A;
        A.ok = false;
        A.err = "parse failed (invalid or duplicate-key JSON, and not a WireGuard .conf)";
        return A;
    }
    return audit_config_json(root);
}

// json serializer (for --json)

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
    o += "  \"evidence_source\": \"configuration\",\n";
    o += "  \"network_confirmed\": false,\n";
    o += "  \"runtime_validated\": false,\n";
    o += "  \"compatibility_errors\": " + std::to_string(a.compatibility_errors) + ",\n";
    o += "  \"protocols\": [";
    for (size_t i = 0; i < a.protocols.size(); ++i) {
        const auto& p = a.protocols[i];
        o += (i ? ",\n" : "\n");
        o += "    { \"inbound\": " + std::to_string(p.inbound);
        o += ", \"protocol\": \"" + jesc(p.protocol) + "\"";
        o += ", \"transport\": \"" + jesc(p.transport) + "\"";
        o += ", \"security\": \"" + jesc(p.security) + "\"";
        o += ", \"encryption\": \"" + jesc(p.encryption) + "\"";
        o += ", \"flow\": \"" + jesc(p.flow) + "\"";
        o += ", \"vision_users\": " + std::to_string(p.vision_users);
        o += ", \"plain_users\": " + std::to_string(p.plain_users);
        o += ", \"invalid_flow_users\": " + std::to_string(p.invalid_flow_users) + " }";
    }
    o += (a.protocols.empty() ? "],\n" : "\n  ],\n");
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
        o += ", \"category\": \"" + jesc(f.category) + "\"";
        o += ", \"tag\": \"" + jesc(f.tag) + "\"";
        o += ", \"where\": \"" + jesc(f.where) + "\"";
        o += ", \"title\": \"" + jesc(f.title) + "\"";
        o += ", \"fix\": \"" + jesc(f.fix) + "\" }";
    }
    o += (a.findings.empty() ? "]\n" : "\n  ]\n");
    o += "}\n";
    return o;
}
