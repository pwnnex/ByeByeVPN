// SPDX-License-Identifier: GPL-3.0-or-later
#include "preflight.h"
#include "../common/winhdr.h"
#include "../common/console.h"
#include "../common/util.h"
#include "../local/local.h"
#include "../net/http.h"
#include "../net/tcp.h"

#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <future>

using std::string;
using std::vector;

namespace {

bool is_loopback(const string& ip) {
    return ip.rfind("127.", 0) == 0 || ip == "::1";
}

// same ranges as dpi_probe looks_like_fake_ip
bool fake_ip(const string& ip) {
    unsigned a = 0, b = 0;
    if (std::sscanf(ip.c_str(), "%u.%u", &a, &b) != 2) return false;
    return (a == 198 && (b == 18 || b == 19)) || (a == 100 && b >= 64 && b <= 127) || a >= 240;
}

string reg_string(HKEY root, const char* path, const char* name) {
    char buf[1024] = {0};
    DWORD size = sizeof(buf) - 1, type = 0;
    if (RegGetValueA(root, path, name, RRF_RT_REG_SZ, &type, buf, &size) != ERROR_SUCCESS) return {};
    return buf;
}

DWORD reg_dword(HKEY root, const char* path, const char* name) {
    DWORD v = 0, size = sizeof(v);
    if (RegGetValueA(root, path, name, RRF_RT_REG_DWORD, nullptr, &v, &size) != ERROR_SUCCESS) return 0;
    return v;
}

string system_proxy() {
    const char* key = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    string out;
    if (reg_dword(HKEY_CURRENT_USER, key, "ProxyEnable")) out = reg_string(HKEY_CURRENT_USER, key, "ProxyServer");
    const string pac = reg_string(HKEY_CURRENT_USER, key, "AutoConfigURL");
    if (!pac.empty()) out += (out.empty() ? "" : ", ") + string("PAC ") + pac;
    return out;
}

vector<string> proxy_env() {
    vector<string> out;
    for (const char* v : {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"}) {
        char buf[8]; size_t n = 0;
        if (getenv_s(&n, buf, sizeof(buf), v) == 0 && n > 1) out.push_back(v);
        else if (n > sizeof(buf)) out.push_back(v);
    }
    return out;
}

string trim_ip(const string& body) {
    string s = trim(body);
    for (char c : s) if (!(std::isxdigit((unsigned char)c) || c == '.' || c == ':')) return {};
    return s.size() <= 45 ? s : string();
}

} // namespace

PreflightFacts preflight_gather(const string& target_ip, bool third_party_ok, const string& expect_ip) {
    PreflightFacts f;
    f.target_ip = target_ip;
    f.expect_ip = expect_ip;
    f.target_is_loopback = is_loopback(target_ip);
    f.fake_ip_target = fake_ip(target_ip);

    const auto adapters = list_local_adapters();
    for (const auto& a : adapters) if (a.is_up && a.is_vpn) f.tunnels_up.push_back(a.friendly);
    const unsigned long tif = best_interface_for(target_ip);
    for (const auto& a : adapters) if (a.if_index == tif) {
        f.target_iface = a.friendly;
        f.target_iface_is_tunnel = a.is_vpn && !f.target_is_loopback;
    }

    for (const auto& p : list_vpn_processes()) {
        if (p.kind == ProcKind::Rewriter) f.rewriters.push_back(p.category);
        else f.proxy_clients.push_back(p.category);
    }
    f.system_proxy = system_proxy();
    f.proxy_env = proxy_env();

    // control probe for the path the target uses
    if (f.target_is_loopback || best_interface_for(PREFLIGHT_DEAD_ADDRESS) != tif) {
        f.ack_all_checked = true;
    } else {
        unsigned char rb[2]; RAND_bytes(rb, 2);
        const int port = 1024 + ((rb[0] << 8 | rb[1]) % 64000);
        string err;
        SOCKET s = tcp_connect(PREFLIGHT_DEAD_ADDRESS, port, 1500, err);
        if (s != INVALID_SOCKET) { closesocket(s); f.local_ack_all = true; }
        f.ack_all_checked = true;
    }

    if (third_party_ok) {
        // plain-text echo services, three operators
        const char* src[] = {"https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"};
        vector<std::future<HttpResp>> fs;
        for (const char* u : src) fs.push_back(std::async(std::launch::async, [u] { return http_get(u, 5000); }));
        for (auto& x : fs) {
            HttpResp r = x.get();
            f.external_ips.push_back(r.ok() ? trim_ip(r.body) : string());
        }
    }
    return f;
}

LocalHealth local_health() {
    LocalHealth h;
    const auto adapters = list_local_adapters();
    const unsigned long pif = best_interface_for("1.1.1.1");
    for (const auto& a : adapters) {
        if (a.is_up && a.is_vpn) h.tunnels_up.push_back(a.friendly);
        if (a.if_index == pif) { h.public_iface = a.friendly; h.public_via_tunnel = a.is_vpn; }
    }
    for (const auto& p : list_vpn_processes()) {
        auto& v = p.kind == ProcKind::Rewriter ? h.rewriters : h.proxy_clients;
        if (std::find(v.begin(), v.end(), p.category) == v.end()) v.push_back(p.category);
    }
    h.system_proxy = system_proxy();
    return h;
}

void print_preflight(const PreflightReport& p) {
    const auto& f = p.facts;
    printf("\n%s[1b/8] Preflight%s  (is this machine fit to measure)\n", col(C::BOLD), col(C::RST));
    printf("  route to target: %s%s\n", f.target_iface.empty() ? "unknown" : f.target_iface.c_str(),
           f.target_iface_is_tunnel ? "  [tunnel]" : "");
    if (!f.external_ips.empty()) {
        string s;
        for (const auto& ip : f.external_ips) { if (!s.empty()) s += ", "; s += ip.empty() ? "no answer" : ip; }
        printf("  external address per lookup service: %s\n", s.c_str());
    }
    for (const auto& w : p.warnings) printf("  %s[warn]%s %s\n", col(C::YEL), col(C::RST), w.c_str());
    for (const auto& b : p.blockers) printf("  %s[BLOCK]%s %s\n", col(C::RED), col(C::RST), b.c_str());
    if (p.blocked && !p.overridden)
        printf("\n  %s!! REPORT UNRELIABLE. No probe is sent and no verdict is given. Fix the causes above,\n"
               "  !! or pass --i-know-what-i-am-doing to scan anyway with the verdict marked as overridden.%s\n",
               col(C::RED), col(C::RST));
    else if (p.overridden)
        printf("\n  %s!! preflight failed and was overridden; every result below is suspect.%s\n", col(C::RED), col(C::RST));
    else if (p.blockers.empty() && p.warnings.empty())
        printf("  %sclean%s\n", col(C::GRN), col(C::RST));
}
