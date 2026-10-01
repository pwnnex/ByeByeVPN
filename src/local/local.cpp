// SPDX-License-Identifier: GPL-3.0-or-later
#include "local.h"
#include "leaks.h"
#include "../common/winhdr.h"
#include "../common/console.h"
#include "../common/util.h"
#include "../net/tcp.h"
#include "../net/udp.h"

#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <map>
#include <set>

using std::string;
using std::vector;

static string sockaddr_to_str(SOCKADDR* sa) {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (sa->sa_family == AF_INET) {
        sockaddr_in* s = (sockaddr_in*)sa;
        inet_ntop(AF_INET, &s->sin_addr, buf, sizeof(buf));
    } else if (sa->sa_family == AF_INET6) {
        sockaddr_in6* s = (sockaddr_in6*)sa;
        inet_ntop(AF_INET6, &s->sin6_addr, buf, sizeof(buf));
    }
    return buf;
}

namespace {
// substring "tun" matched teredo tunneling
bool has_token(const string& hay, const char* tok) {
    const string h = tolower_s(hay), t = tolower_s(tok);
    for (size_t at = h.find(t); at != string::npos; at = h.find(t, at + 1)) {
        const bool left = at == 0 || !std::isalnum((unsigned char)h[at - 1]);
        const size_t end = at + t.size();
        const bool right = end >= h.size() || !std::isalnum((unsigned char)h[end]);
        if (left && right) return true;
    }
    return false;
}
}

bool adapter_is_tunnel(unsigned long if_type, const string& desc, const string& name) {
    // teredo, 6to4, isatap, ip-https: windows' own ipv6 transition
    if (if_type == IF_TYPE_TUNNEL || if_type == IF_TYPE_SOFTWARE_LOOPBACK) return false;
    if (if_type == IF_TYPE_PPP) return true;
    static const char* kw[] = {
        "wintun", "wireguard", "tap-windows", "tap-protonvpn", "sing-tun", "openvpn",
        "nordlynx", "mullvad", "protonvpn", "amneziawg", "amnezia", "warp", "hiddify",
        "sing-box", "singbox", "throne", "nekoray", "clash", "v2ray", "xray", "tailscale",
        "zerotier", "expressvpn", "surfshark", "torguard", "outline",
    };
    for (auto k : kw) if (has_token(desc, k) || has_token(name, k)) return true;
    // wintun and tap register as proprietary virtual
    return if_type == IF_TYPE_PROP_VIRTUAL && (has_token(desc, "tunnel") || has_token(desc, "tun"));
}

vector<LocalAdapter> list_local_adapters() {
    vector<LocalAdapter> out;
    ULONG sz = 0;
    GetAdaptersAddresses(AF_UNSPEC,
                         GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                         nullptr, nullptr, &sz);
    if (!sz) return out;
    vector<unsigned char> buf(sz);
    auto* aa = (IP_ADAPTER_ADDRESSES*)buf.data();
    if (GetAdaptersAddresses(AF_UNSPEC,
                             GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                             nullptr, aa, &sz) != NO_ERROR) return out;
    for (auto* p = aa; p; p = p->Next) {
        LocalAdapter A;
        char fn[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, p->FriendlyName, -1, fn, sizeof(fn), nullptr, nullptr);
        A.friendly = fn;
        char dc[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, p->Description, -1, dc, sizeof(dc), nullptr, nullptr);
        A.description = dc;
        if (p->PhysicalAddressLength)
            A.mac = mac_to_str(p->PhysicalAddress, p->PhysicalAddressLength);
        A.mtu = p->Mtu;
        A.if_index = p->IfIndex;
        A.if_type = p->IfType;
        A.is_up = (p->OperStatus == IfOperStatusUp);
        for (auto* u = p->FirstUnicastAddress; u; u = u->Next) {
            string s = sockaddr_to_str(u->Address.lpSockaddr);
            if (s.empty()) continue;
            if (u->Address.lpSockaddr->sa_family == AF_INET)  A.ipv4.push_back(s);
            else                                              A.ipv6.push_back(s);
        }
        for (auto* g = p->FirstGatewayAddress; g; g = g->Next) {
            string s = sockaddr_to_str(g->Address.lpSockaddr);
            if (!s.empty()) A.gateways.push_back(s);
        }
        for (auto* d = p->FirstDnsServerAddress; d; d = d->Next) {
            string s = sockaddr_to_str(d->Address.lpSockaddr);
            if (!s.empty()) A.dns.push_back(s);
        }
        A.metric = p->Ipv4Metric;
        A.is_vpn = adapter_is_tunnel(A.if_type, A.description, A.friendly);
        out.push_back(std::move(A));
    }
    return out;
}

bool routes_cover_default(const vector<string>& p) {
    auto has = [&](const char* x) { return std::find(p.begin(), p.end(), x) != p.end(); };
    return has("0.0.0.0/0") || (has("0.0.0.0/1") && has("128.0.0.0/1"));
}

unsigned long best_interface_for(const string& ip) {
    sockaddr_storage ss{};
    auto* v4 = (sockaddr_in*)&ss;
    auto* v6 = (sockaddr_in6*)&ss;
    if (inet_pton(AF_INET, ip.c_str(), &v4->sin_addr) == 1) v4->sin_family = AF_INET;
    else if (inet_pton(AF_INET6, ip.c_str(), &v6->sin6_addr) == 1) v6->sin6_family = AF_INET6;
    else return 0;
    DWORD idx = 0;
    if (GetBestInterfaceEx((sockaddr*)&ss, &idx) != NO_ERROR) return 0;
    return idx;
}

vector<LocalRoute> list_local_routes() {
    vector<LocalRoute> out;
    MIB_IPFORWARD_TABLE2* tbl = nullptr;
    if (GetIpForwardTable2(AF_UNSPEC, &tbl) != NO_ERROR || !tbl) return out;
    for (ULONG i = 0; i < tbl->NumEntries; ++i) {
        auto& r = tbl->Table[i];
        LocalRoute R;
        char dst[INET6_ADDRSTRLEN] = {0}, nh[INET6_ADDRSTRLEN] = {0};
        if (r.DestinationPrefix.Prefix.si_family == AF_INET) {
            inet_ntop(AF_INET, &r.DestinationPrefix.Prefix.Ipv4.sin_addr, dst, sizeof(dst));
            inet_ntop(AF_INET, &r.NextHop.Ipv4.sin_addr,                    nh,  sizeof(nh));
        } else if (r.DestinationPrefix.Prefix.si_family == AF_INET6) {
            inet_ntop(AF_INET6, &r.DestinationPrefix.Prefix.Ipv6.sin6_addr, dst, sizeof(dst));
            inet_ntop(AF_INET6, &r.NextHop.Ipv6.sin6_addr,                   nh,  sizeof(nh));
        } else continue;
        R.prefix   = string(dst) + "/" + std::to_string(r.DestinationPrefix.PrefixLength);
        R.nexthop  = nh;
        R.if_index = r.InterfaceIndex;
        R.metric   = r.Metric;
        out.push_back(R);
    }
    FreeMibTable(tbl);
    return out;
}

namespace {
struct KnownProc { const char* exe; const char* category; ProcKind kind; };
const KnownProc VPN_PROCESSES[] = {
    {"xray.exe",          "Xray-core", ProcKind::Proxy},
    {"v2ray.exe",         "V2Ray", ProcKind::Proxy},
    {"sing-box.exe",      "sing-box", ProcKind::Proxy},
    {"singbox.exe",       "sing-box", ProcKind::Proxy},
    {"v2rayN.exe",        "v2rayN (GUI -> Xray)", ProcKind::Proxy},
    {"v2rayNG.exe",       "v2rayNG", ProcKind::Proxy},
    {"nekoray.exe",       "NekoRay (GUI -> sing-box/Xray)", ProcKind::Proxy},
    {"nekobox.exe",       "NekoBox", ProcKind::Proxy},
    {"Throne.exe",        "Throne (GUI -> sing-box)", ProcKind::Proxy},
    {"ThroneCore.exe",    "Throne core (sing-box)", ProcKind::Proxy},
    {"Hiddify.exe",       "Hiddify", ProcKind::Proxy},
    {"HiddifyCli.exe",    "Hiddify CLI", ProcKind::Proxy},
    {"HiddifyTray.exe",   "Hiddify tray", ProcKind::Proxy},
    {"Proxifier.exe",     "Proxifier", ProcKind::Proxy},
    {"ciadpi.exe",        "ByeDPI", ProcKind::Proxy},
    {"spoofdpi.exe",      "SpoofDPI", ProcKind::Proxy},
    {"wg.exe",            "WireGuard CLI", ProcKind::Vpn},
    {"WireGuard.exe",     "WireGuard (Windows client)", ProcKind::Vpn},
    {"wireguard.exe",     "WireGuard", ProcKind::Vpn},
    {"tunnel.exe",        "WireGuard tunnel service", ProcKind::Vpn},
    {"tun2socks.exe",     "tun2socks", ProcKind::Vpn},
    {"openvpn.exe",       "OpenVPN", ProcKind::Vpn},
    {"openvpn-gui.exe",   "OpenVPN GUI", ProcKind::Vpn},
    {"warp-svc.exe",      "Cloudflare WARP service", ProcKind::Vpn},
    {"Cloudflare WARP.exe","Cloudflare WARP", ProcKind::Vpn},
    {"ProtonVPN.exe",     "ProtonVPN", ProcKind::Vpn},
    {"NordVPN.exe",       "NordVPN", ProcKind::Vpn},
    {"ExpressVPN.exe",    "ExpressVPN", ProcKind::Vpn},
    {"Mullvad VPN.exe",   "Mullvad", ProcKind::Vpn},
    {"Shadowsocks.exe",   "Shadowsocks", ProcKind::Proxy},
    {"ShadowsocksR.exe",  "ShadowsocksR", ProcKind::Proxy},
    {"clash.exe",         "Clash", ProcKind::Proxy},
    {"clash-verge.exe",   "Clash Verge", ProcKind::Proxy},
    {"ClashForWindows.exe","Clash for Windows", ProcKind::Proxy},
    {"AmneziaVPN.exe",    "AmneziaVPN", ProcKind::Vpn},
    {"amneziawg.exe",     "AmneziaWG", ProcKind::Vpn},
    {"cisco-vpn.exe",     "Cisco AnyConnect", ProcKind::Vpn},
    {"vpncli.exe",        "Cisco AnyConnect CLI", ProcKind::Vpn},
    // windivert based, rewrite outgoing packets
    {"winws.exe",         "zapret (winws)", ProcKind::Rewriter},
    {"goodbyedpi.exe",    "GoodbyeDPI", ProcKind::Rewriter},
    {"clumsy.exe",        "clumsy (loss emulator)", ProcKind::Rewriter},
};
constexpr size_t VPN_PROCESSES_N = sizeof(VPN_PROCESSES) / sizeof(VPN_PROCESSES[0]);

struct KnownConfig { const char* envvar; const char* subpath; const char* tool; };
const KnownConfig KNOWN_CONFIGS[] = {
    {"APPDATA",      "\\Xray",                            "Xray-core configs"},
    {"APPDATA",      "\\v2rayN",                          "v2rayN configs"},
    {"APPDATA",      "\\v2ray",                           "V2Ray configs"},
    {"APPDATA",      "\\sing-box",                        "sing-box configs"},
    {"APPDATA",      "\\NekoRay",                         "NekoRay configs"},
    {"APPDATA",      "\\nekobox",                         "NekoBox configs"},
    {"APPDATA",      "\\Hiddify",                         "Hiddify configs"},
    {"APPDATA",      "\\Hiddify Next",                    "Hiddify Next"},
    {"APPDATA",      "\\clash",                           "Clash configs"},
    {"APPDATA",      "\\clash-verge",                     "Clash Verge configs"},
    {"LOCALAPPDATA", "\\WireGuard",                       "WireGuard configs"},
    {"LOCALAPPDATA", "\\Programs\\Amnezia",               "AmneziaVPN client"},
    {"LOCALAPPDATA", "\\Programs\\Hiddify",               "Hiddify install"},
    {"PROGRAMFILES", "\\OpenVPN",                         "OpenVPN install"},
    {"PROGRAMFILES", "\\Cloudflare\\Cloudflare WARP",     "Cloudflare WARP"},
    {"PROGRAMFILES", "\\WireGuard",                       "WireGuard (system)"},
    {"PROGRAMFILES", "\\Mullvad VPN",                     "Mullvad"},
    {"PROGRAMFILES", "\\NordVPN",                         "NordVPN"},
    {"PROGRAMFILES", "\\Proton\\VPN",                     "ProtonVPN"},
};
constexpr size_t KNOWN_CONFIGS_N = sizeof(KNOWN_CONFIGS) / sizeof(KNOWN_CONFIGS[0]);
} // namespace

vector<LocalProcess> list_vpn_processes() {
    vector<LocalProcess> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            char name[260] = {0};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, sizeof(name), nullptr, nullptr);
            for (size_t i = 0; i < VPN_PROCESSES_N; ++i) {
                if (_stricmp(name, VPN_PROCESSES[i].exe) == 0) {
                    LocalProcess LP;
                    LP.pid = pe.th32ProcessID;
                    LP.name = name;
                    LP.category = VPN_PROCESSES[i].category;
                    LP.kind = VPN_PROCESSES[i].kind;
                    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                    if (h) {
                        wchar_t path[MAX_PATH] = {0};
                        DWORD szp = MAX_PATH;
                        if (QueryFullProcessImageNameW(h, 0, path, &szp)) {
                            char p[MAX_PATH] = {0};
                            WideCharToMultiByte(CP_UTF8, 0, path, -1, p, sizeof(p), nullptr, nullptr);
                            LP.exe_path = p;
                        }
                        CloseHandle(h);
                    }
                    out.push_back(std::move(LP));
                    break;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

vector<ConfigHit> find_known_configs() {
    vector<ConfigHit> out;
    for (size_t i = 0; i < KNOWN_CONFIGS_N; ++i) {
        const KnownConfig& k = KNOWN_CONFIGS[i];
        char ev[512] = {0}; size_t sz = sizeof(ev);
        if (getenv_s(&sz, ev, sizeof(ev), k.envvar) != 0 || !sz) continue;
        string full = string(ev) + k.subpath;
        DWORD attr = GetFileAttributesA(full.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES)
            out.push_back({k.tool, full});
    }
    return out;
}

namespace {

// public resolvers' ipv6 addresses; a connect shows which local address the system picks
const char* const V6_TARGETS[] = {"2606:4700:4700::1111", "2001:4860:4860::8888"};
constexpr size_t DNS_SERVERS_ASKED = 3;

// windows asks every adapter's resolvers in parallel unless policy turns it off
bool smart_name_resolution() {
    DWORD v = 0, sz = sizeof(v);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
                     L"DisableSmartNameResolution", RRF_RT_REG_DWORD, nullptr, &v, &sz) != ERROR_SUCCESS)
        return true;
    return v == 0;
}

V6Probe probe_v6(const char* target, const vector<LeakAdapter>& ads) {
    V6Probe p;
    p.target = target;
    string err;
    SOCKET s = tcp_connect(target, 443, 2000, err);
    if (s == INVALID_SOCKET) {
        p.seen = err == "unreachable" ? V6Seen::NoPath : V6Seen::Silent;
        p.detail = err;
        return p;
    }
    sockaddr_storage ss{};
    int len = sizeof(ss);
    string local;
    if (getsockname(s, (sockaddr*)&ss, &len) == 0) local = sockaddr_to_str((SOCKADDR*)&ss);
    closesocket(s);
    p.detail = "local address " + local;
    for (const auto& a : ads)
        if (std::find(a.v6.begin(), a.v6.end(), local) != a.v6.end())
            p.seen = a.tunnel ? V6Seen::Tunnel : V6Seen::Outside;
    return p;
}

DnsSeen ask_resolver(const string& server) {
    // a plain recursive query for a reserved name, random id
    unsigned char q[29] = {0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                           7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
    RAND_bytes(q, 2);
    UdpResult u = udp_probe(server, 53, q, sizeof(q), 1500);
    if (u.responded && u.reply.size() >= 12 && u.reply[0] == q[0] && u.reply[1] == q[1] && (u.reply[2] & 0x80))
        return DnsSeen::Answer;
    // a socket the system refuses to send on is a firewall block
    if (u.err == "connect" || u.err == "send" || u.err == "wsa " + std::to_string(WSAEACCES)) return DnsSeen::Blocked;
    return DnsSeen::Silent;
}

void leak_line(const char* what, const LeakCheck& c) {
    const char* clr = c.outcome == Outcome::Positive ? C::RED : c.outcome == Outcome::Negative ? C::GRN
                    : c.outcome == Outcome::Inconclusive ? C::YEL : C::DIM;
    printf("  => %s: %s%s%s. %s\n", what, col(clr), outcome_name(c.outcome), col(C::RST), c.reason.c_str());
}

} // namespace

int run_local_analysis() {
    printf("\n%s[LOCAL ANALYSIS] This machine: adapters, routes, VPN software, leaks%s\n\n",
           col(C::BOLD), col(C::RST));

    auto adapters = list_local_adapters();
    printf("%s[1/6] Network adapters%s\n", col(C::BOLD), col(C::RST));
    int vpn_up = 0;
    for (auto& A: adapters) {
        if (!A.is_up) continue;
        if (A.is_vpn) ++vpn_up;
        const char* tag = A.is_vpn ? "[VPN]" : "     ";
        const char* clr = A.is_vpn ? C::YEL : C::DIM;
        printf("  %s%s%s  %s%s%s  ifidx=%lu  mtu=%lu\n",
               col(clr), tag, col(C::RST),
               col(C::BOLD), A.friendly.c_str(), col(C::RST),
               A.if_index, A.mtu);
        printf("         desc: %s\n", A.description.c_str());
        if (!A.mac.empty()) printf("         mac:  %s\n", A.mac.c_str());
        for (auto& ip: A.ipv4)     printf("         ipv4: %s\n", ip.c_str());
        for (auto& ip: A.ipv6)     printf("         ipv6: %s\n", ip.c_str());
        for (auto& g:  A.gateways) printf("         gw:   %s\n", g.c_str());
    }
    if (vpn_up == 0) printf("  %sno active VPN adapters%s\n", col(C::DIM), col(C::RST));

    auto routes = list_local_routes();
    std::map<unsigned long, LocalAdapter*> by_idx;
    for (auto& A: adapters) by_idx[A.if_index] = &A;
    for (auto& R: routes) {
        auto it = by_idx.find(R.if_index);
        if (it != by_idx.end()) { R.via_adapter = it->second->friendly; R.via_vpn = it->second->is_vpn; }
    }

    printf("\n%s[2/6] Default routes%s\n", col(C::BOLD), col(C::RST));
    vector<LocalRoute*> defaults_v4;
    for (auto& R: routes)
        if (R.prefix == "0.0.0.0/0") defaults_v4.push_back(&R);
    std::sort(defaults_v4.begin(), defaults_v4.end(),
              [](auto* a, auto* b){ return a->metric < b->metric; });
    for (auto* R: defaults_v4) {
        const char* c = R->via_vpn ? C::YEL : C::CYN;
        printf("  %s0.0.0.0/0%s -> %s  via %s%s%s%s  metric=%lu\n",
               col(c), col(C::RST), R->nexthop.c_str(),
               col(C::BOLD),
               R->via_adapter.empty() ? "?" : R->via_adapter.c_str(),
               R->via_vpn ? " [VPN]" : "",
               col(C::RST), R->metric);
    }
    if (defaults_v4.empty()) printf("  %sno IPv4 default route%s\n", col(C::RED), col(C::RST));

    printf("\n%s[3/6] Tunneling mode%s\n", col(C::BOLD), col(C::RST));
    bool has_vpn_if   = vpn_up > 0;
    vector<string> vpn_prefixes;
    for (auto& R: routes) if (R.via_vpn) vpn_prefixes.push_back(R.prefix);
    // wireguard and openvpn def1 install 0/1 + 128/1, not 0/0
    const unsigned long probe_if = best_interface_for("1.1.1.1");
    bool public_via_vpn = false;
    for (auto& A: adapters) if (A.if_index == probe_if && A.is_vpn) public_via_vpn = true;
    bool default_via_vpn = (!defaults_v4.empty() && defaults_v4.front()->via_vpn) ||
                           routes_cover_default(vpn_prefixes) || public_via_vpn;
    auto is_split_default = [](const string& p) { return p == "0.0.0.0/1" || p == "128.0.0.0/1" || p == "::/1" || p == "8000::/1"; };
    bool has_vpn_specific_route = false;
    for (auto& R: routes) {
        if (R.via_vpn && R.prefix != "0.0.0.0/0" && R.prefix != "::/0" && !is_split_default(R.prefix)
            && R.prefix.find("/32") == string::npos && R.prefix.find("/128") == string::npos)
            has_vpn_specific_route = true;
    }
    if (!has_vpn_if) {
        printf("  %s! No VPN adapter active: you're on raw ISP connection%s\n",
               col(C::YEL), col(C::RST));
    } else if (default_via_vpn && !has_vpn_specific_route) {
        printf("  %sFULL-TUNNEL%s: all traffic routed through VPN adapter \"%s\"\n",
               col(C::GRN), col(C::RST), defaults_v4.front()->via_adapter.c_str());
    } else if (default_via_vpn && has_vpn_specific_route) {
        printf("  %sFULL-TUNNEL + extra VPN-specific routes%s (likely VPN provider pushed split rules)\n",
               col(C::GRN), col(C::RST));
    } else if (!default_via_vpn && has_vpn_specific_route) {
        printf("  %sSPLIT-TUNNEL%s: default route goes via ISP, but selected subnets go through VPN:\n",
               col(C::MAG), col(C::RST));
        int shown = 0;
        for (auto& R: routes) {
            if (R.via_vpn && R.prefix != "0.0.0.0/0" && R.prefix.find("/32") == string::npos) {
                printf("         %s  ->  %s%s%s\n",
                       R.prefix.c_str(), col(C::BOLD), R.via_adapter.c_str(), col(C::RST));
                if (++shown >= 8) { printf("         ... (more omitted)\n"); break; }
            }
        }
    } else {
        printf("  %s? Mixed state%s: VPN adapter up, but default route NOT via VPN\n",
               col(C::YEL), col(C::RST));
    }

    printf("\n%s[4/6] VPN software detected (running processes + installed configs)%s\n",
           col(C::BOLD), col(C::RST));
    auto procs = list_vpn_processes();
    if (procs.empty()) printf("  %sno known VPN/proxy processes running%s\n", col(C::DIM), col(C::RST));
    else {
        for (auto& p: procs) {
            printf("  %s* %s%s  pid=%lu  (%s)\n",
                   col(C::GRN), p.name.c_str(), col(C::RST),
                   p.pid, p.category.c_str());
            if (!p.exe_path.empty()) printf("     path: %s\n", p.exe_path.c_str());
        }
    }

    auto cfgs = find_known_configs();
    if (!cfgs.empty()) {
        printf("\n  %sInstalled tools / config dirs:%s\n", col(C::BOLD), col(C::RST));
        for (auto& c: cfgs)
            printf("    %s%-32s%s  %s\n", col(C::CYN), c.tool.c_str(), col(C::RST), c.path.c_str());
    }

    // leaks: the tunnel's own adapters against everything beside them
    vector<LeakAdapter> leak_ads;
    std::set<unsigned long> tunnel_idx;
    for (const auto& A : adapters) {
        LeakAdapter L;
        L.name = A.friendly; L.index = A.if_index; L.metric = A.metric;
        L.tunnel = A.is_vpn; L.up = A.is_up; L.gateway = !A.gateways.empty();
        L.v6 = A.ipv6; L.dns = A.dns;
        if (L.up && L.tunnel) tunnel_idx.insert(L.index);
        leak_ads.push_back(std::move(L));
    }
    // a resolver routed into the tunnel is asked through it
    for (auto& L : leak_ads) {
        if (L.tunnel) continue;
        L.dns.erase(std::remove_if(L.dns.begin(), L.dns.end(), [&](const string& d) {
            return tunnel_idx.count(best_interface_for(d)) > 0;
        }), L.dns.end());
    }

    printf("\n%s[5/6] IPv6 beside the tunnel%s\n", col(C::BOLD), col(C::RST));
    vector<V6Probe> v6probes;
    if (any_tunnel_up(leak_ads) && !v6_outside(leak_ads).empty()) {
        for (const char* t : V6_TARGETS) {
            v6probes.push_back(probe_v6(t, leak_ads));
            const V6Probe& p = v6probes.back();
            printf("  [%s]:443  %s  (%s)\n", p.target.c_str(),
                   p.seen == V6Seen::Outside ? "beside the tunnel" : p.seen == V6Seen::Tunnel ? "into the tunnel"
                   : p.seen == V6Seen::NoPath ? "no path" : "no answer", p.detail.c_str());
        }
    }
    const LeakCheck v6 = ipv6_leak(leak_ads, v6probes);
    leak_line("ipv6 leak", v6);

    printf("\n%s[6/6] DNS beside the tunnel%s\n", col(C::BOLD), col(C::RST));
    const bool smart = smart_name_resolution();
    printf("  parallel queries to every adapter's resolver: %s\n", smart ? "on (windows default)" : "off by policy");
    vector<DnsProbe> dprobes;
    if (any_tunnel_up(leak_ads)) {
        for (const auto& r : dns_outside(leak_ads, smart)) {
            if (dprobes.size() >= DNS_SERVERS_ASKED) break;
            DnsProbe p;
            p.server = r.first;
            p.adapter = r.second->name;
            for (int i = 0; i < 2; ++i) {
                if (i) Sleep(300);
                p.seen.push_back(ask_resolver(p.server));
            }
            const auto answers = std::count(p.seen.begin(), p.seen.end(), DnsSeen::Answer);
            printf("  %-28s on %-20s %lld of 2 answered\n", p.server.c_str(), p.adapter.c_str(), (long long)answers);
            dprobes.push_back(std::move(p));
        }
    }
    const LeakCheck dns = dns_leak(leak_ads, smart, dprobes);
    leak_line("dns leak", dns);

    printf("\n%sSummary:%s\n", col(C::BOLD), col(C::RST));
    if (has_vpn_if && default_via_vpn)
        printf("  %s-> You are currently tunneled through VPN.%s\n", col(C::GRN), col(C::RST));
    else if (has_vpn_if && !default_via_vpn && has_vpn_specific_route)
        printf("  %s-> Partial tunnel (split-tunneling active).%s\n", col(C::MAG), col(C::RST));
    else if (has_vpn_if)
        printf("  %s-> VPN adapter exists but traffic NOT through it (disconnected or misrouted).%s\n",
               col(C::YEL), col(C::RST));
    else
        printf("  %s-> No VPN active. Traffic goes directly via your ISP.%s\n",
               col(C::YEL), col(C::RST));
    if (!procs.empty()) {
        std::set<string> cats;
        for (auto& p: procs) cats.insert(p.category);
        printf("     Software stack running: ");
        int n = 0;
        for (auto& c: cats) printf("%s%s", n++ ? ", " : "", c.c_str());
        printf("\n");
    }
    if (v6.outcome == Outcome::Positive || dns.outcome == Outcome::Positive)
        printf("  %s-> Traffic leaves beside the tunnel: %s%s%s.%s\n", col(C::RED),
               v6.outcome == Outcome::Positive ? "ipv6" : "",
               v6.outcome == Outcome::Positive && dns.outcome == Outcome::Positive ? " and " : "",
               dns.outcome == Outcome::Positive ? "dns" : "", col(C::RST));
    return v6.outcome == Outcome::Positive || dns.outcome == Outcome::Positive ? 2 : 0;
}