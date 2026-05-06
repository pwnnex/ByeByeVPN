#include "local_env.h"
#include "../core/utils.h"
#include "../network/socket_sys.h"
#include <algorithm>
#include <map>
#include <set>
#include <cstdio>

#ifdef _WIN32
#include <iphlpapi.h>
#include <tlhelp32.h>
#endif

static bool icontains(const std::string& hay, const char* needle) {
    std::string a = hay, b = needle;
    std::transform(a.begin(), a.end(), a.begin(), ::tolower);
    std::transform(b.begin(), b.end(), b.begin(), ::tolower);
    return a.find(b) != std::string::npos;
}

#ifdef _WIN32
static std::string mac_to_str(const unsigned char* mac, int len) {
    char buf[64]; buf[0]=0;
    for (int i=0;i<len;++i)
        sprintf(buf+strlen(buf), "%02X%s", mac[i], i<len-1?":":"");
    return buf;
}

static std::string sockaddr_to_str(SOCKADDR* sa) {
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
#endif

static bool adapter_is_vpn(const std::string& desc, const std::string& name) {
    static const char* kw[] = {
        "TAP-Windows", "TAP-ProtonVPN", "WireGuard", "WireGuard Tunnel",
        "Wintun", "TUN", "Tun ", "OpenVPN", "Mullvad", "NordLynx", "ProtonVPN",
        "Cloudflare WARP", "Hiddify", "Amnezia", "singbox", "sing-box",
        "v2ray", "xray", "AmneziaWG", "ExpressVPN", "Private Internet",
        "PIA", "Surfshark", "TorGuard"
    };
    for (auto k: kw) if (icontains(desc, k) || icontains(name, k)) return true;
    return false;
}

std::vector<LocalAdapter> list_local_adapters() {
    std::vector<LocalAdapter> out;
#ifdef _WIN32
    ULONG sz = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                         nullptr, nullptr, &sz);
    if (!sz) return out;
    std::vector<unsigned char> buf(sz);
    auto* aa = (IP_ADAPTER_ADDRESSES*)buf.data();
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
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
        A.is_up = (p->OperStatus == IfOperStatusUp);
        for (auto* u = p->FirstUnicastAddress; u; u = u->Next) {
            std::string s = sockaddr_to_str(u->Address.lpSockaddr);
            if (s.empty()) continue;
            if (u->Address.lpSockaddr->sa_family == AF_INET)  A.ipv4.push_back(s);
            else                                              A.ipv6.push_back(s);
        }
        for (auto* g = p->FirstGatewayAddress; g; g = g->Next) {
            std::string s = sockaddr_to_str(g->Address.lpSockaddr);
            if (!s.empty()) A.gateways.push_back(s);
        }
        A.is_vpn = adapter_is_vpn(A.description, A.friendly);
        out.push_back(std::move(A));
    }
#endif
    return out;
}

std::vector<LocalRoute> list_local_routes() {
    std::vector<LocalRoute> out;
#ifdef _WIN32
    MIB_IPFORWARD_TABLE2* tbl = nullptr;
    if (GetIpForwardTable2(AF_UNSPEC, &tbl) != NO_ERROR || !tbl) return out;
    for (ULONG i=0; i<tbl->NumEntries; ++i) {
        auto& r = tbl->Table[i];
        LocalRoute R;
        char dst[INET6_ADDRSTRLEN]={0}, nh[INET6_ADDRSTRLEN]={0};
        if (r.DestinationPrefix.Prefix.si_family == AF_INET) {
            inet_ntop(AF_INET, &r.DestinationPrefix.Prefix.Ipv4.sin_addr, dst, sizeof(dst));
            inet_ntop(AF_INET, &r.NextHop.Ipv4.sin_addr,                    nh,  sizeof(nh));
        } else if (r.DestinationPrefix.Prefix.si_family == AF_INET6) {
            inet_ntop(AF_INET6, &r.DestinationPrefix.Prefix.Ipv6.sin6_addr, dst, sizeof(dst));
            inet_ntop(AF_INET6, &r.NextHop.Ipv6.sin6_addr,                   nh,  sizeof(nh));
        } else continue;
        R.prefix   = std::string(dst) + "/" + std::to_string(r.DestinationPrefix.PrefixLength);
        R.nexthop  = nh;
        R.if_index = r.InterfaceIndex;
        R.metric   = r.Metric;
        out.push_back(R);
    }
    FreeMibTable(tbl);
#endif
    return out;
}

struct KnownProc { const char* exe; const char* category; };
static const std::vector<KnownProc> VPN_PROCESSES = {
    {"xray.exe",          "Xray-core"},
    {"v2ray.exe",         "V2Ray"},
    {"sing-box.exe",      "sing-box"},
    {"singbox.exe",       "sing-box"},
    {"v2rayN.exe",        "v2rayN (GUI → Xray)"},
    {"v2rayNG.exe",       "v2rayNG"},
    {"nekoray.exe",       "NekoRay (GUI → sing-box/Xray)"},
    {"nekobox.exe",       "NekoBox"},
    {"Hiddify.exe",       "Hiddify"},
    {"HiddifyCli.exe",    "Hiddify CLI"},
    {"HiddifyTray.exe",   "Hiddify tray"},
    {"wg.exe",            "WireGuard CLI"},
    {"WireGuard.exe",     "WireGuard (Windows client)"},
    {"wireguard.exe",     "WireGuard"},
    {"tunnel.exe",        "WireGuard tunnel service"},
    {"tun2socks.exe",     "tun2socks"},
    {"openvpn.exe",       "OpenVPN"},
    {"openvpn-gui.exe",   "OpenVPN GUI"},
    {"warp-svc.exe",      "Cloudflare WARP service"},
    {"Cloudflare WARP.exe","Cloudflare WARP"},
    {"ProtonVPN.exe",     "ProtonVPN"},
    {"NordVPN.exe",       "NordVPN"},
    {"ExpressVPN.exe",    "ExpressVPN"},
    {"Mullvad VPN.exe",   "Mullvad"},
    {"Shadowsocks.exe",   "Shadowsocks"},
    {"ShadowsocksR.exe",  "ShadowsocksR"},
    {"clash.exe",         "Clash"},
    {"clash-verge.exe",   "Clash Verge"},
    {"ClashForWindows.exe","Clash for Windows"},
    {"AmneziaVPN.exe",    "AmneziaVPN"},
    {"amneziawg.exe",     "AmneziaWG"},
    {"cisco-vpn.exe",     "Cisco AnyConnect"},
    {"vpncli.exe",        "Cisco AnyConnect CLI"},
};

std::vector<LocalProcess> list_vpn_processes() {
    std::vector<LocalProcess> out;
#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            char name[260] = {0};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, sizeof(name), nullptr, nullptr);
            for (auto& kp: VPN_PROCESSES) {
                if (_stricmp(name, kp.exe) == 0) {
                    LocalProcess LP;
                    LP.pid = pe.th32ProcessID;
                    LP.name = name;
                    LP.category = kp.category;
                    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                    if (h) {
                        wchar_t path[MAX_PATH] = {0};
                        DWORD sz = MAX_PATH;
                        if (QueryFullProcessImageNameW(h, 0, path, &sz)) {
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
#endif
    return out;
}

struct KnownConfig { const char* envvar; const char* subpath; const char* tool; };
static const std::vector<KnownConfig> KNOWN_CONFIGS = {
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

std::vector<ConfigHit> find_known_configs() {
    std::vector<ConfigHit> out;
#ifdef _WIN32
    for (auto& k: KNOWN_CONFIGS) {
        char ev[512] = {0}; size_t sz = sizeof(ev);
        if (getenv_s(&sz, ev, sizeof(ev), k.envvar) != 0 || !sz) continue;
        std::string full = std::string(ev) + k.subpath;
        DWORD attr = GetFileAttributesA(full.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES)
            out.push_back({k.tool, full});
    }
#endif
    return out;
}

void run_local_analysis() {
    tee_printf("\n%s[LOCAL ANALYSIS] This machine — adapters, routes, VPN software%s\n\n",
           col(C::BOLD), col(C::RST));

    auto adapters = list_local_adapters();
    tee_printf("%s[1/4] Network adapters%s\n", col(C::BOLD), col(C::RST));
    int vpn_up = 0, phys_up = 0;
    for (auto& A: adapters) {
        if (!A.is_up) continue;
        if (A.is_vpn) ++vpn_up; else if (!A.ipv4.empty()) ++phys_up;
        const char* tag = A.is_vpn ? "[VPN]" : "     ";
        const char* clr = A.is_vpn ? C::YEL : C::DIM;
        tee_printf("  %s%s%s  %s%s%s  ifidx=%lu  mtu=%lu\n",
               col(clr), tag, col(C::RST),
               col(C::BOLD), A.friendly.c_str(), col(C::RST),
               A.if_index, A.mtu);
        tee_printf("         desc: %s\n", A.description.c_str());
        if (!A.mac.empty()) tee_printf("         mac:  %s\n", A.mac.c_str());
        for (auto& ip: A.ipv4) tee_printf("         ipv4: %s\n", ip.c_str());
        for (auto& ip: A.ipv6) tee_printf("         ipv6: %s\n", ip.c_str());
        for (auto& g:  A.gateways) tee_printf("         gw:   %s\n", g.c_str());
    }
    if (vpn_up == 0) tee_printf("  %sno active VPN adapters%s\n", col(C::DIM), col(C::RST));

    auto routes = list_local_routes();
    std::map<unsigned long, LocalAdapter*> by_idx;
    for (auto& A: adapters) by_idx[A.if_index] = &A;
    for (auto& R: routes) {
        auto it = by_idx.find(R.if_index);
        if (it != by_idx.end()) { R.via_adapter = it->second->friendly; R.via_vpn = it->second->is_vpn; }
    }

    tee_printf("\n%s[2/4] Default routes%s\n", col(C::BOLD), col(C::RST));
    std::vector<LocalRoute*> defaults_v4, defaults_v6;
    for (auto& R: routes) {
        if (R.prefix == "0.0.0.0/0") defaults_v4.push_back(&R);
        if (R.prefix == "::/0")       defaults_v6.push_back(&R);
    }
    std::sort(defaults_v4.begin(), defaults_v4.end(),
              [](auto* a, auto* b){return a->metric < b->metric;});
    for (auto* R: defaults_v4) {
        const char* c = R->via_vpn ? C::YEL : C::CYN;
        tee_printf("  %s0.0.0.0/0%s → %s  via %s%s%s%s  metric=%lu\n",
               col(c), col(C::RST), R->nexthop.c_str(),
               col(C::BOLD),
               R->via_adapter.empty()?"?":R->via_adapter.c_str(),
               R->via_vpn?" [VPN]":"",
               col(C::RST), R->metric);
    }
    if (defaults_v4.empty()) tee_printf("  %sno IPv4 default route%s\n", col(C::RED), col(C::RST));

    tee_printf("\n%s[3/4] Tunneling mode%s\n", col(C::BOLD), col(C::RST));
    bool has_vpn_if   = vpn_up > 0;
    bool default_via_vpn = !defaults_v4.empty() && defaults_v4.front()->via_vpn;
    bool has_vpn_specific_route = false;
    for (auto& R: routes) {
        if (R.via_vpn && R.prefix != "0.0.0.0/0" && R.prefix != "::/0"
            && R.prefix.find("/32") == std::string::npos && R.prefix.find("/128") == std::string::npos)
            has_vpn_specific_route = true;
    }
    if (!has_vpn_if) {
        tee_printf("  %s⚠ No VPN adapter active — you're on raw ISP connection%s\n",
               col(C::YEL), col(C::RST));
    } else if (default_via_vpn && !has_vpn_specific_route) {
        tee_printf("  %s✓ FULL-TUNNEL%s — all traffic routed through VPN adapter \"%s\"\n",
               col(C::GRN), col(C::RST), defaults_v4.front()->via_adapter.c_str());
    } else if (default_via_vpn && has_vpn_specific_route) {
        tee_printf("  %s↯ FULL-TUNNEL + extra VPN-specific routes%s (likely VPN provider pushed split rules)\n",
               col(C::GRN), col(C::RST));
    } else if (!default_via_vpn && has_vpn_specific_route) {
        tee_printf("  %s✂ SPLIT-TUNNEL%s — default route goes via ISP, but selected subnets go through VPN:\n",
               col(C::MAG), col(C::RST));
        int shown = 0;
        for (auto& R: routes) {
            if (R.via_vpn && R.prefix != "0.0.0.0/0" && R.prefix.find("/32") == std::string::npos) {
                tee_printf("         %s  →  %s%s%s\n",
                       R.prefix.c_str(), col(C::BOLD), R.via_adapter.c_str(), col(C::RST));
                if (++shown >= 8) { tee_printf("         ... (more omitted)\n"); break; }
            }
        }
    } else {
        tee_printf("  %s? Mixed state%s — VPN adapter up, but default route NOT via VPN\n",
               col(C::YEL), col(C::RST));
    }

    tee_printf("\n%s[4/4] VPN software detected (running processes + installed configs)%s\n",
           col(C::BOLD), col(C::RST));
    auto procs = list_vpn_processes();
    if (procs.empty()) tee_printf("  %sno known VPN/proxy processes running%s\n", col(C::DIM), col(C::RST));
    else {
        for (auto& p: procs) {
            tee_printf("  %s● %s%s  pid=%lu  (%s)\n",
                   col(C::GRN), p.name.c_str(), col(C::RST),
                   p.pid, p.category.c_str());
            if (!p.exe_path.empty()) tee_printf("     path: %s\n", p.exe_path.c_str());
        }
    }

    auto cfgs = find_known_configs();
    if (!cfgs.empty()) {
        tee_printf("\n  %sInstalled tools / config dirs:%s\n", col(C::BOLD), col(C::RST));
        for (auto& c: cfgs)
            tee_printf("    %s%-32s%s  %s\n", col(C::CYN), c.tool.c_str(), col(C::RST), c.path.c_str());
    }

    tee_printf("\n%sSummary:%s\n", col(C::BOLD), col(C::RST));
    if (has_vpn_if && default_via_vpn)
        tee_printf("  %s→ You are currently tunneled through VPN.%s\n", col(C::GRN), col(C::RST));
    else if (has_vpn_if && !default_via_vpn && has_vpn_specific_route)
        tee_printf("  %s→ Partial tunnel (split-tunneling active).%s\n", col(C::MAG), col(C::RST));
    else if (has_vpn_if)
        tee_printf("  %s→ VPN adapter exists but traffic NOT through it (disconnected or misrouted).%s\n",
               col(C::YEL), col(C::RST));
    else
        tee_printf("  %s→ No VPN active. Traffic goes directly via your ISP.%s\n",
               col(C::YEL), col(C::RST));
    if (!procs.empty()) {
        std::set<std::string> cats;
        for (auto& p: procs) cats.insert(p.category);
        tee_printf("     Software stack running: ");
        int n=0; for (auto& c: cats) tee_printf("%s%s", n++?", ":"", c.c_str()); tee_printf("\n");
    }
}