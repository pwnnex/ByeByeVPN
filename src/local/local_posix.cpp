// SPDX-License-Identifier: GPL-3.0-or-later
#include "local.h"
#include "../common/console.h"
#include "../common/util.h"

#include <arpa/inet.h>
#include <filesystem>
#include <ifaddrs.h>
#include <net/if.h>
#ifdef __APPLE__
#include <net/if_dl.h>
#endif
#include <sys/ioctl.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <sstream>

using std::string;
using std::vector;

namespace {

bool adapter_is_vpn(const string& name) {
    static const char* keywords[] = {
        "utun", "tun", "tap", "wireguard", "wg", "openvpn", "warp",
        "mullvad", "nordlynx", "proton", "amnezia"
    };
    for (const char* keyword : keywords)
        if (icontains(name, keyword)) return true;
    return false;
}

string socket_address(const sockaddr* address) {
    if (!address) return {};
    char text[INET6_ADDRSTRLEN]{};
    if (address->sa_family == AF_INET)
        inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(address)->sin_addr,
                  text, sizeof(text));
    else if (address->sa_family == AF_INET6)
        inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr,
                  text, sizeof(text));
    return text;
}

struct KnownProcess { const char* name; const char* category; };
const KnownProcess known_processes[] = {
    {"xray", "Xray-core"}, {"v2ray", "V2Ray"}, {"sing-box", "sing-box"},
    {"hiddify", "Hiddify"}, {"wireguard-go", "WireGuard"},
    {"openvpn", "OpenVPN"}, {"cloudflare-warp", "Cloudflare WARP"},
    {"mullvad-daemon", "Mullvad"}, {"clash", "Clash"},
    {"amnezia", "AmneziaVPN"}
};

} // namespace

vector<LocalAdapter> list_local_adapters() {
    vector<LocalAdapter> output;
    std::map<string, size_t> positions;
    ifaddrs* list = nullptr;
    if (getifaddrs(&list) != 0) return output;
    int control = socket(AF_INET, SOCK_DGRAM, 0);
    for (ifaddrs* item = list; item; item = item->ifa_next) {
        if (!item->ifa_name) continue;
        string name = item->ifa_name;
        auto [it, inserted] = positions.emplace(name, output.size());
        if (inserted) {
            LocalAdapter adapter;
            adapter.friendly = name;
            adapter.description = name;
            adapter.if_index = if_nametoindex(name.c_str());
            adapter.is_up = (item->ifa_flags & IFF_UP) != 0;
            adapter.is_vpn = adapter_is_vpn(name);
            if (control >= 0) {
                ifreq request{};
                std::strncpy(request.ifr_name, name.c_str(), IFNAMSIZ - 1);
                if (ioctl(control, SIOCGIFMTU, &request) == 0)
                    adapter.mtu = static_cast<unsigned long>(request.ifr_mtu);
            }
            output.push_back(std::move(adapter));
        }
        LocalAdapter& adapter = output[it->second];
        string address = socket_address(item->ifa_addr);
        if (item->ifa_addr && item->ifa_addr->sa_family == AF_INET && !address.empty())
            adapter.ipv4.push_back(address);
        else if (item->ifa_addr && item->ifa_addr->sa_family == AF_INET6 && !address.empty())
            adapter.ipv6.push_back(address);
#ifdef __APPLE__
        else if (item->ifa_addr && item->ifa_addr->sa_family == AF_LINK) {
            auto* link = reinterpret_cast<sockaddr_dl*>(item->ifa_addr);
            if (link->sdl_alen > 0)
                adapter.mac = mac_to_str(reinterpret_cast<unsigned char*>(LLADDR(link)),
                                         link->sdl_alen);
        }
#endif
    }
    if (control >= 0) close(control);
    freeifaddrs(list);
    return output;
}

vector<LocalRoute> list_local_routes() {
    vector<LocalRoute> output;
#ifdef __APPLE__
    FILE* pipe = popen("/usr/sbin/netstat -rn -f inet 2>/dev/null", "r");
    if (!pipe) return output;
    char line[1024];
    while (fgets(line, sizeof(line), pipe)) {
        std::istringstream in(line);
        string destination, gateway, flags, interface;
        if (!(in >> destination >> gateway >> flags >> interface)) continue;
        if (destination == "Destination" || destination == "Routing") continue;
        LocalRoute route;
        route.prefix = destination == "default" ? "0.0.0.0/0" : destination;
        if (route.prefix.find('/') == string::npos && flags.find('H') != string::npos)
            route.prefix += "/32";
        route.nexthop = gateway;
        route.via_adapter = interface;
        route.if_index = if_nametoindex(interface.c_str());
        route.via_vpn = adapter_is_vpn(interface);
        output.push_back(std::move(route));
    }
    pclose(pipe);
#endif
    return output;
}

vector<LocalProcess> list_vpn_processes() {
    vector<LocalProcess> output;
    FILE* pipe = popen("ps -axo pid=,comm=", "r");
    if (!pipe) return output;
    char line[2048];
    while (fgets(line, sizeof(line), pipe)) {
        std::istringstream in(line);
        unsigned long pid = 0;
        string path;
        if (!(in >> pid >> path)) continue;
        string name = std::filesystem::path(path).filename().string();
        for (const auto& known : known_processes) {
            if (icontains(name, known.name)) {
                output.push_back({pid, name, path, known.category});
                break;
            }
        }
    }
    pclose(pipe);
    return output;
}

vector<ConfigHit> find_known_configs() {
    vector<ConfigHit> output;
    const char* home = std::getenv("HOME");
    if (!home) return output;
    const std::pair<const char*, const char*> paths[] = {
        {"Xray-core configs", ".config/xray"}, {"V2Ray configs", ".config/v2ray"},
        {"sing-box configs", ".config/sing-box"}, {"Clash configs", ".config/clash"},
        {"WireGuard configs", ".config/wireguard"},
        {"Hiddify", "Library/Application Support/app.hiddify.com"},
        {"Mullvad", "Library/Application Support/Mullvad VPN"}
    };
    for (const auto& [tool, relative] : paths) {
        std::filesystem::path path = std::filesystem::path(home) / relative;
        std::error_code error;
        if (std::filesystem::exists(path, error)) output.push_back({tool, path.string()});
    }
    return output;
}

// Keep report formatting shared in spirit with the Windows implementation,
// while using data gathered from native macOS interfaces above.
void run_local_analysis() {
    printf("\n%s[LOCAL ANALYSIS] This machine — adapters, routes, VPN software%s\n\n",
           col(C::BOLD), col(C::RST));
    auto adapters = list_local_adapters();
    printf("%s[1/4] Network adapters%s\n", col(C::BOLD), col(C::RST));
    int vpn_up = 0;
    for (const auto& adapter : adapters) {
        if (!adapter.is_up) continue;
        if (adapter.is_vpn) ++vpn_up;
        printf("  %s%s%s  %s  ifidx=%lu  mtu=%lu\n",
               col(adapter.is_vpn ? C::YEL : C::DIM), adapter.is_vpn ? "[VPN]" : "     ",
               col(C::RST), adapter.friendly.c_str(), adapter.if_index, adapter.mtu);
        for (const auto& ip : adapter.ipv4) printf("         ipv4: %s\n", ip.c_str());
        for (const auto& ip : adapter.ipv6) printf("         ipv6: %s\n", ip.c_str());
    }
    if (!vpn_up) printf("  %sno active VPN adapters%s\n", col(C::DIM), col(C::RST));

    auto routes = list_local_routes();
    printf("\n%s[2/4] Default routes%s\n", col(C::BOLD), col(C::RST));
    const LocalRoute* default_route = nullptr;
    for (const auto& route : routes) if (route.prefix == "0.0.0.0/0") {
        default_route = &route;
        printf("  0.0.0.0/0 -> %s  via %s%s\n", route.nexthop.c_str(),
               route.via_adapter.c_str(), route.via_vpn ? " [VPN]" : "");
    }
    if (!default_route) printf("  %sno IPv4 default route found%s\n", col(C::RED), col(C::RST));

    bool default_vpn = default_route && default_route->via_vpn;
    bool split = false;
    for (const auto& route : routes)
        if (route.via_vpn && route.prefix != "0.0.0.0/0" &&
            route.prefix.find("/32") == string::npos) split = true;
    printf("\n%s[3/4] Tunneling mode%s\n", col(C::BOLD), col(C::RST));
    if (default_vpn) printf("  %sFULL-TUNNEL%s — default route uses %s\n",
                            col(C::GRN), col(C::RST), default_route->via_adapter.c_str());
    else if (split) printf("  %sSPLIT-TUNNEL%s — selected routes use a VPN interface\n",
                           col(C::MAG), col(C::RST));
    else if (vpn_up) printf("  %sVPN interface present, but not the default route%s\n",
                            col(C::YEL), col(C::RST));
    else printf("  %sNo VPN route detected%s\n", col(C::YEL), col(C::RST));

    printf("\n%s[4/4] VPN software detected%s\n", col(C::BOLD), col(C::RST));
    auto processes = list_vpn_processes();
    for (const auto& process : processes)
        printf("  %s* %s%s  pid=%lu  (%s)\n", col(C::GRN), process.name.c_str(),
               col(C::RST), process.pid, process.category.c_str());
    if (processes.empty()) printf("  %sno known VPN/proxy processes running%s\n",
                                  col(C::DIM), col(C::RST));
    for (const auto& config : find_known_configs())
        printf("  config: %-24s %s\n", config.tool.c_str(), config.path.c_str());
}
