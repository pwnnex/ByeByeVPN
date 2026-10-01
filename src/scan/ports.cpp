// SPDX-License-Identifier: GPL-3.0-or-later
#include "ports.h"
#include <algorithm>

using std::vector;

const vector<int> TCP_FAST_PORTS = {
    // ssh/mail/web/dns
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 179, 389, 443,
    445, 465, 514, 515, 548, 587, 631, 636, 873, 990, 993, 995,
    // proxy / socks
    1080, 1081, 1082, 1090, 1180, 1443, 1701, 1723,
    3128, 3129, 3130, 3389, 3690, 4433, 4443, 4444, 4500,
    // tls/https alt
    5000, 5001, 5060, 5061, 5222, 5223, 5228, 5269, 5280, 5432, 5500,
    5555, 5900, 5938, 6000, 6379, 6443, 6667, 6697, 6881,
    // modern alt-tls/http/admin
    7000, 7001, 7070, 7443, 7547, 7777, 7999,
    8000, 8008, 8009, 8010, 8018, 8020, 8030, 8040, 8060, 8080, 8081, 8082,
    8083, 8088, 8090, 8091, 8096, 8100, 8118, 8123, 8181, 8188, 8200, 8222,
    8333, 8383, 8388, 8389, 8443, 8444, 8445, 8480, 8500, 8800, 8843, 8880,
    8888, 8889, 8899, 8989,
    // xray/v2ray/reality defaults
    9000, 9001, 9002, 9007, 9050, 9051, 9090, 9091, 9100, 9200, 9300, 9418,
    9443, 9999,
    // 10k range
    10000, 10001, 10050, 10080, 10443, 10800, 10808, 10809, 10810, 10811,
    11211, 11443, 12000, 13000, 13306, 13579, 14443, 14444, 14567,
    15000, 16000, 16999, 17000, 17777, 18080, 18443, 19132, 19999,
    20000, 20443, 21443, 22222, 22443, 23443, 24443, 25443,
    27015, 27017, 28017, 30000, 30003, 31337, 32400,
    33389, 35000, 36000, 36363, 37000, 38000, 39000, 40000,
    41641, 41642, 42000, 43210, 44443, 45000, 46443, 48000,
    49152, 50000, 50051, 50443, 51443, 51820, 51821, 52323, 53333,
    54321, 55443, 55554, 56789, 57621, 58080, 59999, 60000, 61613, 62078, 65000
};

const vector<int> UDP_SCAN_PORTS = {
    53, 67, 69, 80, 123, 137, 138, 161, 443, 500, 514, 520, 554, 623,
    1194, 1434, 1645, 1701, 1812, 1813, 1900, 2049, 2152, 2302, 2427,
    3702, 4433, 4500, 4789, 5060, 5353, 5683, 6881, 10000, 27015, 41641,
    51820
};

vector<int> build_tcp_ports() {
    vector<int> p;
    switch (g_port_mode) {
        case PortMode::FAST:
            p = TCP_FAST_PORTS; break;
        case PortMode::RANGE: {
            // swap first, then clamp to 1..65535
            // otherwise an out-of-range pair can produce invalid ports or a huge reserve()
            int lo = g_range_lo, hi = g_range_hi;
            if (lo > hi) std::swap(lo, hi);         // a reversed range is a typo
            lo = std::max(1, lo);
            hi = std::min(65535, hi);
            if (lo <= hi) {                         // else: no valid port in range
                p.reserve(static_cast<size_t>(hi) - static_cast<size_t>(lo) + 1);
                for (int i = lo; i <= hi; ++i) p.push_back(i);
            }
        } break;
        case PortMode::LIST:
            // drop invalid ports from raw atoi() output
            for (int v : g_port_list)
                if (v >= 1 && v <= 65535) p.push_back(v);
            break;
        case PortMode::FULL:
        default:
            p.reserve(65535);
            for (int i = 1; i <= 65535; ++i) p.push_back(i);
            break;
    }
    return p;
}

// iana or documented software default only. a guess here reads as a finding;
// reality has no default port, 6443 is the kubernetes api.
struct PortHint { int port; const char* svc; const char* proto; };
static const PortHint PORT_HINTS[] = {
    {22,"SSH","tcp"},{53,"DNS","tcp/udp"},{80,"HTTP","tcp"},{88,"Kerberos","tcp"},
    {443,"HTTPS","tcp"},{465,"SMTPS","tcp"},{587,"SMTP submission","tcp"},
    {853,"DoT","tcp"},{990,"FTPS","tcp"},{993,"IMAPS","tcp"},{995,"POP3S","tcp"},
    {1080,"SOCKS (iana)","tcp"},{1194,"OpenVPN default","tcp/udp"},{1701,"L2TP","udp"},
    {1723,"PPTP","tcp"},{3128,"Squid default","tcp"},{3389,"RDP","tcp"},
    {4433,"HTTPS alt","tcp"},{4443,"HTTPS alt","tcp"},
    {4500,"IKEv2 NAT-T","udp"},{5060,"SIP","tcp/udp"},{5555,"ADB default","tcp"},
    {6443,"Kubernetes API default","tcp"},
    {8080,"HTTP alt","tcp"},{8118,"Privoxy default","tcp"},{8123,"Polipo default","tcp"},
    {8388,"Shadowsocks default","tcp/udp"},{8443,"HTTPS alt","tcp"},
    {8888,"HTTP alt","tcp"},{9050,"Tor SOCKS default","tcp"},{9051,"Tor control default","tcp"},
    {10808,"v2rayN local SOCKS default","tcp"},{10809,"v2rayN local HTTP default","tcp"},
    {51820,"WireGuard default","udp"},{41641,"Tailscale default","udp"},
    {500,"IKE ISAKMP","udp"},
    // one entry per port; port_hint() returns the first match
};
static const size_t PORT_HINTS_N = sizeof(PORT_HINTS) / sizeof(PORT_HINTS[0]);

const char* port_hint(int p) {
    for (size_t i = 0; i < PORT_HINTS_N; ++i)
        if (PORT_HINTS[i].port == p) return PORT_HINTS[i].svc;
    return "";
}