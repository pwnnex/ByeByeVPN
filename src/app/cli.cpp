#include "cli.h"
#include "orchestrator.h"
#include "target.h"
#include "../common/console.h"
#include "../common/config.h"
#include "../common/util.h"
#include "../net/dns.h"
#include "../net/icmp.h"
#include "../scan/ports.h"
#include "../scan/tcp_scan.h"
#include "../scan/udp_probes.h"
#include "../scan/tls.h"
#include "../scan/sni.h"
#include "../scan/j3.h"
#include "../scan/snitch.h"
#include "../geoip/geoip.h"
#include "../local/local.h"

#include <cstdio>
#include <cstdlib>
#include <future>
#include <string>

using std::string;

void help() {
    printf("ByeByeVPN — full TSPU/DPI/VPN detectability scanner\n\n");
    printf("Usage:\n");
    printf("  byebyevpn                      interactive menu\n");
    printf("  byebyevpn <ip-or-host>         full scan (recommended)\n");
    printf("  byebyevpn scan <ip>            full scan same\n");
    printf("  byebyevpn ports <ip>           TCP port scan only\n");
    printf("  byebyevpn udp <ip>             UDP probes only\n");
    printf("  byebyevpn tls <ip> [port]      TLS + SNI consistency only\n");
    printf("  byebyevpn j3 <ip> [port]       J3 active probing only\n");
    printf("  byebyevpn geoip <ip>           GeoIP only\n");
    printf("  byebyevpn snitch <ip> [port]   SNITCH RTT/GeoIP consistency (methodika §10.1)\n");
    printf("  byebyevpn trace <ip>           Traceroute hop-count analysis\n");
    printf("  byebyevpn local                scan THIS machine (split-tunnel / VPN procs)\n\n");
    printf("Port-scan modes (default: --full):\n");
    printf("  --full              scan ALL ports 1-65535  (default)\n");
    printf("  --fast              205 curated VPN/proxy/TLS/admin ports\n");
    printf("  --range 1000-2000   scan a port range\n");
    printf("  --ports 80,443,8443 scan explicit port list\n\n");
    printf("Tuning:\n");
    printf("  --threads N     parallel TCP connects   (default 500)\n");
    printf("  --tcp-to MS     TCP connect timeout      (default 800)\n");
    printf("  --udp-to MS     UDP recv timeout         (default 900)\n");
    printf("  --no-color      disable ANSI colors\n");
    printf("  -v / --verbose  verbose\n\n");
    printf("Stealth / privacy (opt-outs for 3rd-party-service leakage and\n");
    printf("behavioural-burst fingerprint — default OFF, full scan behaviour):\n");
    printf("  --stealth       enable --no-geoip + --no-ct + --udp-jitter together\n");
    printf("  --no-geoip      skip all 9 3rd-party GeoIP/ASN lookups (target IP stays local)\n");
    printf("  --no-ct         skip crt.sh Certificate Transparency lookup (cert SHA stays local)\n");
    printf("  --udp-jitter    add 50-300ms random delay between UDP probes (smears port burst)\n\n");
    printf("Save scan output to file (#7):\n");
    printf("  --save           write the scan to '<target>.md' in the current directory\n");
    printf("  --save <path>    write the scan to <path> (still wrapped as markdown)\n");
    printf("                   ANSI colors are stripped from the file; terminal output is unchanged\n\n");
    printf("GeoIP sources (9 providers, 3 EU / 3 RU / 3 global):\n");
    printf("  EU:     ipapi.is, iplocate.io, freeipapi.com\n");
    printf("  RU:     2ip.io/2ip.me, ip-api.com/ru, sypexgeo.net\n");
    printf("  global: ip-api.com, ipwho.is, ipinfo.io\n");
}

static void pause_for_enter() {
    printf("\n%s[Enter] to continue...%s", col(C::DIM), col(C::RST));
    std::fflush(stdout);
    int c; while ((c = getchar()) != EOF && c != '\n') {}
}

static string ask(const string& prompt) {
    printf("%s", prompt.c_str()); std::fflush(stdout);
    char buf[256] = {0};
    if (!std::fgets(buf, sizeof(buf), stdin)) return {};
    return trim(buf);
}

void interactive() {
    for (;;) {
        std::system("cls");
        banner();
        printf("  %s[1]%s  Full scan             — end-to-end scan of an IP/hostname\n", col(C::CYN), col(C::RST));
        printf("  %s[2]%s  TCP port scan         — TCP port-scan only\n", col(C::CYN), col(C::RST));
        printf("  %s[3]%s  UDP probes            — OpenVPN / WireGuard / IKE / QUIC / DNS\n", col(C::CYN), col(C::RST));
        printf("  %s[4]%s  TLS + SNI consistency — TLS audit on a single port (Reality discriminator)\n", col(C::CYN), col(C::RST));
        printf("  %s[5]%s  J3 active probing     — TSPU/GFW-style probes on one port\n", col(C::CYN), col(C::RST));
        printf("  %s[6]%s  GeoIP lookup          — country / ASN / VPN-flag aggregation\n", col(C::CYN), col(C::RST));
        printf("  %s[7]%s  Local analysis        — this machine: VPN adapters, split-tunnel, processes\n", col(C::CYN), col(C::RST));
        printf("  %s[8]%s  SNITCH latency check  — RTT + GeoIP consistency (methodika §10.1)\n", col(C::CYN), col(C::RST));
        printf("  %s[9]%s  Traceroute            — ICMP hop count analysis (ttl sweep)\n", col(C::CYN), col(C::RST));
        printf("  %s[0]%s  Exit\n\n", col(C::CYN), col(C::RST));
        string s = ask("  > ");
        if (s.empty()) continue;
        char c = s[0];
        if (c == '0' || c == 'q' || c == 'Q') break;
        else if (c == '1') {
            string t = ask("  target (IP or hostname): ");
            if (!t.empty()) run_full_target(t);
            pause_for_enter();
        } else if (c == '2') {
            string t = ask("  target IP: ");
            if (!t.empty()) {
                auto rs = resolve_host(t);
                auto op = scan_tcp(rs.primary_ip.empty() ? t : rs.primary_ip,
                                   build_tcp_ports(), g_threads, g_tcp_to);
                for (auto& o: op)
                    printf("  :%-5d  %lldms  %s%s\n", o.port, o.connect_ms,
                           port_hint(o.port),
                           o.banner.empty() ? "" : (" banner=" + printable_prefix(o.banner, 60)).c_str());
            }
            pause_for_enter();
        } else if (c == '3') {
            string t = ask("  target IP: ");
            if (!t.empty()) {
                auto rs = resolve_host(t); string ip = rs.primary_ip.empty() ? t : rs.primary_ip;
                auto show = [&](const char* n, int p, UdpResult u){
                    printf("  UDP:%-5d  %-22s  %s\n", p, n,
                        u.responded ? ("RESP " + std::to_string(u.bytes) + "B " + u.reply_hex).c_str()
                                    : ("no answer (" + u.err + ")").c_str());
                };
                show("DNS",       53,    dns_probe(ip, 53));
                show("IKEv2",     500,   ike_probe(ip, 500));
                show("IKE NAT-T", 4500,  ike_probe(ip, 4500));
                show("OpenVPN",   1194,  openvpn_probe(ip, 1194));
                show("QUIC",      443,   quic_probe(ip, 443));
                show("WireGuard", 51820, wireguard_probe(ip, 51820));
                show("Tailscale", 41641, wireguard_probe(ip, 41641));
            }
            pause_for_enter();
        } else if (c == '4') {
            string t = ask("  target host (used as SNI): ");
            string ps = ask("  port (default 443): ");
            int port = ps.empty() ? 443 : std::atoi(ps.c_str());
            if (!t.empty()) {
                auto rs = resolve_host(t);
                string ip = rs.primary_ip.empty() ? t : rs.primary_ip;
                auto tp = tls_probe(ip, port, t);
                if (!tp.ok) printf("  TLS fail: %s\n", tp.err.c_str());
                else {
                    printf("  %s%s%s / %s / ALPN=%s / %s / %lldms\n",
                           col(C::BOLD), tp.version.c_str(), col(C::RST),
                           tp.cipher.c_str(), tp.alpn.c_str(), tp.group.c_str(), tp.handshake_ms);
                    printf("  cert: %s\n", tp.cert_subject.c_str());
                    printf("  issuer: %s\n", tp.cert_issuer.c_str());
                    printf("  sha256: %s\n", tp.cert_sha256.c_str());
                    auto sc = sni_consistency(ip, port, t);
                    for (auto& e: sc.entries)
                        printf("    alt SNI %-35s  %s  %s\n",
                               e.sni.c_str(),
                               e.ok ? ("sha:" + e.sha.substr(0, 16)).c_str() : "fail",
                               (e.ok && e.sha == sc.base_sha) ? "SAME" : "diff");
                    if (sc.reality_like)
                        printf("  %s=> Reality/XTLS pattern: cert covers foreign SNI '%s'%s\n",
                               col(C::GRN), sc.matched_foreign_sni.c_str(), col(C::RST));
                    else if (sc.default_cert_only)
                        printf("  %s=> plain TLS server with a single default cert (NOT Reality)%s\n",
                               col(C::CYN), col(C::RST));
                    else if (sc.same_cert_always)
                        printf("  %s=> identical cert for all SNIs but covers no foreign SNI (inconclusive)%s\n",
                               col(C::YEL), col(C::RST));
                    else
                        printf("  %s=> cert varies per SNI (multi-tenant TLS, NOT Reality)%s\n",
                               col(C::YEL), col(C::RST));
                }
            }
            pause_for_enter();
        } else if (c == '5') {
            string t = ask("  target IP: ");
            string ps = ask("  port: ");
            if (!t.empty() && !ps.empty()) {
                int port = std::atoi(ps.c_str());
                auto rs = resolve_host(t); string ip = rs.primary_ip.empty() ? t : rs.primary_ip;
                auto probes = j3_probes(ip, port);
                for (auto& p: probes) {
                    printf("  %-30s  %s  %dB %s\n", p.name.c_str(),
                        p.responded ? "RESP" : "SILENT",
                        p.bytes,
                        p.responded ? printable_prefix(p.first_line, 60).c_str() : "(dropped)");
                }
            }
            pause_for_enter();
        } else if (c == '6') {
            string t = ask("  IP (blank = your IP): ");
            auto f1 = std::async(std::launch::async, geo_ipapi_is,   t);
            auto f2 = std::async(std::launch::async, geo_iplocate,   t);
            auto f3 = std::async(std::launch::async, geo_freeipapi,  t);
            auto f4 = std::async(std::launch::async, geo_2ip_ru,     t);
            auto f5 = std::async(std::launch::async, geo_ipapi_ru,   t);
            auto f6 = std::async(std::launch::async, geo_sypex,      t);
            auto f7 = std::async(std::launch::async, geo_ip_api_com, t);
            auto f8 = std::async(std::launch::async, geo_ipwho_is,   t);
            auto f9 = std::async(std::launch::async, geo_ipinfo_io,  t);
            printf("  %s-- EU --%s\n", col(C::BOLD), col(C::RST));
            print_geo(f1.get()); print_geo(f2.get()); print_geo(f3.get());
            printf("  %s-- RU --%s\n", col(C::BOLD), col(C::RST));
            print_geo(f4.get()); print_geo(f5.get()); print_geo(f6.get());
            printf("  %s-- global --%s\n", col(C::BOLD), col(C::RST));
            print_geo(f7.get()); print_geo(f8.get()); print_geo(f9.get());
            pause_for_enter();
        } else if (c == '7') {
            run_local_analysis();
            pause_for_enter();
        } else if (c == '8') {
            string t = ask("  target IP or host: ");
            string ps = ask("  TCP port (default 443): ");
            int port = ps.empty() ? 443 : std::atoi(ps.c_str());
            if (!t.empty()) {
                auto rs = resolve_host(t);
                string ip = rs.primary_ip.empty() ? t : rs.primary_ip;
                auto g = geo_ip_api_com(ip);
                string cc = g.country_code;
                auto sn = snitch_check(ip, port, cc);
                printf("  Country (ip-api.com): %s  /  Target port: %d\n", cc.c_str(), port);
                printf("  median=%.1fms  min=%.1fms  max=%.1fms  stddev=%.1fms  samples=%d\n",
                       sn.median_ms, sn.min_ms, sn.max_ms, sn.stddev_ms, sn.samples);
                printf("  Anchors:  Cloudflare=%.1fms  Google=%.1fms  Yandex=%.1fms\n",
                       sn.cf_median_ms, sn.google_median_ms, sn.yandex_median_ms);
                printf("  Expected physical_min for %s: %.0fms\n",
                       cc.c_str(), sn.expected_min_ms);
                printf("  %s%s%s\n",
                       (sn.too_low || sn.too_high) ? col(C::RED) :
                       (sn.high_jitter || sn.anchor_ratio_off) ? col(C::YEL) : col(C::GRN),
                       sn.summary.c_str(), col(C::RST));
            }
            pause_for_enter();
        } else if (c == '9') {
            string t = ask("  target IP or host: ");
            if (!t.empty()) {
                auto rs = resolve_host(t);
                string ip = rs.primary_ip.empty() ? t : rs.primary_ip;
                auto tr = trace_hops(ip, 20);
                if (!tr.ok) { printf("  no hops returned (ICMP filtered)\n"); }
                else {
                    for (auto& h: tr.hops) {
                        if (h.rtt_ms < 0) printf("  %2d  *\n", h.ttl);
                        else              printf("  %2d  %-16s  %dms\n", h.ttl, h.addr.c_str(), h.rtt_ms);
                    }
                    printf("  => %d hops, reached=%s, max_rtt_jump=%dms, long_hops>150ms=%d\n",
                           tr.hop_count, tr.reached_target ? "yes" : "no",
                           tr.max_rtt_jump_ms, tr.long_hops);
                }
            }
            pause_for_enter();
        }
    }
}
