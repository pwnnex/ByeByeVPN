// SPDX-License-Identifier: GPL-3.0-or-later
// entry point: WSAStartup + OpenSSL init, CLI arg parsing, dispatch.
#include "common/winhdr.h"
#include "common/console.h"
#include "common/config.h"
#include "common/util.h"
#include "net/dns.h"
#include "net/icmp.h"
#include "scan/ports.h"
#include "scan/tcp_scan.h"
#include "scan/udp_probes.h"
#include "scan/tls.h"
#include "scan/sni.h"
#include "scan/j3.h"
#include "scan/snitch.h"
#include "geoip/geoip.h"
#include "local/local.h"
#include "app/cli.h"
#include "app/orchestrator.h"
#include "app/target.h"
#include "app/json_report.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <future>
#include <set>
#include <string>
#include <vector>

using std::string;
using std::vector;
using std::set;

int main(int argc, char** argv) {
    enable_vt();
    WSADATA ws; WSAStartup(MAKEWORD(2, 2), &ws);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    vector<string> pos;
    for (int i = 1; i < argc; ++i) {
        string a = argv[i];
        if      (a == "--no-color")              g_no_color = true;
        else if (a == "--verbose" || a == "-v")  g_verbose = true;
        else if (a == "--threads" && i + 1 < argc) g_threads = std::max(1, std::atoi(argv[++i]));
        else if (a == "--tcp-to"  && i + 1 < argc) g_tcp_to  = std::max(1, std::atoi(argv[++i]));
        else if (a == "--udp-to"  && i + 1 < argc) g_udp_to  = std::max(1, std::atoi(argv[++i]));
        else if (a == "--stealth") {
            g_stealth = true;
            g_no_geoip = true;
            g_no_ct = true;
            g_udp_jitter = true;
        }
        else if (a == "--no-geoip")   g_no_geoip = true;
        else if (a == "--no-ct")      g_no_ct = true;
        else if (a == "--udp-jitter") g_udp_jitter = true;
        else if (a == "--passive")    g_passive = true;
        else if (a == "--j3-subset" && i + 1 < argc) {
            int n = std::atoi(argv[++i]);
            if (n > 0 && n < 8) g_j3_subset = n;
        }
        else if (a == "--json")       g_json = true;
        else if (a == "--save") {
            g_save_requested = true;
            if (i + 1 < argc) {
                string nxt = argv[i + 1];
                if (!nxt.empty() && nxt[0] != '-') {
                    g_save_path = nxt;
                    ++i;
                }
            }
        }
        else if (a == "--full")  g_port_mode = PortMode::FULL;
        else if (a == "--fast")  g_port_mode = PortMode::FAST;
        else if (a == "--range" && i + 1 < argc) {
            string v = argv[++i];
            size_t dash = v.find('-');
            if (dash != string::npos) {
                g_range_lo = std::atoi(v.substr(0, dash).c_str());
                g_range_hi = std::atoi(v.substr(dash + 1).c_str());
                g_port_mode = PortMode::RANGE;
            }
        }
        else if (a == "--ports" && i + 1 < argc) {
            string v = argv[++i]; g_port_list.clear();
            size_t p = 0;
            while (p < v.size()) {
                size_t c = v.find(',', p);
                string tok = v.substr(p, c == string::npos ? string::npos : c - p);
                if (!tok.empty()) g_port_list.push_back(std::atoi(tok.c_str()));
                if (c == string::npos) break;
                p = c + 1;
            }
            if (!g_port_list.empty()) g_port_mode = PortMode::LIST;
        }
        else if (a == "--help" || a == "-h" || a == "/?") { help(); return 0; }
        else pos.push_back(a);
    }

    // open save file BEFORE banner so it captures the banner too.
    if (g_save_requested) {
        string path = g_save_path;
        if (path.empty()) {
            string target;
            if (!pos.empty()) {
                static const set<string> cmds = {
                    "scan","full","ports","udp","tls","j3","geoip",
                    "snitch","trace","traceroute","local","me","self","help"
                };
                if (pos.size() >= 2 && cmds.count(pos[0])) target = pos[1];
                else                                       target = pos[0];
            }
            if (target.empty() || target == "local" || target == "me" || target == "self")
                path = "byebyevpn-scan.md";
            else {
                string safe;
                for (char c: target) {
                    if (c==':'||c=='/'||c=='\\'||c=='*'||c=='?'||c=='"'||
                        c=='<'||c=='>'||c=='|') safe += '_';
                    else                        safe += c;
                }
                path = safe + ".md";
            }
        }
        g_save_fp = std::fopen(path.c_str(), "w");
        if (!g_save_fp) {
            std::fprintf(stderr,
                "warn: --save: cannot open '%s' for writing (%s); continuing without save\n",
                path.c_str(), std::strerror(errno));
        } else {
            g_save_path = path;
            time_t now = std::time(nullptr);
            struct tm* lt = std::localtime(&now);
            std::fprintf(g_save_fp, "# Scan report\n\n");
            if (lt) std::fprintf(g_save_fp,
                                 "**Date:** %04d-%02d-%02d %02d:%02d:%02d  \n",
                                 1900 + lt->tm_year, 1 + lt->tm_mon, lt->tm_mday,
                                 lt->tm_hour, lt->tm_min, lt->tm_sec);
            if (!pos.empty())
                std::fprintf(g_save_fp, "**Target:** `%s`  \n", pos.back().c_str());
            std::fprintf(g_save_fp, "**Scanner version:** v2.7.0  \n\n");
            std::fprintf(g_save_fp, "```\n");
        }
    }

    banner();
    int rc = 0;
    // exit-code helper: a completed full scan exits 0/1/2/3 by verdict tier
    // so wrapper scripts can branch without parsing output.
    //   0 = CLEAN, 1 = NOISY, 2 = SUSPICIOUS, 3 = OBVIOUSLY-VPN
    // usage / runtime errors use 64 (EX_USAGE) to stay out of that range.
    auto verdict_exit = [](const FullReport& R) -> int {
        if (R.score >= 85) return 0;
        if (R.score >= 70) return 1;
        if (R.score >= 50) return 2;
        return 3;
    };
    if (pos.empty()) {
        interactive();
    } else {
        string cmd = pos[0];
        if (cmd == "scan" || cmd == "full") {
            if (pos.size() < 2) { printf("need target\n"); rc = 64; goto done; }
            FullReport R = run_full_target(pos[1]);
            if (g_json) std::fputs(json_report(R).c_str(), stdout);
            rc = verdict_exit(R);
        } else if (cmd == "ports") {
            if (pos.size() < 2) { printf("need target\n"); rc = 64; goto done; }
            auto rs = resolve_host(pos[1]);
            auto op = scan_tcp(rs.primary_ip.empty() ? pos[1] : rs.primary_ip,
                               build_tcp_ports(), g_threads, g_tcp_to);
            for (auto& o: op)
                printf("  :%-5d  %lldms  %s\n", o.port, o.connect_ms, port_hint(o.port));
        } else if (cmd == "udp") {
            if (pos.size() < 2) { printf("need target\n"); rc = 64; goto done; }
            auto rs = resolve_host(pos[1]); string ip = rs.primary_ip.empty() ? pos[1] : rs.primary_ip;
            auto show = [&](const char* n, int p, const UdpResult& u){
                printf("  UDP:%-5d  %-22s  %s\n", p, n,
                    u.responded ? ("RESP " + std::to_string(u.bytes) + "B " + u.reply_hex).c_str()
                                : ("no answer (" + u.err + ")").c_str());
            };
            show("WireGuard",      51820, wireguard_probe(ip, 51820));
            show("AmneziaWG Sx=8", 51820, amneziawg_probe(ip, 51820));
            show("AmneziaWG Sx=8", 55555, amneziawg_probe(ip, 55555));
            show("Hysteria2 QUIC", 36712, hysteria2_probe(ip, 36712));
            show("Hysteria2 QUIC", 443,   hysteria2_probe(ip, 443));
        } else if (cmd == "tls") {
            if (pos.size() < 2) { printf("need target\n"); rc = 64; goto done; }
            int port = pos.size() >= 3 ? std::atoi(pos[2].c_str()) : 443;
            auto rs = resolve_host(pos[1]);
            string ip = rs.primary_ip.empty() ? pos[1] : rs.primary_ip;
            auto tp = tls_probe(ip, port, pos[1]);
            if (!tp.ok) { printf("TLS fail: %s\n", tp.err.c_str()); rc = 1; goto done; }
            printf("  %s / %s / ALPN=%s / %s / %lldms\n",
                   tp.version.c_str(), tp.cipher.c_str(), tp.alpn.c_str(),
                   tp.group.c_str(), tp.handshake_ms);
            printf("  cert:   %s\n", tp.cert_subject.c_str());
            printf("  issuer: %s\n", tp.cert_issuer.c_str());
            printf("  sha256: %s\n", tp.cert_sha256.c_str());
            auto sc = sni_consistency(ip, port, pos[1]);
            for (auto& e: sc.entries)
                printf("    %-35s  %s  %s\n", e.sni.c_str(),
                       e.ok ? ("sha:" + e.sha.substr(0, 16)).c_str() : "fail",
                       (e.ok && e.sha == sc.base_sha) ? "SAME" : "diff");
            if (sc.reality_like)
                printf("  => Reality/XTLS pattern (cert covers foreign SNI '%s')\n",
                       sc.matched_foreign_sni.c_str());
            else if (sc.default_cert_only)
                printf("  => plain TLS server with single default cert (NOT Reality)\n");
            else if (sc.same_cert_always)
                printf("  => identical cert across SNIs but covers no foreign SNI (inconclusive)\n");
            else
                printf("  => cert varies per SNI (multi-tenant TLS, NOT Reality)\n");
        } else if (cmd == "j3") {
            if (pos.size() < 2) { printf("need target\n"); rc = 64; goto done; }
            int port = pos.size() >= 3 ? std::atoi(pos[2].c_str()) : 443;
            auto rs = resolve_host(pos[1]); string ip = rs.primary_ip.empty() ? pos[1] : rs.primary_ip;
            auto probes = j3_probes(ip, port);
            for (auto& p: probes)
                printf("  %-28s  %s  %dB %s\n", p.name.c_str(),
                    p.responded ? "RESP" : "SILENT", p.bytes,
                    p.responded ? printable_prefix(p.first_line, 60).c_str() : "(dropped)");
        } else if (cmd == "geoip") {
            string ip = pos.size() >= 2 ? pos[1] : "";
            auto f1 = std::async(std::launch::async, geo_ipapi_is,  ip);
            auto f2 = std::async(std::launch::async, geo_iplocate,  ip);
            auto f3 = std::async(std::launch::async, geo_freeipapi, ip);
            auto f4 = std::async(std::launch::async, geo_ipwho_is,  ip);
            auto f5 = std::async(std::launch::async, geo_ipinfo_io, ip);
            printf("  %s-- 5 HTTPS providers --%s\n", col(C::BOLD), col(C::RST));
            print_geo(f1.get()); print_geo(f2.get()); print_geo(f3.get());
            print_geo(f4.get()); print_geo(f5.get());
        } else if (cmd == "local" || cmd == "me" || cmd == "self") {
            run_local_analysis();
        } else if (cmd == "snitch") {
            if (pos.size() < 2) { printf("need target\n"); rc = 64; goto done; }
            int port = pos.size() >= 3 ? std::atoi(pos[2].c_str()) : 443;
            auto rs = resolve_host(pos[1]);
            string ip = rs.primary_ip.empty() ? pos[1] : rs.primary_ip;
            auto g = geo_ipapi_is(ip);
            string cc = g.country_code;
            auto sn = snitch_check(ip, port, cc);
            printf("  target=%s  port=%d  geoip=%s  asn=%s\n",
                   ip.c_str(), port, cc.c_str(), g.asn_org.c_str());
            printf("  median=%.1fms  min=%.1fms  max=%.1fms  stddev=%.1fms  samples=%d\n",
                   sn.median_ms, sn.min_ms, sn.max_ms, sn.stddev_ms, sn.samples);
            printf("  anchors: cf=%.1fms  google=%.1fms  yandex=%.1fms\n",
                   sn.cf_median_ms, sn.google_median_ms, sn.yandex_median_ms);
            printf("  expected-min for %s = %.0fms\n", cc.c_str(), sn.expected_min_ms);
            printf("  => %s\n", sn.summary.c_str());
        } else if (cmd == "trace" || cmd == "traceroute") {
            if (pos.size() < 2) { printf("need target\n"); rc = 64; goto done; }
            auto rs = resolve_host(pos[1]);
            string ip = rs.primary_ip.empty() ? pos[1] : rs.primary_ip;
            int maxh = pos.size() >= 3 ? std::atoi(pos[2].c_str()) : 18;
            auto tr = trace_hops(ip, maxh);
            if (!tr.ok) { printf("  no hops returned\n"); rc = 1; goto done; }
            for (auto& h: tr.hops) {
                if (h.rtt_ms < 0) printf("  %2d  *\n", h.ttl);
                else              printf("  %2d  %-16s  %dms\n", h.ttl, h.addr.c_str(), h.rtt_ms);
            }
            printf("  => %d hops, reached=%s, max_rtt_jump=%dms, long_hops>150ms=%d\n",
                   tr.hop_count, tr.reached_target ? "yes" : "no",
                   tr.max_rtt_jump_ms, tr.long_hops);
        } else if (cmd == "help" || cmd == "--help") {
            help();
        } else {
            // bare argument: treat as a target for a full scan.
            FullReport R = run_full_target(cmd);
            if (g_json) std::fputs(json_report(R).c_str(), stdout);
            rc = verdict_exit(R);
        }
    }
done:
    if (g_save_fp) {
        std::fprintf(g_save_fp, "```\n");
        std::fclose(g_save_fp);
        g_save_fp = nullptr;
        std::fprintf(stderr, "saved to %s\n", g_save_path.c_str());
    }
    WSACleanup();
    return rc;
}