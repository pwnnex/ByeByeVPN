#include "orchestrator.h"
#include "../core/utils.h"
#include "../network/port_scan.h"
#include "../network/vpn_probes.h"
#include "../network/vpn_probes2.h"
#include "../network/tls_probe.h"
#include "../analysis/sni_consistency.h"
#include "../analysis/ct_check.h"
#include "../network/https_probe.h"
#include "../network/j3_probes.h"
#include "../analysis/brand_cert.h"
#include "../analysis/snitch.h"
#include "../analysis/traceroute.h"
#include <algorithm>
#include <set>
#include <future>
#include <climits>
#include <cmath>
#include <cstring>

FullReport run_full_target(const std::string& target) {
    FullReport R; R.target = target;

    tee_printf("\n%s[1/8] DNS resolve%s\n", col(C::BOLD), col(C::RST));
    R.dns = resolve_host(target);
    if (!R.dns.err.empty()) {
        tee_printf("  %sERR%s: %s\n", col(C::RED), col(C::RST), R.dns.err.c_str());
        return R;
    }
    tee_printf("  %s%s%s  ->  ", col(C::WHT), target.c_str(), col(C::RST));
    for (auto& ip: R.dns.ips) tee_printf("%s ", ip.c_str());
    tee_printf(" [%s, %lldms]\n", R.dns.family.c_str(), R.dns.ms);
    if (R.dns.primary_ip != target) {
        tee_printf("  %susing primary IP%s %s%s%s  for all probes%s\n",
               col(C::DIM), col(C::RST),
               col(C::BOLD), R.dns.primary_ip.c_str(), col(C::RST),
               col(C::RST));
    }

    if (g_no_geoip) {
        tee_printf("\n%s[2/8] GeoIP%s  SKIPPED (--no-geoip / --stealth)\n",
               col(C::BOLD), col(C::RST));
    } else {
        tee_printf("\n%s[2/8] GeoIP%s  (9 providers in parallel: 3 EU / 3 RU / 3 global)\n",
               col(C::BOLD), col(C::RST));
        auto fg_eu1 = std::async(std::launch::async, geo_ipapi_is,   R.dns.primary_ip);
        auto fg_eu2 = std::async(std::launch::async, geo_iplocate,   R.dns.primary_ip);
        auto fg_eu3 = std::async(std::launch::async, geo_freeipapi,  R.dns.primary_ip);
        auto fg_ru1 = std::async(std::launch::async, geo_2ip_ru,     R.dns.primary_ip);
        auto fg_ru2 = std::async(std::launch::async, geo_ipapi_ru,   R.dns.primary_ip);
        auto fg_ru3 = std::async(std::launch::async, geo_sypex,      R.dns.primary_ip);
        auto fg_gl1 = std::async(std::launch::async, geo_ip_api_com, R.dns.primary_ip);
        auto fg_gl2 = std::async(std::launch::async, geo_ipwho_is,   R.dns.primary_ip);
        auto fg_gl3 = std::async(std::launch::async, geo_ipinfo_io,  R.dns.primary_ip);
        R.geos.push_back(fg_eu1.get()); R.geos.push_back(fg_eu2.get()); R.geos.push_back(fg_eu3.get());
        R.geos.push_back(fg_ru1.get()); R.geos.push_back(fg_ru2.get()); R.geos.push_back(fg_ru3.get());
        R.geos.push_back(fg_gl1.get()); R.geos.push_back(fg_gl2.get()); R.geos.push_back(fg_gl3.get());
        for (auto& g: R.geos) {
            if (!g.err.empty()) {
                tee_printf("  %s%-12s%s %serr: %s%s\n",
                       col(C::CYN), g.source.c_str(), col(C::RST),
                       col(C::RED), g.err.c_str(), col(C::RST));
                continue;
            }
            tee_printf("  %s%-12s%s IP %s%-15s%s  %s%s%s  (%s) AS %s %s\n",
                   col(C::CYN), g.source.c_str(), col(C::RST),
                   col(C::WHT), g.ip.c_str(), col(C::RST),
                   col(C::BOLD), g.country_code.empty() ? g.country.c_str() : g.country_code.c_str(), col(C::RST),
                   g.city.c_str(), g.asn.c_str(), g.asn_org.c_str());
            std::string flags;
            auto add = [&](bool v, const char* n, const char* c){
                if (v) { if(!flags.empty()) flags += " "; flags += col(c); flags += n; flags += col(C::RST); }
            };
            add(g.is_hosting, "HOSTING", C::YEL);
            add(g.is_vpn,     "VPN",     C::RED);
            add(g.is_proxy,   "PROXY",   C::RED);
            add(g.is_tor,     "TOR",     C::RED);
            add(g.is_abuser,  "ABUSER",  C::RED);
            if (!flags.empty()) tee_printf("               flags: %s\n", flags.c_str());
        }
    }

    auto _ports = build_tcp_ports();
    const char* _mode_name =
        g_port_mode==PortMode::FULL  ? "FULL 1-65535" :
        g_port_mode==PortMode::FAST  ? "FAST (205 curated)" :
        g_port_mode==PortMode::RANGE ? "RANGE" : "LIST";
    tee_printf("\n%s[3/8] TCP port scan%s  mode=%s%s%s  (%zu ports, %d threads, %dms timeout)\n",
           col(C::BOLD), col(C::RST),
           col(C::CYN), _mode_name, col(C::RST),
           _ports.size(), g_threads, g_tcp_to);
    R.open_tcp = scan_tcp(R.dns.primary_ip, _ports, g_threads, g_tcp_to, &R.scan_stats);
    if (!R.scan_stats.skipped && R.scan_stats.scanned >= 1000 && R.open_tcp.empty()) {
        size_t tmo = R.scan_stats.timeouts;
        size_t rst = R.scan_stats.refused;
        if (rst == 0 && tmo >= R.scan_stats.scanned * 99 / 100) {
            R.bgp_blackhole_likely = true;
        }
    }
    bool warp_like = false;
    if (R.open_tcp.size() > 60) {
        long long mn = LLONG_MAX, mx = 0;
        for (auto& o: R.open_tcp) { mn = std::min(mn, o.connect_ms); mx = std::max(mx, o.connect_ms); }
        if (mx - mn < 80) warp_like = true;
    }
    if (warp_like) {
        tee_printf("  %s!! %zu ports reported open with near-identical RTT — looks like Cloudflare WARP / a local proxy / CGNAT middlebox that accept-hooks every TCP SYN. Disable WARP/proxy and re-run; otherwise results are fake%s\n",
               col(C::RED), R.open_tcp.size(), col(C::RST));
    }
    if (R.open_tcp.empty()) {
        tee_printf("  %sno open TCP ports found%s\n", col(C::YEL), col(C::RST));
        if (R.bgp_blackhole_likely) {
            tee_printf("  %s!! %zu/%zu ports TIMEOUT with 0 RST - looks like L3 blackhole "
                   "(tspu type B / BGP-pushed IP-list, not a regular dead host)%s\n",
                   col(C::RED), R.scan_stats.timeouts, R.scan_stats.scanned, col(C::RST));
        } else if (R.scan_stats.scanned >= 100) {
            tee_printf("  %s  (breakdown: %zu timeout, %zu refused, %zu other)%s\n",
                   col(C::DIM), R.scan_stats.timeouts, R.scan_stats.refused,
                   R.scan_stats.other, col(C::RST));
        }
    } else {
        for (auto& o: R.open_tcp) {
            const char* hint = port_hint(o.port);
            tee_printf("  %s:%-5d%s  %3lldms  %s%s%s",
                   col(C::GRN), o.port, col(C::RST),
                   o.connect_ms,
                   col(C::DIM), hint[0]?hint:"-", col(C::RST));
            if (!o.banner.empty()) {
                tee_printf("  %sbanner:%s %s",
                       col(C::CYN), col(C::RST),
                       printable_prefix(o.banner, 60).c_str());
            }
            tee_printf("\n");
        }
    }

    tee_printf("\n%s[4/8] UDP probes%s\n", col(C::BOLD), col(C::RST));
    auto udp_show = [&](int port, const char* name, UdpResult u){
        const char* c = u.responded ? col(C::GRN) : col(C::DIM);
        tee_printf("  %sUDP:%-5d%s  %-18s  ",
               c, port, col(C::RST), name);
        if (u.responded) tee_printf("%sRESP %dB%s  %s", col(C::GRN), u.bytes, col(C::RST), u.reply_hex.c_str());
        else             tee_printf("%sno answer (%s)%s", col(C::DIM), u.err.empty()?"closed/filtered":u.err.c_str(), col(C::RST));
        tee_printf("\n");
        R.udp_probes.push_back({port, u});
    };
    udp_show(53,    "DNS query",         dns_probe(R.dns.primary_ip, 53));
    udp_show(500,   "IKEv2 SA_INIT",     ike_probe(R.dns.primary_ip, 500));
    udp_show(4500,  "IKEv2 NAT-T",       ike_probe(R.dns.primary_ip, 4500));
    udp_show(1194,  "OpenVPN HARD_RESET",openvpn_probe(R.dns.primary_ip, 1194));
    udp_show(443,   "QUIC v1 Initial",   quic_probe(R.dns.primary_ip, 443));
    R.quic = R.udp_probes.back().second;
    udp_show(51820, "WireGuard handshake", wireguard_probe(R.dns.primary_ip, 51820));
    udp_show(41641, "Tailscale handshake", wireguard_probe(R.dns.primary_ip, 41641));
    
    auto udp_extra = [&](int port, const char* name, UdpResult u){
        const char* c = u.responded ? col(C::GRN) : col(C::DIM);
        tee_printf("  %sUDP:%-5d%s  %-18s  ",
               c, port, col(C::RST), name);
        if (u.responded) tee_printf("%sRESP %dB%s  %s", col(C::GRN), u.bytes, col(C::RST), u.reply_hex.c_str());
        else             tee_printf("%sno answer (%s)%s", col(C::DIM), u.err.empty()?"closed/filtered":u.err.c_str(), col(C::RST));
        tee_printf("\n");
        R.udp_extra.push_back({port, u});
    };
    udp_extra(1701,  "L2TP SCCRQ",         l2tp_probe(R.dns.primary_ip, 1701));
    udp_extra(36712, "Hysteria2 QUIC",     hysteria2_probe(R.dns.primary_ip, 36712));
    udp_extra(8443,  "TUIC v5",            tuic_probe(R.dns.primary_ip, 8443));
    udp_extra(55555, "AmneziaWG Sx=8",     amneziawg_probe(R.dns.primary_ip, 55555));
    udp_extra(51820, "AmneziaWG Sx=8",     amneziawg_probe(R.dns.primary_ip, 51820));

    tee_printf("\n%s[5/8] Service fingerprints per open port%s\n", col(C::BOLD), col(C::RST));
    auto is_tls_port = [](int p){
        return p==443||p==4433||p==4443||p==8443||p==8080||p==8843||p==8444
             ||p==9443||p==10443||p==14443||p==20443||p==21443||p==22443||p==50443||p==51443||p==55443
             ||p==2083||p==2087||p==2096||p==6443||p==7443||p==853;
    };
    for (auto& o: R.open_tcp) {
        FullReport::PortFp pf; pf.port = o.port;
        bool printed = false;
        auto line = [&](const FpResult& f){
            printed = true;
            tee_printf("  %s:%-5d%s  %s%-16s%s  %s",
                   col(C::CYN), o.port, col(C::RST),
                   col(C::BOLD), f.service.c_str(), col(C::RST),
                   f.details.c_str());
            if (f.is_vpn_like) tee_printf("  %s[vpn-like]%s", col(C::YEL), col(C::RST));
            tee_printf("\n");
            pf.fp = f;
        };
        if (starts_with(o.banner, "SSH-") || o.port==22 || o.port==2222 || o.port==22222) {
            line(fp_ssh(o.banner, R.dns.primary_ip, o.port));
        }
        if (is_tls_port(o.port)) {
            TlsProbe tp = tls_probe(R.dns.primary_ip, o.port, R.dns.host);
            if (tp.ok) {
                FpResult f; f.service = "TLS";
                char agebuf[96] = {0};
                snprintf(agebuf, sizeof(agebuf), "age=%dd left=%dd",
                         tp.age_days, tp.days_left);
                f.details = tp.version + " / " + tp.cipher + " / ALPN=" +
                            (tp.alpn.empty()?"-":tp.alpn) + " / " + tp.group +
                            " / " + std::to_string(tp.handshake_ms) + "ms" +
                            "\n                       cert CN=" +
                            (tp.subject_cn.empty() ? "(none)" : tp.subject_cn) +
                            "  issuer=" + (tp.issuer_cn.empty() ? "(none)" : tp.issuer_cn) +
                            "  " + agebuf +
                            "  SAN=" + std::to_string(tp.san_count) +
                            (tp.is_wildcard  ? " wildcard" : "") +
                            (tp.self_signed  ? " self-signed" : "") +
                            (tp.is_letsencrypt ? " [free-CA]" : "");
                line(f);
                pf.tls = tp;
                SniConsistency sc = sni_consistency(R.dns.primary_ip, o.port, R.dns.host);
                pf.sni = sc;
                if (sc.reality_like && sc.passthrough_mode) {
                    tee_printf("        %sSNI behaviour: cert varies per SNI BUT base cert is for brand '%s' — Reality with real passthrough to dest= (stealth-optimised)%s\n",
                           col(C::RED), sc.matched_foreign_sni.c_str(), col(C::RST));
                } else if (sc.reality_like) {
                    tee_printf("        %sSNI steering: same cert returned for ALL foreign SNIs, and cert is valid for '%s' -> Reality/XTLS pattern%s\n",
                           col(C::GRN), sc.matched_foreign_sni.c_str(), col(C::RST));
                } else if (sc.default_cert_only) {
                    tee_printf("        %sSNI behaviour: single default cert returned regardless of SNI (plain server, not Reality)%s\n",
                           col(C::CYN), col(C::RST));
                } else if (sc.same_cert_always) {
                    tee_printf("        %sSNI behaviour: identical cert across SNIs, but cert does not cover any foreign SNI (inconclusive)%s\n",
                           col(C::YEL), col(C::RST));
                } else {
                    tee_printf("        %sSNI behaviour: cert varies per SNI (normal multi-tenant TLS, not Reality)%s\n",
                           col(C::YEL), col(C::RST));
                }
                if (!sc.base_sha.empty()) {
                    tee_printf("        cert-sha256: %s%.16s...%s  issuer: %s\n",
                           col(C::DIM), sc.base_sha.c_str(), col(C::RST),
                           printable_prefix(tp.cert_issuer, 60).c_str());
                    if (g_no_ct) {
                        tee_printf("        %sCT-log (crt.sh): SKIPPED (--no-ct / --stealth)%s\n",
                               col(C::DIM), col(C::RST));
                    } else {
                    CtCheck ct = ct_check(sc.base_sha);
                    pf.ct = ct;
                    if (ct.queried && !ct.err.empty()) {
                        tee_printf("        %sCT-log (crt.sh): query failed — %s%s\n",
                               col(C::DIM), ct.err.c_str(), col(C::RST));
                    } else if (ct.queried && ct.found) {
                        tee_printf("        %sCT-log (crt.sh): cert IS in public CT logs (%d entries) — normal legit cert%s\n",
                               col(C::GRN), ct.log_entries, col(C::RST));
                    } else if (ct.queried && !ct.found) {
                        tee_printf("        %sCT-log (crt.sh): cert NOT found in public CT logs — self-signed / private-CA / LE-staging / forged cert%s\n",
                               col(C::RED), col(C::RST));
                    }
                    }
                }
                HttpsProbe hp = https_probe(R.dns.primary_ip, o.port, R.dns.host);
                pf.https = hp;
                if (hp.tls_ok) {
                    if (hp.responded) {
                        tee_printf("        %sHTTP-over-TLS:%s %s%s%s",
                               col(C::DIM), col(C::RST),
                               hp.version_anomaly ? col(C::RED) :
                                 (hp.status_code>=200 && hp.status_code<600 ? col(C::GRN) : col(C::YEL)),
                               printable_prefix(hp.first_line, 70).c_str(),
                               col(C::RST));
                        if (!hp.server_hdr.empty())
                            tee_printf("   Server: %s%s%s",
                                   col(C::CYN),
                                   printable_prefix(hp.server_hdr, 40).c_str(),
                                   col(C::RST));
                        else if (hp.status_code > 0)
                            tee_printf("   %s(no Server header)%s",
                                   col(C::YEL), col(C::RST));
                        if (hp.version_anomaly)
                            tee_printf("   %s[!version anomaly]%s",
                                   col(C::RED), col(C::RST));
                        tee_printf("\n");
                    } else {
                        tee_printf("        %sHTTP-over-TLS: no reply (TLS ok, origin silent on HTTP request) — stream-layer proxy signature%s\n",
                               col(C::RED), col(C::RST));
                    }
                    if (hp.has_proxy_leak) {
                        tee_printf("        %s[proxy-leak]%s",
                               col(C::YEL), col(C::RST));
                        if (!hp.via_hdr.empty())
                            tee_printf(" Via='%s'", printable_prefix(hp.via_hdr, 36).c_str());
                        if (!hp.forwarded_hdr.empty())
                            tee_printf(" Forwarded='%s'", printable_prefix(hp.forwarded_hdr, 36).c_str());
                        if (!hp.xff_hdr.empty())
                            tee_printf(" XFF='%s'", printable_prefix(hp.xff_hdr, 36).c_str());
                        if (!hp.xreal_ip_hdr.empty())
                            tee_printf(" X-Real-IP='%s'", printable_prefix(hp.xreal_ip_hdr, 24).c_str());
                        tee_printf("\n");
                    }
                    if (hp.has_cdn_hdr) {
                        std::string cdn;
                        if (!hp.cf_ray_hdr.empty())       cdn = "Cloudflare (CF-Ray=" + printable_prefix(hp.cf_ray_hdr, 22) + ")";
                        else if (!hp.x_amz_cf_id.empty()) cdn = "CloudFront (X-Amz-Cf-Id=" + printable_prefix(hp.x_amz_cf_id, 22) + ", pop=" + hp.x_amz_cf_pop + ")";
                        else if (!hp.x_azure_ref.empty()) cdn = "Azure Front Door (X-Azure-Ref=" + printable_prefix(hp.x_azure_ref, 24) + ")";
                        else if (!hp.x_served_by.empty()) cdn = "Fastly (X-Served-By=" + printable_prefix(hp.x_served_by, 24) + ")";
                        if (!cdn.empty())
                            tee_printf("        %s[cdn]%s  %s\n",
                                   col(C::CYN), col(C::RST), cdn.c_str());
                    }
                    if (!hp.alt_svc.empty())
                        tee_printf("        %s[alt-svc]%s  %s  (QUIC endpoint advertisement)\n",
                               col(C::DIM), col(C::RST),
                               printable_prefix(hp.alt_svc, 80).c_str());
                }
            } else {
                FpResult f; f.service = "TLS-FAIL";
                f.details = tp.err;
                line(f);
                pf.tls = tp; 
            }
        }
        if (o.port==80||o.port==8080||o.port==8000||o.port==8088||o.port==8880||
            o.port==8888||o.port==81||o.port==3128||o.port==8118||o.port==8123) {
            FpResult hp = fp_http_plain(R.dns.primary_ip, o.port);
            if (!hp.details.empty() || hp.silent) line(hp);
            FpResult pp = fp_http_connect(R.dns.primary_ip, o.port);
            if (pp.service == "HTTP-PROXY") line(pp);
        }
        if (o.port==1080||o.port==1081||o.port==1082||o.port==9050||
            o.port==10808||o.port==10810||o.port==7890||o.port==7891) {
            line(fp_socks5(R.dns.primary_ip, o.port));
        }
        if (o.port==8388||o.port==8488||o.port==8787||o.port==8989) {
            line(fp_shadowsocks(R.dns.primary_ip, o.port));
        }
        if (!printed) {
            FpResult g; g.service = "unknown";
            if (!o.banner.empty()) g.details = "banner: " + printable_prefix(o.banner, 70);
            else                   g.details = "open but silent on connect (ambiguous: firewalled service / Shadowsocks / Trojan / Reality wrapper — inconclusive without protocol match)";
            if (!o.banner.empty() || R.open_tcp.size() < 20) line(g);
            else pf.fp = g;
        }
        R.fps.push_back(std::move(pf));
    }

    tee_printf("\n%s[6/8] J3 / TSPU active probing%s\n", col(C::BOLD), col(C::RST));
    for (auto& o: R.open_tcp) {
        if (!is_tls_port(o.port) && o.port != 80 && o.port != 8080) continue;
        tee_printf("  %s-> port :%d%s\n", col(C::BOLD), o.port, col(C::RST));
        auto probes = j3_probes(R.dns.primary_ip, o.port);
        int silent = 0, resp = 0;
        for (auto& p: probes) {
            const char* c = p.responded ? col(C::YEL) : col(C::GRN);
            const char* tag = p.responded ? "RESP" : "SILENT";
            tee_printf("     %s%-7s%s  %-28s  ", c, tag, col(C::RST), p.name.c_str());
            if (p.responded) {
                tee_printf("%dB  %s  [%s]", p.bytes,
                       printable_prefix(p.first_line, 50).c_str(),
                       p.hex_head.c_str());
                ++resp;
            } else {
                tee_printf("(dropped)");
                ++silent;
            }
            tee_printf("\n");
        }
        J3Analysis ja = j3_analyze(probes);
        for (auto& pf: R.fps) if (pf.port == o.port) {
            pf.j3  = std::move(probes);
            pf.j3a = ja;
            break;
        }
        const char* verdict;
        if (silent >= 6)      verdict = "silent-on-junk (TLS-only / Reality-hidden / firewalled — ambiguous)";
        else if (resp >= 6)   verdict = "responds to arbitrary bytes (plaintext HTTP-style origin)";
        else if (silent >= 3) verdict = "mixed: partly strict, partly permissive";
        else                  verdict = "mixed behaviour";
        tee_printf("     %s-> %s%s  (silent=%d / resp=%d)\n",
               col(C::MAG), verdict, col(C::RST), silent, resp);
        
        bool inline_is_tls = false, inline_https_anomaly = false;
        for (auto& pf: R.fps) if (pf.port == o.port) {
            inline_is_tls = (pf.tls && pf.tls->ok);
            if (pf.https && pf.https->tls_ok &&
                (!pf.https->responded || pf.https->version_anomaly ||
                 (pf.https->responded && pf.https->server_hdr.empty())))
                inline_https_anomaly = true;
            break;
        }
        bool inline_canned_hard = (ja.canned_identical >= 2) &&
                                  (!inline_is_tls || inline_https_anomaly);
        if (inline_canned_hard) {
            tee_printf("     %s!! canned response:%s the SAME first-line (%dB '%s') came back for %d different probes — not a real web server, that's a static fallback page (classic Xray `fallback+redirect`, Trojan, or Caddy placeholder)\n",
                   col(C::RED), col(C::RST),
                   ja.canned_bytes,
                   printable_prefix(ja.canned_line, 50).c_str(),
                   ja.canned_identical);
        } else if (ja.canned_identical >= 2 && inline_is_tls) {
            tee_printf("     %suniform reply:%s the SAME first-line (%dB '%s') for %d raw-TCP probes, but the HTTP-over-TLS probe is clean — that's normal nginx/CDN behaviour on a TLS port (not a fallback)\n",
                   col(C::DIM), col(C::RST),
                   ja.canned_bytes,
                   printable_prefix(ja.canned_line, 50).c_str(),
                   ja.canned_identical);
        }
        if (ja.http_bad_version > 0) {
            tee_printf("     %s!! HTTP version anomaly:%s %d probe(s) came back with an invalid HTTP version string (e.g. HTTP/0.0) — signature of a stream-proxy's fallback/redirect code path, not of nginx/Apache/Caddy\n",
                   col(C::RED), col(C::RST), ja.http_bad_version);
        }
        if (ja.raw_non_http > 0 && ja.http_real == 0) {
            tee_printf("     %s!! raw non-HTTP bytes:%s %d probe(s) got binary replies instead of HTTP — origin is speaking its own framing (Shadowsocks, Trojan, custom proxy)\n",
                   col(C::YEL), col(C::RST), ja.raw_non_http);
        }
    }

    tee_printf("\n%s[7/8] SNITCH latency + traceroute + SSTP%s\n",
           col(C::BOLD), col(C::RST));

    std::set<int> openset_early;
    for (auto& o: R.open_tcp) openset_early.insert(o.port);

    int rtt_port = 443;
    if (!openset_early.count(443) && !R.open_tcp.empty()) rtt_port = R.open_tcp.front().port;

    std::string consensus_cc;
    {
        std::map<std::string,int> votes;
        for (auto& g: R.geos) if (!g.country_code.empty())
            ++votes[g.country_code];
        int best = 0;
        for (auto& [cc, v]: votes)
            if (v > best) { best = v; consensus_cc = cc; }
    }
    SnitchResult sn = snitch_check(R.dns.primary_ip, rtt_port, consensus_cc);
    R.snitch = sn;
    if (!sn.ok) {
        tee_printf("  %sSNITCH: %s%s\n", col(C::DIM), sn.summary.c_str(), col(C::RST));
    } else {
        const char* sc_col = (sn.too_low || sn.too_high) ? col(C::RED) :
                             (sn.high_jitter || sn.anchor_ratio_off) ? col(C::YEL) : col(C::GRN);
        tee_printf("  %sSNITCH RTT:%s  median=%.1fms  min=%.1fms  max=%.1fms  stddev=%.1fms  (%d samples)\n",
               col(C::BOLD), col(C::RST),
               sn.median_ms, sn.min_ms, sn.max_ms, sn.stddev_ms, sn.samples);
        tee_printf("  %sAnchors:%s   Cloudflare=%s  Google=%s  Yandex=%s\n",
               col(C::DIM), col(C::RST),
               sn.cf_median_ms>=0     ? (std::to_string((int)sn.cf_median_ms)+"ms").c_str()     : "n/a",
               sn.google_median_ms>=0 ? (std::to_string((int)sn.google_median_ms)+"ms").c_str() : "n/a",
               sn.yandex_median_ms>=0 ? (std::to_string((int)sn.yandex_median_ms)+"ms").c_str() : "n/a");
        if (sn.expected_min_ms > 0)
            tee_printf("  %sExpected:%s  country=%s  physical_min=%.0fms  (from %s observer)\n",
                   col(C::DIM), col(C::RST),
                   sn.country_code.c_str(), sn.expected_min_ms,
                   consensus_cc.empty() ? "unknown" : consensus_cc.c_str());
        tee_printf("  %s=>%s %s%s%s\n",
               col(C::BOLD), col(C::RST), sc_col, sn.summary.c_str(), col(C::RST));
        if (sn.too_low)
            tee_printf("  %s[!]%s Latency impossibly low for %s geo — likely anycast proxy (Cloudflare/Google) OR GeoIP lies\n",
                   col(C::RED), col(C::RST), consensus_cc.c_str());
        if (sn.too_high)
            tee_printf("  %s[!]%s Latency significantly above expected band — extra hops in path (VPN tunnel or long middlebox chain)\n",
                   col(C::RED), col(C::RST));
        if (sn.high_jitter)
            tee_printf("  %s[-]%s High RTT jitter — typical of tunnel queue/encryption overhead\n",
                   col(C::YEL), col(C::RST));
    }

    TraceResult tr = trace_hops(R.dns.primary_ip, 18);
    R.trace = tr;
    if (tr.ok) {
        tee_printf("  %sTraceroute:%s %d hops, reached=%s, max_rtt_jump=%dms, long_hops(>150ms)=%d\n",
               col(C::BOLD), col(C::RST),
               tr.hop_count, tr.reached_target ? "yes" : "no",
               tr.max_rtt_jump_ms, tr.long_hops);
        int shown = 0;
        for (auto& h: tr.hops) {
            if (shown >= 12) { tee_printf("    ...\n"); break; }
            if (h.rtt_ms < 0)
                tee_printf("    %2d  %s*%s\n", h.ttl, col(C::DIM), col(C::RST));
            else
                tee_printf("    %2d  %-16s  %dms\n", h.ttl, h.addr.c_str(), h.rtt_ms);
            ++shown;
        }
    } else {
        tee_printf("  %sTraceroute:%s no hops returned (ICMP filtered / no admin on strict hosts)\n",
               col(C::DIM), col(C::RST));
    }

    if (openset_early.count(443)) {
        FpResult sstp = sstp_probe(R.dns.primary_ip, 443);
        R.sstp = sstp;
        const char* c = sstp.is_vpn_like ? col(C::RED) : col(C::DIM);
        tee_printf("  %sSSTP/443:%s %s%s%s  %s\n",
               col(C::BOLD), col(C::RST),
               c, sstp.service.c_str(), col(C::RST),
               printable_prefix(sstp.details, 80).c_str());
    }

    {
        Ja3Info j = our_openssl_ja3_signature();
        tee_printf("  %sOur ClientHello JA3:%s %s%s%s  (OpenSSL 3.x default — real browsers use uTLS-Chrome)\n",
               col(C::BOLD), col(C::RST),
               col(C::DIM), j.ja3_hash.c_str(), col(C::RST));
        bool any_reality_port = false;
        for (auto& pf: R.fps) if (pf.sni && pf.sni->reality_like) any_reality_port = true;
        if (any_reality_port)
            tee_printf("  %s  -> Reality server here accepted our non-Chrome JA3 — either uTLS-enforcement is OFF (typical Reality default), or the ACCEPT path always runs and divergence is only in fallback routing%s\n",
                   col(C::DIM), col(C::RST));
    }

    tee_printf("\n%s[8/8] Verdict%s\n", col(C::BOLD), col(C::RST));
    int score = 100;
    std::vector<std::string> signals_major;  
    std::vector<std::string> signals_minor;  
    std::vector<std::pair<std::string,std::string>> notes;   
    std::vector<std::pair<std::string,std::string>> hardening; 
    std::vector<std::pair<int,std::string>>    port_roles; 
    std::vector<std::pair<std::string,std::string>> dpi_axes;   
    bool xray_reality_primary = false, xray_reality_hidden = false;
    int  reality_port_count   = 0;

    auto flag_minor = [&](const std::string& s, int penalty = 3) {
        signals_minor.push_back(s);
        score -= penalty;
    };
    auto flag_major = [&](const std::string& s, int penalty) {
        signals_major.push_back(s);
        score -= penalty;
    };
    auto note = [&](const std::string& tag, const std::string& s) {
        notes.push_back({tag, s});
    };

    int vpn_hits = 0, proxy_hits = 0, hosting_hits = 0, tor_hits = 0;
    for (auto& g: R.geos) {
        if (g.is_hosting) ++hosting_hits;
        if (g.is_vpn)     ++vpn_hits;
        if (g.is_proxy)   ++proxy_hits;
        if (g.is_tor)     ++tor_hits;
    }
    int gprov = (int)R.geos.size();
    if (tor_hits)
        flag_major("flagged as Tor exit by " + std::to_string(tor_hits) + " GeoIP source(s)", 25);
    if (vpn_hits >= 2)
        flag_major("flagged as VPN by " + std::to_string(vpn_hits) + " GeoIP sources (multi-source consensus)", 18);
    else if (vpn_hits == 1)
        note("geo-vpn", "1 of " + std::to_string(gprov) + " GeoIP sources tagged this IP as VPN (single-source — likely a false positive)");
    if (proxy_hits >= 2)
        flag_major("flagged as proxy by " + std::to_string(proxy_hits) + " GeoIP sources (multi-source consensus)", 12);
    else if (proxy_hits == 1)
        note("geo-proxy", "1 of " + std::to_string(gprov) + " GeoIP sources tagged this IP as proxy (single-source — likely a false positive)");
    if (hosting_hits >= 1)
        note("asn-hosting", std::to_string(hosting_hits) + " of " + std::to_string(gprov) + " sources classify the ASN as hosting/datacenter "
             "(normal for any public server — not a red flag on its own)");
    if (R.geos.size() >= 2 && !R.geos[0].country_code.empty() && !R.geos[1].country_code.empty()
        && R.geos[0].country_code != R.geos[1].country_code)
        note("geo-cc-mismatch", "GeoIP country codes disagree between providers (normal GeoIP noise)");

    std::set<int> openset;
    for (auto& o: R.open_tcp) openset.insert(o.port);
    if (openset.count(3389)) flag_major("RDP/3389 reachable from Internet (attack surface, not VPN-specific)", 10);
    if (openset.count(1080) || openset.count(1081))
        flag_major("SOCKS5 exposed without wrapper (proxy signature)", 15);
    if (openset.count(3128) || openset.count(8118))
        flag_major("HTTP proxy exposed without wrapper", 12);
    if (openset.count(1194))
        flag_major("OpenVPN TCP/1194 default port open (hard protocol signature)", 15);
    if (openset.count(8388) || openset.count(8488))
        flag_major("Shadowsocks default port exposed (instantly fingerprintable)", 15);
    if (openset.count(10808) || openset.count(10809) || openset.count(10810))
        flag_major("v2ray/xray local-style inbound port exposed to WAN (misconfig)", 12);
    if (openset.count(22))
        note("ssh-22", "SSH/22 open with a standard banner — visible on Shodan/ASN-sweeps as 'server host', not as VPN");
    if (openset.count(500) || openset.count(4500))
        note("ike-ports", "IKE control ports (500/4500) open — normal for any IPsec-capable router");
    if (openset.count(443) && R.open_tcp.size() == 1)
        note("single-443", "only :443 is reachable — indistinguishable from a typical reverse-proxy / corporate single-service host, but provides no web 'context' (no :80 redirect, no decoy services)");
    else if (openset.count(443) && R.open_tcp.size() <= 3 && hosting_hits)
        note("sparse-ports", std::to_string(R.open_tcp.size()) + " TCP ports open on a hosting ASN with :443 — sparse profile; common for both minimal corporate servers and single-purpose proxy VPSes");

    for (auto& [p,u]: R.udp_probes) {
        if (!u.responded) continue;
        if (p == 1194)  flag_major("OpenVPN UDP/1194 reflects HARD_RESET (protocol-level match)", 22);
        if (p == 500)   flag_minor("IKEv2 responder on UDP/500 (IPsec endpoint)", 5);
        if (p == 4500)  flag_minor("IKEv2 NAT-T responder on UDP/4500 (IPsec endpoint)", 5);
        if (p == 51820) flag_major("WireGuard UDP/51820 answers handshake (default port signature)", 15);
        if (p == 41641) flag_minor("Tailscale UDP/41641 answers handshake (default port)", 5);
    }

    int xui_cluster_hits = 0;
    std::vector<int> xui_open;
    for (int p: {2053, 2083, 2087, 2096, 8443, 8880, 6443, 7443, 9443}) {
        if (openset.count(p)) { ++xui_cluster_hits; xui_open.push_back(p); }
    }
    bool xui_cluster_seen = false;
    if (xui_cluster_hits >= 2) {
        std::string portstr;
        for (size_t i=0;i<xui_open.size();++i) {
            if (i) portstr += ",";
            portstr += std::to_string(xui_open[i]);
        }
        flag_major(std::to_string(xui_cluster_hits) + " of the classical 3x-ui/x-ui/Marzban panel TLS ports are open ({" + portstr + "}) — installer fingerprint; regular webhosts rarely open this exact set", 14);
        xui_cluster_seen = true;
    } else if (xui_cluster_hits == 1) {
        note("xui-single-port", "one panel-installer TLS port open (:" + std::to_string(xui_open[0]) +
             ") — ambiguous by itself, but these ports are strongly associated with 3x-ui/x-ui proxy panels");
    }

    int silent_high_ports = 0;
    for (auto& o: R.open_tcp) {
        if (o.port >= 10000 && o.banner.empty()) ++silent_high_ports;
    }
    bool tls_on_443 = openset.count(443) > 0;
    if (tls_on_443 && silent_high_ports >= 1 && R.open_tcp.size() <= 6) {
        flag_minor(std::to_string(silent_high_ports) + " silent high-port(s) open alongside :443 TLS on a sparse host — classic multi-inbound proxy layout (Xray VLESS :443 + direct listener on high port)", 7);
    }

    bool any_tls = false, any_reality = false;
    bool any_impersonation = false;
    int  cert_issuers_seen_free_ca = 0;
    int  cert_fresh_ports = 0;
    int  cert_self_signed_ports = 0;
    int  cert_short_validity_ports = 0;
    int  cert_impersonation_ports = 0;
    int  tls_not_13_ports = 0;
    int  alpn_not_h2_ports = 0;
    int  group_not_x25519_ports = 0;
    bool sparse_vps_profile = (openset.count(443) && R.open_tcp.size() <= 3 && hosting_hits > 0);

    std::vector<std::string> asn_orgs_all;
    for (auto& g: R.geos) if (!g.asn_org.empty()) asn_orgs_all.push_back(g.asn_org);
    for (auto& pf: R.fps) {
        if (pf.tls && pf.tls->ok) {
            any_tls = true;
            if (pf.tls->version != "TLSv1.3") {
                flag_minor("TLS < 1.3 on :" + std::to_string(pf.port) +
                           " (" + pf.tls->version + ") — weak handshake posture, modern clients expect TLS 1.3", 4);
                ++tls_not_13_ports;
            }
            if (pf.tls->alpn != "h2") {
                note("alpn", "ALPN on :" + std::to_string(pf.port) + " = '" +
                     (pf.tls->alpn.empty() ? "-" : pf.tls->alpn) +
                     "' (HTTP/1.1-only is still normal for many corporate apps; h2 is not mandatory)");
                ++alpn_not_h2_ports;
            }
            if (!pf.tls->group.empty() && pf.tls->group != "X25519") {
                note("kex", "KEX group on :" + std::to_string(pf.port) + " = '" + pf.tls->group +
                     "' (X25519 is preferred by modern browsers but ECDHE-P256 is perfectly valid)");
                ++group_not_x25519_ports;
            }
            if (pf.tls->age_days > 0 && pf.tls->age_days < 14) {
                ++cert_fresh_ports;
                if (sparse_vps_profile) {
                    flag_minor("cert on :" + std::to_string(pf.port) +
                               " is fresh (" + std::to_string(pf.tls->age_days) +
                               "d) AND open-port profile is sparse on hosting ASN — classic 'new VLESS host' fingerprint",
                               6);
                } else {
                    note("cert-fresh", "cert on :" + std::to_string(pf.port) + " is " +
                         std::to_string(pf.tls->age_days) + "d old (fresh LE certs are normal for any site rotating every 60-90d)");
                }
            }
            if (pf.tls->self_signed) {
                flag_major("self-signed cert on :" + std::to_string(pf.port) +
                           " (subject==issuer) — browsers would reject; typical of Shadowsocks/Trojan/test setups", 10);
                ++cert_self_signed_ports;
            }
            if (pf.tls->is_letsencrypt) {
                ++cert_issuers_seen_free_ca;
            }
            if (pf.tls->days_left < 0) {
                flag_minor("cert on :" + std::to_string(pf.port) +
                           " EXPIRED " + std::to_string(-pf.tls->days_left) +
                           "d ago — no legit site runs an expired cert; abandonment or misconfig signal", 8);
            }
            if (pf.tls->san_count == 0 && !pf.tls->subject_cn.empty()) {
                note("no-san", "cert on :" + std::to_string(pf.port) +
                     " has no SAN entries (only legacy CN) — unusual for modern public TLS, but some internal certs do this");
            }
            if (pf.tls->total_validity_days > 0 && pf.tls->total_validity_days < 14) {
                flag_major("cert on :" + std::to_string(pf.port) +
                           " has a total validity of only " + std::to_string(pf.tls->total_validity_days) +
                           " days (notBefore→notAfter) — no public CA issues <14d certs to real sites; this is a hand-rolled internal cert or LE staging, a hard signal of a proxy/test setup",
                           15);
                ++cert_short_validity_ports;
            }
        }
        if (pf.sni && pf.sni->cert_impersonation && !pf.sni->brand_claimed.empty()) {
            bool owns = asn_owns_brand(pf.sni->brand_claimed, asn_orgs_all);
            if (!owns) {
                flag_major("cert on :" + std::to_string(pf.port) +
                           " vouches for brand '" + pf.sni->brand_claimed +
                           "' but the ASN is not owned by that brand — Reality-static / "
                           "cert-cloning signature (Xray `dest=" + pf.sni->brand_claimed + "` profile)",
                           22);
                ++cert_impersonation_ports;
                any_impersonation = true;
            } else {
                note("brand-legit", "cert on :" + std::to_string(pf.port) +
                     " is for '" + pf.sni->brand_claimed + "' and the ASN does match that brand — legitimate brand endpoint");
            }
        }
        if (pf.sni && pf.sni->reality_like) {
            any_reality = true;
            ++reality_port_count;
            if (pf.sni->passthrough_mode) {
                flag_major("Reality in passthrough mode on :" + std::to_string(pf.port) +
                           " (base cert is for '" + pf.sni->matched_foreign_sni +
                           "' — stream tunnelled to the real brand, SNI-based vhost routing "
                           "then returns different certs per SNI; cert + ASN disagree)", 14);
            } else {
                flag_major("Reality cert-steering pattern on :" + std::to_string(pf.port) +
                           " (cert covers foreign SNI '" + pf.sni->matched_foreign_sni + "')", 12);
            }
        }
        if (pf.https && pf.https->tls_ok && pf.https->responded &&
            !pf.https->server_hdr.empty()) {
            std::string sbr = server_header_brand(pf.https->server_hdr);
            if (!sbr.empty()) {
                bool owns = asn_owns_brand(sbr, asn_orgs_all);
                if (!owns) {
                    flag_major("HTTP-over-TLS on :" + std::to_string(pf.port) +
                               " returns `Server: " + printable_prefix(pf.https->server_hdr, 40) +
                               "` — that banner is only emitted by '" + sbr +
                               "' infrastructure, yet the ASN isn't owned by that brand "
                               "(origin is proxying the HTTP stream to the real brand = Reality passthrough)",
                               18);
                    if (!(pf.sni && pf.sni->cert_impersonation)) {
                        ++cert_impersonation_ports;
                        any_impersonation = true;
                    }
                }
            }
        }
        if (pf.https && pf.https->tls_ok) {
            if (pf.https->version_anomaly && pf.https->responded) {
                flag_major("HTTP-over-TLS on :" + std::to_string(pf.port) +
                           " returned an invalid HTTP version ('" +
                           printable_prefix(pf.https->first_line, 40) +
                           "') — no real web server emits that; classic Xray/Trojan fallback signature",
                           14);
            }
            if (pf.https->responded && pf.https->server_hdr.empty() && !pf.https->version_anomaly) {
                flag_minor("HTTP-over-TLS on :" + std::to_string(pf.port) +
                           " responded without a Server: header — real nginx/Apache/Caddy/CDN set one; absence is a middleware tell",
                           5);
            }
            if (!pf.https->responded) {
                flag_minor("HTTP-over-TLS on :" + std::to_string(pf.port) +
                           " — TLS handshake succeeded but origin did not return any HTTP bytes to a valid GET / request. Legitimate web origins always reply (200/301/404/502). Silence here = stream-layer proxy.",
                           8);
            }
            if (pf.https->has_proxy_leak) {
                std::string hdrs;
                if (!pf.https->via_hdr.empty())        hdrs += "Via=\"" + printable_prefix(pf.https->via_hdr, 32) + "\" ";
                if (!pf.https->forwarded_hdr.empty())  hdrs += "Forwarded=\"" + printable_prefix(pf.https->forwarded_hdr, 32) + "\" ";
                if (!pf.https->xff_hdr.empty())        hdrs += "X-Forwarded-For=\"" + printable_prefix(pf.https->xff_hdr, 32) + "\" ";
                if (!pf.https->xreal_ip_hdr.empty())   hdrs += "X-Real-IP=\"" + printable_prefix(pf.https->xreal_ip_hdr, 24) + "\" ";
                flag_major("HTTP-over-TLS on :" + std::to_string(pf.port) +
                           " leaks proxy-chain headers (" + hdrs +
                           ") — methodika §10.2 diagnostic: the origin IS behind (or IS) a middle proxy",
                           12);
            }
        }
        if (pf.ct && pf.ct->queried && !pf.ct->found && pf.ct->err.empty()) {
            if (pf.tls && pf.tls->ok && pf.tls->age_days < 30) {
                flag_major("cert on :" + std::to_string(pf.port) +
                           " is NOT in public CT logs AND is fresh (" +
                           std::to_string(pf.tls->age_days) + "d) — never issued by a public CA; "
                           "hand-rolled internal / self-signed / cloned cert typical of Xray/Trojan quickfire setups",
                           15);
            } else if (pf.tls && pf.tls->ok) {
                flag_minor("cert on :" + std::to_string(pf.port) +
                           " is NOT in public CT logs — private-CA / internal issuance / LE-staging (legitimate in corporate internal use, but suspicious on a public-facing IP)",
                           6);
            }
        }
    }

    if (R.sstp && R.sstp->is_vpn_like) {
        flag_major("Microsoft SSTP VPN detected on :443 (SSTP_DUPLEX_POST / sra_{...} replied with 200 OK + 2^64-1 Content-Length) — classical SSTP endpoint", 18);
    }

    for (auto& [p, u]: R.udp_extra) {
        if (!u.responded) continue;
        if (p == 1701)
            flag_major("L2TP UDP/1701 responds to SCCRQ (L2TP control signature)", 15);
        else if (p == 36712)
            flag_major("Hysteria2 default port UDP/36712 is live (QUIC-based Hysteria tunnel)", 15);
        else if (p == 8443)
            flag_minor("TUIC v5 / QUIC on UDP/8443 answers handshake (modern QUIC-based proxy)", 7);
        else if (p == 55555)
            flag_major("AmneziaWG on UDP/55555 with Sx=8 junk prefix replies — obfuscated WireGuard", 15);
        else if (p == 51820) {
            bool wg_replied = false;
            for (auto& x: R.udp_probes) if (x.first == 51820 && x.second.responded) wg_replied = true;
            if (!wg_replied) {
                flag_major("AmneziaWG on default UDP/51820 (vanilla-WG header REJECTED, Sx=8 junk-prefix ACCEPTED) — obfuscated WireGuard at 2026-standard obfuscation params", 16);
            }
        }
    }

    if (R.snitch && R.snitch->ok) {
        auto& sn = *R.snitch;
        if (sn.too_low)
            flag_major("SNITCH: RTT " + std::to_string((int)sn.median_ms) + "ms to " +
                       sn.country_code + " is impossibly low (physical min ≥" +
                       std::to_string((int)sn.expected_min_ms) +
                       "ms from a typical EU/RU observer). GeoIP lies OR anycast proxy fronts this IP",
                       15);
        else if (sn.too_high)
            flag_minor("SNITCH: RTT " + std::to_string((int)sn.median_ms) +
                       "ms is 3x+ the expected band for " + sn.country_code +
                       " — extra hops in path (tunnel / long middlebox chain)", 6);
        else if (sn.high_jitter)
            note("snitch-jitter",
                 "SNITCH: RTT stddev " + std::to_string((int)sn.stddev_ms) +
                 "ms over " + std::to_string(sn.samples) +
                 " samples — elevated jitter typical of tunnel encryption/queue overhead (not conclusive)");
        else if (sn.anchor_ratio_off)
            note("snitch-anchor",
                 "SNITCH: target RTT doesn't match the closest anchor ratio — geolocation may be off");
    }

    if (R.trace && R.trace->ok) {
        auto& tr = *R.trace;
        if (tr.hop_count >= 20)
            flag_minor("traceroute shows " + std::to_string(tr.hop_count) +
                       " hops to target — longer than typical (residential→DC = 7-12 hops); extra hops suggest tunnel / overlay",
                       5);
        else if (tr.max_rtt_jump_ms >= 100 && tr.long_hops >= 2)
            note("trace-jump",
                 "traceroute has a large RTT step (" + std::to_string(tr.max_rtt_jump_ms) +
                 "ms jump) and " + std::to_string(tr.long_hops) +
                 " hops above 150ms — may indicate a long-haul tunnel between adjacent hops");
        else
            note("trace-ok",
                 "traceroute: " + std::to_string(tr.hop_count) +
                 " hops, max RTT step " + std::to_string(tr.max_rtt_jump_ms) +
                 "ms — path looks clean");
        if (tr.tspu_hops > 0) {
            flag_minor("traceroute goes through " + std::to_string(tr.tspu_hops) +
                       " hop(s) matching the tspu management-subnet layout "
                       "(10.X.Y.[131-235]/[241-245]/254) - indicates a tspu site "
                       "is between you and the target",
                       5 * tr.tspu_hops);
        }
    }

    if (R.bgp_blackhole_likely) {
        flag_major("L3 BGP-blackhole pattern on target: " +
                   std::to_string(R.scan_stats.timeouts) + "/" +
                   std::to_string(R.scan_stats.scanned) +
                   " ports TIMEOUT with 0 RST - tspu type B / operator ip-list block",
                   40);
    }

    for (auto& pf: R.fps) {
        if (pf.fp.tspu_redirect && !pf.fp.redirect_marker.empty()) {
            flag_major("HTTP on :" + std::to_string(pf.port) +
                       " redirects to operator warning page '" +
                       pf.fp.redirect_marker + "' (Location: '" +
                       printable_prefix(pf.fp.redirect_target, 60) +
                       "') - tspu type A active block",
                       30);
        }
    }

    int j3_silent_total = 0, j3_resp_total = 0, j3_ports_checked = 0;
    int j3_canned_ports = 0, j3_badver_ports = 0, j3_raw_nonhttp_ports = 0;
    bool proxy_middleware_seen = false;
    for (auto& pf: R.fps) {
        if (pf.j3.size() < 6) continue;
        ++j3_ports_checked;
        int sil = 0, rsp = 0;
        int http_like_responses = 0;
        for (auto& j: pf.j3) {
            if (j.responded) {
                ++rsp;
                if (j.first_line.rfind("HTTP/", 0) == 0) ++http_like_responses;
            } else {
                ++sil;
            }
        }
        j3_silent_total += sil;
        j3_resp_total   += rsp;

        bool is_tls_port        = (pf.tls && pf.tls->ok);
        bool https_probe_anomaly =
            (pf.https && pf.https->tls_ok &&
             (!pf.https->responded ||
              pf.https->version_anomaly ||
              (pf.https->responded && pf.https->server_hdr.empty())));
        bool canned_real = (pf.j3a && pf.j3a->canned_identical >= 2) &&
                           (!is_tls_port || https_probe_anomaly);
        if (canned_real) {
            ++j3_canned_ports;
            flag_major("port :" + std::to_string(pf.port) +
                       " returns a canned fallback page (same first-line '" +
                       printable_prefix(pf.j3a->canned_line, 50) +
                       "' with identical byte count " + std::to_string(pf.j3a->canned_bytes) +
                       "B for " + std::to_string(pf.j3a->canned_identical) +
                       " different probes" +
                       (is_tls_port ? " AND the HTTP-over-TLS probe is also anomalous" : "") +
                       ") — real web servers vary their replies; this is the Xray/Trojan `fallback+redirect` signature",
                       18);
        }
        if (pf.j3a) {
            if (pf.j3a->http_bad_version >= 1) {
                ++j3_badver_ports;
                flag_major("port :" + std::to_string(pf.port) +
                           " emits an HTTP reply with an invalid version (e.g. HTTP/0.0) " +
                           std::to_string(pf.j3a->http_bad_version) +
                           " time(s) — nginx/Apache/Caddy never produce this; classic Xray fallback signature",
                           14);
            }
            if (pf.j3a->raw_non_http >= 2 && pf.j3a->http_real == 0) {
                ++j3_raw_nonhttp_ports;
                flag_minor("port :" + std::to_string(pf.port) +
                           " answers with raw non-HTTP bytes (" + std::to_string(pf.j3a->raw_non_http) +
                           " probes) — stream-layer proxy framing (Shadowsocks/Trojan/custom)", 7);
            }
        }

        bool has_reality = pf.sni && pf.sni->reality_like;
        bool tls_ok      = pf.tls && pf.tls->ok;
        bool tls_failed  = pf.tls && !pf.tls->ok;

        std::string role;
        if (has_reality && tls_ok) {
            if (sil >= 6) {
                role = "Reality hidden-mode (silent-on-junk — strong DPI signature)";
                xray_reality_hidden = true;
                score -= 3;
            } else if (rsp >= 4) {
                role = "Reality + HTTP fallback (mimics real web server on junk)";
                xray_reality_primary = true;
            } else {
                role = "Reality (TLS endpoint)";
            }
        } else if (tls_ok) {
            if (sil >= 6 && rsp == 0) {
                role = "TLS endpoint that silently drops all HTTP/junk — proxy/middleware in front of origin (Xray/Trojan/SS-AEAD — nginx/Apache would return HTTP 400)";
                flag_minor("port :" + std::to_string(pf.port) +
                           " does TLS 1.3 cleanly but silently drops every HTTP junk probe — "
                           "strong signature of a stream-layer proxy sitting in front of the origin "
                           "(Xray/Trojan/SS). Normal web servers reply with HTTP 400 on non-TLS bytes.",
                           7);
                proxy_middleware_seen = true;
            } else if (rsp >= 4 && http_like_responses == 0) {
                role = "TLS endpoint that answers junk with non-HTTP replies — atypical middleware (bytes come back but not in HTTP form)";
                flag_minor("port :" + std::to_string(pf.port) +
                           " answered " + std::to_string(rsp) +
                           " junk probes but none looked like HTTP — origin is not a standard web server "
                           "(possible custom proxy framing)", 5);
                proxy_middleware_seen = true;
            } else if (rsp >= 7) {
                role = "generic HTTPS / CDN origin (junk probes get HTTP 4xx as expected)";
            } else {
                role = "TLS endpoint (not Reality, mixed probe behaviour)";
            }
            bool server_brand_mismatch = false;
            if (pf.https && pf.https->tls_ok && !pf.https->server_hdr.empty()) {
                std::string sb = server_header_brand(pf.https->server_hdr);
                if (!sb.empty() && !asn_owns_brand(sb, asn_orgs_all))
                    server_brand_mismatch = true;
            }
            char buf[512] = {0};
            snprintf(buf, sizeof(buf),
                     " — %s / ALPN=%s / CN=%s / issuer=%s / age=%dd / validity=%dd / SAN=%d%s%s%s%s",
                     pf.tls->version.c_str(),
                     pf.tls->alpn.empty() ? "-" : pf.tls->alpn.c_str(),
                     pf.tls->subject_cn.empty() ? "(none)" : pf.tls->subject_cn.c_str(),
                     pf.tls->issuer_cn.empty() ? "(none)" : pf.tls->issuer_cn.c_str(),
                     pf.tls->age_days, pf.tls->total_validity_days, pf.tls->san_count,
                     (pf.tls->total_validity_days > 0 && pf.tls->total_validity_days < 14) ? " [!short-validity]" : "",
                     (pf.sni && pf.sni->cert_impersonation) ? " [!brand-impersonation]" : "",
                     server_brand_mismatch ? " [!server-impersonation]" : "",
                     canned_real ? " [!canned-fallback]" : "");
            role += buf;
            bool role_upgraded = false;
            if (pf.sni && pf.sni->cert_impersonation && !pf.sni->brand_claimed.empty()) {
                bool owns = asn_owns_brand(pf.sni->brand_claimed, asn_orgs_all);
                if (!owns) {
                    const char* label = (pf.sni->passthrough_mode)
                        ? "Reality with real passthrough (cert tunnelled from '"
                        : "Reality-static / cert-cloning (cert impersonates '";
                    role = std::string(label) + pf.sni->brand_claimed +
                           (pf.sni->passthrough_mode
                              ? "' via `dest=` — TLS stream transparently tunnelled) "
                              : "' on an unrelated ASN) ") + role;
                    role_upgraded = true;
                }
            }
            if (!role_upgraded && pf.https && pf.https->tls_ok &&
                !pf.https->server_hdr.empty()) {
                std::string sb = server_header_brand(pf.https->server_hdr);
                if (!sb.empty() && !asn_owns_brand(sb, asn_orgs_all)) {
                    role = "Reality with real passthrough (`Server: " +
                           printable_prefix(pf.https->server_hdr, 24) +
                           "` banner comes from '" + sb +
                           "' infrastructure on non-owner ASN) " + role;
                    role_upgraded = true;
                }
            }
            if (!role_upgraded && canned_real) {
                role = "TLS endpoint emitting canned fallback response "
                       "(Xray/Trojan `fallback+redirect` page served for every probe) " + role;
            }
        } else if (tls_failed && sil >= 6) {
            role = "TLS handshake refused AND silent on HTTP — stream-layer proxy that only speaks its own framing (Shadowsocks-AEAD / Trojan / strict-mode Reality / custom SOCKS-over-TLS) OR a firewalled service";
            flag_minor("port :" + std::to_string(pf.port) +
                       " rejects TLS AND drops HTTP junk — likely a stream-proxy that only accepts its own framing "
                       "(SS-AEAD, Trojan, Reality-strict). Not conclusive: could also be a firewalled internal service.",
                       5);
        } else if (tls_failed) {
            role = "TLS handshake failed + mixed probes (ambiguous — internal service / non-TLS-on-TLS-port misconfig)";
        }
        if (!role.empty()) port_roles.push_back({pf.port, role});
    }

    for (auto& o: R.open_tcp) {
        bool is_ssh_std  = (o.port==22 || o.port==2222 || o.port==22222);
        bool has_banner  = !o.banner.empty() && o.banner.rfind("SSH-",0)==0;
        if (is_ssh_std && has_banner)
            port_roles.push_back({o.port, "SSH (advertised banner, standard port) — '" +
                                          printable_prefix(o.banner, 40) + "'"});
        else if (has_banner && !is_ssh_std)
            port_roles.push_back({o.port, "SSH on non-standard port (banner still leaks version) — '" +
                                          printable_prefix(o.banner, 40) + "'"});
    }

    for (auto& pf: R.fps) {
        if (pf.fp.service == "HTTP" || pf.fp.service == "HTTP?") {
            port_roles.push_back({pf.port, "plain HTTP — " +
                                          (pf.fp.details.empty() ? "no banner" : printable_prefix(pf.fp.details, 90))});
        } else if (pf.fp.service == "HTTP-PROXY") {
            port_roles.push_back({pf.port, "OPEN HTTP PROXY (accepts CONNECT) — " +
                                          printable_prefix(pf.fp.details, 80)});
            flag_major("open HTTP proxy (accepts CONNECT) on :" + std::to_string(pf.port), 20);
        } else if (pf.fp.service == "SOCKS5") {
            port_roles.push_back({pf.port, "OPEN SOCKS5 — " +
                                          printable_prefix(pf.fp.details, 80)});
            flag_major("open SOCKS5 endpoint on :" + std::to_string(pf.port), 20);
        }
    }

    score = std::max(0, std::min(100, score));
    R.score = score;
    if (score >= 85)      R.label = "CLEAN";
    else if (score >= 70) R.label = "NOISY";
    else if (score >= 50) R.label = "SUSPICIOUS";
    else                  R.label = "OBVIOUSLY-VPN";

    const char* color = score>=85?C::GRN : score>=70?C::YEL : score>=50?C::YEL : C::RED;

    std::string stack_name;
    bool any_wg = std::any_of(R.udp_probes.begin(), R.udp_probes.end(),
                              [](auto& x){return x.first==51820 && x.second.responded;});
    bool any_ovpn_udp = std::any_of(R.udp_probes.begin(), R.udp_probes.end(),
                                    [](auto& x){return x.first==1194 && x.second.responded;});
    bool any_canned    = (j3_canned_ports > 0);
    bool any_bad_ver   = (j3_badver_ports  > 0);
    bool any_short_val = (cert_short_validity_ports > 0);
    if (any_impersonation && xui_cluster_seen)
        stack_name = "Xray-core VLESS+Reality on a 3x-ui/x-ui/Marzban panel install "
                     "(cert impersonates a major brand + multiple panel-preset TLS ports open)";
    else if (any_impersonation)
        stack_name = "Xray-core VLESS+Reality (static dest — TLS cert cloned from a major brand)";
    else if (reality_port_count >= 2)
        stack_name = "Xray-core / sing-box (VLESS+Reality, multi-port)";
    else if (xray_reality_primary)
        stack_name = "Xray-core (VLESS+Reality with HTTP fallback)";
    else if (xray_reality_hidden)
        stack_name = "Xray-core (VLESS+Reality, hidden-mode)";
    else if (any_reality)
        stack_name = "Xray / Reality-compatible TLS steering";
    else if (any_canned || any_bad_ver)
        stack_name = "TLS front + Xray/Trojan stream-layer proxy "
                     "(canned fallback response / invalid HTTP version — not a real web server)";
    else if (any_short_val)
        stack_name = "TLS endpoint with a hand-rolled short-lifetime cert "
                     "(validity < 14d — never issued by real CAs; Xray/Trojan quickfire setup)";
    else if (xui_cluster_seen)
        stack_name = "3x-ui/x-ui/Marzban panel install (multiple preset TLS ports open) — "
                     "VLESS/Trojan/Shadowsocks multiplex likely";
    else if (any_ovpn_udp || openset.count(1194) || openset.count(1193))
        stack_name = "OpenVPN (plaintext wire protocol)";
    else if (any_wg)
        stack_name = "WireGuard (default UDP port)";
    else if (openset.count(8388) || openset.count(8488))
        stack_name = "Shadowsocks (naked default port)";
    else if (proxy_middleware_seen)
        stack_name = "TLS front + stream-layer proxy (Xray / Trojan / SS-AEAD) — TLS handshake is clean, "
                     "but the origin silently drops non-TLS bytes instead of returning HTTP 400 like a real web server";
    else if (any_tls && openset.count(443))
        stack_name = "generic TLS / HTTPS origin (no direct VPN signature)";
    else
        stack_name = "no VPN protocol signature identified";

    tee_printf("\n  %sStack identified:%s  %s%s%s\n",
           col(C::BOLD), col(C::RST),
           col(C::CYN), stack_name.c_str(), col(C::RST));

    if (!port_roles.empty()) {
        tee_printf("\n  %sPer-port classification:%s\n", col(C::BOLD), col(C::RST));
        for (auto& [p, role]: port_roles)
            tee_printf("    %s:%-5d%s  %s\n", col(C::CYN), p, col(C::RST), role.c_str());
    }

    auto axis = [&](const char* name, const char* level, const std::string& note) {
        const char* c = !strcmp(level,"HIGH")   ? C::RED :
                        !strcmp(level,"MEDIUM") ? C::YEL :
                        !strcmp(level,"LOW")    ? C::GRN :
                        !strcmp(level,"NONE")   ? C::DIM : C::CYN;
        dpi_axes.push_back({name, std::string(level) + " — " + note});
        tee_printf("    %-36s %s%-6s%s  %s\n", name, col(c), level, col(C::RST), note.c_str());
    };

    int https_bad_ver_ports = 0, https_no_server_ports = 0, https_empty_ports = 0, https_ok_real_ports = 0;
    for (auto& pf: R.fps) if (pf.https && pf.https->tls_ok) {
        if (pf.https->responded && pf.https->version_anomaly)                                 ++https_bad_ver_ports;
        else if (pf.https->responded && pf.https->server_hdr.empty())                         ++https_no_server_ports;
        else if (!pf.https->responded)                                                        ++https_empty_ports;
        else                                                                                  ++https_ok_real_ports;
    }

    tee_printf("\n  %sDPI exposure matrix:%s\n", col(C::BOLD), col(C::RST));
    {
        int naive_hits = 0;
        for (int p: {1194, 1723, 500, 4500, 51820, 1701, 8388, 8488, 8090, 10808, 10809})
            if (openset.count(p)) ++naive_hits;
        axis("Port-based (default VPN ports)",
             naive_hits >= 2 ? "HIGH" : naive_hits == 1 ? "MEDIUM" : "LOW",
             naive_hits ? std::to_string(naive_hits) + " default VPN port(s) open" :
                          "no default VPN ports among open set");
    }
    {
        bool ovpn = any_ovpn_udp || openset.count(1194);
        bool wg   = any_wg;
        bool ike  = false;
        for (auto& [p,u]: R.udp_probes) if ((p==500||p==4500) && u.responded) ike = true;
        if (ovpn || wg)      axis("Protocol handshake signature", "HIGH",
                                  std::string(ovpn?"OpenVPN ":"") + (wg?"WireGuard":"") + " signature matched");
        else if (ike)        axis("Protocol handshake signature", "MEDIUM", "IKEv2 responds on control ports");
        else if (any_reality) axis("Protocol handshake signature", "LOW", "TLS 1.3 handshake looks normal (Reality identified by cert-steering, not handshake bytes)");
        else if (any_tls)    axis("Protocol handshake signature", "LOW", "TLS handshake looks normal");
        else                 axis("Protocol handshake signature", "NONE", "no TLS / no VPN protocol replies");
    }
    {
        if (any_reality)            axis("Cert-steering (Reality discriminator)", "HIGH",
                                         "Reality steering pattern positively identified");
        else {
            bool same_cert_seen = false, varies_seen = false;
            for (auto& pf: R.fps) if (pf.sni) {
                if (pf.sni->same_cert_always) same_cert_seen = true;
                else if (!pf.sni->default_cert_only) varies_seen = true;
            }
            if (varies_seen)        axis("Cert-steering (Reality discriminator)", "NONE",
                                         "cert varies per SNI (multi-tenant TLS, not Reality)");
            else if (same_cert_seen) axis("Cert-steering (Reality discriminator)", "NONE",
                                          "single default cert — plain server, not Reality");
            else                    axis("Cert-steering (Reality discriminator)", "NONE",
                                         "no TLS to test");
        }
    }
    {
        if (hosting_hits >= 2)   axis("ASN classifier (VPS/hosting)", "LOW",
                                      std::to_string(hosting_hits) + " sources classify the ASN as hosting/datacenter — normal for any public server");
        else if (hosting_hits == 1) axis("ASN classifier (VPS/hosting)", "LOW",
                                         "1 source classifies the ASN as hosting (ambiguous)");
        else                     axis("ASN classifier (VPS/hosting)", "NONE",
                                      "no GeoIP source classifies the ASN as hosting");
    }
    {
        if (tor_hits) {
            axis("Threat-intel tags (VPN/Proxy/Tor)", "HIGH",
                 std::to_string(tor_hits) + " sources tag this IP as Tor exit");
        } else if (vpn_hits >= 2 || proxy_hits >= 2) {
            std::string n = std::to_string(vpn_hits) + " VPN / " + std::to_string(proxy_hits) + " proxy tags";
            axis("Threat-intel tags (VPN/Proxy/Tor)", "HIGH", n);
        } else if (vpn_hits || proxy_hits) {
            axis("Threat-intel tags (VPN/Proxy/Tor)", "NONE",
                 "1 single-source tag — false-positive rate too high to count");
        } else {
            axis("Threat-intel tags (VPN/Proxy/Tor)", "NONE", "no VPN/Proxy/Tor tag from any source");
        }
    }
    {
        if (cert_short_validity_ports >= 1)
            axis("Cert freshness (new-LE watch)", "HIGH",
                 std::to_string(cert_short_validity_ports) +
                 " port(s) with impossibly short cert validity (<14d total — real CAs never issue this)");
        else if (cert_fresh_ports >= 1)
            axis("Cert freshness (new-LE watch)", "MEDIUM",
                 std::to_string(cert_fresh_ports) + " port(s) with cert <14d old");
        else
            axis("Cert freshness (new-LE watch)", "LOW", "no suspiciously fresh certs");
    }
    {
        if (j3_ports_checked == 0)   axis("Active junk probing (J3)", "NONE", "no J3 probes ran");
        else if (j3_silent_total >= j3_resp_total && j3_silent_total >= 4)
            axis("Active junk probing (J3)", "MEDIUM",
                 std::to_string(j3_silent_total) + " silent / " + std::to_string(j3_resp_total) +
                 " resp — strict TLS-only posture (fingerprintable by TSPU)");
        else if (j3_resp_total >= j3_silent_total)
            axis("Active junk probing (J3)", "LOW",
                 std::to_string(j3_resp_total) + " responses — looks like a permissive web-origin");
        else
            axis("Active junk probing (J3)", "LOW",
                 std::to_string(j3_silent_total) + " silent / " + std::to_string(j3_resp_total) + " resp");
    }
    {
        size_t np = R.open_tcp.size();
        if (xui_cluster_seen)
            axis("Open-port profile (sparsity)", "HIGH",
                 std::to_string(np) + " ports open, dominated by the 3x-ui/x-ui/Marzban preset TLS cluster " +
                 std::to_string(xui_cluster_hits) + " hits (2053/2083/2087/2096/8443/…) — installer fingerprint");
        else if (np == 1 && openset.count(443))
            axis("Open-port profile (sparsity)", "LOW",
                 ":443 only — common for reverse-proxies, corporate apps, and single-purpose hosts alike");
        else if (np <= 3 && openset.count(443) && hosting_hits)
            axis("Open-port profile (sparsity)", "LOW",
                 "sparse (<=3 ports) on hosting ASN — ambiguous (minimal corp server / proxy VPS)");
        else if (np >= 8)
            axis("Open-port profile (sparsity)", "NONE",
                 std::to_string(np) + " ports open — diverse service host, clearly not a dedicated proxy");
        else
            axis("Open-port profile (sparsity)", "LOW",
                 std::to_string(np) + " ports open");
    }
    {
        int bad = tls_not_13_ports + alpn_not_h2_ports + cert_self_signed_ports;
        if (bad >= 2) axis("TLS hygiene (1.3 + h2 + trusted-CA)", "MEDIUM",
                           std::to_string(bad) + " hygiene issues (weak TLS / ALPN / self-signed)");
        else if (bad == 1) axis("TLS hygiene (1.3 + h2 + trusted-CA)", "LOW", "1 hygiene issue");
        else if (any_tls)  axis("TLS hygiene (1.3 + h2 + trusted-CA)", "LOW", "TLS posture is clean (1.3 + h2 + trusted-CA)");
        else               axis("TLS hygiene (1.3 + h2 + trusted-CA)", "NONE", "no TLS observed");
    }
    {
        if (any_impersonation) {
            int cnt = 0; std::string bdom;
            for (auto& pf: R.fps) if (pf.sni && pf.sni->cert_impersonation) {
                ++cnt; if (bdom.empty()) bdom = pf.sni->brand_claimed;
            }
            int svr_cnt = 0;
            for (auto& pf: R.fps)
                if (pf.https && pf.https->tls_ok && !pf.https->server_hdr.empty()) {
                    std::string sb = server_header_brand(pf.https->server_hdr);
                    if (!sb.empty() && !asn_owns_brand(sb, asn_orgs_all)) {
                        ++svr_cnt; if (bdom.empty()) bdom = sb;
                    }
                }
            std::string detail = std::to_string(cnt) + " cert port(s)";
            if (svr_cnt > 0) detail += " + " + std::to_string(svr_cnt) + " Server-header port(s)";
            detail += " claim brand '" + bdom + "' on an ASN that does NOT own it — Reality `dest=` cloning signature";
            axis("Cert impersonation (Reality-static tell)", "HIGH", detail);
        } else {
            axis("Cert impersonation (Reality-static tell)", "NONE",
                 "no cert claims a major-brand domain the ASN doesn't own");
        }
    }
    {
        if (https_bad_ver_ports >= 1) {
            axis("Active HTTP-over-TLS probe", "HIGH",
                 std::to_string(https_bad_ver_ports) +
                 " port(s) returned an invalid HTTP version (HTTP/0.0 or malformed) — no real web server emits this");
        } else if (https_empty_ports >= 1) {
            axis("Active HTTP-over-TLS probe", "MEDIUM",
                 std::to_string(https_empty_ports) +
                 " port(s) accept TLS but return 0 bytes to a valid GET / — stream-layer proxy tell");
        } else if (https_no_server_ports >= 1) {
            axis("Active HTTP-over-TLS probe", "MEDIUM",
                 std::to_string(https_no_server_ports) +
                 " port(s) responded without a Server: header — nginx/Apache/Caddy always set one");
        } else if (https_ok_real_ports >= 1) {
            axis("Active HTTP-over-TLS probe", "LOW",
                 std::to_string(https_ok_real_ports) +
                 " port(s) returned a well-formed HTTP reply with a Server: header — looks like a real web origin");
        } else {
            axis("Active HTTP-over-TLS probe", "NONE", "no TLS port to probe");
        }
    }
    {
        if (xui_cluster_hits >= 2)
            axis("Panel-port cluster (3x-ui/x-ui/Marzban)", "HIGH",
                 std::to_string(xui_cluster_hits) + " of the preset panel TLS ports are open "
                 "(2053/2083/2087/2096/8443/8880/6443/7443/9443)");
        else if (xui_cluster_hits == 1)
            axis("Panel-port cluster (3x-ui/x-ui/Marzban)", "MEDIUM",
                 "1 panel-preset TLS port open — ambiguous (could be Cloudflare-Origin anyway)");
        else
            axis("Panel-port cluster (3x-ui/x-ui/Marzban)", "NONE",
                 "no panel-preset TLS ports among open set");
    }
    {
        int worst = std::max({j3_canned_ports, j3_badver_ports, j3_raw_nonhttp_ports});
        if (j3_canned_ports >= 1 || j3_badver_ports >= 1)
            axis("J3 canned/anomaly aggregate", "HIGH",
                 std::to_string(j3_canned_ports) + " canned / " +
                 std::to_string(j3_badver_ports) + " bad-version / " +
                 std::to_string(j3_raw_nonhttp_ports) + " raw-non-HTTP port(s) — static fallback signature");
        else if (j3_raw_nonhttp_ports >= 1)
            axis("J3 canned/anomaly aggregate", "MEDIUM",
                 std::to_string(j3_raw_nonhttp_ports) + " port(s) return non-HTTP bytes — Shadowsocks/Trojan/custom proxy");
        else if (j3_ports_checked)
            axis("J3 canned/anomaly aggregate", "LOW", "no canned / bad-version / raw-non-HTTP replies");
        else
            axis("J3 canned/anomaly aggregate", "NONE", "no J3 probes ran");
        (void)worst;
    }

    tee_printf("\n  %sStrong signals (%zu)%s  [%s!%s = real evidence of VPN/proxy]\n",
           col(C::BOLD), signals_major.size(), col(C::RST), col(C::RED), col(C::RST));
    if (signals_major.empty()) tee_printf("    (none)\n");
    else for (auto& s: signals_major) tee_printf("    %s[!]%s %s\n", col(C::RED), col(C::RST), s.c_str());

    tee_printf("\n  %sSoft signals (%zu)%s  [%s-%s = suggestive pattern, not proof]\n",
           col(C::BOLD), signals_minor.size(), col(C::RST), col(C::YEL), col(C::RST));
    if (signals_minor.empty()) tee_printf("    (none)\n");
    else for (auto& s: signals_minor) tee_printf("    %s[-]%s %s\n", col(C::YEL), col(C::RST), s.c_str());

    tee_printf("\n  %sInformational (%zu)%s  [%si%s = observation only, no penalty — normal sites can have these]\n",
           col(C::BOLD), notes.size(), col(C::RST), col(C::CYN), col(C::RST));
    if (notes.empty()) tee_printf("    (none)\n");
    else for (auto& [tag, s]: notes)
        tee_printf("    %s[i]%s %s%s%s  %s\n",
               col(C::CYN), col(C::RST),
               col(C::DIM), tag.c_str(), col(C::RST), s.c_str());

    tee_printf("\n  %sFinal score:%s %s%d/100%s  verdict: %s%s%s\n",
           col(C::BOLD), col(C::RST), col(C::BOLD), score, col(C::RST),
           col(color), R.label.c_str(), col(C::RST));

    tee_printf("\n  %sHardening suggestions:%s\n", col(C::BOLD), col(C::RST));
    auto sug = [](const char* tag, const char* body) {
        tee_printf("    %s[%s]%s\n      %s\n", col(C::GRN), tag, col(C::RST), body);
    };

    bool any_sug = false;
    auto has_note = [&](const std::string& t) {
        for (auto& [k,_]: notes) if (k == t) return true;
        return false;
    };

    if (xray_reality_primary && xray_reality_hidden) {
        sug("reality-mixed",
            "Mixed Reality config: one port uses HTTP-fallback, another is hidden-mode.\n"
            "      The hidden port exposes the silent-on-junk DPI signature. Either drop\n"
            "      the duplicate listener, or configure the Reality `fallback` block so\n"
            "      EVERY port returns HTTP 400/502 on non-handshake traffic (match nginx).");
        any_sug = true;
    } else if (xray_reality_hidden) {
        sug("reality-hidden",
            "Reality hidden-mode: TLS handshake ok, but non-TLS bytes are silently dropped.\n"
            "      That pattern is DPI-detectable (TSPU/GFW fingerprint it).\n"
            "      Fix: set `dest=` to a real HTTPS site you don't control, and configure\n"
            "      `fallback` so the server returns its own 400/502 page on unrecognised bytes.");
        any_sug = true;
    } else if (xray_reality_primary) {
        sug("reality-ok",
            "Reality HTTP-fallback is wired correctly: junk bytes get HTTP 400, which is\n"
            "      indistinguishable from nginx/Apache. No action needed.");
        any_sug = true;
    }
    if (proxy_middleware_seen) {
        sug("proxy-middleware",
            "TLS is clean on this port, but the origin silently drops every HTTP-junk probe\n"
            "      instead of returning HTTP 400 like nginx/Apache/Caddy would. That silence\n"
            "      is the proxy-middleware signature TSPU actively tests for. Fix: put a real\n"
            "      nginx in front that handles both the TLS handshake AND the HTTP fallback,\n"
            "      so non-TLS bytes hit nginx's own 400 page.");
        any_sug = true;
    }
    if (reality_port_count >= 2) {
        char buf[256];
        snprintf(buf, sizeof(buf),
            "Reality is listening on %d ports of the same IP. ASN/port sweeps flag multi-port\n"
            "      TLS-steering anomalies; keep Reality on a single port and populate the\n"
            "      other ports with real services (or close them).", reality_port_count);
        sug("reality-multiport", buf);
        any_sug = true;
    }

    if (any_ovpn_udp || openset.count(1194) || openset.count(1193)) {
        sug("openvpn",
            "OpenVPN on default port 1194: TSPU/GFW drop this on the first HARD_RESET.\n"
            "      Wrap in TLS (stunnel / Cloak) or migrate to VLESS+Reality on :443.");
        any_sug = true;
    }
    if (any_wg) {
        sug("wireguard",
            "WireGuard on UDP/51820 answers its handshake — the handshake is a fixed-offset\n"
            "      signature TSPU already has. Use amneziawg (obfuscated WG) or tunnel WG\n"
            "      inside a TCP-TLS wrapper if you need to survive active DPI.");
        any_sug = true;
    }
    if (openset.count(8388) || openset.count(8488)) {
        sug("shadowsocks",
            "Shadowsocks on its default port is trivially probed via AEAD-length oracle.\n"
            "      Wrap it with v2ray/xray stream-settings + TLS, or drop it for VLESS+Reality.");
        any_sug = true;
    }
    if (openset.count(3389)) {
        sug("rdp",
            "RDP/3389 is reachable from the Internet — not a VPN issue, but a critical\n"
            "      attack surface. Firewall it; expose only through a jump host or VPN.");
        any_sug = true;
    }

    if (any_impersonation) {
        std::string bdom;
        for (auto& pf: R.fps)
            if (pf.sni && pf.sni->cert_impersonation && !pf.sni->brand_claimed.empty()) {
                bdom = pf.sni->brand_claimed; break;
            }
        if (bdom.empty())
            for (auto& pf: R.fps)
                if (pf.https && pf.https->tls_ok && !pf.https->server_hdr.empty()) {
                    std::string sb = server_header_brand(pf.https->server_hdr);
                    if (!sb.empty()) { bdom = sb; break; }
                }
        std::string body =
            "Reality `dest=` points at '" + bdom + "', so the endpoint serves a cert (and/or\n"
            "      `Server:` banner) for that brand on an ASN that doesn't own it. This is the\n"
            "      cheapest tell in the book — DPI engines cross-reference cert subject + HTTP\n"
            "      Server-header + ASN ownership. Pick a `dest=` on the SAME ASN/CDN as your VPS\n"
            "      (e.g. a small regional site on the same hosting provider's netblock), or —\n"
            "      safer — move to a real domain you own with its own full LE chain. Never pick\n"
            "      amazon/apple/microsoft/google/cloudflare on a random VPS.";
        sug("cert-impersonation", body.c_str());
        any_sug = true;
    }
    if (cert_short_validity_ports > 0) {
        sug("cert-short-validity",
            "One of the certs has total validity < 14 days. Real CAs never issue that:\n"
            "      Let's Encrypt = 90d, commercial = 30d+. A sub-14d cert is a hand-rolled\n"
            "      short-lifetime self-signed or a test-CA issuance — classic Xray/Trojan\n"
            "      quickfire setup. Fix: switch to LE (certbot / lego / acme.sh) with auto-renew,\n"
            "      OR front the origin behind a CDN so visitors see the CDN's cert instead.");
        any_sug = true;
    }
    if (j3_canned_ports > 0 || j3_badver_ports > 0) {
        sug("canned-fallback",
            "At least one port returns a canned fallback (same byte-exact first line for\n"
            "      different probes) or a malformed HTTP version — classic Xray `fallback` /\n"
            "      Trojan default handler. Real nginx/Apache/Caddy vary their replies per\n"
            "      request (different URIs -> different statuses, different bodies). Fix:\n"
            "      put a real nginx in front with a proper error-page map, and make the Xray\n"
            "      `fallbacks` point at that nginx so non-handshake bytes get REAL HTTP.");
        any_sug = true;
    }
    if (https_bad_ver_ports > 0) {
        sug("http-version-anomaly",
            "Active HTTP-over-TLS probe got back an invalid HTTP version (HTTP/0.0 or\n"
            "      similar). No real web server emits that — it's generated by Xray/Trojan's\n"
            "      stream handler when it partially decodes a non-protocol request. Same fix as\n"
            "      above: wire the `fallback` block to a real nginx so it emits `HTTP/1.1 400`.");
        any_sug = true;
    }
    if (https_empty_ports > 0 && !any_reality) {
        sug("http-silent-origin",
            "Active HTTP-over-TLS probe completed the handshake but got zero response bytes\n"
            "      back to a plain `GET /`. A legitimate web origin always answers (200 / 301 /\n"
            "      404 / 502). Silence is the stream-layer-proxy signature (Xray/Trojan/SS-AEAD\n"
            "      that only speaks its own framing). Fix: add an HTTP `fallback` that proxies\n"
            "      to a real web root so `GET /` always returns something with a `Server:` header.");
        any_sug = true;
    }
    if (https_no_server_ports > 0 && !any_reality) {
        sug("http-missing-server-header",
            "The origin replies to HTTP but without a `Server:` header. nginx/Apache/Caddy/CDNs\n"
            "      set one unambiguously. Absence is a middleware / custom-handler tell — fix by\n"
            "      fronting the origin with a real nginx that sets `server_tokens on` (or even\n"
            "      forges a plausible `Server: cloudflare` / `Server: nginx/1.24.0`).");
        any_sug = true;
    }
    if (xui_cluster_seen) {
        sug("xui-panel",
            "The open-port profile matches the 3x-ui / x-ui / Marzban panel installer set\n"
            "      (2053/2083/2087/2096/8443/8880/6443/7443/9443). That exact cluster is the\n"
            "      single strongest fingerprint a TSPU-class DPI engine looks for. Fix: close\n"
            "      the unused panel ports (keep ONE listener on :443 on the real Reality inbound),\n"
            "      firewall the panel UI to admin source IPs only, and avoid the defaults.");
        any_sug = true;
    }

    for (auto& pf: R.fps)
        if (pf.tls && pf.tls->ok && pf.tls->version != "TLSv1.3") {
            char buf[256];
            snprintf(buf, sizeof(buf),
                "Upgrade TLS to 1.3 on :%d (current: %s). Modern clients expect TLS 1.3;\n"
                "      VLESS/Reality requires it. Bump the OpenSSL/nginx config.",
                pf.port, pf.tls->version.c_str());
            sug("tls-version", buf);
            any_sug = true;
        }
    if (cert_self_signed_ports > 0) {
        sug("tls-self-signed",
            "Self-signed TLS cert: browsers reject it instantly, and it is the classic\n"
            "      Shadowsocks/Trojan/test-setup signature. Issue a real cert (Let's\n"
            "      Encrypt on a real domain) or front the endpoint with a CDN.");
        any_sug = true;
    }

    if (has_note("single-443")) {
        sug("port-profile",
            "Only :443 is reachable. Not a red flag on its own — TSPU classifies by the\n"
            "      bytes on the wire, not by how many ports you open. But if you want to\n"
            "      look like a typical corporate web host, open :80 with a 301 HTTP→HTTPS\n"
            "      redirect, serve a real-looking page on `/` (not the default nginx page),\n"
            "      and optionally add a firewalled :22 or :25 so the host has 'context'.");
        any_sug = true;
    }
    if (has_note("ssh-22")) {
        sug("ssh-banner",
            "SSH/22 is open with a default banner. It doesn't tag you as a VPN, but it\n"
            "      does tell every ASN-sweep that you run a real server. Move SSH to a\n"
            "      high port (40000+) and firewall it to known admin source IPs.");
        any_sug = true;
    }
    if (cert_fresh_ports > 0 && sparse_vps_profile) {
        sug("cert-fresh",
            "Fresh cert (<14d) on a sparse-port hosting host is a classical 'new VLESS\n"
            "      instance' fingerprint. Fix: use a long-lived wildcard cert on a domain\n"
            "      you've owned >90d, or front the origin behind a CDN (Cloudflare free\n"
            "      tier) so visitors see the CDN's cert instead of yours.");
        any_sug = true;
    } else if (has_note("cert-fresh")) {
        sug("cert-fresh",
            "Fresh cert (<14d) is normal LE rotation on its own. Only becomes a signal\n"
            "      when combined with hosting-ASN + sparse port profile. No action needed\n"
            "      unless you're also on a single-purpose VPS profile.");
        any_sug = true;
    }
    if (has_note("asn-hosting") && !any_reality && !proxy_middleware_seen) {
        sug("asn-hosting",
            "Being on a hosting ASN is the norm for every public server — this alone is\n"
            "      NOT a VPN signal. TSPU does use ASN as a gate for deeper checks, but\n"
            "      what it then verifies is the TLS/HTTP behaviour, not the ASN itself.\n"
            "      If you want to escape the 'hosting ASN' category entirely, the only\n"
            "      clean move is a residential-ASN proxy in front (rare) or a CDN.");
        any_sug = true;
    }
    if (has_note("geo-vpn") || has_note("geo-proxy")) {
        sug("threat-intel",
            "One of the 9 GeoIP providers (3 EU / 3 RU / 3 global) tagged this IP as\n"
            "      VPN/proxy. Single-source tags are very noisy (false positives are common).\n"
            "      Fix only if it blocks you in practice: rotate to a fresh IP, or if IP\n"
            "      reputation really matters to your use-case, use an IP on a residential /\n"
            "      business ASN instead of hosting.");
        any_sug = true;
    }

    if (!any_sug)
        tee_printf("    (no actionable hardening — protocol posture looks clean)\n");

    tee_printf("\n  %sТСПУ / TSPU classification (emulated Russian DPI verdict):%s\n",
           col(C::BOLD), col(C::RST));
    {
        struct TspuRule { const char* name; bool hit; const char* why; };
        std::vector<TspuRule> rules;
        bool ovpn_hit = any_ovpn_udp || openset.count(1194);
        bool wg_hit   = any_wg;
        bool ike_hit  = false;
        bool l2tp_hit = false, hysteria_hit = false, amnezia_hit = false;
        for (auto& [p,u]: R.udp_probes) if ((p==500||p==4500) && u.responded) ike_hit = true;
        for (auto& [p,u]: R.udp_extra) {
            if (p==1701 && u.responded) l2tp_hit = true;
            if (p==36712 && u.responded) hysteria_hit = true;
            if ((p==55555 || p==51820) && u.responded) amnezia_hit = true;
        }
        rules.push_back({"OpenVPN wire signature",      ovpn_hit,     "UDP/1194 HARD_RESET_CLIENT reply OR TCP/1194 open"});
        rules.push_back({"WireGuard wire signature",    wg_hit,       "UDP/51820 MessageInitiation reply"});
        rules.push_back({"AmneziaWG obfuscation",       amnezia_hit,  "WireGuard with Sx=8 junk prefix accepted (obfuscation params detected)"});
        rules.push_back({"Hysteria2 default port",      hysteria_hit, "UDP/36712 replied to QUIC-initial"});
        rules.push_back({"L2TP SCCRQ reply",            l2tp_hit,     "UDP/1701 L2TP control-channel signature"});
        rules.push_back({"IKE responder",               ike_hit,      "UDP/500 or UDP/4500 IKEv2 SA_INIT reply (IPsec endpoint)"});
        rules.push_back({"SSTP VPN (TLS-wrapped)",      R.sstp && R.sstp->is_vpn_like, "HTTPS/443 SSTP_DUPLEX_POST / sra_{BA195980-...} replied"});
        bool shadowsocks_default = openset.count(8388) > 0 || openset.count(8488) > 0;
        rules.push_back({"Shadowsocks default port",    shadowsocks_default, "TCP/8388 or TCP/8488 open"});
        bool socks_open = openset.count(1080) > 0 || openset.count(1081) > 0;
        rules.push_back({"Open SOCKS5 proxy",           socks_open,   "TCP/1080 SOCKS5 greeting accepted"});
        bool tspu_redirect_a = false;
        for (auto& pf: R.fps) if (pf.fp.tspu_redirect) { tspu_redirect_a = true; break; }
        rules.push_back({"TSPU http redirect to warning", tspu_redirect_a,
                         "HTTP 302 Location: matches operator block/warning page"});
        rules.push_back({"BGP-blackhole (tspu type B)",    R.bgp_blackhole_likely,
                         "all ports TIMEOUT with zero RST - operator ip-list block"});

        bool reality_hit = any_reality;
        rules.push_back({"Reality/XTLS cert-steering",  reality_hit,  "Reality cert-steering pattern detected"});
        rules.push_back({"Cert impersonation",          any_impersonation, "Cert vouches for a famous brand on non-owning ASN"});
        bool panel_hit = xui_cluster_seen;
        rules.push_back({"3x-ui/x-ui/Marzban panel",    panel_hit,    "Panel-installer preset TLS-port cluster open"});
        bool canned_hit = (j3_canned_ports > 0 || j3_badver_ports > 0);
        rules.push_back({"Canned-fallback / HTTP/0.0",  canned_hit,   "J3 canned-response or invalid HTTP version"});
        bool cert_short = (cert_short_validity_ports > 0);
        rules.push_back({"Short-validity cert (<14d)",  cert_short,   "Cert total_validity < 14d (hand-rolled)"});
        bool proxy_leak_any = false;
        for (auto& pf: R.fps) if (pf.https && pf.https->has_proxy_leak) proxy_leak_any = true;
        rules.push_back({"HTTP proxy-chain leak (§10.2)", proxy_leak_any, "Via / Forwarded / X-Forwarded-For set by origin"});
        bool ct_absent = false;
        for (auto& pf: R.fps) if (pf.ct && pf.ct->queried && !pf.ct->found && pf.ct->err.empty()) ct_absent = true;
        rules.push_back({"CT-log absence",              ct_absent,    "Cert SHA-256 not found in crt.sh — never publicly logged"});
        bool geo_conflict = (R.snitch && R.snitch->ok && (R.snitch->too_low || R.snitch->too_high));
        rules.push_back({"SNITCH geo conflict (§10.1)", geo_conflict, "RTT doesn't match claimed GeoIP country"});
        rules.push_back({"Multi-source VPN/proxy tag",  (vpn_hits >= 2 || proxy_hits >= 2),
                         "≥2 GeoIP providers tag the IP as VPN/proxy"});
        rules.push_back({"Tor exit relay",              (tor_hits >= 1), "At least 1 GeoIP provider tags the IP as Tor exit"});
        bool tspu_hops_hit = (R.trace && R.trace->ok && R.trace->tspu_hops > 0);
        rules.push_back({"TSPU mgmt-subnet in traceroute", tspu_hops_hit,
                         "hop(s) in 10.X.Y.[131-235]/[241-245]/254 range - tspu site on path"});

        int A_hits = 0, B_hits = 0;
        const int A_end = 11; 
        for (size_t i = 0; i < rules.size(); ++i) {
            if (!rules[i].hit) continue;
            if ((int)i < A_end) ++A_hits; else ++B_hits;
        }

        const char* tier_col   = C::GRN;
        const char* tier_name  = "PASS / ALLOW";
        const char* tier_desc  = "no TSPU-level signatures matched — this host passes inspection";
        if (A_hits > 0) {
            tier_col  = C::RED;
            tier_name = "IMMEDIATE BLOCK";
            tier_desc = "a named VPN/proxy protocol signature matched — this host would be DROPPED on the first TSPU handshake inspection";
        } else if (B_hits >= 2) {
            tier_col  = C::RED;
            tier_name = "BLOCK (accumulative)";
            tier_desc = "≥2 B-tier anomalies matched — TSPU-class classifiers accumulate soft signals and this would cross the block threshold";
        } else if (B_hits == 1) {
            tier_col  = C::YEL;
            tier_name = "THROTTLE / QoS";
            tier_desc = "1 B-tier anomaly — TSPU would tag this host for further monitoring / rate-limiting but not instant block";
        }

        tee_printf("    %sVerdict:%s %s%s%s  —  %s\n",
               col(C::BOLD), col(C::RST),
               col(tier_col), tier_name, col(C::RST), tier_desc);
        tee_printf("    %sTSPU-tier hits:%s A=%d (protocol block) / B=%d (soft anomaly)\n",
               col(C::DIM), col(C::RST), A_hits, B_hits);
        if (A_hits + B_hits > 0) {
            tee_printf("    %sTriggered rules:%s\n", col(C::DIM), col(C::RST));
            for (size_t i = 0; i < rules.size(); ++i) {
                if (!rules[i].hit) continue;
                const char* tag = ((int)i < A_end) ? "A" : "B";
                const char* tc  = ((int)i < A_end) ? C::RED : C::YEL;
                tee_printf("      %s[%s]%s %-36s  %s\n",
                       col(tc), tag, col(C::RST),
                       rules[i].name, rules[i].why);
            }
        }
        tee_printf("    %sWhat the operator sees:%s\n", col(C::DIM), col(C::RST));
        if (A_hits > 0) {
            tee_printf("      The destination matches a protocol signature in the TSPU ruleset. SYN/\n"
                   "      handshake packets to this IP are dropped at the PE router level. End\n"
                   "      users get connection-reset or timeout on every attempt.\n");
        } else if (B_hits >= 2) {
            tee_printf("      The destination accumulates multiple B-tier anomalies. The classifier\n"
                   "      raises confidence above threshold; the IP gets added to the reputation\n"
                   "      list and future flows are dropped/throttled until the signature changes.\n");
        } else if (B_hits == 1) {
            tee_printf("      The destination is flagged but not blocked. Flows are logged, RTT +\n"
                   "      handshake patterns are sampled over time. If the anomaly persists or\n"
                   "      converges with other hosts in the same /24, the block threshold trips.\n");
        } else {
            tee_printf("      The destination looks like a normal TLS web origin. TSPU sampling at\n"
                   "      the TLS-handshake layer finds no named protocol match, no cert-steering,\n"
                   "      no static fallback page. Traffic passes without classifier intervention.\n");
        }
    }

    tee_printf("\n  %sThreat-model note:%s\n", col(C::BOLD), col(C::RST));
    tee_printf("    TSPU/GFW classify a destination by what the IP actually does on the wire —\n"
           "    TLS handshake bytes, cert-steering, active HTTP-over-TLS reply shape,\n"
           "    reactions to junk, default-port replies. IP 'reputation' (hosting ASN /\n"
           "    GeoIP VPN tag) is only a coarse pre-filter, so this tool treats it as\n"
           "    informational and focuses the score on the actual protocol signatures at\n"
           "    the endpoint. v2.4 strong signals are: cert impersonation (brand CN on\n"
           "    non-owning ASN), short-validity certs (<14d), canned-fallback pages,\n"
           "    HTTP-version anomalies, 3x-ui/x-ui/Marzban panel-port clusters, CT-log\n"
           "    absence on fresh certs, proxy-chain header leakage (Via/Forwarded/XFF),\n"
           "    SNITCH geo-latency inconsistency (§10.1), modern tunnels (AmneziaWG /\n"
           "    Hysteria2 / TUIC / L2TP / SSTP) — these are expensive-to-fake tells that\n"
           "    map directly to Xray / Reality / Trojan / modern obfuscated VPN stacks.\n"
           "    If every strong signal is 'none' and soft signals are quiet, the host is\n"
           "    essentially invisible to passive DPI regardless of what the ASN looks like.\n"
           "    Reference methodology: Russian OCR методика выявления VPN/Proxy (§5-10).\n");

    return R;
}