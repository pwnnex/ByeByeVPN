// SPDX-License-Identifier: GPL-3.0-or-later
// run_full_target: scan phases and verdict
// port results feed tls, sni, j3 and the final score
#include "orchestrator.h"
#include "verdict.h"
#include "target.h"
#include "preflight.h"
#include "../common/console.h"
#include "../common/config.h"
#include "../common/util.h"
#include "../common/tspu.h"
#include "../net/dns.h"
#include "../net/icmp.h"
#include "../scan/ports.h"
#include "../scan/tcp_scan.h"
#include "../scan/udp_probes.h"
#include "../scan/fingerprint.h"
#include "../scan/tls.h"
#include "../scan/https_probe.h"
#include "../scan/sni.h"
#include "../scan/brand.h"
#include "../scan/hostname_marks.h"
#include "../scan/j3.h"
#include "../scan/snitch.h"
#include "../scan/ct.h"
#include "../scan/utls.h"
#include "../scan/grpc.h"
#include "../scan/transport_probe.h"
#include "../scan/tcpfp.h"
#include "../scan/ja4.h"
#include "../scan/ja4s_db.h"
#include "../scan/amnezia_probe.h"
#include "../geoip/geoip.h"

#include "../net/tcp.h"

#include <algorithm>
#include <chrono>
#include <climits>
#include <cstdio>
#include <cstring>
#include <future>
#include <map>
#include <optional>
#include <set>
#include <utility>

using std::string;
using std::vector;
using std::set;

namespace {
std::optional<FullReport> g_last;
FullReport run_full_target_impl(const string& target);
}

FullReport run_full_target(const string& target) {
    FullReport r = run_full_target_impl(target);
    g_last = r;
    return r;
}

const FullReport* last_full_report() { return g_last ? &*g_last : nullptr; }

namespace {
FullReport run_full_target_impl(const string& target) {
    FullReport R; R.target = target;

    // 1) dns resolve
    section(1, 8, "DNS resolve");
    R.dns = resolve_host(target);
    if (!R.dns.err.empty()) {
        printf("  %sERR%s: %s\n", col(C::RED), col(C::RST), R.dns.err.c_str());
        return R;
    }
    printf("  %s%s%s  ->  ", col(C::WHT), target.c_str(), col(C::RST));
    for (auto& ip: R.dns.ips) printf("%s ", ip.c_str());
    printf(" [%s, %lldms]\n", R.dns.family.c_str(), R.dns.ms);
    if (R.dns.primary_ip != target) {
        printf("  %susing primary IP%s %s%s%s  for all probes%s\n",
               col(C::DIM), col(C::RST),
               col(C::BOLD), R.dns.primary_ip.c_str(), col(C::RST),
               col(C::RST));
    }

    // our own stack first; a tunnel on the path voids every probe
    R.preflight = preflight_decide(preflight_gather(R.dns.primary_ip, !g_no_geoip, g_expect_ip),
                                   g_override_preflight);
    R.preflight_ran = true;
    print_preflight(R.preflight);
    // probing through the tunnel would scan from its exit address
    if (R.preflight.blocked && !R.preflight.overridden) {
        printf("  scan stopped before any probe reached the target\n");
        R.completed = true;
        evaluate_report(R);
        print_verdict(R);
        return R;
    }

    // 2) geoip
    if (g_no_geoip) {
        section(2, 8, "GeoIP", "skipped (--no-geoip / --stealth)");
    } else {
    section(2, 8, "GeoIP", "5 HTTPS providers in parallel, reference only");
    auto fg1 = std::async(std::launch::async, geo_ipapi_is,  R.dns.primary_ip);
    auto fg2 = std::async(std::launch::async, geo_iplocate,  R.dns.primary_ip);
    auto fg3 = std::async(std::launch::async, geo_freeipapi, R.dns.primary_ip);
    auto fg4 = std::async(std::launch::async, geo_ipwho_is,  R.dns.primary_ip);
    auto fg5 = std::async(std::launch::async, geo_ipinfo_io, R.dns.primary_ip);
    R.geos.push_back(fg1.get()); R.geos.push_back(fg2.get()); R.geos.push_back(fg3.get());
    R.geos.push_back(fg4.get()); R.geos.push_back(fg5.get());
    for (auto& g: R.geos) print_geo(g);
    }

    // 3) tcp scan
    auto _ports = build_tcp_ports();
    const char* _mode_name =
        g_port_mode==PortMode::FULL  ? "FULL 1-65535" :
        g_port_mode==PortMode::FAST  ? "FAST (205 curated)" :
        g_port_mode==PortMode::RANGE ? "RANGE" : "LIST";
    section(3, 8, "TCP port scan", "mode " + tolower_s(_mode_name) + " \xc2\xb7 " + std::to_string(_ports.size()) +
            " ports \xc2\xb7 " + std::to_string(g_threads) + " threads \xc2\xb7 " + std::to_string(g_tcp_to) + " ms timeout");
    R.open_tcp = scan_tcp(R.dns.primary_ip, _ports, g_threads, g_tcp_to, &R.scan_stats);

    // bgp-blackhole heuristic (tspu type B): all-timeout with zero RST
    if (!R.scan_stats.skipped && R.scan_stats.scanned >= 1000 && R.open_tcp.empty()) {
        size_t tmo = R.scan_stats.timeouts;
        size_t rst = R.scan_stats.refused;
        if (rst == 0 && tmo >= R.scan_stats.scanned * 99 / 100) {
            R.tcp_timeout_pattern = true;
        }
    }
    // bogus-open detection: warp/cgnat/proxy ack every port with same latency
    if (R.open_tcp.size() > 60) {
        long long mn = LLONG_MAX, mx = 0;
        for (auto& o: R.open_tcp) { mn = std::min(mn, o.connect_ms); mx = std::max(mx, o.connect_ms); }
        if (mx - mn < 80) R.ack_all_heuristic = true;
    }
    // control: random dynamic-range ports nobody listens on
    if (!R.open_tcp.empty() && !R.scan_stats.skipped) {
        set<int> scanned(_ports.begin(), _ports.end());
        // --full leaves no unscanned port to draw
        for (int draw = 0; draw < 64 && R.ack_all_control_tried < 3; ++draw) {
            unsigned char rb[2]; csprng_bytes(rb, 2);
            const int port = 49152 + ((rb[0] << 8 | rb[1]) % 16384);
            if (scanned.count(port)) continue;
            scanned.insert(port);
            ++R.ack_all_control_tried;
            string err;
            SOCKET s = tcp_connect(R.dns.primary_ip, port, g_tcp_to, err);
            if (s != INVALID_SOCKET) { closesocket(s); ++R.ack_all_control_open; }
        }
    }
    if (ack_all_suspected(R)) {
        printf("  %s!! %d of %d random control ports accepted a connection. Something on the path "
               "(local proxy, WARP, CGNAT or the host itself) accepts every SYN; open ports below are not evidence.%s\n",
               col(C::RED), R.ack_all_control_open, R.ack_all_control_tried, col(C::RST));
    } else if (R.ack_all_heuristic) {
        printf("  %s%zu ports open with near-identical RTT; control ports refused, so the path is not ack-all%s\n",
               col(C::YEL), R.open_tcp.size(), col(C::RST));
    }

    // path quality on a known-open port before anything reads silence
    if (!R.open_tcp.empty()) {
        const int cp = R.open_tcp.front().port;
        vector<double> ok;
        const int attempts = 10;
        for (int i = 0; i < attempts; ++i) {
            auto t0 = std::chrono::steady_clock::now();
            string err;
            SOCKET s = tcp_connect(R.dns.primary_ip, cp, std::max(g_tcp_to, 1000), err);
            if (s == INVALID_SOCKET) continue;
            ok.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count());
            closesocket(s);
        }
        R.channel = assess_channel(cp, attempts, ok);
        printf("  path check :%d  %d/%d connects, loss %.0f%%, rtt median %.1f ms, stddev %.1f ms%s\n",
               cp, R.channel.ok, R.channel.attempts, R.channel.loss * 100, R.channel.rtt_median_ms,
               R.channel.rtt_stddev_ms,
               R.channel.unusable ? "  [unusable, no verdict]" : R.channel.degraded ? "  [lossy, silence is not evidence]" : "");
    }
    if (R.open_tcp.empty()) {
        printf("  %sno open TCP ports found%s\n", col(C::YEL), col(C::RST));
        if (R.tcp_timeout_pattern) {
            printf("  %s!! %zu/%zu ports TIMEOUT with 0 RST - no TCP response observed "
                   "(filtering, loss, routing or an offline host; cause unverified)%s\n",
                   col(C::RED), R.scan_stats.timeouts, R.scan_stats.scanned, col(C::RST));
        } else if (R.scan_stats.scanned >= 100) {
            printf("  %s  (breakdown: %zu timeout, %zu refused, %zu other)%s\n",
                   col(C::DIM), R.scan_stats.timeouts, R.scan_stats.refused,
                   R.scan_stats.other, col(C::RST));
        }
    } else {
        for (auto& o: R.open_tcp) {
            const char* hint = port_hint(o.port);
            printf("  %s:%-5d%s  %3lldms  %s%s%s",
                   col(C::GRN), o.port, col(C::RST),
                   o.connect_ms,
                   col(C::DIM), hint[0]?hint:"-", col(C::RST));
            if (!o.banner.empty()) {
                printf("  %sbanner:%s %s",
                       col(C::CYN), col(C::RST),
                       printable_prefix(o.banner, 60).c_str());
            }
            printf("\n");
        }
    }

    // 3b) tcp behavior fingerprint (v2.5.9)
    // probes the lowest open port for handshake-time distribution + SIO_TCP_INFO
    // peer window/mss + closed-port behavior. coarse os guess only, no admin
    // required, no raw socket, no extra fingerprint on the wire (just regular
    // SOCK_STREAM connects, same shape as scan_tcp itself).
    if (!R.open_tcp.empty()) {
        // pick a closed port for the closed-port-behavior probe. prefer one
        // whose scan classified as "refused" (RST), otherwise the highest-
        // numbered timeout port. -1 if scan was skipped or all open.
        int closed_hint = -1;
        // very simple selection: 65000 if not in open set, else 1.
        auto in_open = [&](int p){
            for (auto& o: R.open_tcp) if (o.port == p) return true;
            return false;
        };
        if (!in_open(65000)) closed_hint = 65000;
        else if (!in_open(1)) closed_hint = 1;
        TcpFp fp = tcp_fingerprint(R.dns.primary_ip, R.open_tcp.front().port, closed_hint);
        R.tcp_fp = fp;
        if (fp.ok) {
            printf("\n%sTCP stack fingerprint%s  (handshake distribution + SIO_TCP_INFO)\n",
                   col(C::BOLD), col(C::RST));
            printf("  handshake median=%.1fms min=%.1fms max=%.1fms stddev=%.1fms (%d samples%s)\n",
                   fp.handshake_median_ms, fp.handshake_min_ms, fp.handshake_max_ms,
                   fp.handshake_stddev_ms, fp.samples_taken, fp.bimodal ? ", bimodal" : "");
            if (fp.tcp_info_ok) {
                printf("  peer recv-window: %d  MSS: %d\n", fp.peer_window, fp.peer_mss);
            } else {
                printf("  %sSIO_TCP_INFO: not available on this OS build%s\n",
                       col(C::DIM), col(C::RST));
            }
            if (closed_hint > 0) {
                printf("  closed-port :%d behavior: %s%s%s",
                       closed_hint, col(C::CYN), fp.closed_port_behavior.c_str(), col(C::RST));
                if (fp.closed_port_rtt_ms >= 0) printf(" (RTT %dms)", fp.closed_port_rtt_ms);
                printf("\n");
            }
            printf("  %sreference only; no OS or stack is inferred%s\n", col(C::DIM), col(C::RST));
        } else if (!fp.err.empty()) {
            printf("\n%sTCP stack fingerprint%s: %s\n",
                   col(C::BOLD), col(C::RST), fp.err.c_str());
        }
    }

    // 4) udp probes
    // v2.6.0 scope: only the modern signature-less tunnel set is probed.
    // WireGuard / amneziawg / hysteria2. each result lands in R.udp_probes
    // tagged by (port, kind) so the verdict engine and the amneziawg
    // deep-probe can tell vanilla-wg from amneziawg-junk-prefix.
    section(4, 8, "UDP probes", "WireGuard \xc2\xb7 AmneziaWG \xc2\xb7 Hysteria2 / QUIC");
    // these probes have no valid mac1; a timeout cannot establish the protocol.
    printf("  %snote: these WG/AWG probes lack a valid mac1. No reply cannot distinguish\n"
           "  a working listener from filtering or an unavailable service. A UDP reply\n"
           "  alone also does not establish WG/AWG.%s\n", col(C::DIM), col(C::RST));
    auto udp_show = [&](int port, const char* kind, const char* name, const UdpResult& u){
        const char* c = u.responded ? col(C::GRN) : col(C::DIM);
        printf("  %sUDP:%-5d%s  %-22s  ", c, port, col(C::RST), name);
        if (u.responded) printf("%sRESP %dB%s  %s", col(C::GRN), u.bytes, col(C::RST), u.reply_hex.c_str());
        else             printf("%sno answer (%s)%s", col(C::DIM), u.err.empty() ? "no reply" : u.err.c_str(), col(C::RST));
        printf("\n");
        if (u.responded && std::strcmp(kind, "hysteria2") == 0) {
            string qs = quic_reply_summary(u);
            if (!qs.empty())
                printf("             %s-> %s%s\n", col(C::CYN), qs.c_str(), col(C::RST));
        }
        R.udp_probes.push_back({port, kind, u});
    };
    // a reply gets two more probes, silence gets none
    auto wg_series = [&](int port, const char* kind, const char* name, UdpResult (*probe)(const string&, int)) {
        UdpResult first = probe(R.dns.primary_ip, port);
        udp_show(port, kind, name, first);
        if (!first.responded) return;
        for (int i = 0; i < 2; ++i) {
            stealth_sleep_ms(150, 900);
            udp_show(port, kind, name, probe(R.dns.primary_ip, port));
        }
    };
    // vanilla WireGuard on the default port.
    wg_series(51820, "wg",      "WireGuard handshake", wireguard_probe);
    // amneziawg (sx=8 junk-prefix) on the default wg port and a common alt.
    wg_series(51820, "amnezia", "AmneziaWG Sx=8",      amneziawg_probe);
    wg_series(55555, "amnezia", "AmneziaWG Sx=8",      amneziawg_probe);
    // owner self-check: only the holder of a peer key can get an answer
    R.wg_self.requested = !g_wg_pubkey.empty() || !g_wg_key.empty();
    if (R.wg_self.requested) {
        WgKeys keys;
        if (!wg_load_keys(g_wg_pubkey, g_wg_key, g_wg_psk, keys, R.wg_self.error)) {
            printf("  %sWireGuard self-check not run: %s%s\n", col(C::YEL), R.wg_self.error.c_str(), col(C::RST));
        } else {
            R.wg_self.ran = true;
            R.wg_self.port = g_wg_port;
            printf("  %sWireGuard self-check: keys loaded, not shown. The node moves this peer's\n"
                   "  endpoint to this machine until its own client sends again.%s\n", col(C::DIM), col(C::RST));
            std::vector<Outcome> obs;
            while (!observations_settled(obs)) {
                if (!obs.empty()) wg_keyed_gap();
                WgReply rep = WgReply::Unrelated;
                UdpResult u = wireguard_keyed_probe(R.dns.primary_ip, g_wg_port, keys, rep);
                UdpProbeRec rec{g_wg_port, "wg-keyed", u};
                rec.outcome = wg_keyed_outcome(u, rep);
                rec.detail = !u.responded ? "no answer (" + (u.err.empty() ? string("no reply") : u.err) + ")"
                           : u.echoed     ? string("reply echoes the probe")
                                          : string(wg_reply_name(rep));
                printf("  %sUDP:%-5d%s  %-22s  %s\n", u.responded ? col(C::GRN) : col(C::DIM), g_wg_port,
                       col(C::RST), "WireGuard keyed", rec.detail.c_str());
                obs.push_back(rec.outcome);
                R.udp_probes.push_back(std::move(rec));
            }
            keys.wipe();
        }
    }
    // hysteria2 (real protected quic v1 Initial). probe a curated set of
    // community-common hysteria2/quic ports plus any open tcp port >= 443 (a
    // hysteria2 listener usually shares its number with a tls masquerade on
    // the same port). deduped via the set; capped so a busy host can't blow up
    // the udp phase. the first port that answers is remembered for the vn
    // follow-up.
    // presets first; a sorted set used to cut 36712 behind open ports
    vector<int> hy_ports = {443, 8443, 2096, 36712, 5667, 34567, 20000};
    for (auto& o : R.open_tcp)
        if (o.port >= 443 && std::find(hy_ports.begin(), hy_ports.end(), o.port) == hy_ports.end())
            hy_ports.push_back(o.port);
    int hy_live_port = 0, hy_done = 0;
    vector<int> hy_silent;
    for (int hp : hy_ports) {
        if (hy_done++ >= 12) { R.udp_not_probed.push_back(hp); continue; }
        UdpResult u = hysteria2_probe(R.dns.primary_ip, hp);
        R.udp_probes.push_back({hp, "hysteria2", u});
        if (u.responded) {
            printf("  %sUDP:%-5d%s  %-22s  %sRESP %dB%s  %s\n",
                   col(C::GRN), hp, col(C::RST), "Hysteria2 QUIC",
                   col(C::GRN), u.bytes, col(C::RST), u.reply_hex.c_str());
            string qs = quic_reply_summary(u);
            if (!qs.empty())
                printf("             %s-> %s%s\n", col(C::CYN), qs.c_str(), col(C::RST));
            // vn only where quic really answered, stand U
            if (!hy_live_port && quic_response_valid(u)) hy_live_port = hp;
        } else {
            hy_silent.push_back(hp);
        }
    }
    // collapse the (usually all) silent ports into one line instead of a wall.
    if (!hy_silent.empty()) {
        string ports;
        for (size_t i = 0; i < hy_silent.size(); ++i) {
            if (i) ports += ",";
            ports += std::to_string(hy_silent[i]);
        }
        printf("  %sUDP Hysteria2/QUIC%s   %zu port(s) silent (%s)\n",
               col(C::DIM), col(C::RST), hy_silent.size(), ports.c_str());
    }
    if (!R.udp_not_probed.empty())
        printf("  %sUDP Hysteria2/QUIC%s   %zu port(s) not probed, cap of 12 reached\n",
               col(C::YEL), col(C::RST), R.udp_not_probed.size());
    // if a quic listener answered, fire one version-negotiation probe to the
    // live port to recover its supported-version list - a quic-stack
    // fingerprint. only sent when there's actually a quic endpoint, so dead
    // hosts cost no extra datagram. skipped under --passive.
    if (hy_live_port && !g_passive) {
        UdpResult vn = hysteria2_vn_probe(R.dns.primary_ip, hy_live_port);
        string qs = quic_reply_summary(vn);
        printf("  %sUDP:%-5d%s  %-22s  ",
               vn.responded ? col(C::GRN) : col(C::DIM),
               hy_live_port, col(C::RST), "QUIC version-negotiation");
        if (vn.responded)
            printf("%sRESP %dB%s  %s", col(C::GRN), vn.bytes, col(C::RST),
                   qs.empty() ? vn.reply_hex.c_str() : qs.c_str());
        else
            printf("%sno VN answer (%s)%s", col(C::DIM),
                   vn.err.empty() ? "filtered" : vn.err.c_str(), col(C::RST));
        printf("\n");
    }

    // 4b) amneziawg s1 junk-prefix deep-probe
    // legacy udp response-size experiment, not a protocol/s1 detector.
    // modern awg needs authenticated packets. real traffic entropy/sequence
    // analysis is available through the separate awg-entropy command.
    // skipped under --passive: a 12-datagram sweep is one of the loudest
    // scanner patterns we emit.
    if (!g_passive) {
        AmneziaSweep sw = amnezia_deep_probe(R.dns.primary_ip, 51820);
        R.amnezia_sweep = sw;
        printf("  %sUDP prefix experiment :51820 (AWG/S1 unconfirmed)%s  ", col(C::BOLD), col(C::RST));
        for (auto& [s1, resp] : sw.sweep) {
            printf("%s%d%s%s ", resp ? col(C::GRN) : col(C::DIM),
                   s1, resp ? "*" : "", col(C::RST));
        }
        printf("\n  %s=>%s %s%s%s\n", col(C::BOLD), col(C::RST),
               (sw.detected_s1 >= 0 && !sw.vanilla_wg_responds) ? col(C::RED) :
               sw.any_responded ? col(C::YEL) : col(C::DIM),
               sw.summary.c_str(), col(C::RST));
    }

    // 5) fingerprint per open tcp port
    section(5, 8, "Service fingerprints", "per open port");
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
            printf("  %s:%-5d%s  %s%-16s%s  %s",
                   col(C::CYN), o.port, col(C::RST),
                   col(C::BOLD), f.service.c_str(), col(C::RST),
                   f.details.c_str());
            if (f.is_vpn_like) printf("  %s[vpn-like]%s", col(C::YEL), col(C::RST));
            printf("\n");
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
                std::snprintf(agebuf, sizeof(agebuf), "age=%dd left=%dd",
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
                            (tp.is_letsencrypt ? " [issuer-name: Let's Encrypt]" : "");
                line(f);
                pf.tls = tp;
                // sni consistency loop = 10 sequential tls handshakes with
                // rotating snis. distinctive scanner pattern; under
                // --passive we skip the rotation and use a stub default
                // (sc.base_sha stays empty, the explainer chain is skipped).
                SniConsistency sc;
                if (!g_passive) {
                    sc = sni_consistency(R.dns.primary_ip, o.port, R.dns.host);
                    pf.sni = sc;
                } else {
                    sc.base_sha = tp.cert_sha256;
                    pf.sni = sc;
                }
                if (g_passive) {
                    printf("        %sSNI behaviour: skipped (--passive)%s\n",
                           col(C::DIM), col(C::RST));
                } else {
                    printf("        SNI: %s (%d comparable, %d failed); software unconfirmed\n",
                           sc.pattern.c_str(), sc.compared, sc.failed);
                }
                if (!sc.base_sha.empty()) {
                    printf("        cert-sha256: %s%.16s...%s  issuer: %s\n",
                           col(C::DIM), sc.base_sha.c_str(), col(C::RST),
                           printable_prefix(tp.cert_issuer, 60).c_str());
                    if (g_no_ct) {
                        printf("        %sCT-log (crt.sh): SKIPPED (--no-ct / --stealth)%s\n",
                               col(C::DIM), col(C::RST));
                    } else {
                    CtCheck ct = ct_check(sc.base_sha);
                    pf.ct = ct;
                    if (ct.queried && !ct.err.empty()) {
                        printf("        %sCT-log (crt.sh): query failed: %s%s\n",
                               col(C::DIM), ct.err.c_str(), col(C::RST));
                    } else if (ct.queried && ct.found) {
                        printf("        %sCT-log (crt.sh): %d matching search record(s); trust not verified%s\n",
                               col(C::GRN), ct.log_entries, col(C::RST));
                    } else if (ct.lookup_complete && !ct.found) {
                        printf("        %sCT-log (crt.sh): no matching records; absence from all logs is not established%s\n",
                               col(C::RED), col(C::RST));
                    }
                    }
                }
                HttpsProbe hp = https_probe(R.dns.primary_ip, o.port, R.dns.host);
                pf.https = hp;
                if (hp.tls_ok) {
                    if (hp.responded) {
                        printf("        %sHTTP-over-TLS:%s %s%s%s",
                               col(C::DIM), col(C::RST),
                               hp.version_anomaly ? col(C::RED) :
                                 (hp.status_code>=200 && hp.status_code<600 ? col(C::GRN) : col(C::YEL)),
                               printable_prefix(hp.first_line, 70).c_str(),
                               col(C::RST));
                        if (!hp.server_hdr.empty())
                            printf("   Server: %s%s%s",
                                   col(C::CYN),
                                   printable_prefix(hp.server_hdr, 40).c_str(),
                                   col(C::RST));
                        else if (hp.status_code > 0)
                            printf("   %s(no Server header)%s", col(C::YEL), col(C::RST));
                        if (hp.version_anomaly)
                            printf("   %s[!version anomaly]%s", col(C::RED), col(C::RST));
                        printf("\n");
                    } else {
                        printf("        %sHTTP-over-TLS: no response bytes observed; service unconfirmed%s\n",
                               col(C::RED), col(C::RST));
                    }
                    if (hp.has_proxy_leak) {
                        printf("        %s[forwarding headers]%s", col(C::DIM), col(C::RST));
                        if (!hp.via_hdr.empty())        printf(" Via='%s'",       printable_prefix(hp.via_hdr, 36).c_str());
                        if (!hp.forwarded_hdr.empty())  printf(" Forwarded='%s'", printable_prefix(hp.forwarded_hdr, 36).c_str());
                        if (!hp.xff_hdr.empty())        printf(" XFF='%s'",       printable_prefix(hp.xff_hdr, 36).c_str());
                        if (!hp.xreal_ip_hdr.empty())   printf(" X-Real-IP='%s'", printable_prefix(hp.xreal_ip_hdr, 24).c_str());
                        printf("\n");
                    }
                    if (hp.has_cdn_hdr) {
                        string cdn;
                        if      (!hp.cf_ray_hdr.empty())   cdn = "Cloudflare (CF-Ray=" + printable_prefix(hp.cf_ray_hdr, 22) + ")";
                        else if (!hp.x_amz_cf_id.empty())  cdn = "CloudFront (X-Amz-Cf-Id=" + printable_prefix(hp.x_amz_cf_id, 22) + ", pop=" + hp.x_amz_cf_pop + ")";
                        else if (!hp.x_azure_ref.empty())  cdn = "Azure Front Door (X-Azure-Ref=" + printable_prefix(hp.x_azure_ref, 24) + ")";
                        else if (!hp.x_served_by.empty())  cdn = "Fastly (X-Served-By=" + printable_prefix(hp.x_served_by, 24) + ")";
                        if (!cdn.empty())
                            printf("        %s[cdn]%s  %s\n", col(C::CYN), col(C::RST), cdn.c_str());
                    }
                    if (!hp.alt_svc.empty())
                        printf("        %s[alt-svc]%s  %s  (QUIC endpoint advertisement)\n",
                               col(C::DIM), col(C::RST),
                               printable_prefix(hp.alt_svc, 80).c_str());
                }
                // compare raw chrome serverhello with the openssl handshake
                // skip the extra probes under --passive
                if (!g_passive) {
                    UtlsDualProbe ud = utls_dual_probe(R.dns.primary_ip, o.port, R.dns.host);
                    pf.utls = ud;
                    auto fmt_one = [&](const UtlsProbeResult& u) {
                        printf("        %sJA4 (%s):%s ja4=%s ja4s=%s%s%s\n",
                               col(C::DIM), u.flavor.c_str(), col(C::RST),
                               u.ja4.empty()  ? "(parse-fail)" : u.ja4.c_str(),
                               u.ja4s.empty() ? "(no SH)"      : u.ja4s.c_str(),
                               (u.handshake_completed || u.server_hello_received) ? "" : " [hs-fail: ",
                               (u.handshake_completed || u.server_hello_received) ? "" : (u.err + "]").c_str());
                    };
                    fmt_one(ud.openssl);
                    fmt_one(ud.chrome);
                    const char* col_v;
                    if (ud.cert_differs || ud.only_chrome_ok || ud.only_openssl_ok)
                        col_v = col(C::CYN);
                    else if (ud.ja4s_differs)
                        col_v = col(C::YEL);
                    else
                        col_v = col(C::GRN);
                    printf("        %sutls dual-probe:%s %s%s%s\n",
                           col(C::BOLD), col(C::RST), col_v, ud.verdict.c_str(), col(C::RST));
                    // classify the openssl-flavor ja4s against the
                    // backend-stack table. names the tls terminator when
                    // the ext-hash is known, otherwise a structural family.
                    {
                        const string& js = !ud.openssl.ja4s.empty()
                                             ? ud.openssl.ja4s : ud.chrome.ja4s;
                        if (!js.empty()) {
                            Ja4sInfo ji = ja4s_classify(js);
                            const char* jc = (ji.confidence == "exact")
                                               ? col(C::CYN) : col(C::DIM);
                            printf("        %sJA4S stack:%s %s%s%s (%s) %s\n",
                                   col(C::DIM), col(C::RST),
                                   jc, ji.family.c_str(), col(C::RST),
                                   ji.confidence.c_str(), ji.note.c_str());
                        }
                    }
                }

                // http/2 + grpc transport probe (one extra tls handshake on
                // the tls port; skipped under --passive). detects h2-only
                // origins and how they react to a grpc-shaped http/2 request.
                if (!g_passive) {
                    GrpcProbe gp = grpc_probe(R.dns.primary_ip, o.port, R.dns.host);
                    pf.grpc = gp;
                    if (gp.tls_ok) {
                        const char* gc = (gp.stream_reset || (gp.alpn_h2 && !gp.h2_frames))
                                           ? col(C::YEL)
                                           : gp.alpn_h2 ? col(C::CYN) : col(C::DIM);
                        printf("        %sgRPC/h2 probe:%s %s%s%s\n",
                               col(C::DIM), col(C::RST), gc, gp.note.c_str(), col(C::RST));
                    }
                }

                // vless/vmess-websocket transport probe (up to six tls
                // handshakes - one per guessed path, stopping at the first 101;
                // skipped under --passive, jittered under --stealth).
                if (!g_passive) {
                    WsProbe wp = ws_probe(R.dns.primary_ip, o.port, R.dns.host);
                    pf.websocket = wp;
                    if (wp.ws_upgrade) {
                        printf("        %sWebSocket:%s %svalidated upgrade on '%s'; application protocol unconfirmed%s\n",
                               col(C::DIM), col(C::RST), col(C::YEL),
                               wp.path_hit.c_str(), col(C::RST));
                    }
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
            pf.connect = pp;
            if (pp.connect_accepted) printf("        CONNECT: accepted; relay access untested\n");
        }
        if (o.port==1080||o.port==1081||o.port==1082||o.port==9050||
            o.port==10808||o.port==10810||o.port==7890||o.port==7891) {
            // up to three greetings, two must agree
            vector<Outcome> seen;
            while (!observations_settled(seen)) {
                FpResult f = fp_socks5(R.dns.primary_ip, o.port);
                seen.push_back(f.outcome);
                pf.socks5_obs.push_back(f);
                if (seen.size() == 1) line(f);
            }
        }
        if (o.port==8388||o.port==8488||o.port==8787||o.port==8989) {
            line(fp_shadowsocks(R.dns.primary_ip, o.port));
        }
        // one tls handshake on a silent unlisted port, few ports only
        if (!printed && o.banner.empty() && R.open_tcp.size() < 20 && !ack_all_suspected(R)) {
            TlsProbe tp = tls_probe(R.dns.primary_ip, o.port, R.dns.host);
            if (tp.ok) {
                FpResult f; f.service = "TLS";
                f.details = tp.version + " / ALPN=" + (tp.alpn.empty() ? "-" : tp.alpn) +
                            " / cert CN=" + (tp.subject_cn.empty() ? "(none)" : tp.subject_cn) +
                            "  (single handshake, no further probes on this port)";
                line(f);
                pf.tls = tp;
            }
        }
        if (!printed) {
            FpResult g; g.service = "unknown";
            if (!o.banner.empty()) g.details = "banner: " + printable_prefix(o.banner, 70);
            else                   g.details = "open, silent on connect; no protocol probe for this port number";
            if (!o.banner.empty() || R.open_tcp.size() < 20) line(g);
            else pf.fp = g;
        }
        R.fps.push_back(std::move(pf));
    }

    // keep the origin of every name, including cn values on other ports.
    {
        vector<ObservedHostname> names = {{R.dns.host, "target"}};
        for (const auto& pf : R.fps) {
            if (!pf.tls || !pf.tls->ok) continue;
            const string port = ":" + std::to_string(pf.port);
            names.push_back({pf.tls->subject_cn, "cert_cn" + port});
            for (const auto& s : pf.tls->san) names.push_back({s, "cert_san" + port});
        }
        R.hostnames = analyze_host_names(names);
        if (R.hostnames.any()) {
            printf("\n%sHostname markers%s (names only; no protocol confirmation)\n", col(C::BOLD), col(C::RST));
            for (const auto& m : R.hostnames.marks) {
                string sources;
                for (const auto& s : m.sources) { if (!sources.empty()) sources += ", "; sources += s; }
                printf("  [%-8s] %s in %s [%s]: %s\n", hostname_tier_name(m.tier),
                       m.token.c_str(), m.host.c_str(), sources.c_str(), m.why.c_str());
            }
        }
    }

    // 6) j3 active probing per tls-like port
    // skipped under --passive: even shuffled, this is 8 distinct probes per
    // tls-like port and the loudest signal we emit. when --j3-subset=N is
    // given, j3_probes() itself trims down to N random probes.
    section(6, 8, "J3 junk probes", g_passive ? "skipped (--passive)" : "how each TLS port handles malformed first flights");
    if (!g_passive)
    for (auto& o: R.open_tcp) {
        if (!is_tls_port(o.port) && o.port != 80 && o.port != 8080) continue;
        printf("  %s-> port :%d%s\n", col(C::BOLD), o.port, col(C::RST));
        auto probes = j3_probes(R.dns.primary_ip, o.port);
        for (auto& p: probes) {
            const char* c = p.responded ? col(C::YEL) : col(C::DIM);
            printf("     %s%-20s%s  %-28s  ", c, read_end_name(p.end), col(C::RST), p.name.c_str());
            if (p.responded)
                printf("%dB  %s  [%s]", p.bytes,
                       printable_prefix(p.first_line, 50).c_str(),
                       p.hex_head.c_str());
            printf("\n");
        }
        J3Analysis ja = j3_analyze(probes);
        // control: a well-formed exchange on this same port worked
        bool control = false;
        for (auto& pf: R.fps) if (pf.port == o.port) {
            control = (pf.tls && pf.tls->ok) || (pf.https && pf.https->http_valid) ||
                      (pf.fp.service == "HTTP" && !pf.fp.silent);
            pf.j3  = std::move(probes);
            pf.j3a = ja;
            break;
        }
        printf("     %s-> %d replied, %d closed, %d reset, %d held open, %d no connect%s\n",
               col(C::MAG), ja.resp, ja.closed, ja.reset, ja.held, ja.no_connect, col(C::RST));
        if (!control)
            printf("     %s   control failed: no well-formed exchange worked on this port; the counts say nothing about the target%s\n",
                   col(C::YEL), col(C::RST));
        else if (R.channel.degraded)
            printf("     %s   lossy path: silence and held connections are not evidence%s\n", col(C::YEL), col(C::RST));
        else
            printf("     %s   reference only: many ordinary servers ignore malformed input%s\n", col(C::DIM), col(C::RST));

        if (ja.canned_identical >= 2)
            printf("     uniform reply: %d probes shared a first line and captured byte count; protocol unconfirmed\n", ja.canned_identical);
        if (ja.http_bad_version > 0)
            printf("     HTTP start-line anomalies: %d; not a software signature\n", ja.http_bad_version);
        if (ja.raw_non_http > 0)
            printf("     non-HTTP replies: %d; service framing unverified\n", ja.raw_non_http);
    }

    // 7) snitch + traceroute + sstp
    section(7, 8, "Latency, traceroute, SSTP", "SNITCH RTT vs GeoIP, ICMP hops, SSTP setup");

    set<int> openset_early;
    for (auto& o: R.open_tcp) openset_early.insert(o.port);

    int rtt_port = 443;
    if (!openset_early.count(443) && !R.open_tcp.empty()) rtt_port = R.open_tcp.front().port;

    string consensus_cc;
    {
        std::map<string,int> votes;
        for (auto& g: R.geos) if (!g.country_code.empty()) ++votes[g.country_code];
        int best = 0;
        for (auto& [cc, v]: votes)
            if (v > best) { best = v; consensus_cc = cc; }
    }
    SnitchResult sn = snitch_check(R.dns.primary_ip, rtt_port, consensus_cc);
    R.snitch = sn;
    if (!sn.ok) {
        printf("  %sSNITCH: %s%s\n", col(C::DIM), sn.summary.c_str(), col(C::RST));
    } else {
        // reference output, never red
        const char* sc_col = (sn.too_low || sn.too_high || sn.high_jitter || sn.anchor_ratio_off) ? col(C::YEL) : col(C::GRN);
        printf("  %sSNITCH RTT:%s  median=%.1fms  min=%.1fms  max=%.1fms  stddev=%.1fms  (%d samples)\n",
               col(C::BOLD), col(C::RST),
               sn.median_ms, sn.min_ms, sn.max_ms, sn.stddev_ms, sn.samples);
        printf("  %sAnchors:%s   Cloudflare=%s  Google=%s  Yandex=%s\n",
               col(C::DIM), col(C::RST),
               sn.cf_median_ms>=0     ? (std::to_string((int)sn.cf_median_ms)+"ms").c_str()     : "n/a",
               sn.google_median_ms>=0 ? (std::to_string((int)sn.google_median_ms)+"ms").c_str() : "n/a",
               sn.yandex_median_ms>=0 ? (std::to_string((int)sn.yandex_median_ms)+"ms").c_str() : "n/a");
        if (sn.expected_min_ms > 0)
            printf("  %sExpected:%s  country=%s  physical_min=%.0fms  (from %s observer)\n",
                   col(C::DIM), col(C::RST),
                   sn.country_code.c_str(), sn.expected_min_ms,
                   consensus_cc.empty() ? "unknown" : consensus_cc.c_str());
        printf("  %s=>%s %s%s%s\n",
               col(C::BOLD), col(C::RST), sc_col, sn.summary.c_str(), col(C::RST));
        if (R.preflight.facts.target_iface_is_tunnel || !R.preflight.facts.tunnels_up.empty())
            printf("  %sanchor RTTs may run through a local tunnel; see preflight%s\n", col(C::YEL), col(C::RST));
    }

    TraceResult tr = trace_hops(R.dns.primary_ip, 18);
    R.trace = tr;
    if (tr.ok) {
        printf("  %sTraceroute:%s %d hops, reached=%s, max_rtt_jump=%dms, long_hops(>150ms)=%d\n",
               col(C::BOLD), col(C::RST),
               tr.hop_count, tr.reached_target ? "yes" : "no",
               tr.max_rtt_jump_ms, tr.long_hops);
        int shown = 0;
        for (auto& h: tr.hops) {
            if (shown >= 12) { printf("    ...\n"); break; }
            if (h.rtt_ms < 0)
                printf("    %2d  %s*%s\n", h.ttl, col(C::DIM), col(C::RST));
            else
                printf("    %2d  %-16s  %dms\n", h.ttl, h.addr.c_str(), h.rtt_ms);
            ++shown;
        }
    } else {
        printf("  %sTraceroute:%s no hops returned (ICMP filtered / no admin on strict hosts)\n",
               col(C::DIM), col(C::RST));
    }

    if (openset_early.count(443)) {
        // real clients send the host name as sni, never an ip
        const string sni = is_ip_literal(R.dns.host) ? "" : R.dns.host;
        vector<Outcome> seen;
        while (!observations_settled(seen)) {
            FpResult sstp = sstp_probe(R.dns.primary_ip, 443, sni);
            seen.push_back(sstp.outcome);
            R.sstp_obs.push_back(sstp);
            R.sstp = sstp;
        }
        const Outcome o = combine_observations(seen);
        const FpResult& last = R.sstp_obs.back();
        const char* c = o == Outcome::Positive ? col(C::RED) : col(C::DIM);
        printf("  %sSSTP/443:%s %s%s%s  %s  (%zu probes, %s)\n",
               col(C::BOLD), col(C::RST),
               c, last.service.c_str(), col(C::RST),
               printable_prefix(last.details, 80).c_str(), seen.size(), outcome_name(o));
    }

    {
        Ja3Info j = our_openssl_ja3_signature();
        printf("  %sOur ClientHello JA3:%s %s%s%s  (OpenSSL 3.x default; real browsers use uTLS-Chrome)\n",
               col(C::BOLD), col(C::RST),
               col(C::DIM), j.ja3_hash.c_str(), col(C::RST));
    }

    {
        // disclose the ja4h of our own http-over-tls probe request - same
        // transparency spirit as the ja3 line above. these are the bytes we
        // put on the wire (get / with host, accept: */*, connection: close),
        // no cookies / referer / accept-language.
        Ja4hInput hin;
        hin.method = "GET";
        hin.http_version = "1.1";
        hin.has_cookie = false;
        hin.has_referer = false;
        hin.accept_language = "";
        hin.header_names_in_order = {"host", "accept", "connection"};
        string h4 = ja4h(hin);
        printf("  %sOur HTTP request JA4H:%s %s%s%s  (minimal GET: Host / Accept / Connection)\n",
               col(C::BOLD), col(C::RST), col(C::DIM), h4.c_str(), col(C::RST));
    }

    R.completed = true;
    evaluate_report(R);
    print_verdict(R);
    return R;
}
} // namespace

