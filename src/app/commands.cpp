// SPDX-License-Identifier: GPL-3.0-or-later
// command dispatch shared by the command line and the interactive panel,
// plus the --save file around one run.
#include "../common/winhdr.h"
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
#include "../scan/grpc.h"
#include "../scan/dpi_probe.h"
#include "../scan/volume_probe.h"
#include "../common/json.h"
#include "../scan/ech.h"
#include "../scan/hostname_marks.h"
#include "../scan/snitch.h"
#include "../geoip/geoip.h"
#include "../local/local.h"
#include "cli.h"
#include "orchestrator.h"
#include "target.h"
#include "verdict.h"
#include "preflight.h"
#include "json_report.h"
#include "sweep.h"

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

void save_begin(const vector<string>& pos) {
    if (g_save_requested && !g_save_fp) {
        string path = g_save_path;
        if (path.empty()) {
            string target;
            if (!pos.empty()) {
                static const set<string> cmds = {
                    "scan","full","ports","udp","tls","j3","geoip",
                    "snitch","trace","traceroute","local","me","self","help",
                    "audit-config","audit","sweep","grpc","dpi","ech","awg-entropy",
                    "names","name"
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
            std::fprintf(g_save_fp, "**Scanner version:** %s  \n\n", SCANNER_VERSION);
            std::fprintf(g_save_fp, "```\n");
        }
    }
}

void save_end() {
    if (!g_save_fp) return;
    std::fprintf(g_save_fp, "```\n");
    std::fclose(g_save_fp);
    g_save_fp = nullptr;
    std::fprintf(stderr, "saved to %s\n", g_save_path.c_str());
}

namespace {
// same gate as the full scan, before any packet reaches the target
bool preflight_ok(const string& ip) {
    PreflightReport pf = preflight_decide(preflight_gather(ip, false, ""), g_override_preflight);
    print_preflight(pf);
    return !pf.blocked || pf.overridden;
}

string target_ip(const string& arg) {
    auto rs = resolve_host(arg);
    return rs.primary_ip.empty() ? arg : rs.primary_ip;
}

// printed with every client-side result, text and json
const char* const PATH_SCOPE =
    "This measures the path from this machine to this host at this moment; it does not "
    "carry over to another connection, operator or day.";

string jstr(const string& s) { return "\"" + json_escape_string(s) + "\""; }

string dpi_json(const string& host, int port, const DpiProbe& d, const char* target_state, const char* benign_state) {
    string o = "{\n  \"check\": \"sni\",\n";
    o += "  \"target\": " + jstr(host) + ",\n  \"port\": " + std::to_string(port) + ",\n";
    o += "  \"outcome\": " + jstr(outcome_name(dpi_outcome(d))) + ",\n";
    o += "  \"target_sni\": " + jstr(target_state) + ",\n  \"benign_sni\": " + jstr(benign_state) + ",\n";
    o += string("  \"split_ch\": ") + (!d.frag_tested ? "null" : d.frag_evades ? "\"reply\"" : "\"reset\"") + ",\n";
    o += "  \"note\": " + jstr(d.note) + ",\n  \"scope\": " + jstr(PATH_SCOPE) + "\n}\n";
    return o;
}

string trace_line(const VolumeTrace& t) {
    string s = string(volume_end_name(t.end)) + " after " + std::to_string(t.wire) + " B on the wire, " +
               std::to_string(t.body) + " B of body, " + std::to_string(t.total_ms) + " ms";
    if (t.status) s += ", HTTP " + std::to_string(t.status);
    if (!t.err.empty()) s += " (" + t.err + ")";
    return s;
}

string trace_json(const char* role, const VolumeTrace& t) {
    return string("    { \"role\": \"") + role + "\", \"end\": " + jstr(volume_end_name(t.end)) +
           ", \"wire\": " + std::to_string(t.wire) + ", \"body\": " + std::to_string(t.body) +
           ", \"status\": " + std::to_string(t.status) + ", \"ms\": " + std::to_string(t.total_ms) +
           ", \"outcome\": " + jstr(outcome_name(volume_transfer_outcome(t))) + " }";
}

// dpi --volume: control, targets until two agree, control again
int run_volume_check(const string& host, const string& ip, int port) {
    string chost, cpath;
    int cport = 443;
    const bool have_control = !g_volume_control.empty();
    if (have_control && !volume_parse_endpoint(g_volume_control, chost, cport, cpath)) {
        printf("  --control wants host[:port][/path]\n");
        return 64;
    }
    if (g_volume_path.empty() || g_volume_path[0] != '/' || g_volume_path.find_first_of("\r\n \t") != string::npos) {
        printf("  --volume wants a path starting with /\n");
        return 64;
    }
    string cip;
    if (have_control) {
        cip = target_ip(chost);
        if (!preflight_ok(cip)) return 5;
    }
    printf("  volume check: %s:%d%s, control %s\n", host.c_str(), port, g_volume_path.c_str(),
           have_control ? g_volume_control.c_str() : "none");
    printf("  %s\n", PATH_SCOPE);
    std::vector<VolumeTrace> targets, controls;
    std::vector<std::pair<const char*, VolumeTrace>> order;
    auto control = [&] {
        if (!have_control) return;
        controls.push_back(volume_fetch(cip, cport, chost, cpath));
        order.emplace_back("control", controls.back());
        printf("  control : %s\n", trace_line(controls.back()).c_str());
    };
    control();
    std::vector<Outcome> obs;
    while (!observations_settled(obs)) {
        if (!obs.empty()) Sleep(500);
        targets.push_back(volume_fetch(ip, port, host, g_volume_path));
        obs.push_back(volume_transfer_outcome(targets.back()));
        order.emplace_back("target", targets.back());
        printf("  target  : %s\n", trace_line(targets.back()).c_str());
        // a resource below the window cannot answer the question
        if (obs.back() == Outcome::NotApplicable) break;
    }
    control();
    const VolumeVerdict v = volume_verdict(targets, controls);
    printf("  => volume: %s. %s\n", outcome_name(v.outcome), v.reason.c_str());
    if (g_json) {
        string o = "{\n  \"check\": \"volume\",\n  \"target\": " + jstr(host) + ",\n  \"port\": " + std::to_string(port) +
                   ",\n  \"path\": " + jstr(g_volume_path) + ",\n  \"control\": " + (have_control ? jstr(g_volume_control) : "null") +
                   ",\n  \"outcome\": " + jstr(outcome_name(v.outcome)) + ",\n  \"reason\": " + jstr(v.reason) +
                   ",\n  \"stall_wire\": " + std::to_string(v.stall_wire) + ",\n  \"transfers\": [\n";
        for (size_t i = 0; i < order.size(); ++i)
            o += trace_json(order[i].first, order[i].second) + (i + 1 < order.size() ? ",\n" : "\n");
        o += "  ],\n  \"scope\": " + jstr(PATH_SCOPE) + "\n}\n";
        std::fputs(o.c_str(), stdout);
    }
    return v.outcome == Outcome::Positive ? 2 : v.outcome == Outcome::Negative ? 0 : 4;
}
} // namespace

// one target-facing command; shared by the cli and the interactive panel
int run_command(const vector<string>& pos) {
    int rc = 0;
    if (pos.empty()) return 64;
    // exit-code helper: a completed full scan exits 0/1/2/3 by verdict tier
    // so wrapper scripts can branch without parsing output.
    //   0 = clean, 1 = noisy, 2 = suspicious, 3 = obviously-vpn
    // usage / runtime errors use 64 (ex_usage) to stay out of that range.
    auto verdict_exit = [](const FullReport& R) { return report_exit_code(R); };
    {
        string cmd = pos[0];
        if (cmd == "awg-entropy") {
            if (pos.size() != 2) { printf("usage: awg-entropy <capture.pcap|capture.pcapng> [--json]\n"); rc = 64; goto done; }
            rc = run_awg_analysis(pos[1]);
        } else if (cmd == "scan" || cmd == "full") {
            if (pos.size() < 2) { printf("need target\n"); rc = 64; goto done; }
            FullReport R = run_full_target(pos[1]);
            if (g_json) std::fputs(json_report(R).c_str(), stdout);
            rc = verdict_exit(R);
        } else if (cmd == "ports") {
            if (pos.size() < 2) { printf("need target\n"); rc = 64; goto done; }
            const string ip = target_ip(pos[1]);
            if (!preflight_ok(ip)) { rc = 5; goto done; }
            auto op = scan_tcp(ip, build_tcp_ports(), g_threads, g_tcp_to);
            for (auto& o: op)
                printf("  :%-5d  %lldms  %s\n", o.port, o.connect_ms, port_hint(o.port));
        } else if (cmd == "udp") {
            if (pos.size() < 2) { printf("need target\n"); rc = 64; goto done; }
            const string ip = target_ip(pos[1]);
            if (!preflight_ok(ip)) { rc = 5; goto done; }
            auto show = [&](const char* n, int p, const UdpResult& u){
                printf("  UDP:%-5d  %-22s  %s\n", p, n,
                    u.responded ? ("RESP " + std::to_string(u.bytes) + "B " + u.reply_hex).c_str()
                                : ("no answer (" + u.err + ")").c_str());
            };
            show("WireGuard",      51820, wireguard_probe(ip, 51820));
            show("AmneziaWG Sx=8", 51820, amneziawg_probe(ip, 51820));
            show("AmneziaWG Sx=8", 55555, amneziawg_probe(ip, 55555));
            if (!g_wg_pubkey.empty() || !g_wg_key.empty()) {
                WgKeys keys;
                string err;
                if (!wg_load_keys(g_wg_pubkey, g_wg_key, g_wg_psk, keys, err)) {
                    printf("  WireGuard self-check not run: %s\n", err.c_str());
                    rc = 64;
                } else {
                    // two agreeing answers, as in the full scan
                    vector<Outcome> obs;
                    while (!observations_settled(obs)) {
                        if (!obs.empty()) wg_keyed_gap();
                        WgReply rep = WgReply::Unrelated;
                        UdpResult u = wireguard_keyed_probe(ip, g_wg_port, keys, rep);
                        obs.push_back(wg_keyed_outcome(u, rep));
                        printf("  UDP:%-5d  %-22s  %s\n", g_wg_port, "WireGuard keyed",
                               !u.responded ? ("no answer (" + u.err + ")").c_str()
                                            : u.echoed ? "reply echoes the probe" : wg_reply_name(rep));
                    }
                    keys.wipe();
                    printf("  WireGuard self-check :%d  %s (keys not shown)\n", g_wg_port,
                           outcome_name(combine_observations(obs)));
                }
            }
            // curated hysteria2/quic port set (was just 36712 + 443); print
            // responders individually, collapse the silent ones to one line.
            static const int HY_PORTS[] = {443, 8443, 2096, 36712, 5667, 34567, 20000};
            int qp = 0;
            string hy_silent;
            for (int hp : HY_PORTS) {
                UdpResult u = hysteria2_probe(ip, hp);
                if (u.responded) {
                    show("Hysteria2 QUIC", hp, u);
                    string qs = quic_reply_summary(u);
                    if (!qs.empty()) printf("                            %s\n", qs.c_str());
                    if (!qp && quic_response_valid(u)) qp = hp;
                } else {
                    if (!hy_silent.empty()) hy_silent += ",";
                    hy_silent += std::to_string(hp);
                }
            }
            if (!hy_silent.empty())
                printf("  Hysteria2/QUIC:  silent on %s\n", hy_silent.c_str());
            if (qp) {
                UdpResult vn = hysteria2_vn_probe(ip, qp);
                string qs = quic_reply_summary(vn);
                string line = vn.responded ? (qs.empty() ? vn.reply_hex : qs)
                                           : ("no VN answer (" + vn.err + ")");
                printf("  UDP:%-5d  %-22s  %s\n", qp, "QUIC version-negotiation", line.c_str());
            }
        } else if (cmd == "tls") {
            if (pos.size() < 2) { printf("need target\n"); rc = 64; goto done; }
            int port = pos.size() >= 3 ? std::atoi(pos[2].c_str()) : 443;
            const string ip = target_ip(pos[1]);
            if (!preflight_ok(ip)) { rc = 5; goto done; }
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
            printf("  SNI: %s (%d comparable, %d failed); software unconfirmed\n",
                   sc.pattern.c_str(), sc.compared, sc.failed);
        } else if (cmd == "j3") {
            if (pos.size() < 2) { printf("need target\n"); rc = 64; goto done; }
            int port = pos.size() >= 3 ? std::atoi(pos[2].c_str()) : 443;
            const string ip = target_ip(pos[1]);
            if (!preflight_ok(ip)) { rc = 5; goto done; }
            auto probes = j3_probes(ip, port);
            for (auto& p: probes)
                printf("  %-28s  %-20s %dB %s\n", p.name.c_str(), read_end_name(p.end), p.bytes,
                    p.responded ? printable_prefix(p.first_line, 60).c_str() : "");
            printf("  reference only: many ordinary servers ignore malformed input\n");
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
            const string ip = target_ip(pos[1]);
            if (!preflight_ok(ip)) { rc = 5; goto done; }
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
            const string ip = target_ip(pos[1]);
            if (!preflight_ok(ip)) { rc = 5; goto done; }
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
        } else if (cmd == "grpc") {
            if (pos.size() < 2) { printf("need target\n"); rc = 64; goto done; }
            int port = pos.size() >= 3 ? std::atoi(pos[2].c_str()) : 443;
            const string ip = target_ip(pos[1]);
            if (!preflight_ok(ip)) { rc = 5; goto done; }
            GrpcProbe gp = grpc_probe(ip, port, pos[1]);
            if (!gp.tls_ok) { printf("  TLS fail: %s\n", gp.err.c_str()); rc = 1; goto done; }
            printf("  ALPN=%s  h2=%s  h2-frames=%s  headers=%s  rst=%s  goaway=%s\n",
                   gp.alpn.empty() ? "-" : gp.alpn.c_str(),
                   gp.alpn_h2 ? "yes" : "no", gp.h2_frames ? "yes" : "no",
                   gp.headers_resp ? "yes" : "no", gp.stream_reset ? "yes" : "no",
                   gp.goaway ? "yes" : "no");
            printf("  => %s\n", gp.note.c_str());
        } else if (cmd == "dpi") {
            if (pos.size() < 2) { printf("need target\n"); rc = 64; goto done; }
            int port = pos.size() >= 3 ? std::atoi(pos[2].c_str()) : 443;
            const string ip = target_ip(pos[1]);
            // a tunnel on the path measures the tunnel, not the isp
            if (!preflight_ok(ip)) { rc = 5; goto done; }
            if (!g_volume_path.empty()) { rc = run_volume_check(pos[1], ip, port); goto done; }
            DpiProbe d = dpi_probe(ip, port, pos[1]);
            printf("  target=%s  sni=%s\n", ip.c_str(), pos[1].c_str());
            if (d.tunneled) {
                printf("  %s!! %s%s\n", col(C::YEL), d.note.c_str(), col(C::RST));
                if (g_json) std::fputs(dpi_json(pos[1], port, d, "tunneled", "tunneled").c_str(), stdout);
                rc = 64; goto done;
            }
            auto state = [](bool conn, bool reset, bool silent, bool prog) {
                return !conn ? "no-tcp" : reset ? "RESET" : prog ? "ok" : silent ? "silent" : "no-reply";
            };
            const char* ts = state(d.target_connected, d.target_reset, d.target_silent, d.target_progressed);
            const char* bs = state(d.benign_connected, d.benign_reset, d.benign_silent, d.benign_progressed);
            printf("  target-SNI: %-8s   benign-SNI: %-8s\n", ts, bs);
            if (d.frag_tested)
                printf("  split CH: %s\n", d.frag_evades ? "got a reply" : "still reset");
            printf("  => %s\n", d.note.c_str());
            printf("  SNI check: %s. %s\n", outcome_name(dpi_outcome(d)), PATH_SCOPE);
            if (g_json) std::fputs(dpi_json(pos[1], port, d, ts, bs).c_str(), stdout);
            rc = dpi_exit_code(d);
        } else if (cmd == "ech") {
            if (pos.size() < 2) { printf("need a domain\n"); rc = 64; goto done; }
            EchInfo e = ech_query(pos[1]);
            if (e.bad_input) { printf("  %s\n", e.err.c_str()); rc = 64; goto done; }
            if (!e.lookup_complete) {
                // failed lookup is not a fact about the domain
                printf("  %sHTTPS RR unknown for %s%s: lookup failed (%s)\n",
                       col(C::YEL), pos[1].c_str(), col(C::RST), e.err.c_str());
                rc = 4; goto done;
            }
            if (!e.has_https_rr) {
                printf("  %sno HTTPS RR for %s%s  (resolver answered NOERROR without one)\n",
                       col(C::DIM), pos[1].c_str(), col(C::RST));
                rc = 1; goto done;
            }
            printf("  %sHTTPS RR (DNS type 65) published for %s%s\n",
                   col(C::BOLD), pos[1].c_str(), col(C::RST));
            printf("  ALPN: %s%s%s%s\n", col(C::CYN),
                   e.alpn.empty() ? "-" : e.alpn.c_str(), col(C::RST),
                   e.alpn.find("h3") != string::npos ? "  (HTTP/3 advertised)" : "");
            if (!e.ipv4hint.empty()) printf("  ipv4hint: %s\n", e.ipv4hint.c_str());
            if (!e.ipv6hint.empty()) printf("  ipv6hint: %s\n", e.ipv6hint.c_str());
            if (e.has_ech)
                printf("  %sECH: published%s  (ECHConfigList ~%d bytes); clients that use it hide the inner SNI\n",
                       col(C::GRN), col(C::RST), e.ech_len);
            else
                printf("  %sECH: not published%s  (no ech= param; clients send the SNI in cleartext)\n",
                       col(C::YEL), col(C::RST));
            rc = 0;
        } else if (cmd == "names" || cmd == "name") {
            rc = run_hostname_analysis(vector<string>(pos.begin() + 1, pos.end()));
        } else if (cmd == "audit-config" || cmd == "audit") {
            if (pos.size() < 2) { printf("need a config file path\n"); rc = 64; goto done; }
            rc = run_config_audit(pos[1]);
        } else if (cmd == "sweep") {
            if (pos.size() < 2) { printf("need a CIDR (e.g. 1.2.3.0/24)\n"); rc = 64; goto done; }
            rc = run_sweep(pos[1]);
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
    return rc;
}
