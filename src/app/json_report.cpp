// SPDX-License-Identifier: GPL-3.0-or-later
#include "json_report.h"
#include "verdict.h"
#include "../common/config.h"
#include "../common/json.h"
#include "../scan/ja4s_db.h"
#include "../common/util.h"

#include <cstdio>
#include <string>

using std::string;

namespace {

// banners, headers and certificate names come from the network; invalid
// utf-8 would make the whole document invalid json, so it is replaced.
string esc(const string& s) { return json_escape_string(s); }

// callers supply commas; the builder handles quoting and indentation
struct Json {
    string out;
    int    indent = 0;

    void pad() { for (int i = 0; i < indent; ++i) out += "  "; }

    void raw(const string& s) { out += s; }

    void key(const char* k) {
        pad();
        out += '"'; out += k; out += "\": ";
    }
    void kv_str(const char* k, const string& v, bool comma) {
        key(k); out += '"'; out += esc(v); out += '"';
        out += comma ? ",\n" : "\n";
    }
    void kv_int(const char* k, long long v, bool comma) {
        key(k); out += std::to_string(v);
        out += comma ? ",\n" : "\n";
    }
    void kv_bool(const char* k, bool v, bool comma) {
        key(k); out += v ? "true" : "false";
        out += comma ? ",\n" : "\n";
    }
    void kv_dbl(const char* k, double v, bool comma) {
        char b[64]; std::snprintf(b, sizeof(b), "%.2f", v);
        key(k); out += b;
        out += comma ? ",\n" : "\n";
    }
    void open_obj(const char* k) { key(k); out += "{\n"; ++indent; }
    void open_arr(const char* k) { key(k); out += "[\n"; ++indent; }
    void close_obj(bool comma)   { --indent; pad(); out += comma ? "},\n" : "}\n"; }
    void close_arr(bool comma)   { --indent; pad(); out += comma ? "],\n" : "]\n"; }
};

} // namespace

string json_report(const FullReport& R) {
    Json j;
    j.out += "{\n";
    j.indent = 1;

    j.kv_str("tool",        "byebyevpn", true);
    j.kv_str("version",     SCANNER_VERSION, true);
    j.kv_str("target",      R.target, true);
    j.kv_str("resolved_ip", R.dns.primary_ip, true);
    j.kv_str("dns_family",  R.dns.family, true);
    j.kv_bool("completed", R.completed, true);
    j.kv_str("error", R.dns.err, true);
    if (R.completed && R.score_available) j.kv_int("score", R.score, true);
    else { j.key("score"); j.raw("null,\n"); }
    j.kv_bool("score_available", R.score_available, true);
    j.kv_str("label",       R.label, true);
    j.kv_str("stack",       R.stack_name, true);
    j.kv_bool("score_is_heuristic", true, true);
    j.kv_bool("unreliable", R.unreliable, true);
    j.kv_bool("preflight_overridden", R.overridden, true);
    j.open_arr("failed_reasons");
    for (size_t i = 0; i < R.failed_reasons.size(); ++i) {
        j.pad(); j.out += '"' + esc(R.failed_reasons[i]) + '"';
        j.out += (i + 1 < R.failed_reasons.size()) ? ",\n" : "\n";
    }
    j.close_arr(true);

    j.open_obj("preflight");
    j.kv_bool("ran", R.preflight_ran, true);
    j.kv_bool("blocked", R.preflight.blocked, true);
    j.kv_str("target_interface", R.preflight.facts.target_iface, true);
    j.kv_bool("target_via_tunnel", R.preflight.facts.target_iface_is_tunnel, true);
    j.kv_bool("local_ack_all", R.preflight.facts.local_ack_all, true);
    auto str_arr = [&](const char* k, const std::vector<std::string>& v, bool comma) {
        j.open_arr(k);
        for (size_t i = 0; i < v.size(); ++i) {
            j.pad(); j.out += '"' + esc(v[i]) + '"';
            j.out += (i + 1 < v.size()) ? ",\n" : "\n";
        }
        j.close_arr(comma);
    };
    str_arr("blockers", R.preflight.blockers, true);
    str_arr("warnings", R.preflight.warnings, false);
    j.close_obj(true);

    // no keys and no paths here, only whether the check ran
    j.open_obj("wg_self_check");
    j.kv_bool("requested", R.wg_self.requested, true);
    j.kv_bool("ran", R.wg_self.ran, true);
    j.kv_int("port", R.wg_self.port, false);
    j.close_obj(true);

    j.open_obj("channel");
    j.kv_bool("measured", R.channel.measured, true);
    j.kv_int("port", R.channel.port, true);
    j.kv_int("attempts", R.channel.attempts, true);
    j.kv_int("ok", R.channel.ok, true);
    j.kv_dbl("loss", R.channel.loss, true);
    j.kv_dbl("rtt_median_ms", R.channel.rtt_median_ms, true);
    j.kv_dbl("rtt_stddev_ms", R.channel.rtt_stddev_ms, true);
    j.kv_bool("degraded", R.channel.degraded, true);
    j.kv_bool("unusable", R.channel.unusable, false);
    j.close_obj(true);

    j.open_obj("ack_all");
    j.kv_bool("flat_rtt_heuristic", R.ack_all_heuristic, true);
    j.kv_int("control_ports_tried", R.ack_all_control_tried, true);
    j.kv_int("control_ports_open", R.ack_all_control_open, true);
    j.kv_bool("suspected", ack_all_suspected(R), false);
    j.close_obj(true);

    j.open_obj("coverage");
    j.kv_int("checks_applicable", R.checks_applicable, true);
    j.kv_int("checks_conclusive", R.checks_conclusive, false);
    j.close_obj(true);

    j.open_arr("checks");
    for (size_t i = 0; i < R.checks.size(); ++i) {
        const auto& c = R.checks[i];
        j.pad(); j.raw("{\n"); ++j.indent;
        j.kv_str("id", c.id, true);
        j.kv_int("port", c.port, true);
        j.kv_str("outcome", outcome_name(c.outcome), true);
        j.kv_int("observations", c.observations, true);
        j.kv_str("observed", c.observed, true);
        j.kv_str("reason", c.reason, true);
        j.kv_str("passport", signal_passport(c.id), false);
        --j.indent; j.pad(); j.raw(i + 1 < R.checks.size() ? "},\n" : "}\n");
    }
    j.close_arr(true);

    j.open_obj("scan_coverage");
    j.kv_int("tcp_attempted", R.scan_stats.scanned, true);
    j.kv_int("tcp_timeouts", R.scan_stats.timeouts, true);
    j.kv_int("tcp_refused", R.scan_stats.refused, true);
    j.kv_bool("tcp_interrupted", R.scan_stats.skipped, true);
    j.kv_bool("tcp_timeout_pattern", R.tcp_timeout_pattern, true);
    j.kv_bool("bgp_block_confirmed", false, false);
    j.close_obj(true);
    j.open_arr("service_observations");
    for (size_t i = 0; i < R.port_observations.size(); ++i) {
        j.pad(); j.raw("{\n"); ++j.indent;
        j.kv_int("port", R.port_observations[i].first, true);
        j.kv_str("detail", printable_prefix(R.port_observations[i].second, 256), false);
        --j.indent; j.pad(); j.raw(i + 1 < R.port_observations.size() ? "},\n" : "}\n");
    }
    j.close_arr(true);

    // tspu block
    j.open_obj("tspu");
    j.kv_bool("thresholds_validated", false, true);
    j.kv_bool("blocking_verified", false, true);
    j.kv_str("tier",   R.tspu_tier.empty() ? "UNKNOWN" : R.tspu_tier, true);
    j.kv_int("a_hits", R.tspu_a_hits, true);
    j.kv_int("b_hits", R.tspu_b_hits, false);
    j.close_obj(true);

    // signals block
    j.open_obj("signals");
    j.open_arr("scored");
    for (size_t i = 0; i < R.scored.size(); ++i) {
        const auto& s = R.scored[i];
        j.pad(); j.raw("{\n"); ++j.indent;
        j.kv_str("id", s.id, true);
        j.kv_str("tier", std::string(1, s.tier), true);
        j.kv_int("weight", s.weight, true);
        j.kv_int("port", s.port, true);
        j.kv_int("observations", s.observations, true);
        j.kv_bool("author_heuristic", s.heuristic, true);
        j.kv_str("observed", s.observed, true);
        j.kv_str("passport", signal_passport(s.id), false);
        --j.indent; j.pad(); j.raw(i + 1 < R.scored.size() ? "},\n" : "}\n");
    }
    j.close_arr(true);
    j.open_arr("inconclusive");
    {
        size_t n = 0, seen = 0;
        for (const auto& c : R.checks) n += c.outcome == Outcome::Inconclusive;
        for (const auto& c : R.checks) {
            if (c.outcome != Outcome::Inconclusive) continue;
            j.pad(); j.out += "{ \"id\": \"" + esc(c.id) + "\", \"port\": " + std::to_string(c.port) +
                              ", \"reason\": \"" + esc(c.reason) + "\" }";
            j.out += (++seen < n) ? ",\n" : "\n";
        }
    }
    j.close_arr(true);
    j.open_arr("major");
    for (size_t i = 0; i < R.signals_major.size(); ++i) {
        j.pad(); j.out += '"'; j.out += esc(R.signals_major[i]); j.out += '"';
        j.out += (i + 1 < R.signals_major.size()) ? ",\n" : "\n";
    }
    j.close_arr(true);
    j.open_arr("minor");
    for (size_t i = 0; i < R.signals_minor.size(); ++i) {
        j.pad(); j.out += '"'; j.out += esc(R.signals_minor[i]); j.out += '"';
        j.out += (i + 1 < R.signals_minor.size()) ? ",\n" : "\n";
    }
    j.close_arr(true);
    j.open_arr("notes");
    for (size_t i = 0; i < R.notes.size(); ++i) {
        j.pad(); j.out += "{ \"tag\": \"" + esc(R.notes[i].first) +
                          "\", \"text\": \"" + esc(R.notes[i].second) + "\" }";
        j.out += (i + 1 < R.notes.size()) ? ",\n" : "\n";
    }
    j.close_arr(false);
    j.close_obj(true);

    // naming findings remain separate from the scan verdict.
    j.kv_bool("hostname_protocol_confirmed", false, true);
    j.kv_int("hostname_score_impact", 0, true);
    j.key("hostname_marks");
    j.raw(hostname_marks_json(R.hostnames) + ",\n");

    // geo array
    j.open_arr("geo");
    for (size_t i = 0; i < R.geos.size(); ++i) {
        const GeoInfo& g = R.geos[i];
        j.pad(); j.out += "{\n"; ++j.indent;
        j.kv_str("source",       g.source, true);
        j.kv_str("country_code", g.country_code, true);
        j.kv_str("asn",          g.asn, true);
        j.kv_str("asn_org",      g.asn_org, true);
        j.kv_bool("is_hosting",  g.is_hosting, true);
        j.kv_bool("is_vpn",      g.is_vpn, true);
        j.kv_bool("is_proxy",    g.is_proxy, true);
        j.kv_bool("is_tor",      g.is_tor, true);
        j.kv_str("err",          g.err, false);
        --j.indent; j.pad();
        j.out += (i + 1 < R.geos.size()) ? "},\n" : "}\n";
    }
    j.close_arr(true);

    // open tcp ports
    j.open_arr("open_tcp");
    for (size_t i = 0; i < R.open_tcp.size(); ++i) {
        const TcpOpen& o = R.open_tcp[i];
        j.pad(); j.out += "{\n"; ++j.indent;
        j.kv_int("port",       o.port, true);
        j.kv_int("connect_ms", o.connect_ms, true);
        j.kv_str("banner",     o.banner, false);
        --j.indent; j.pad();
        j.out += (i + 1 < R.open_tcp.size()) ? "},\n" : "}\n";
    }
    j.close_arr(true);

    // udp probes
    j.open_arr("udp");
    for (size_t i = 0; i < R.udp_probes.size(); ++i) {
        const UdpProbeRec& u = R.udp_probes[i];
        j.pad(); j.out += "{\n"; ++j.indent;
        j.kv_int("port",      u.port, true);
        j.kv_str("kind",      u.kind, true);
        j.kv_bool("responded", u.result.responded, true);
        j.kv_int("bytes",     u.result.bytes, false);
        --j.indent; j.pad();
        j.out += (i + 1 < R.udp_probes.size()) ? "},\n" : "}\n";
    }
    j.close_arr(true);

    // tls ports (one entry per fingerprinted tls port)
    j.open_arr("tls_ports");
    {
        // count tls-bearing ports first so we know where the last comma goes
        size_t tls_n = 0;
        for (auto& pf : R.fps) if (pf.tls && pf.tls->ok) ++tls_n;
        size_t seen = 0;
        for (auto& pf : R.fps) {
            if (!(pf.tls && pf.tls->ok)) continue;
            ++seen;
            j.pad(); j.out += "{\n"; ++j.indent;
            j.kv_int("port",          pf.port, true);
            j.kv_str("tls_version",   pf.tls->version, true);
            j.kv_str("cipher",        pf.tls->cipher, true);
            j.kv_str("alpn",          pf.tls->alpn, true);
            j.kv_str("cert_cn",       pf.tls->subject_cn, true);
            j.kv_str("cert_issuer",   pf.tls->issuer_cn, true);
            j.kv_str("cert_sha256",   pf.tls->cert_sha256, true);
            j.kv_int("cert_age_days", pf.tls->age_days, true);
            j.kv_int("cert_validity_days", pf.tls->total_validity_days, true);
            j.kv_bool("certificate_present", pf.tls->certificate_present, true);
            j.kv_bool("certificate_times_valid", pf.tls->certificate_times_valid, true);
            j.kv_int("cert_validity_seconds", pf.tls->total_validity_seconds, true);
            j.kv_bool("certificate_expired", pf.tls->certificate_expired, true);
            j.kv_bool("certificate_not_yet_valid", pf.tls->certificate_not_yet_valid, true);
            j.kv_bool("certificate_trust_checked", false, true);
            j.kv_bool("self_issued", pf.tls->self_issued, true);
            j.kv_bool("self_signature_checked", pf.tls->self_signature_checked, true);
            j.kv_bool("self_signed",  pf.tls->self_signed, true);
            if (pf.https) {
                j.open_obj("https");
                j.kv_bool("request_sent", pf.https->request_sent, true);
                j.kv_bool("responded", pf.https->responded, true);
                j.kv_bool("headers_complete", pf.https->headers_complete, true);
                j.kv_bool("http_valid", pf.https->http_valid, true);
                j.kv_int("status_code", pf.https->status_code, true);
                j.kv_str("first_line", printable_prefix(pf.https->first_line, 256), true);
                j.kv_str("server_header", printable_prefix(pf.https->server_hdr, 256), true);
                j.kv_bool("forwarding_headers_observed", pf.https->has_proxy_leak, true);
                j.kv_str("error", pf.https->err, false);
                j.close_obj(true);
            } else { j.key("https"); j.raw("null,\n"); }
            if (pf.ct) {
                j.open_obj("ct_search");
                j.kv_str("source", "crt.sh", true);
                j.kv_bool("queried", pf.ct->queried, true);
                j.kv_bool("lookup_complete", pf.ct->lookup_complete, true);
                j.kv_bool("found", pf.ct->found, true);
                j.kv_int("result_count", pf.ct->log_entries, true);
                j.kv_str("error", pf.ct->err, false);
                j.close_obj(true);
            } else { j.key("ct_search"); j.raw("null,\n"); }
            j.kv_bool("reality_like", false, true);
            if (pf.sni) {
                j.open_obj("sni_observation");
                j.kv_str("pattern", pf.sni->pattern, true);
                j.kv_int("compared", pf.sni->compared, true);
                j.kv_int("failed", pf.sni->failed, true);
                j.kv_int("distinct_certificates", pf.sni->distinct_certs, true);
                j.kv_bool("protocol_confirmed", false, false);
                j.close_obj(true);
            } else { j.key("sni_observation"); j.raw("null,\n"); }
            if (pf.websocket) {
                j.open_obj("websocket");
                j.kv_bool("handshake_valid", pf.websocket->ws_upgrade, true);
                j.kv_str("path", pf.websocket->path_hit, true);
                j.kv_bool("vpn_protocol_confirmed", false, true);
                j.kv_str("error", pf.websocket->err, false);
                j.close_obj(true);
            } else { j.key("websocket"); j.raw("null,\n"); }
            if (pf.grpc) {
                j.open_obj("http2");
                j.kv_bool("alpn_h2", pf.grpc->alpn_h2, true);
                j.kv_bool("complete_frames_seen", pf.grpc->h2_frames, true);
                j.kv_bool("headers_seen", pf.grpc->headers_resp, true);
                j.kv_bool("grpc_confirmed", false, true);
                j.kv_str("error", pf.grpc->err, false);
                j.close_obj(true);
            } else { j.key("http2"); j.raw("null,\n"); }
            // utls dual-probe + ja4 + ja4s classification
            if (pf.utls) {
                j.open_obj("utls");
                j.kv_bool("protocol_confirmed", false, true);
                j.kv_str("chrome_probe_stage", "server_hello_only", true);
                j.kv_bool("chrome_server_hello", pf.utls->chrome.server_hello_received, true);
                j.kv_bool("openssl_server_hello", pf.utls->openssl.server_hello_received, true);
                j.kv_bool("chrome_handshake_completed", pf.utls->chrome.handshake_completed, true);
                j.kv_bool("openssl_handshake_completed", pf.utls->openssl.handshake_completed, true);
                j.kv_str("ja4_openssl",  pf.utls->openssl.ja4,  true);
                j.kv_str("ja4_chrome",   pf.utls->chrome.ja4,   true);
                j.kv_str("ja4s_openssl", pf.utls->openssl.ja4s, true);
                j.kv_str("ja4s_chrome",  pf.utls->chrome.ja4s,  true);
                j.kv_bool("cert_differs",   pf.utls->cert_differs, true);
                j.kv_bool("ja4s_differs",   pf.utls->ja4s_differs, true);
                const string& js = !pf.utls->openssl.ja4s.empty()
                                     ? pf.utls->openssl.ja4s : pf.utls->chrome.ja4s;
                Ja4sInfo ji = ja4s_classify(js);
                j.kv_str("ja4s_family",     ji.family,     true);
                j.kv_str("ja4s_confidence", ji.confidence, false);
                j.close_obj(false);
            } else {
                j.key("utls"); j.out += "null\n";
            }
            --j.indent; j.pad();
            j.out += (seen < tls_n) ? "},\n" : "}\n";
        }
    }
    j.close_arr(true);

    // snitch
    if (R.snitch && R.snitch->ok) {
        const SnitchResult& s = *R.snitch;
        j.open_obj("snitch");
        j.kv_dbl("median_ms",     s.median_ms, true);
        j.kv_dbl("stddev_ms",     s.stddev_ms, true);
        j.kv_str("country_code",  s.country_code, true);
        j.kv_dbl("expected_min_ms", s.expected_min_ms, true);
        j.kv_bool("too_low",      s.too_low, true);
        j.kv_bool("too_high",     s.too_high, true);
        j.kv_bool("high_jitter",  s.high_jitter, true);
        j.kv_str("summary",       s.summary, false);
        j.close_obj(true);
    } else {
        j.key("snitch"); j.out += "null,\n";
    }

    // traceroute
    if (R.trace && R.trace->ok) {
        const TraceResult& t = *R.trace;
        j.open_obj("trace");
        j.kv_int("hop_count",       t.hop_count, true);
        j.kv_bool("reached_target", t.reached_target, true);
        j.kv_int("max_rtt_jump_ms", t.max_rtt_jump_ms, true);
        j.kv_int("tspu_hops",       t.tspu_hops, false);
        j.close_obj(true);
    } else {
        j.key("trace"); j.out += "null,\n";
    }

    // tcp fingerprint
    if (R.tcp_fp && R.tcp_fp->ok) {
        const TcpFp& f = *R.tcp_fp;
        j.open_obj("tcp_fp");
        j.kv_dbl("handshake_median_ms", f.handshake_median_ms, true);
        j.kv_dbl("handshake_stddev_ms", f.handshake_stddev_ms, true);
        j.kv_bool("bimodal",            f.bimodal, true);
        j.kv_int("peer_window",         f.peer_window, true);
        j.kv_int("peer_mss",            f.peer_mss, true);
        j.kv_str("closed_port_behavior", f.closed_port_behavior, true);
        j.kv_str("os_guess",            f.os_guess, false);
        j.close_obj(true);
    } else {
        j.key("tcp_fp"); j.out += "null,\n";
    }

    // amnezia sweep
    if (R.amnezia_sweep && R.amnezia_sweep->ok) {
        const AmneziaSweep& a = *R.amnezia_sweep;
        j.open_obj("amnezia_sweep");
        j.kv_bool("any_responded",       a.any_responded, true);
        j.kv_bool("vanilla_wg_responds", a.vanilla_wg_responds, true);
        j.kv_int("detected_s1",          a.detected_s1, true);
        j.kv_str("summary",              a.summary, false);
        j.close_obj(false);
    } else {
        j.key("amnezia_sweep"); j.out += "null\n";
    }

    j.out += "}\n";
    return j.out;
}
