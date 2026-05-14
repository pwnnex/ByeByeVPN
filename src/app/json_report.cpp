// SPDX-License-Identifier: GPL-3.0-or-later
#include "json_report.h"
#include "../scan/ja4s_db.h"

#include <cstdio>
#include <string>

using std::string;

namespace {

// minimal RFC 8259 string escaper. handles the mandatory escapes plus
// control chars; everything else (including UTF-8 multibyte) passes
// through untouched.
string esc(const string& s) {
    string o; o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\b': o += "\\b";  break;
            case '\f': o += "\\f";  break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (c < 0x20) {
                    char b[8];
                    std::snprintf(b, sizeof(b), "\\u%04x", c);
                    o += b;
                } else {
                    o += (char)c;
                }
        }
    }
    return o;
}

// small builder. callers append key/value pairs; it tracks comma state
// per nesting level so the output has no trailing commas.
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
    j.kv_str("version",     "v2.6.0", true);
    j.kv_str("target",      R.target, true);
    j.kv_str("resolved_ip", R.dns.primary_ip, true);
    j.kv_str("dns_family",  R.dns.family, true);
    j.kv_int("score",       R.score, true);
    j.kv_str("label",       R.label, true);
    j.kv_str("stack",       R.stack_name, true);

    // tspu block
    j.open_obj("tspu");
    j.kv_str("tier",   R.tspu_tier.empty() ? "PASS / ALLOW" : R.tspu_tier, true);
    j.kv_int("a_hits", R.tspu_a_hits, true);
    j.kv_int("b_hits", R.tspu_b_hits, false);
    j.close_obj(true);

    // signals block
    j.open_obj("signals");
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

    // tls ports (one entry per fingerprinted TLS port)
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
            j.kv_bool("self_signed",  pf.tls->self_signed, true);
            bool reality = pf.sni && pf.sni->reality_like;
            j.kv_bool("reality_like", reality, true);
            // utls dual-probe + ja4 + ja4s classification
            if (pf.utls) {
                j.open_obj("utls");
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
