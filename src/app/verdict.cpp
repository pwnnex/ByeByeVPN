// SPDX-License-Identifier: GPL-3.0-or-later
#include "verdict.h"
#include "../scan/udp_validate.h"
#include "../common/util.h"
#include <algorithm>
#include <cmath>
#include <map>
#include <set>

namespace {

// a silent or closed udp port shows no listener; that is not a negative
Outcome wg_observation(const UdpResult& u, bool amnezia) {
    if (!u.responded) return Outcome::NotApplicable;
    if (u.echoed) return Outcome::Negative;
    const bool shaped = amnezia ? awg_response_offset(u) >= 0 : wg_response_valid(u);
    return shaped ? Outcome::Positive : Outcome::Negative;
}

// kinds are different probes of one port; both must not contradict
Outcome merge_kinds(const std::vector<Outcome>& per_kind) {
    bool pos = false, neg = false, inc = false;
    for (Outcome o : per_kind) {
        pos |= o == Outcome::Positive;
        neg |= o == Outcome::Negative;
        inc |= o == Outcome::Inconclusive;
    }
    if (pos && neg) return Outcome::Inconclusive;
    if (pos) return Outcome::Positive;
    if (neg) return Outcome::Negative;
    if (inc) return Outcome::Inconclusive;
    return Outcome::NotApplicable;
}

std::string count_line(const std::vector<Outcome>& obs) {
    int p = 0, n = 0, other = 0;
    for (Outcome o : obs) (o == Outcome::Positive ? p : o == Outcome::Negative ? n : other)++;
    return std::to_string(obs.size()) + " probes: " + std::to_string(p) + " matching, " +
           std::to_string(n) + " non-matching, " + std::to_string(other) + " without a reply";
}

std::string why_inconclusive(const std::vector<Outcome>& obs) {
    int p = 0, n = 0;
    for (Outcome o : obs) { p += o == Outcome::Positive; n += o == Outcome::Negative; }
    if (p && n) return "repeats disagree; unstable, not counted";
    if (p == 1) return "one matching reply; a second agreeing observation is required";
    if (n == 1) return "one non-matching reply; a second agreeing observation is required";
    return "no usable reply";
}

} // namespace

Outcome wg_keyed_outcome(const UdpResult& u, WgReply reply) {
    // with the owner's keys silence is a failed measurement, not "no listener"
    if (!u.responded) return Outcome::Inconclusive;
    if (u.echoed) return Outcome::Negative;
    switch (reply) {
    case WgReply::Authenticated:
    case WgReply::PskMismatch:     return Outcome::Positive;   // mac1 came from the server key
    case WgReply::Cookie:          return Outcome::Inconclusive;
    default:                       return Outcome::Negative;
    }
}

std::vector<CheckResult> build_checks(const FullReport& r) {
    std::vector<CheckResult> out;

    std::map<int, std::vector<Outcome>> keyed;
    for (const auto& u : r.udp_probes)
        if (u.kind == "wg-keyed") keyed[u.port].push_back(u.outcome);
    for (const auto& [port, obs] : keyed) {
        CheckResult c; c.id = "wg-keyed"; c.port = port;
        c.observations = (int)obs.size();
        c.outcome = combine_observations(obs);
        c.observed = count_line(obs);
        bool any_reply = false;
        for (const auto& u : r.udp_probes)
            if (u.kind == "wg-keyed" && u.port == port) any_reply |= u.result.responded;
        if (c.outcome == Outcome::Inconclusive)
            c.reason = any_reply ? why_inconclusive(obs)
                                 : "no reply to a keyed initiation; a wrong server or peer key, a filter and a missing listener look the same";
        out.push_back(c);
    }

    std::map<int, std::map<std::string, std::vector<Outcome>>> wg;
    for (const auto& u : r.udp_probes)
        if (u.kind == "wg" || u.kind == "amnezia")
            wg[u.port][u.kind].push_back(wg_observation(u.result, u.kind == "amnezia"));
    for (const auto& [port, kinds] : wg) {
        CheckResult c; c.id = "wg-family"; c.port = port;
        std::vector<Outcome> per_kind, all;
        for (const auto& [kind, obs] : kinds) {
            per_kind.push_back(combine_observations(obs));
            all.insert(all.end(), obs.begin(), obs.end());
            c.observations += (int)obs.size();
        }
        c.outcome = merge_kinds(per_kind);
        c.observed = count_line(all);
        if (c.outcome == Outcome::NotApplicable) c.reason = "no UDP reply; a listener without our key stays silent, so nothing was measured";
        else if (c.outcome == Outcome::Inconclusive) c.reason = why_inconclusive(all);
        out.push_back(c);
    }

    for (const auto& p : r.fps) {
        if (p.socks5_obs.empty()) continue;
        CheckResult c; c.id = "socks5"; c.port = p.port;
        std::vector<Outcome> obs;
        for (const auto& f : p.socks5_obs) obs.push_back(f.outcome);
        c.observations = (int)obs.size();
        c.outcome = combine_observations(obs);
        c.observed = count_line(obs);
        if (c.outcome == Outcome::Inconclusive) c.reason = why_inconclusive(obs);
        out.push_back(c);
    }

    if (!r.sstp_obs.empty()) {
        CheckResult c; c.id = "sstp"; c.port = 443;
        std::vector<Outcome> obs;
        for (const auto& f : r.sstp_obs) obs.push_back(f.outcome);
        c.observations = (int)obs.size();
        c.outcome = combine_observations(obs);
        c.observed = count_line(obs);
        if (c.outcome == Outcome::Inconclusive) c.reason = why_inconclusive(obs);
        out.push_back(c);
    }
    return out;
}

ChannelQuality assess_channel(int port, int attempts, const std::vector<double>& ok) {
    ChannelQuality q;
    q.port = port;
    q.attempts = attempts;
    q.ok = (int)ok.size();
    if (attempts <= 0) return q;
    q.measured = true;
    q.loss = double(attempts - q.ok) / attempts;
    if (!ok.empty()) {
        std::vector<double> v = ok;
        std::sort(v.begin(), v.end());
        q.rtt_median_ms = v.size() % 2 ? v[v.size() / 2] : 0.5 * (v[v.size() / 2 - 1] + v[v.size() / 2]);
        double mean = 0; for (double x : v) mean += x; mean /= v.size();
        double s = 0; for (double x : v) s += (x - mean) * (x - mean);
        q.rtt_stddev_ms = std::sqrt(s / v.size());
    }
    // 2 of 10 lost already hides a silent drop
    q.degraded = q.loss >= 0.2;
    q.unusable = q.loss >= 0.5;
    return q;
}

bool ack_all_suspected(const FullReport& r) {
    // random high ports should refuse; two open ones prove the path lies
    if (r.ack_all_control_open >= 2) return true;
    return r.ack_all_heuristic && r.ack_all_control_open >= 1;
}

void evaluate_report(FullReport& r) {
    r.score = 100;
    r.score_available = false;
    r.signals_major.clear(); r.signals_minor.clear(); r.notes.clear(); r.port_observations.clear();
    r.scored.clear(); r.failed_reasons.clear();
    r.tspu_a_hits = r.tspu_b_hits = 0;
    r.checks_applicable = r.checks_conclusive = 0;
    std::set<std::string> services;
    bool observed = false;
    auto note = [&](const std::string& tag, const std::string& text) { r.notes.emplace_back(tag, text); };
    auto service = [&](int port, const std::string& text) {
        r.port_observations.emplace_back(port, text);
        observed = true;
    };

    // geoip tags are reference output, docs/SIGNALS.md#geoip-tags
    int vpn = 0, proxy = 0, tor = 0;
    std::set<std::string> providers;
    for (const auto& g : r.geos) {
        if (!g.err.empty() || g.source.empty() || !providers.insert(tolower_s(g.source)).second) continue;
        vpn += g.is_vpn; proxy += g.is_proxy; tor += g.is_tor;
    }
    if (vpn || proxy || tor)
        note("geoip-tags", std::to_string(vpn) + " VPN, " + std::to_string(proxy) + " proxy, " + std::to_string(tor) +
             " Tor tags from lookup services; several tag any hosting address, reference only, not scored");

    r.checks = build_checks(r);
    std::set<std::string> weighted;
    for (const auto& c : r.checks) {
        const SignalSpec* spec = signal_spec(c.id);
        if (!spec) continue;
        if (c.outcome != Outcome::NotApplicable) ++r.checks_applicable;
        if (c.outcome == Outcome::Positive || c.outcome == Outcome::Negative) ++r.checks_conclusive;
        if (c.outcome == Outcome::Positive) {
            const auto port = std::to_string(c.port);
            if (c.id == "wg-family") { service(c.port, "UDP WireGuard-family response layout; peer unauthenticated"); services.insert("WireGuard-family response layout"); }
            if (c.id == "wg-keyed")  { service(c.port, "UDP WireGuard handshake answered for the owner's peer key"); services.insert("WireGuard endpoint (owner self-check)"); }
            if (c.id == "socks5")    { service(c.port, "SOCKS5 method negotiation; relay access untested"); services.insert("SOCKS5 negotiation"); }
            if (c.id == "sstp")      { service(c.port, "SSTP-compatible HTTP setup; control exchange and authentication untested"); services.insert("SSTP-compatible HTTP setup"); }
            if (spec->tier == 'R' || !weighted.insert(spec->group).second) continue;
            ScoredSignal s{c.id, spec->tier, spec->weight, c.port, c.observations, spec->heuristic, c.observed};
            r.scored.push_back(s);
            r.signals_major.push_back(std::string(spec->claim) + " (:" + port + ", " + c.observed + ")");
            r.score -= spec->weight;
            if (spec->tier == 'A') ++r.tspu_a_hits; else ++r.tspu_b_hits;
        }
    }

    bool wg_attempted = false, wg_answered = false;
    for (const auto& u : r.udp_probes) {
        if (u.kind == "wg" || u.kind == "amnezia") { wg_attempted = true; wg_answered |= u.result.responded; }
        if (!u.result.responded) continue;
        const auto port = std::to_string(u.port);
        if (u.result.echoed) { note("udp-echo", "UDP :" + port + " echoed the probe; excluded from protocol attribution"); continue; }
        if (u.kind == "hysteria2" && quic_response_valid(u.result))
            note("quic-endpoint", "QUIC on :" + port + " answered; HTTP/3 and tunnel applications are not distinguished, including on a preset port");
        else if (u.kind == "hysteria2")
            note("udp-unmatched", "UDP :" + port + " returned bytes with no validated protocol match");
    }
    if (wg_attempted && !wg_answered) note("wg-silence-uninformative", "WG/AWG probes lack an authenticated handshake. Silence does not identify or exclude a listener; use a real client capture for awg-entropy.");
    if (r.wg_self.ran)
        note("wg-self-check", "keyed WireGuard handshake from this machine to :" + std::to_string(r.wg_self.port) +
             "; the node moves that peer's endpoint here until its own client sends again");
    else if (r.wg_self.requested)
        note("wg-self-check", "requested, not run: the keys could not be loaded (the text output names the file)");
    if (!r.udp_not_probed.empty()) {
        std::string ports;
        for (int p : r.udp_not_probed) ports += (ports.empty() ? "" : ",") + std::to_string(p);
        note("udp-not-probed", "QUIC probe cap reached; not probed: " + ports);
    }

    for (const auto& p : r.fps) {
        const auto port = ":" + std::to_string(p.port);
        if (p.tls && p.tls->ok) {
            service(p.port, "TLS " + p.tls->version + "; ALPN=" + (p.tls->alpn.empty() ? "none" : p.tls->alpn));
            const auto& t = *p.tls;
            if (t.certificate_present) {
                if (!t.certificate_times_valid) note("cert-invalid-time", port + " certificate validity dates are invalid");
                else {
                    if (t.certificate_expired) note("cert-expired", port + " certificate is expired; check renewal and the local clock");
                    if (t.certificate_not_yet_valid) note("cert-not-yet-valid", port + " certificate is not yet valid");
                    if (t.total_validity_seconds < 14 * 86400) note("cert-short-validity", port + " short-lived certificate; normal for public CAs too");
                }
                if (t.self_signed) note("cert-self-signed", port + " leaf signature verifies with its own key; client trust is untested");
            }
        }
        if (p.fp.service == "HTTP" && !p.fp.silent) service(p.port, "HTTP response; " + printable_prefix(p.fp.details, 160));
        if (p.fp.service == "SSH") service(p.port, "SSH banner; authentication untested");
        if (p.fp.connect_accepted || (p.connect && p.connect->connect_accepted)) {
            service(p.port, "HTTP CONNECT accepted; relay access untested");
            note("connect-unverified", port + " returned 2xx to CONNECT; no end-to-end relay check was performed");
        }
        if (p.fp.tspu_redirect) note("warning-redirect", port + " redirects to " + printable_prefix(p.fp.redirect_marker, 100) + "; server or intermediary origin unverified, not proof of operator blocking");
        if (p.sni) {
            note("sni-routing", port + " " + p.sni->pattern + "; " + std::to_string(p.sni->compared) + " comparable, " + std::to_string(p.sni->failed) + " failed probes; software unconfirmed");
            if (!p.sni->brand_claimed.empty()) note("cert-brand", port + " certificate names reference " + printable_prefix(p.sni->brand_claimed, 80) + "; issuer trust, ownership and hosting relationship unverified; reference only");
        }
        if (p.https) {
            const auto& h = *p.https;
            if (h.http_valid) service(p.port, "HTTPS status " + std::to_string(h.status_code) + (h.server_hdr.empty() ? "; optional Server header absent" : ""));
            else note("https-incomplete", port + " " + h.err + "; no application protocol attribution");
            if (h.has_proxy_leak) note("forwarding-headers", port + " forwarding headers observed; also common on ordinary reverse proxies");
        }
        if (p.ct) note("ct-search", port + (p.ct->lookup_complete ? (p.ct->found ? " crt.sh returned records; trust unchecked" : " crt.sh returned no rows; absence from all logs is not established") : " crt.sh lookup incomplete: " + p.ct->err));
        if (p.websocket && p.websocket->ws_upgrade) service(p.port, "WebSocket handshake verified on " + printable_prefix(p.websocket->path_hit, 80) + "; application protocol unknown");
        if (p.grpc && p.grpc->alpn_h2) note("http2-response", port + " " + p.grpc->note);
        if (p.j3a) {
            const auto& a = *p.j3a;
            std::string t = port + " " + std::to_string(a.resp) + " replied, " + std::to_string(a.closed) + " closed, " +
                            std::to_string(a.reset) + " reset, " + std::to_string(a.held) + " held open, " +
                            std::to_string(a.no_connect) + " no connect; reference only";
            if (r.channel.degraded) t += "; lossy path, silence is not evidence";
            note("junk-probes", t);
        }
        if (p.utls && !p.utls->verdict.empty()) note("tls-profile", port + " " + p.utls->verdict);
    }
    for (const auto& p : r.open_tcp) {
        if (p.banner.rfind("SSH-", 0) == 0) service(p.port, "SSH banner observed");
    }
    if (!r.open_tcp.empty()) note("port-profile", std::to_string(r.open_tcp.size()) + " TCP ports accepted connections; port numbers do not identify VPN software or panel installations");
    r.tcp_timeout_pattern = !r.scan_stats.skipped && r.scan_stats.scanned >= 1000 && r.open_tcp.empty() &&
        r.scan_stats.refused == 0 && r.scan_stats.timeouts >= r.scan_stats.scanned - r.scan_stats.scanned / 100;
    r.bgp_blackhole_likely = false;
    if (r.tcp_timeout_pattern) note("tcp-timeouts", "almost all TCP attempts timed out; filtering, loss, routing and an offline host remain possible; no BGP attribution");
    if (r.snitch && r.snitch->ok) note("latency", "RTT and GeoIP depend on observer location and routing; excluded from VPN scoring");
    if (r.scan_stats.skipped) note("scan-incomplete", "TCP scan was interrupted; untested ports remain unknown");
    if (r.hostnames.any()) note("hostname-markers", std::to_string(r.hostnames.marks.size()) + " naming associations; no score impact or protocol confirmation");
    if (r.ack_all_heuristic && !ack_all_suspected(r))
        note("flat-open-ports", std::to_string(r.open_tcp.size()) + " ports open with near-identical RTT; random control ports refused, so this is not treated as an ack-all path");

    // no verdict without a working instrument
    if (r.preflight_ran && r.preflight.blocked && !r.preflight.overridden) r.unreliable = true;
    else r.unreliable = false;
    r.overridden = r.preflight_ran && r.preflight.overridden;
    if (ack_all_suspected(r))
        r.failed_reasons.push_back("the target or its path accepted " + std::to_string(r.ack_all_control_open) + " of " +
                                   std::to_string(r.ack_all_control_tried) + " random control ports; open ports are not evidence");
    if (r.channel.unusable)
        r.failed_reasons.push_back("path lost " + std::to_string((int)std::lround(r.channel.loss * 100)) + "% of control connects");
    if (r.checks_applicable > 0 && (r.checks_applicable - r.checks_conclusive) * 2 > r.checks_applicable)
        r.failed_reasons.push_back(std::to_string(r.checks_applicable - r.checks_conclusive) + " of " +
                                   std::to_string(r.checks_applicable) + " applicable checks were inconclusive");
    if (r.scan_stats.skipped) r.failed_reasons.push_back("TCP scan interrupted");
    if (!observed) r.failed_reasons.push_back("no service answered in a way that can be attributed");

    r.score = std::clamp(r.score, 0, 100);
    // a-tier is a signature drop: never clean or noisy
    if (r.tspu_a_hits) r.score = std::min(r.score, 69);
    r.score_available = r.completed && !r.unreliable && r.failed_reasons.empty();
    r.label = !r.completed ? "INCONCLUSIVE" : r.unreliable ? "UNRELIABLE" : !r.score_available ? "INCONCLUSIVE" :
              r.score >= 85 ? "CLEAN" : r.score >= 70 ? "NOISY" : r.score >= 50 ? "SUSPICIOUS" : "OBVIOUSLY-VPN";
    r.stack_name.clear();
    for (const auto& s : services) { if (!r.stack_name.empty()) r.stack_name += "; "; r.stack_name += s; }
    if (r.stack_name.empty()) r.stack_name = observed ? "observed services; no VPN-specific response identified" : "insufficient service observations";
    r.tspu_tier = !r.score_available ? "UNKNOWN" : r.tspu_a_hits ? "IMMEDIATE BLOCK" : r.tspu_b_hits >= 2 ? "BLOCK (accumulative)" : r.tspu_b_hits ? "THROTTLE / QoS" : "PASS / ALLOW";
}

int report_exit_code(const FullReport& r) {
    if (!r.completed) return 64;
    if (r.unreliable) return 5;
    if (!r.score_available) return 4;
    return r.score >= 85 ? 0 : r.score >= 70 ? 1 : r.score >= 50 ? 2 : 3;
}
