// SPDX-License-Identifier: GPL-3.0-or-later
// FullReport: every observation a single target scan produces. lives long
// enough for the orchestrator to populate it and the verdict engine to read.
#pragma once

#include "../net/dns.h"
#include "../net/icmp.h"
#include "../net/udp.h"
#include "../geoip/geoip.h"
#include "../scan/tcp_scan.h"
#include "../scan/fingerprint.h"
#include "../scan/tls.h"
#include "../scan/https_probe.h"
#include "../scan/sni.h"
#include "../scan/j3.h"
#include "../scan/snitch.h"
#include "../scan/ct.h"
#include "../scan/utls.h"
#include "../scan/tcpfp.h"
#include "../scan/amnezia_probe.h"
#include "../scan/hostname_marks.h"
#include "../scan/grpc.h"
#include "../scan/transport_probe.h"
#include "../scan/wg_handshake.h"
#include "signals.h"
#include "preflight.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

// key udp results by kind and port; different probes can share a port.
// repeats of one probe are separate records with the same key.
struct UdpProbeRec {
    UdpProbeRec() = default;
    UdpProbeRec(int p, std::string k, UdpResult r) : port(p), kind(std::move(k)), result(std::move(r)) {}
    int         port = 0;
    std::string kind;        // "wg" / "amnezia" / "hysteria2" / "wg-keyed"
    UdpResult   result;
    // wg-keyed only: judged at probe time, the handshake state is wiped after
    Outcome     outcome = Outcome::NotApplicable;
    std::string detail;
};

// owner self-check with --wg-pubkey / --wg-key; no key material kept here
struct WgSelfCheck {
    bool        requested = false;
    bool        ran = false;
    int         port = 0;
    std::string error;       // names paths only, never printed to json
};

// connects to one open port before the probes; loss makes silence meaningless
struct ChannelQuality {
    bool   measured = false;
    int    port = 0;
    int    attempts = 0;
    int    ok = 0;
    double loss = 0.0;
    double rtt_median_ms = 0.0;
    double rtt_stddev_ms = 0.0;
    bool   degraded = false;   // silence-based output turns inconclusive
    bool   unusable = false;   // no verdict at all
};

struct ScoredSignal {
    std::string id;
    char        tier = 'A';
    int         weight = 0;
    int         port = 0;
    int         observations = 0;
    bool        heuristic = false;
    std::string observed;
};

struct FullReport {
    bool completed = false;
    std::string target;
    Resolved    dns;
    std::vector<GeoInfo> geos;
    std::vector<TcpOpen> open_tcp;
    std::vector<UdpProbeRec> udp_probes;
    WgSelfCheck wg_self;

    struct PortFp {
        int      port = 0;
        FpResult fp;
        std::optional<TlsProbe>       tls;
        std::optional<SniConsistency> sni;
        std::vector<J3Result>         j3;
        std::optional<J3Analysis>     j3a;
        std::optional<HttpsProbe>     https;
        std::optional<CtCheck>        ct;
        std::optional<GrpcProbe>      grpc;
        std::optional<WsProbe>        websocket;
        std::optional<FpResult>       connect;
        // per-port chrome-vs-openssl dual handshake. populated only
        // for tls-class ports (same gate as is_tls_port in the orchestrator).
        std::optional<UtlsDualProbe>  utls;
        std::vector<FpResult>         socks5_obs;   // repeated greetings
    };
    std::vector<PortFp> fps;

    // v2.4 phases
    std::optional<SnitchResult>          snitch;
    std::optional<TraceResult>           trace;
    std::optional<FpResult>              sstp;       // last observation
    std::vector<FpResult>                sstp_obs;   // every observation

    // measurement health
    PreflightReport preflight;
    bool            preflight_ran = false;
    ChannelQuality  channel;
    bool            ack_all_heuristic = false;   // many open ports, flat rtt
    int             ack_all_control_tried = 0;   // random high ports
    int             ack_all_control_open = 0;
    std::vector<int> udp_not_probed;             // cut by the port cap

    // scan-phase stats + blackhole detector
    ScanStats scan_stats;
    bool      bgp_blackhole_likely = false;
    bool      tcp_timeout_pattern = false;

    // per-host tcp behavior fingerprint (no admin, no raw socket).
    std::optional<TcpFp> tcp_fp;

    // amneziawg s1 junk-prefix size sweep on the default wg port.
    std::optional<AmneziaSweep> amnezia_sweep;

    // naming tells across every name we learned: the scanned host, the cert
    // cn, every san. costs nothing on the wire but is exactly what passive
    // dns and ct-log monitoring index.
    HostnameAnalysis hostnames;

    // verdict
    int         score = 0;
    bool        score_available = false;
    std::string label;
    std::vector<std::pair<int, std::string>> port_observations;

    // store verdict fields for the json report
    std::string                                     stack_name;
    std::vector<std::string>                        signals_major;
    std::vector<std::string>                        signals_minor;
    std::vector<std::pair<std::string,std::string>> notes;       // (tag, text)
    std::string                                     tspu_tier;   // pass / throttle / block / immediate-block
    int                                             tspu_a_hits = 0;
    int                                             tspu_b_hits = 0;

    // derived by evaluate_report
    std::vector<CheckResult>  checks;
    std::vector<ScoredSignal> scored;
    std::vector<std::string>  failed_reasons;    // why no verdict
    int  checks_applicable = 0;
    int  checks_conclusive = 0;
    bool unreliable = false;                     // preflight blocked, no override
    bool overridden = false;
};

// pure helpers, unit tested
std::vector<CheckResult> build_checks(const FullReport& r);
Outcome wg_keyed_outcome(const UdpResult& u, WgReply reply);
ChannelQuality assess_channel(int port, int attempts, const std::vector<double>& ok_rtts_ms);
bool ack_all_suspected(const FullReport& r);
