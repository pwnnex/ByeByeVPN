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

#include <optional>
#include <string>
#include <utility>
#include <vector>

struct Advice {
    std::string kind;   // "risk" / "good" / "note"
    std::string text;
};

// one UDP probe result tagged by protocol kind. since v2.6.0 two probes
// can target the same port (vanilla WireGuard vs AmneziaWG both on 51820),
// so the verdict engine keys on `kind`, not just `port`.
struct UdpProbeRec {
    int         port = 0;
    std::string kind;        // "wg" / "amnezia" / "hysteria2"
    UdpResult   result;
};

struct FullReport {
    std::string target;
    Resolved    dns;
    std::vector<GeoInfo> geos;
    std::vector<TcpOpen> open_tcp;
    std::vector<UdpProbeRec> udp_probes;

    struct PortFp {
        int      port = 0;
        FpResult fp;
        std::optional<TlsProbe>       tls;
        std::optional<SniConsistency> sni;
        std::vector<J3Result>         j3;
        std::optional<J3Analysis>     j3a;
        std::optional<HttpsProbe>     https;
        std::optional<CtCheck>        ct;
        // v2.5.9: per-port chrome-vs-openssl dual handshake. populated only
        // for TLS-class ports (same gate as is_tls_port in the orchestrator).
        std::optional<UtlsDualProbe>  utls;
    };
    std::vector<PortFp> fps;

    // v2.4 phases
    std::optional<SnitchResult>          snitch;
    std::optional<TraceResult>           trace;
    std::optional<FpResult>              sstp;

    // v2.5.5 — scan-phase stats + blackhole detector
    ScanStats scan_stats;
    bool      bgp_blackhole_likely = false;

    // v2.5.9 - per-host TCP behavior fingerprint (no admin, no raw socket).
    std::optional<TcpFp> tcp_fp;

    // v2.6.0 - AmneziaWG S1 junk-prefix size sweep on the default WG port.
    std::optional<AmneziaSweep> amnezia_sweep;

    // verdict
    int                      score = 0;
    std::string              label;
    std::vector<Advice>      advices;
    std::vector<std::string> guess_stack;

    // v2.6.0 - verdict fields captured for the --json report. these are
    // computed as locals in the verdict block and mirrored here so the
    // JSON serializer does not have to re-derive anything.
    std::string                                     stack_name;
    std::vector<std::string>                        signals_major;
    std::vector<std::string>                        signals_minor;
    std::vector<std::pair<std::string,std::string>> notes;       // (tag, text)
    std::string                                     tspu_tier;   // PASS / THROTTLE / BLOCK / IMMEDIATE-BLOCK
    int                                             tspu_a_hits = 0;
    int                                             tspu_b_hits = 0;
};