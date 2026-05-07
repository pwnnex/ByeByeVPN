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

#include <optional>
#include <string>
#include <utility>
#include <vector>

struct Advice {
    std::string kind;   // "risk" / "good" / "note"
    std::string text;
};

struct FullReport {
    std::string target;
    Resolved    dns;
    std::vector<GeoInfo> geos;
    std::vector<TcpOpen> open_tcp;
    std::vector<std::pair<int, UdpResult>> udp_probes;

    struct PortFp {
        int      port = 0;
        FpResult fp;
        std::optional<TlsProbe>       tls;
        std::optional<SniConsistency> sni;
        std::vector<J3Result>         j3;
        std::optional<J3Analysis>     j3a;
        std::optional<HttpsProbe>     https;
        std::optional<CtCheck>        ct;
    };
    std::vector<PortFp> fps;

    UdpResult quic;

    // v2.4 phases
    std::optional<SnitchResult>          snitch;
    std::optional<TraceResult>           trace;
    std::vector<std::pair<int,UdpResult>> udp_extra;
    std::optional<FpResult>              sstp;

    // v2.5.5 — scan-phase stats + blackhole detector
    ScanStats scan_stats;
    bool      bgp_blackhole_likely = false;

    // verdict
    int                      score = 0;
    std::string              label;
    std::vector<Advice>      advices;
    std::vector<std::string> guess_stack;
};
