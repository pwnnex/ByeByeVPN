#ifndef ANALYSIS_VERDICT_H
#define ANALYSIS_VERDICT_H

#include <string>
#include <vector>
#include <optional>
#include "../network/dns.h"
#include "geoip.h"
#include "../network/port_scan.h"
#include "../network/udp_scanner.h"
#include "../network/service_probes.h"
#include "../network/tls_probe.h"
#include "sni_consistency.h"
#include "../network/j3_probes.h"
#include "../network/https_probe.h"
#include "ct_check.h"
#include "snitch.h"
#include "traceroute.h"

using std::optional;

struct Ja3Info {
    std::string version;
    std::string ciphers;
    std::string extensions;
    std::string groups;
    std::string ec_formats;
    std::string ja3_hash;
};
Ja3Info our_openssl_ja3_signature();

struct Advice {
    std::string  kind;
    std::string  text;
};

struct FullReport {
    std::string target;
    Resolved dns;
    std::vector<GeoInfo> geos;
    std::vector<TcpOpen> open_tcp;
    std::vector<std::pair<int,UdpResult>> udp_probes;
    struct PortFp {
        int port;
        FpResult fp;
        optional<TlsProbe>        tls;
        optional<SniConsistency>  sni;
        std::vector<J3Result>          j3;
        optional<J3Analysis>      j3a;
        optional<HttpsProbe>      https;
        optional<CtCheck>         ct;
    };
    std::vector<PortFp> fps;
    UdpResult quic;
    optional<SnitchResult>             snitch;
    optional<TraceResult>              trace;
    std::vector<std::pair<int,UdpResult>>   udp_extra;
    optional<FpResult>                 sstp;
    ScanStats scan_stats;
    bool      bgp_blackhole_likely = false;
    int    score = 0;
    std::string label;
    std::vector<Advice> advices;
    std::vector<std::string> guess_stack;
};

#endif // ANALYSIS_VERDICT_H