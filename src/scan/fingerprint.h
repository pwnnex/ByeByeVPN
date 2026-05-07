// per-port service fingerprint probes: HTTP, SSH, SOCKS5, HTTP-CONNECT,
// shadowsocks heuristic, SSTP-over-TLS.
#pragma once

#include <string>

struct FpResult {
    std::string service;
    std::string details;
    std::string raw_hex;
    bool        is_vpn_like   = false;
    bool        silent        = false;
    bool        tspu_redirect = false;
    std::string redirect_target;
    std::string redirect_marker;
};

FpResult fp_http_plain   (const std::string& host, int port);
FpResult fp_ssh          (const std::string& banner_hint, const std::string& host, int port);
FpResult fp_socks5       (const std::string& host, int port);
FpResult fp_http_connect (const std::string& host, int port);
FpResult fp_shadowsocks  (const std::string& host, int port);

// SSTP probe wraps TLS first then sends the magic SSTP_DUPLEX_POST request.
FpResult sstp_probe(const std::string& host, int port);
