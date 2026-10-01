// SPDX-License-Identifier: GPL-3.0-or-later
// per-port service fingerprint probes: http, ssh, socks5, http-connect,
// shadowsocks heuristic, sstp-over-tls.
#pragma once

#include <string>
#include "https_probe.h"
#include "../common/outcome.h"
#include "../net/read_end.h"

struct FpResult {
    std::string service;
    std::string details;
    std::string raw_hex;
    bool        is_vpn_like   = false;
    bool        silent        = false;
    bool        tspu_redirect = false;
    bool        connect_accepted = false;
    std::string redirect_target;
    std::string redirect_marker;
    Outcome     outcome = Outcome::Inconclusive;   // for the probed protocol
    ReadEnd     end = ReadEnd::NoConnect;
};

FpResult fp_http_plain   (const std::string& host, int port);
FpResult fp_ssh          (const std::string& banner_hint, const std::string& host, int port);
FpResult fp_socks5       (const std::string& host, int port);
FpResult fp_http_connect (const std::string& host, int port);
FpResult fp_shadowsocks  (const std::string& host, int port);

// sstp probe wraps tls first then sends the magic sstp_duplex_post request.
// sni: a hostname, or empty for none; never an ip literal.
FpResult sstp_probe(const std::string& host, int port, const std::string& sni = "");
FpResult http_fingerprint_response(const HttpsProbe& response, bool connect_probe = false);
FpResult sstp_response(const HttpsProbe& response);

// pure outcome rules, unit tested
Outcome socks5_reply_outcome(const unsigned char* reply, int n, ReadEnd end);
std::string sstp_setup_request(const std::string& authority, const unsigned char guid[16]);
