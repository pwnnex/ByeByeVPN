#ifndef NETWORK_SERVICE_PROBES_H
#define NETWORK_SERVICE_PROBES_H

#include <string>

struct FpResult {
    std::string service;
    std::string details;
    std::string raw_hex;
    bool   is_vpn_like = false;
    bool   silent      = false;
    bool   tspu_redirect = false;
    std::string redirect_target;
    std::string redirect_marker;
};

std::string printable_prefix(const std::string& s, size_t lim = 80);

FpResult fp_http_plain(const std::string& host, int port);
FpResult fp_ssh(const std::string& banner_hint, const std::string& host, int port);
FpResult fp_socks5(const std::string& host, int port);
FpResult fp_http_connect(const std::string& host, int port);
FpResult fp_shadowsocks(const std::string& host, int port);

#endif // NETWORK_SERVICE_PROBES_H