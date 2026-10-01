// SPDX-License-Identifier: GPL-3.0-or-later
// bounded http/1.x response observations over tls; no protocol attribution.
#pragma once

#include <string>
#include <map>

struct HttpsProbe {
    bool        tls_ok    = false;
    bool        responded = false;
    bool        request_sent = false;
    bool        headers_complete = false;
    bool        http_valid = false;
    int         bytes     = 0;
    std::string first_line;
    std::string server_hdr;
    std::string http_version;
    int         status_code     = 0;
    std::map<std::string, std::string> headers;
    bool        version_anomaly = false;
    // check server_hdr.empty() when needed; no duplicate flag

    // observed forwarding headers; these do not establish an open proxy or vpn.
    std::string via_hdr;
    std::string forwarded_hdr;
    std::string xff_hdr;
    std::string xreal_ip_hdr;
    std::string x_forwarded_proto;
    std::string x_forwarded_host;
    std::string cf_ray_hdr;
    std::string cf_cache_status;
    std::string x_amz_cf_id;
    std::string x_amz_cf_pop;
    std::string x_azure_ref;
    std::string x_azure_clientip;
    std::string x_cache;
    std::string x_served_by;
    std::string alt_svc;
    bool        has_proxy_leak = false;
    bool        has_cdn_hdr    = false;
    std::string err;
};

HttpsProbe https_probe(const std::string& ip, int port,
                       const std::string& host_hdr, int to_ms = 5000);
HttpsProbe https_exchange(const std::string& ip, int port, const std::string& sni,
                          const std::string& request, int to_ms);
std::string http_authority(const std::string& host, int port, int default_port = 443);

// pure parser; skips interim responses and ignores body text.
HttpsProbe parse_https_response(const std::string& bytes);
constexpr size_t HTTPS_HEADER_LIMIT = 16 * 1024;
