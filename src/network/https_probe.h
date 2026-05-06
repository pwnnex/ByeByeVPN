#ifndef NETWORK_HTTPS_PROBE_H
#define NETWORK_HTTPS_PROBE_H

#include <string>

struct HttpsProbe {
    bool   tls_ok   = false;
    bool   responded = false;
    int    bytes    = 0;
    std::string first_line;
    std::string server_hdr;
    std::string http_version;
    int    status_code = 0;
    bool   version_anomaly = false;
    bool   no_server_hdr   = false;
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
    bool   has_proxy_leak = false;
    bool   has_cdn_hdr = false;
    std::string err;
};

HttpsProbe https_probe(const std::string& ip, int port, const std::string& host_hdr, int to_ms = 5000);

#endif // NETWORK_HTTPS_PROBE_H