// SPDX-License-Identifier: GPL-3.0-or-later
#include "https_probe.h"
#include "tls_ctx.h"
#include "../common/winhdr.h"
#include "../common/util.h"
#include "../net/tcp.h"

#include <openssl/ssl.h>

#include <string>

using std::string;

HttpsProbe https_probe(const string& ip, int port, const string& host_hdr, int to_ms) {
    HttpsProbe r;
    string err;
    SOCKET s = tcp_connect(ip, port, to_ms, err);
    if (s == INVALID_SOCKET) { r.err = err; return r; }

    SSL_CTX* ctx = shared_tls_client_ctx();
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)s);
    if (!host_hdr.empty()) SSL_set_tlsext_host_name(ssl, host_hdr.c_str());
    static const unsigned char alpn_h11[] = {8,'h','t','t','p','/','1','.','1'};
    SSL_set_alpn_protos(ssl, alpn_h11, sizeof(alpn_h11));
    if (SSL_connect(ssl) != 1) {
        r.err = "tls handshake failed";
        SSL_free(ssl); closesocket(s);
        return r;
    }
    r.tls_ok = true;
    string req = "GET / HTTP/1.1\r\nHost: " +
                 (host_hdr.empty() ? string("example.com") : host_hdr) +
                 "\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    SSL_write(ssl, req.data(), (int)req.size());

    string body;
    char buf[1024];
    for (int i = 0; i < 6; ++i) {
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) break;
        body.append(buf, n);
        if (body.size() >= 4096) break;
    }
    SSL_shutdown(ssl); SSL_free(ssl); closesocket(s);
    r.bytes = (int)body.size();
    if (body.empty()) return r;
    r.responded = true;
    size_t nl = body.find('\n');
    r.first_line = trim(body.substr(0, nl == string::npos ? body.size() : nl));

    if (starts_with(r.first_line, "HTTP/")) {
        size_t sp = r.first_line.find(' ');
        r.http_version = r.first_line.substr(0, sp == string::npos ? r.first_line.size() : sp);
        if (r.http_version.size() >= 8) {
            char x = r.http_version[5], y = r.http_version[7];
            if (!(x == '1' || x == '2') || !(y == '0' || y == '1')) r.version_anomaly = true;
            if (x == '0') r.version_anomaly = true;
        } else r.version_anomaly = true;
        if (sp != string::npos) {
            size_t sp2 = r.first_line.find(' ', sp + 1);
            if (sp2 != string::npos) {
                string code = r.first_line.substr(sp + 1, sp2 - sp - 1);
                r.status_code = std::atoi(code.c_str());
            }
        }
    } else {
        r.version_anomaly = true;
    }

    // Server: header
    size_t sh = body.find("\nServer:");
    if (sh == string::npos) sh = body.find("\nserver:");
    if (sh != string::npos) {
        size_t se = body.find('\n', sh + 1);
        string sv = body.substr(sh + 8, (se == string::npos ? body.size() : se) - (sh + 8));
        r.server_hdr = trim(sv);
    } else {
        r.no_server_hdr = (r.status_code > 0);
    }

    // case-insensitive header lookup. precompute lowercase body once
    // (was twice per call in the original — minor saving).
    string body_lower = tolower_s(body);
    auto get_hdr = [&](const char* key) -> string {
        string lk = string("\n") + key;
        for (auto& c: lk) c = (char)std::tolower((unsigned char)c);
        size_t p = body_lower.find(lk);
        if (p == string::npos) return {};
        size_t eol = body.find('\n', p + 1);
        size_t colon = body.find(':', p + 1);
        if (colon == string::npos || (eol != string::npos && colon > eol)) return {};
        string val = body.substr(colon + 1, (eol == string::npos ? body.size() : eol) - (colon + 1));
        return trim(val);
    };
    r.via_hdr           = get_hdr("Via");
    r.forwarded_hdr     = get_hdr("Forwarded");
    r.xff_hdr           = get_hdr("X-Forwarded-For");
    r.xreal_ip_hdr      = get_hdr("X-Real-IP");
    r.x_forwarded_proto = get_hdr("X-Forwarded-Proto");
    r.x_forwarded_host  = get_hdr("X-Forwarded-Host");
    r.cf_ray_hdr        = get_hdr("CF-Ray");
    r.cf_cache_status   = get_hdr("CF-Cache-Status");
    r.x_amz_cf_id       = get_hdr("X-Amz-Cf-Id");
    r.x_amz_cf_pop      = get_hdr("X-Amz-Cf-Pop");
    r.x_azure_ref       = get_hdr("X-Azure-Ref");
    r.x_azure_clientip  = get_hdr("X-Azure-ClientIP");
    r.x_cache           = get_hdr("X-Cache");
    r.x_served_by       = get_hdr("X-Served-By");
    r.alt_svc           = get_hdr("Alt-Svc");

    r.has_proxy_leak = !r.via_hdr.empty() ||
                       !r.forwarded_hdr.empty() ||
                       !r.xff_hdr.empty() ||
                       !r.xreal_ip_hdr.empty();
    r.has_cdn_hdr    = !r.cf_ray_hdr.empty() ||
                       !r.x_amz_cf_id.empty() ||
                       !r.x_azure_ref.empty() ||
                       !r.x_served_by.empty();
    return r;
}