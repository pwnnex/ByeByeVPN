#include "http_client.h"
#include <memory>
#include "tcp_scanner.h"
#include "../core/utils.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <chrono>
#include <vector>

HttpResp http_get(const std::string& url, int timeout_ms) {
    HttpResp r;
    auto t0 = std::chrono::steady_clock::now();
    
    // Simple URL parser
    std::string host, path = "/";
    int port = 80;
    bool is_https = false;
    
    std::string u = url;
    if (starts_with(u, "https://")) { is_https = true; port = 443; u = u.substr(8); }
    else if (starts_with(u, "http://")) { u = u.substr(7); }
    else { r.err = "bad url scheme"; return r; }
    
    size_t slash = u.find('/');
    if (slash != std::string::npos) {
        host = u.substr(0, slash);
        path = u.substr(slash);
    } else {
        host = u;
    }
    
    size_t colon = host.find(':');
    if (colon != std::string::npos) {
        port = std::stoi(host.substr(colon + 1));
        host = host.substr(0, colon);
    }

    std::string err;
    SOCKET s = tcp_connect(host, port, timeout_ms, err);
    if (s == INVALID_SOCKET) { r.err = "connect " + err; return r; }

    SSL_CTX* raw_ctx = nullptr;
    SSL* raw_ssl = nullptr;
    if (is_https) {
        raw_ctx = SSL_CTX_new(TLS_client_method());
        raw_ssl = SSL_new(raw_ctx);
        SSL_set_fd(raw_ssl, (int)s);
        SSL_set_tlsext_host_name(raw_ssl, host.c_str());
        
        // Timeout handling for SSL handshake is complex in non-blocking, so we rely on TCP timeout blocking
        if (SSL_connect(raw_ssl) <= 0) {
            r.err = "ssl_connect";
            SSL_free(raw_ssl);
            SSL_CTX_free(raw_ctx);
            closesocket(s);
            return r;
        }
    }

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(raw_ctx, SSL_CTX_free);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(raw_ssl, SSL_free);

    std::string req = "GET " + path + " HTTP/1.1\r\n"
                      "Host: " + host + "\r\n"
                      "Connection: close\r\n"
                      "User-Agent: \r\n"
                      "\r\n";

    if (is_https) {
        SSL_write(ssl.get(), req.data(), req.size());
    } else {
        tcp_send_all(s, req.data(), req.size());
    }

    std::string resp_data;
    char buf[4096];
    while (true) {
        int got = 0;
        if (is_https) {
            got = SSL_read(ssl.get(), buf, sizeof(buf));
        } else {
            got = tcp_recv_to(s, buf, sizeof(buf), timeout_ms);
        }
        if (got <= 0) break;
        resp_data.append(buf, got);
        if (resp_data.size() > 1024 * 1024) break; // 1MB max
    }

    closesocket(s);

    size_t header_end = resp_data.find("\r\n\r\n");
    if (header_end != std::string::npos) {
        std::string headers = resp_data.substr(0, header_end);
        r.body = resp_data.substr(header_end + 4);
        
        size_t space1 = headers.find(' ');
        if (space1 != std::string::npos) {
            size_t space2 = headers.find(' ', space1 + 1);
            if (space2 != std::string::npos) {
                r.status = std::stoi(headers.substr(space1 + 1, space2 - space1 - 1));
            }
        }
        
        // Handle chunked transfer encoding loosely
        std::string h_lower = tolower_s(headers);
        if (h_lower.find("transfer-encoding: chunked") != std::string::npos) {
            std::string decoded;
            size_t pos = 0;
            while (pos < r.body.size()) {
                size_t nl = r.body.find("\r\n", pos);
                if (nl == std::string::npos) break;
                std::string hex_len = r.body.substr(pos, nl - pos);
                int len = 0;
                try { len = std::stoi(hex_len, nullptr, 16); } catch(...) { break; }
                if (len == 0) break;
                pos = nl + 2;
                if (pos + len > r.body.size()) break;
                decoded.append(r.body.substr(pos, len));
                pos += len + 2; // skip \r\n
            }
            r.body = decoded;
        }
    } else {
        r.err = "no header";
    }

    r.ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count());
    return r;
}