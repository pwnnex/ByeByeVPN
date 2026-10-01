// SPDX-License-Identifier: GPL-3.0-or-later
#include "https_probe.h"
#include "tls_ctx.h"
#include "tls_io.h"
#include "../common/winhdr.h"
#include "../net/tcp.h"
#include "../common/util.h"

#include <openssl/ssl.h>
#include <algorithm>
#include <chrono>
#include <string>

HttpsProbe https_exchange(const std::string& ip, int port, const std::string& host_hdr,
                          const std::string& request, int to_ms) {
    HttpsProbe r;
    if (to_ms < 1 || request.empty() || request.size() > HTTPS_HEADER_LIMIT ||
        host_hdr.find_first_of("\r\n") != std::string::npos ||
        host_hdr.find('\0') != std::string::npos) {
        r.err = "invalid HTTP probe arguments";
        return r;
    }
    std::string error;
    SOCKET socket = tcp_connect(ip, port, to_ms, error);
    if (socket == INVALID_SOCKET) { r.err = error; return r; }
    SSL_CTX* ctx = shared_tls_client_ctx();
    SSL* ssl = ctx ? SSL_new(ctx) : nullptr;
    if (!ssl) { closesocket(socket); r.err = "ssl alloc"; return r; }
    SSL_set_fd(ssl, static_cast<int>(socket));
    if (!host_hdr.empty() && !is_ip_literal(host_hdr)) SSL_set_tlsext_host_name(ssl, host_hdr.c_str());
    static const unsigned char h11[] = {8,'h','t','t','p','/','1','.','1'};
    SSL_set_alpn_protos(ssl, h11, sizeof(h11));
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(to_ms);
    u_long nonblocking = 1;
    if (ioctlsocket(socket, FIONBIO, &nonblocking) != 0) {
        r.err = "cannot enable nonblocking TLS I/O";
        SSL_free(ssl); closesocket(socket); return r;
    }
    auto transfer = [&](auto operation, const char* fallback) {
        return tls_io(ssl, socket, deadline, operation, error, fallback);
    };
    if (transfer([&] { return SSL_connect(ssl); }, "TLS handshake failed") != 1) {
        r.err = error.empty() ? "TLS handshake closed" : error;
        SSL_free(ssl); closesocket(socket); return r;
    }
    const int written = transfer([&] { return SSL_write(ssl, request.data(), static_cast<int>(request.size())); }, "HTTP request write failed");
    const bool sent = written == static_cast<int>(request.size());
    if (!sent && error.empty()) error = "HTTP request was not fully written";
    std::string bytes;
    char buffer[1024];
    if (sent) {
        while (bytes.size() < HTTPS_HEADER_LIMIT) {
            const int size = transfer([&] {
                return SSL_read(ssl, buffer, static_cast<int>(std::min(sizeof(buffer), HTTPS_HEADER_LIMIT - bytes.size())));
            }, "HTTP response read failed");
            if (size <= 0) break;
            bytes.append(buffer, size);
            r = parse_https_response(bytes);
            if (r.headers_complete) break;
            if (!r.err.empty() && r.err.rfind("incomplete", 0) != 0) break;
        }
    }
    SSL_free(ssl);
    closesocket(socket);
    r = parse_https_response(bytes);
    r.tls_ok = true;
    r.request_sent = sent;
    if (!error.empty()) r.err = r.err.empty() ? error : r.err + "; " + error;
    return r;
}

HttpsProbe https_probe(const std::string& ip, int port, const std::string& host_hdr, int to_ms) {
    const auto authority = http_authority(host_hdr.empty() ? ip : host_hdr, port);
    if (authority.empty()) { HttpsProbe r; r.err = "invalid HTTP authority"; return r; }
    return https_exchange(ip, port, host_hdr,
        "GET / HTTP/1.1\r\nHost: " + authority + "\r\nAccept: */*\r\nConnection: close\r\n\r\n", to_ms);
}
