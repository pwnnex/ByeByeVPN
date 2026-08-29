// SPDX-License-Identifier: GPL-3.0-or-later
#include "transport_probe.h"
#include "tls_ctx.h"
#include "../common/platform.h"
#include "../common/util.h"
#include "../net/tcp.h"

#include <openssl/ssl.h>

#include <string>
#include <vector>

using std::string;
using std::vector;

namespace {

// one TLS request/response round-trip. returns the raw response (up to ~4 KB)
// or empty on failure; *ok reports whether the TLS handshake completed.
string tls_round_trip(const string& ip, int port, const string& sni,
                      const string& request, int to_ms, bool& tls_ok) {
    tls_ok = false;
    string err;
    SOCKET s = tcp_connect(ip, port, to_ms, err);
    if (s == INVALID_SOCKET) return {};
    set_socket_recv_timeout(s, to_ms);

    SSL_CTX* ctx = shared_tls_client_ctx();
    SSL* ssl = ctx ? SSL_new(ctx) : nullptr;
    if (!ssl) { closesocket(s); return {}; }
    SSL_set_fd(ssl, (int)s);
    if (!sni.empty()) SSL_set_tlsext_host_name(ssl, sni.c_str());
    static const unsigned char alpn_h11[] = {8,'h','t','t','p','/','1','.','1'};
    SSL_set_alpn_protos(ssl, alpn_h11, sizeof(alpn_h11));
    if (SSL_connect(ssl) != 1) { SSL_free(ssl); closesocket(s); return {}; }
    tls_ok = true;

    string out;
    if (SSL_write(ssl, request.data(), (int)request.size()) > 0) {
        char buf[1024];
        for (int i = 0; i < 5; ++i) {
            int n = SSL_read(ssl, buf, sizeof(buf));
            if (n <= 0) break;
            out.append(buf, n);
            if (out.size() >= 4096) break;
        }
    }
    SSL_shutdown(ssl); SSL_free(ssl); closesocket(s);
    return out;
}

string first_line_of(const string& resp) {
    size_t nl = resp.find('\n');
    return trim(resp.substr(0, nl == string::npos ? resp.size() : nl));
}

int status_of(const string& first) {
    if (first.compare(0, 5, "HTTP/") != 0) return 0;
    size_t sp = first.find(' ');
    if (sp == string::npos) return 0;
    return std::atoi(first.c_str() + sp + 1);
}

} // namespace

WsProbe ws_probe(const string& ip, int port, const string& sni, int to_ms) {
    WsProbe r;
    // common VLESS/VMess-ws paths people leave on defaults.
    static const char* PATHS[] = { "/", "/ws", "/vless", "/vmess", "/websocket", "/ray" };
    for (const char* path : PATHS) {
        string host = sni.empty() ? ip : sni;
        string req =
            string("GET ") + path + " HTTP/1.1\r\n"
            "Host: " + host + "\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n";
        bool ok = false;
        string resp = tls_round_trip(ip, port, sni, req, to_ms, ok);
        if (ok) r.tls_ok = true;
        if (resp.empty()) continue;
        string fl = first_line_of(resp);
        if (status_of(fl) == 101) {           // Switching Protocols
            r.ws_upgrade = true;
            r.path_hit = path;
            r.first_line = fl;
            return r;
        }
        if (r.first_line.empty()) r.first_line = fl;
    }
    return r;
}
