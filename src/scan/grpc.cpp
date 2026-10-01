// SPDX-License-Identifier: GPL-3.0-or-later
#include "grpc.h"
#include "https_probe.h"
#include <algorithm>
#include "tls_ctx.h"
#include "tls_io.h"
#include "../common/winhdr.h"
#include "../net/tcp.h"
#include "../common/util.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <cstdint>
#include <cstring>
#include <vector>

using std::string;
using std::vector;

namespace {

// alpn offer: prefer h2, allow http/1.1 fallback so the handshake still
// completes against a plain web server (we then see it chose http/1.1).
const unsigned char ALPN_H2[] = { 2,'h','2', 8,'h','t','t','p','/','1','.','1' };

void put_frame(vector<uint8_t>& o, uint8_t type, uint8_t flags,
               uint32_t stream, const vector<uint8_t>& payload) {
    uint32_t len = (uint32_t)payload.size();
    o.push_back((uint8_t)(len >> 16));
    o.push_back((uint8_t)(len >> 8));
    o.push_back((uint8_t)len);
    o.push_back(type);
    o.push_back(flags);
    o.push_back((uint8_t)(stream >> 24));
    o.push_back((uint8_t)(stream >> 16));
    o.push_back((uint8_t)(stream >> 8));
    o.push_back((uint8_t)stream);
    o.insert(o.end(), payload.begin(), payload.end());
}

} // namespace

GrpcProbe grpc_probe(const string& ip, int port, const string& sni, int to_ms) {
    GrpcProbe r;
    string err;
    SOCKET s = tcp_connect(ip, port, to_ms, err);
    if (s == INVALID_SOCKET) { r.err = err; return r; }
    DWORD tv = (DWORD)to_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { closesocket(s); r.err = "ctx"; return r; }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL* ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); closesocket(s); r.err = "ssl alloc"; return r; }
    SSL_set_fd(ssl, (int)s);
    if (!sni.empty() && !is_ip_literal(sni)) SSL_set_tlsext_host_name(ssl, sni.c_str());
    SSL_set_alpn_protos(ssl, ALPN_H2, sizeof(ALPN_H2));

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(to_ms);
    u_long nonblocking = 1;
    if (ioctlsocket(s, FIONBIO, &nonblocking) != 0) {
        r.err = "cannot enable nonblocking TLS I/O";
        SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s); return r;
    }
    auto transfer = [&](auto operation, const char* fallback) {
        return tls_io(ssl, s, deadline, operation, err, fallback);
    };
    if (transfer([&] { return SSL_connect(ssl); }, "TLS handshake failed") != 1) {
        r.err = err.empty() ? "TLS handshake closed" : err;
        SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s); return r;
    }
    r.tls_ok = true;
    const unsigned char* ap = nullptr; unsigned apl = 0;
    SSL_get0_alpn_selected(ssl, &ap, &apl);
    if (apl) r.alpn.assign((const char*)ap, apl);
    r.alpn_h2 = (r.alpn == "h2");

    if (!r.alpn_h2) {
        r.note = "server negotiated ALPN '" + (r.alpn.empty() ? string("-") : r.alpn) +
                 "' (not h2); gRPC requires HTTP/2, so a gRPC transport is unlikely here";
        SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
        return r;
    }

    // h2 negotiated: send the client preface + settings + a grpc headers frame.
    static const char PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    vector<uint8_t> out(PREFACE, PREFACE + (sizeof(PREFACE) - 1));
    put_frame(out, 0x4, 0x0, 0, {});   // empty settings
    string authority = http_authority(sni.empty() ? ip : sni, port);
    vector<uint8_t> hb = grpc_request_headers(
        authority, "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo");
    put_frame(out, 0x1, 0x5, 1, hb);   // headers, end_headers|end_stream, stream 1

    if (transfer([&] { return SSL_write(ssl, out.data(), (int)out.size()); }, "h2 write failed") != (int)out.size()) {
        r.err = "h2 write failed";
        SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
        return r;
    }

    vector<uint8_t> buf;
    char tmp[2048];
    while (buf.size() < 8192) {
        int n = transfer([&] { return SSL_read(ssl, tmp, static_cast<int>(std::min(sizeof(tmp), size_t(8192) - buf.size()))); }, "h2 read failed");
        if (n <= 0) break;
        buf.insert(buf.end(), tmp, tmp + n);
        analyze_h2_response(buf, r);
        if (r.headers_resp || r.stream_reset || r.goaway || (!r.err.empty() && r.err.rfind("incomplete", 0) != 0)) break;
    }
    SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);

    analyze_h2_response(buf, r);
    if (!err.empty()) r.err = r.err.empty() ? err : r.err + "; " + err;
    return r;
}
