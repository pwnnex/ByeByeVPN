// SPDX-License-Identifier: GPL-3.0-or-later
#include "grpc.h"
#include "../common/platform.h"
#include "../net/tcp.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <cstdint>
#include <cstring>
#include <vector>

using std::string;
using std::vector;

namespace {

// ALPN offer: prefer h2, allow http/1.1 fallback so the handshake still
// completes against a plain web server (we then see it chose http/1.1).
const unsigned char ALPN_H2[] = { 2,'h','2', 8,'h','t','t','p','/','1','.','1' };

// append a length-prefixed (no-Huffman) HPACK string literal.
void hpack_str(vector<uint8_t>& o, const string& s) {
    o.push_back((uint8_t)(s.size() & 0x7f));   // 7-bit length, H=0 (we keep <127)
    o.insert(o.end(), s.begin(), s.end());
}

// build the HPACK header block for a minimal gRPC request.
vector<uint8_t> grpc_headers_block(const string& authority, const string& path) {
    vector<uint8_t> h;
    h.push_back(0x83);                 // :method POST          (static idx 3)
    h.push_back(0x87);                 // :scheme https         (static idx 7)
    h.push_back(0x41); hpack_str(h, authority);                 // :authority (name idx 1)
    h.push_back(0x44); hpack_str(h, path);                      // :path      (name idx 4)
    h.push_back(0x5f); hpack_str(h, "application/grpc");        // content-type (name idx 31)
    // te: trailers  — literal with incremental indexing, new name
    h.push_back(0x40); hpack_str(h, "te"); hpack_str(h, "trailers");
    return h;
}

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
    set_socket_recv_timeout(s, to_ms);

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { closesocket(s); r.err = "ctx"; return r; }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL* ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); closesocket(s); r.err = "ssl alloc"; return r; }
    SSL_set_fd(ssl, (int)s);
    if (!sni.empty()) SSL_set_tlsext_host_name(ssl, sni.c_str());
    SSL_set_alpn_protos(ssl, ALPN_H2, sizeof(ALPN_H2));

    if (SSL_connect(ssl) != 1) {
        r.err = "tls handshake failed";
        SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
        return r;
    }
    r.tls_ok = true;
    const unsigned char* ap = nullptr; unsigned apl = 0;
    SSL_get0_alpn_selected(ssl, &ap, &apl);
    if (apl) r.alpn.assign((const char*)ap, apl);
    r.alpn_h2 = (r.alpn == "h2");

    if (!r.alpn_h2) {
        r.note = "server negotiated ALPN '" + (r.alpn.empty() ? string("-") : r.alpn) +
                 "' (not h2) — gRPC requires HTTP/2, so a gRPC transport is unlikely here";
        SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
        return r;
    }

    // h2 negotiated: send the client preface + SETTINGS + a gRPC HEADERS frame.
    static const char PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    vector<uint8_t> out(PREFACE, PREFACE + (sizeof(PREFACE) - 1));
    put_frame(out, 0x4, 0x0, 0, {});   // empty SETTINGS
    string authority = sni.empty() ? ip : sni;
    vector<uint8_t> hb = grpc_headers_block(
        authority, "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo");
    put_frame(out, 0x1, 0x5, 1, hb);   // HEADERS, END_HEADERS|END_STREAM, stream 1

    if (SSL_write(ssl, out.data(), (int)out.size()) <= 0) {
        r.err = "h2 write failed";
        SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
        return r;
    }

    vector<uint8_t> buf;
    char tmp[2048];
    for (int i = 0; i < 6; ++i) {
        int n = SSL_read(ssl, tmp, sizeof(tmp));
        if (n <= 0) break;
        buf.insert(buf.end(), tmp, tmp + n);
        if (buf.size() >= 8192) break;
    }
    SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);

    // best-effort marker scan (servers that don't Huffman-encode headers).
    for (size_t i = 0; i + 4 <= buf.size(); ++i)
        if (std::memcmp(buf.data() + i, "grpc", 4) == 0) { r.grpc_marker = true; break; }

    // walk HTTP/2 frames.
    size_t p = 0;
    while (p + 9 <= buf.size()) {
        uint32_t len = ((uint32_t)buf[p] << 16) | ((uint32_t)buf[p + 1] << 8) | buf[p + 2];
        uint8_t  type = buf[p + 3];
        uint32_t stream = (((uint32_t)buf[p + 5] << 24) | ((uint32_t)buf[p + 6] << 16) |
                           ((uint32_t)buf[p + 7] << 8) | buf[p + 8]) & 0x7fffffff;
        r.h2_frames = true;
        if (type == 0x1 && stream == 1) r.headers_resp = true;   // HEADERS
        if (type == 0x3 && stream == 1) r.stream_reset = true;   // RST_STREAM
        if (type == 0x7)                r.goaway = true;         // GOAWAY
        if (p + 9 + len < p + 9) break;                          // overflow guard
        p += 9 + len;
    }

    if (!r.h2_frames) {
        r.note = "ALPN h2 negotiated but the server returned no HTTP/2 frames to a "
                 "gRPC request — h2-advertised but unresponsive (stream-proxy tell)";
    } else if (r.headers_resp) {
        r.note = string("HTTP/2 server answered the gRPC request with a HEADERS frame") +
                 (r.grpc_marker ? " and gRPC markers — looks like a real gRPC service"
                                : " — an HTTP/2 request handler (gRPC service or h2 web app)");
    } else if (r.stream_reset) {
        r.note = "HTTP/2 server RST our gRPC stream — h2 origin that doesn't serve this "
                 "gRPC path (a VLESS/VMess-gRPC inbound routes only its configured "
                 "serviceName, or a non-gRPC h2 server)";
    } else if (r.goaway) {
        r.note = "HTTP/2 server sent GOAWAY to the gRPC request — rejected at the "
                 "connection level";
    } else {
        r.note = "HTTP/2 frames seen (SETTINGS) but no answer to the gRPC stream";
    }
    return r;
}
