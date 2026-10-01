// SPDX-License-Identifier: GPL-3.0-or-later
#include "tls.h"
#include "tls_ctx.h"
#include "../common/winhdr.h"
#include "../common/util.h"
#include "../net/tcp.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <chrono>
#include <vector>

using std::string;
using std::vector;

TlsProbe tls_probe(const string& ip, int port, const string& sni,
                   const string& alpn, int to_ms) {
    TlsProbe r;
    auto t0 = std::chrono::steady_clock::now();
    string err; SOCKET s = tcp_connect(ip, port, to_ms, err);
    if (s == INVALID_SOCKET) { r.err = err; return r; }

    SSL_CTX* ctx = shared_tls_client_ctx();
    SSL* ssl = ctx ? SSL_new(ctx) : nullptr;
    if (!ssl) { closesocket(s); r.err = "ssl alloc"; return r; }
    SSL_set_fd(ssl, (int)s);
    if (!sni.empty() && !is_ip_literal(sni)) SSL_set_tlsext_host_name(ssl, sni.c_str());

    // alpn wire format: [len][bytes][len][bytes]...
    vector<unsigned char> wire;
    for (auto& p: split(alpn, ',')) {
        string v = trim(p); if (v.empty()) continue;
        wire.push_back((unsigned char)v.size());
        for (char c: v) wire.push_back((unsigned char)c);
    }
    if (!wire.empty()) SSL_set_alpn_protos(ssl, wire.data(), (unsigned)wire.size());

    ssl_clear_errors();
    if (SSL_connect(ssl) != 1) {
        r.err = ssl_error_string("tls handshake failed");
        SSL_free(ssl); closesocket(s);
        return r;
    }
    r.ok = true;
    r.version = SSL_get_version(ssl);
    r.cipher  = SSL_get_cipher_name(ssl);
    const unsigned char* ap = nullptr; unsigned apl = 0;
    SSL_get0_alpn_selected(ssl, &ap, &apl);
    if (apl) r.alpn.assign((const char*)ap, apl);
    int nid = SSL_get_negotiated_group(ssl);
    const char* gn = OBJ_nid2sn(nid);
    if (gn) r.group = gn;

    X509* cert = SSL_get_peer_certificate(ssl);
    inspect_certificate(cert, r, std::time(nullptr));
    X509_free(cert);
    SSL_shutdown(ssl);
    SSL_free(ssl); closesocket(s);
    r.handshake_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0).count();
    return r;
}