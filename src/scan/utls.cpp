// SPDX-License-Identifier: GPL-3.0-or-later
#include "utls.h"
#include "../common/winhdr.h"
#include "../common/util.h"
#include "../net/tcp.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <chrono>
#include <cstring>

using std::string;
using std::vector;

namespace {

// callback ctx attached via SSL_set_msg_callback_arg. captures the FIRST
// outbound ClientHello and the FIRST inbound ServerHello as raw bytes
// starting from the HandshakeType byte (no TLS record header).
struct CapCtx {
    vector<uint8_t> ch;
    vector<uint8_t> sh;
};

void msg_cb(int write_p, int /*version*/, int content_type,
            const void* buf, size_t len, SSL* /*ssl*/, void* arg) {
    if (content_type != SSL3_RT_HANDSHAKE) return;
    if (!arg || !buf || len == 0) return;
    auto* c = static_cast<CapCtx*>(arg);
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    if (write_p == 1 && p[0] == 0x01 /*ClientHello*/ && c->ch.empty()) {
        c->ch.assign(p, p + len);
    } else if (write_p == 0 && p[0] == 0x02 /*ServerHello*/ && c->sh.empty()) {
        c->sh.assign(p, p + len);
    }
}

// Chrome 13x cipher list ordered as the real client emits it. names are the
// IANA / OpenSSL form so SSL_CTX_set_ciphersuites + set_cipher_list accept them.
// TLS 1.3 suites go via set_ciphersuites, TLS 1.2 via set_cipher_list.
const char* CHROME_TLS13_SUITES =
    "TLS_AES_128_GCM_SHA256:"
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256";

const char* CHROME_TLS12_LIST =
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "AES128-GCM-SHA256:"
    "AES256-GCM-SHA384:"
    "AES128-SHA:"
    "AES256-SHA";

// Chrome group preference. real Chrome 130+ prepends X25519MLKEM768
// (0x11ec) but OpenSSL 3.2+ accepts it only when MLKEM is compiled in.
// keep "X25519:P-256:P-384:P-521" which is universally supported and
// still ordered Chrome-style. avoids JA3 that screams "openssl-default".
const char* CHROME_GROUPS_LIST = "X25519:P-256:P-384:P-521";

// Chrome sigalgs preference. real Chrome includes ed25519, ecdsa, rsa-pss
// in this order. we mirror it.
const char* CHROME_SIGALGS_LIST =
    "ECDSA+SHA256:"
    "RSA-PSS+SHA256:"
    "RSA+SHA256:"
    "ECDSA+SHA384:"
    "RSA-PSS+SHA384:"
    "RSA+SHA384:"
    "RSA-PSS+SHA512:"
    "RSA+SHA512";

// Chrome ALPN: h2 first, http/1.1 fallback.
const unsigned char CHROME_ALPN[] = {
    2, 'h','2',
    8, 'h','t','t','p','/','1','.','1'
};

// minimal ALPN matching what existing tls_probe sends, so the openssl-default
// flavor matches the rest of the tool's behavior (no second JA4 surface).
const unsigned char DEFAULT_ALPN[] = {
    2, 'h','2',
    8, 'h','t','t','p','/','1','.','1'
};

string cert_sha256_hex(X509* cert) {
    if (!cert) return {};
    unsigned char dgst[32]; unsigned dl = 0;
    if (X509_digest(cert, EVP_sha256(), dgst, &dl) != 1) return {};
    static const char hexd[] = "0123456789abcdef";
    string s; s.reserve(dl * 2);
    for (unsigned i = 0; i < dl; ++i) {
        s += hexd[(dgst[i] >> 4) & 0xF];
        s += hexd[dgst[i] & 0xF];
    }
    return s;
}

UtlsProbeResult run_one(const string& ip, int port, const string& sni,
                        bool chrome_flavor, int to_ms) {
    UtlsProbeResult r;
    r.flavor = chrome_flavor ? "chrome" : "openssl";

    auto t0 = std::chrono::steady_clock::now();
    string err;
    SOCKET s = tcp_connect(ip, port, to_ms, err);
    if (s == INVALID_SOCKET) { r.err = err; return r; }

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        closesocket(s);
        r.err = "ctx alloc";
        return r;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);

    if (chrome_flavor) {
        // restrict cipher list to chrome's preferences. failures here are
        // non-fatal: if openssl rejects an entry, set_cipher_list returns 0
        // but the ones it accepted stay configured.
        SSL_CTX_set_ciphersuites(ctx, CHROME_TLS13_SUITES);
        SSL_CTX_set_cipher_list(ctx, CHROME_TLS12_LIST);
        SSL_CTX_set1_groups_list(ctx, CHROME_GROUPS_LIST);
        SSL_CTX_set1_sigalgs_list(ctx, CHROME_SIGALGS_LIST);
    }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx); closesocket(s);
        r.err = "ssl alloc";
        return r;
    }
    SSL_set_fd(ssl, (int)s);
    if (!sni.empty()) SSL_set_tlsext_host_name(ssl, sni.c_str());

    // ALPN. wire bytes are identical between flavors so the change vector
    // stays JA4-side, not ALPN-side.
    if (chrome_flavor) {
        SSL_set_alpn_protos(ssl, CHROME_ALPN, sizeof(CHROME_ALPN));
    } else {
        SSL_set_alpn_protos(ssl, DEFAULT_ALPN, sizeof(DEFAULT_ALPN));
    }

    CapCtx cap;
    SSL_set_msg_callback(ssl, msg_cb);
    SSL_set_msg_callback_arg(ssl, &cap);

    int rc = SSL_connect(ssl);
    r.handshake_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0).count();

    if (rc != 1) {
        // capture alert / error string
        unsigned long e = ERR_get_error();
        char eb[256] = {0};
        ERR_error_string_n(e, eb, sizeof(eb));
        r.err = eb[0] ? string(eb) : string("tls handshake failed");
        // even on failure we may have the captured CH/SH bytes
        r.ch_bytes = std::move(cap.ch);
        r.sh_bytes = std::move(cap.sh);
        SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
    } else {
        r.handshake_completed = true;
        const char* v = SSL_get_version(ssl);
        if (v) {
            if      (!std::strcmp(v, "TLSv1.3")) r.tls_version = 0x0304;
            else if (!std::strcmp(v, "TLSv1.2")) r.tls_version = 0x0303;
            else if (!std::strcmp(v, "TLSv1.1")) r.tls_version = 0x0302;
            else if (!std::strcmp(v, "TLSv1"))   r.tls_version = 0x0301;
        }
        const char* cn = SSL_get_cipher_name(ssl);
        if (cn) r.cipher = cn;
        const unsigned char* ap = nullptr; unsigned apl = 0;
        SSL_get0_alpn_selected(ssl, &ap, &apl);
        if (apl) r.alpn.assign((const char*)ap, apl);

        X509* cert = SSL_get_peer_certificate(ssl);
        if (cert) {
            r.cert_sha256 = cert_sha256_hex(cert);
            X509_free(cert);
        }
        r.ch_bytes = std::move(cap.ch);
        r.sh_bytes = std::move(cap.sh);

        SSL_shutdown(ssl);
        SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
    }

    // best-effort parse + JA4 even on partial captures
    if (!r.ch_bytes.empty()) {
        if (parse_client_hello(r.ch_bytes.data(), r.ch_bytes.size(), r.ch_fp)) {
            r.ja4 = ja4_client(r.ch_fp);
        }
    }
    if (!r.sh_bytes.empty()) {
        if (parse_server_hello(r.sh_bytes.data(), r.sh_bytes.size(), r.sh_fp)) {
            r.ja4s = ja4s_server(r.sh_fp);
        }
    }
    r.ok = !r.ch_bytes.empty();   // we at least got our CH out
    return r;
}

} // namespace

UtlsProbeResult utls_probe_chrome(const string& ip, int port, const string& sni, int to_ms) {
    return run_one(ip, port, sni, /*chrome_flavor=*/true, to_ms);
}

UtlsProbeResult utls_probe_openssl(const string& ip, int port, const string& sni, int to_ms) {
    return run_one(ip, port, sni, /*chrome_flavor=*/false, to_ms);
}

UtlsDualProbe utls_dual_probe(const string& ip, int port, const string& sni) {
    UtlsDualProbe d;
    d.chrome  = utls_probe_chrome (ip, port, sni);
    d.openssl = utls_probe_openssl(ip, port, sni);
    d.both_completed = d.chrome.handshake_completed && d.openssl.handshake_completed;

    if (d.chrome.handshake_completed && !d.openssl.handshake_completed) {
        d.only_chrome_ok = true;
        d.verdict = "only chrome-flavored handshake completed (openssl-default rejected). "
                    "server filters clients by JA3 / utls enforcement profile.";
        return d;
    }
    if (!d.chrome.handshake_completed && d.openssl.handshake_completed) {
        d.only_openssl_ok = true;
        d.verdict = "only openssl-default handshake completed (chrome-flavored rejected). "
                    "atypical: server expects raw openssl JA3, not chrome-class clients.";
        return d;
    }
    if (d.both_completed) {
        if (!d.chrome.cert_sha256.empty() && !d.openssl.cert_sha256.empty()
            && d.chrome.cert_sha256 != d.openssl.cert_sha256) {
            d.cert_differs = true;
            d.verdict = "both handshakes completed but server returned a different cert "
                        "per client flavor. reality / utls-aware cert steering.";
            return d;
        }
        if (!d.chrome.ja4s.empty() && !d.openssl.ja4s.empty()
            && d.chrome.ja4s != d.openssl.ja4s) {
            d.ja4s_differs = true;
            d.verdict = "both handshakes completed but ServerHello (JA4S) differs between "
                        "client flavors. server adapts its TLS parameters to client JA3 "
                        "(utls-aware multi-stack frontend).";
            return d;
        }
        d.verdict = "both flavors got the same JA4S and same cert. server does not adapt "
                    "to client fingerprint at the handshake layer.";
        return d;
    }
    d.verdict = "both handshakes failed. cannot infer JA3-adaptive behavior.";
    return d;
}