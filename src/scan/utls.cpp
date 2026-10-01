// SPDX-License-Identifier: GPL-3.0-or-later
#include "utls.h"
#include "chrome_ch.h"
#include "tls_ctx.h"
#include "../common/winhdr.h"
#include "../common/util.h"
#include "../net/tcp.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <chrono>
#include <cstdio>
#include <cstring>

using std::string;
using std::vector;

namespace {

// rfc 8446 4.1.3: this random marks a retry, not a negotiated serverhello
const uint8_t HRR_RANDOM[32] = {
    0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,
    0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C
};

// callback ctx attached via SSL_set_msg_callback_arg. captures the first
// outbound clienthello and the first inbound serverhello as raw bytes
// starting from the handshaketype byte (no tls record header).
struct CapCtx {
    vector<uint8_t> ch;
    vector<uint8_t> sh;
};

void msg_cb(int write_p, int /*version */, int content_type,
            const void* buf, size_t len, SSL* /*ssl */, void* arg) {
    if (content_type != SSL3_RT_HANDSHAKE) return;
    if (!arg || !buf || len == 0) return;
    auto* c = static_cast<CapCtx*>(arg);
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    if (write_p == 1 && p[0] == 0x01 /*clienthello */ && c->ch.empty()) {
        c->ch.assign(p, p + len);
    } else if (write_p == 0 && p[0] == 0x02 /*serverhello */ && c->sh.empty()) {
        if (len >= 38 && std::memcmp(p + 6, HRR_RANDOM, sizeof(HRR_RANDOM)) == 0) return;
        c->sh.assign(p, p + len);
    }
}

// minimal alpn matching what the rest of the tool sends, so the
// openssl-default flavor doesn't add a second alpn surface.
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

void parse_captures(UtlsProbeResult& r) {
    r.server_hello_received = false;
    if (!r.ch_bytes.empty()) {
        if (parse_client_hello(r.ch_bytes.data(), r.ch_bytes.size(), r.ch_fp)) {
            r.ja4 = ja4_client(r.ch_fp);
        }
    }
    if (!r.sh_bytes.empty()) {
        if (parse_server_hello(r.sh_bytes.data(), r.sh_bytes.size(), r.sh_fp)) {
            r.ja4s = ja4s_server(r.sh_fp);
            r.server_hello_received = r.sh_bytes.size() >= 38 &&
                std::memcmp(r.sh_bytes.data() + 6, HRR_RANDOM, sizeof(HRR_RANDOM)) != 0;
        }
    }
}

// openssl-default flavor
// the same ctx the rest of the tool uses. openssl builds the clienthello,
// completes the handshake, so this path also recovers the peer certificate.
UtlsProbeResult run_openssl(const string& ip, int port, const string& sni, int to_ms) {
    UtlsProbeResult r;
    r.flavor = "openssl";

    auto t0 = std::chrono::steady_clock::now();
    string err;
    SOCKET s = tcp_connect(ip, port, to_ms, err);
    if (s == INVALID_SOCKET) { r.err = err; return r; }

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { closesocket(s); r.err = "ctx alloc"; return r; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);

    SSL* ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); closesocket(s); r.err = "ssl alloc"; return r; }
    SSL_set_fd(ssl, (int)s);
    if (!sni.empty() && !is_ip_literal(sni)) SSL_set_tlsext_host_name(ssl, sni.c_str());
    SSL_set_alpn_protos(ssl, DEFAULT_ALPN, sizeof(DEFAULT_ALPN));

    CapCtx cap;
    SSL_set_msg_callback(ssl, msg_cb);
    SSL_set_msg_callback_arg(ssl, &cap);

    ssl_clear_errors();
    int rc = SSL_connect(ssl);
    r.handshake_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0).count();

    if (rc != 1) {
        r.err = ssl_error_string("tls handshake failed");
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

    parse_captures(r);
    r.ok = !r.ch_bytes.empty();
    return r;
}

const char* cipher_name(uint16_t c) {
    switch (c) {
        case 0x1301: return "TLS_AES_128_GCM_SHA256";
        case 0x1302: return "TLS_AES_256_GCM_SHA384";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
        default:     return nullptr;
    }
}

// raw chrome probe stops before the encrypted tls 1.3 handshake
UtlsProbeResult run_chrome_raw(const string& ip, int port, const string& sni, int to_ms) {
    UtlsProbeResult r;
    r.flavor = "chrome";

    auto t0 = std::chrono::steady_clock::now();
    string err;
    SOCKET s = tcp_connect(ip, port, to_ms, err);
    if (s == INVALID_SOCKET) { r.err = err; return r; }

    vector<uint8_t> rec = build_chromelike_clienthello(sni);
    if (rec.size() > 5) r.ch_bytes.assign(rec.begin() + 5, rec.end());

    bool sent_ok = tcp_send_all(s, rec.data(), (int)rec.size()) == (int)rec.size();
    if (!sent_ok) {
        r.err = "send failed";
    } else {
        // accumulate until the first tls record is complete, or timeout.
        vector<uint8_t> buf;
        char tmp[4096];
        for (int i = 0; i < 8; ++i) {
            int n = tcp_recv_to(s, tmp, sizeof(tmp), to_ms);
            if (n <= 0) break;
            buf.insert(buf.end(), tmp, tmp + (size_t)n);
            if (buf.size() >= 5) {
                size_t reclen = ((size_t)buf[3] << 8) | buf[4];
                if (buf.size() >= 5 + reclen) break;
            }
        }

        if (buf.size() < 5) {
            r.err = "no server response";
        } else {
            uint8_t  rt     = buf[0];
            size_t   reclen = ((size_t)buf[3] << 8) | buf[4];
            if (rt == 0x15 /* alert */) {
                if (buf.size() >= 7) {
                    char e[64];
                    std::snprintf(e, sizeof(e), "tls alert level=%u desc=%u",
                                  buf[5], buf[6]);
                    r.err = e;
                } else {
                    r.err = "tls alert";
                }
            } else if (rt == 0x16 /* handshake */) {
                if (buf.size() < 5 + reclen || reclen < 4) {
                    r.err = "truncated handshake record";
                } else {
                    const uint8_t* hp = buf.data() + 5;
                    if (hp[0] == 0x02 /* serverhello */) {
                        size_t mlen = ((size_t)hp[1] << 16) | ((size_t)hp[2] << 8) | hp[3];
                        if (4 + mlen <= reclen) {
                            r.sh_bytes.assign(hp, hp + 4 + mlen);
                            bool is_hrr = mlen >= 34
                                && std::memcmp(hp + 6, HRR_RANDOM, 32) == 0;
                            if (is_hrr) {
                                r.err = "HelloRetryRequest "
                                        "(server could not satisfy the Chrome key_share)";
                            }
                        } else {
                            r.err = "truncated ServerHello";
                        }
                    } else {
                        r.err = "unexpected handshake message type";
                    }
                }
            } else {
                r.err = "unexpected record type";
            }
        }
    }
    closesocket(s);
    r.handshake_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0).count();

    parse_captures(r);
    if (r.sh_fp.ok) {
        r.tls_version = r.sh_fp.real_version ? r.sh_fp.real_version
                                             : r.sh_fp.legacy_version;
        const char* cn = cipher_name(r.sh_fp.cipher);
        if (cn) {
            r.cipher = cn;
        } else {
            char hb[8];
            std::snprintf(hb, sizeof(hb), "%04x", r.sh_fp.cipher);
            r.cipher = string("0x") + hb;
        }
        r.alpn = r.sh_fp.alpn_negotiated;
    }
    r.ok = !r.ch_bytes.empty();
    return r;
}

} // namespace

UtlsProbeResult utls_probe_chrome(const string& ip, int port, const string& sni, int to_ms) {
    return run_chrome_raw(ip, port, sni, to_ms);
}

UtlsProbeResult utls_probe_openssl(const string& ip, int port, const string& sni, int to_ms) {
    return run_openssl(ip, port, sni, to_ms);
}

UtlsDualProbe utls_dual_probe(const string& ip, int port, const string& sni) {
    auto chrome = utls_probe_chrome(ip, port, sni);
    stealth_sleep_ms(300, 1500);
    auto openssl = utls_probe_openssl(ip, port, sni);
    return compare_utls_probes(std::move(chrome), std::move(openssl));
}
