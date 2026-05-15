// SPDX-License-Identifier: GPL-3.0-or-later
#include "utls.h"
#include "chrome_ch.h"
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

// minimal ALPN matching what the rest of the tool sends, so the
// openssl-default flavor does not add a second ALPN surface.
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

// JA4S is "a_b_c": a = version+extcount+alpn, b = the single negotiated
// cipher, c = the ServerHello extension-set hash. the b part changes purely
// because the two client flavors offer ciphers in a different preference
// order and the server honours it — that is RFC-standard negotiation, not
// fingerprint steering. real steering shows up in a (different ext count /
// ALPN) or c (different ext set). so for the "does the server adapt"
// comparison we drop b and compare a_c only.
string ja4s_structural(const string& ja4s) {
    size_t u1 = ja4s.find('_');
    size_t u2 = (u1 == string::npos) ? string::npos : ja4s.find('_', u1 + 1);
    if (u1 == string::npos || u2 == string::npos) return ja4s;
    return ja4s.substr(0, u1) + "_" + ja4s.substr(u2 + 1);
}

void parse_captures(UtlsProbeResult& r) {
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
}

// ---- openssl-default flavor -------------------------------------------------
// the same ctx the rest of the tool uses. OpenSSL builds the ClientHello,
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
    if (!sni.empty()) SSL_set_tlsext_host_name(ssl, sni.c_str());
    SSL_set_alpn_protos(ssl, DEFAULT_ALPN, sizeof(DEFAULT_ALPN));

    CapCtx cap;
    SSL_set_msg_callback(ssl, msg_cb);
    SSL_set_msg_callback_arg(ssl, &cap);

    int rc = SSL_connect(ssl);
    r.handshake_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0).count();

    if (rc != 1) {
        unsigned long e = ERR_get_error();
        char eb[256] = {0};
        ERR_error_string_n(e, eb, sizeof(eb));
        r.err = eb[0] ? string(eb) : string("tls handshake failed");
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

// the HelloRetryRequest sentinel: a ServerHello whose random equals this
// fixed value is an HRR, not a real accept (RFC 8446 4.1.3).
const uint8_t HRR_RANDOM[32] = {
    0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,
    0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C
};

// ---- chrome flavor: byte-accurate, raw socket -------------------------------
// hand-built Chrome 131 ClientHello sent over a raw socket. we cannot finish
// the TLS 1.3 handshake (the key schedule is OpenSSL's job), and the peer
// cert lives inside the encrypted handshake, so this path has no cert. what
// it DOES have is byte-accurate JA4 and the server's plaintext ServerHello:
//   * a real ServerHello (not HRR, not an alert) => server accepted the
//     Chrome fingerprint  -> handshake_completed = true
//   * an alert / RST / HRR => server rejected or could not satisfy it
// that accept/reject split, compared against the openssl flavor, is the
// uTLS-enforcement signal.
UtlsProbeResult run_chrome_raw(const string& ip, int port, const string& sni, int to_ms) {
    UtlsProbeResult r;
    r.flavor = "chrome";

    auto t0 = std::chrono::steady_clock::now();
    string err;
    SOCKET s = tcp_connect(ip, port, to_ms, err);
    if (s == INVALID_SOCKET) { r.err = err; return r; }

    vector<uint8_t> rec = build_chrome131_clienthello(sni);
    if (rec.size() > 5) r.ch_bytes.assign(rec.begin() + 5, rec.end());

    bool sent_ok = tcp_send_all(s, rec.data(), (int)rec.size()) == (int)rec.size();
    if (!sent_ok) {
        r.err = "send failed";
    } else {
        // accumulate until the first TLS record is complete, or timeout.
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
                    if (hp[0] == 0x02 /* ServerHello */) {
                        size_t mlen = ((size_t)hp[1] << 16) | ((size_t)hp[2] << 8) | hp[3];
                        if (4 + mlen <= reclen) {
                            r.sh_bytes.assign(hp, hp + 4 + mlen);
                            bool is_hrr = mlen >= 34
                                && std::memcmp(hp + 6, HRR_RANDOM, 32) == 0;
                            if (is_hrr) {
                                r.err = "HelloRetryRequest "
                                        "(server could not satisfy the Chrome key_share)";
                            } else {
                                r.handshake_completed = true;
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
    UtlsDualProbe d;
    d.chrome  = utls_probe_chrome (ip, port, sni);
    // chrome immediately followed by openssl to the same port is itself a
    // scanner-shaped pair. under --stealth, separate them 300-1500ms.
    stealth_sleep_ms(300, 1500);
    d.openssl = utls_probe_openssl(ip, port, sni);
    d.both_completed = d.chrome.handshake_completed && d.openssl.handshake_completed;

    if (d.chrome.handshake_completed && !d.openssl.handshake_completed) {
        d.only_chrome_ok = true;
        d.verdict = "byte-accurate Chrome ClientHello got a ServerHello, openssl-default "
                    "did not. server enforces a uTLS / browser fingerprint profile.";
        return d;
    }
    if (!d.chrome.handshake_completed && d.openssl.handshake_completed) {
        d.only_openssl_ok = true;
        d.verdict = "openssl-default handshake completed but the byte-accurate Chrome "
                    "ClientHello was rejected. atypical: server expects raw openssl JA3.";
        return d;
    }
    if (d.both_completed) {
        if (!d.chrome.cert_sha256.empty() && !d.openssl.cert_sha256.empty()
            && d.chrome.cert_sha256 != d.openssl.cert_sha256) {
            d.cert_differs = true;
            d.verdict = "both handshakes completed but the server returned a different cert "
                        "per client flavor. reality / utls-aware cert steering.";
            return d;
        }
        if (!d.chrome.ja4s.empty() && !d.openssl.ja4s.empty()
            && ja4s_structural(d.chrome.ja4s) != ja4s_structural(d.openssl.ja4s)) {
            d.ja4s_differs = true;
            d.verdict = "both handshakes completed but the ServerHello structure (JA4S "
                        "version / extension set / ALPN) differs between client flavors. "
                        "server adapts its TLS parameters to client JA3 (utls-aware "
                        "multi-stack frontend).";
            return d;
        }
        d.verdict = "both flavors got the same ServerHello structure. server does not "
                    "adapt to client fingerprint at the handshake layer (a differing "
                    "negotiated cipher is just normal client-preference negotiation).";
        return d;
    }
    d.verdict = "both handshakes failed. cannot infer JA3-adaptive behavior.";
    return d;
}
