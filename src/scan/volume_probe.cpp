// SPDX-License-Identifier: GPL-3.0-or-later
// network side of the volume check: one tls download, bytes timed as they arrive
#include "volume_probe.h"
#include "https_probe.h"
#include "tls_ctx.h"
#include "tls_io.h"
#include "../common/util.h"
#include "../common/platform.h"
#include "../net/tcp.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <string>

using std::string;

namespace {

// a drip of one byte every few seconds is neither a pass nor a freeze
constexpr int VOLUME_TOTAL_MS = 45000;

long long header_length(const string& head) {
    const string low = tolower_s(head);
    size_t at = low.find("\r\ncontent-length:");
    if (at == string::npos) return -1;
    at += 17;
    while (at < low.size() && (low[at] == ' ' || low[at] == '\t')) ++at;
    long long v = 0;
    bool any = false;
    while (at < low.size() && low[at] >= '0' && low[at] <= '9' && v < (1LL << 40)) { v = v * 10 + (low[at] - '0'); ++at; any = true; }
    return any ? v : -1;
}

} // namespace

VolumeTrace volume_fetch(const string& ip, int port, const string& host, const string& path) {
    VolumeTrace t;
    const auto t0 = std::chrono::steady_clock::now();
    auto ms = [&] { return (int)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count(); };
    string error;
    SOCKET s = tcp_connect(ip, port, 5000, error);
    if (s == INVALID_SOCKET) { t.err = "tcp " + error; t.total_ms = ms(); return t; }
    t.connected = true;
    SSL_CTX* ctx = shared_tls_client_ctx();
    SSL* ssl = ctx ? SSL_new(ctx) : nullptr;
    if (!ssl) { closesocket(s); t.err = "ssl alloc"; return t; }
    SSL_set_fd(ssl, static_cast<int>(s));
    if (!host.empty() && !is_ip_literal(host)) SSL_set_tlsext_host_name(ssl, host.c_str());
    static const unsigned char h11[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    SSL_set_alpn_protos(ssl, h11, sizeof(h11));
    u_long nonblocking = 1;
    auto done = [&](VolumeTrace::End end) {
        t.end = end;
        t.wire = (long long)BIO_number_read(SSL_get_rbio(ssl));
        t.total_ms = ms();
        SSL_free(ssl);
        closesocket(s);
        return t;
    };
    if (ioctlsocket(s, FIONBIO, &nonblocking) != 0) { t.err = "nonblocking"; return done(VolumeTrace::End::Failed); }
    auto io = [&](auto op, int budget_ms, const char* fallback) {
        return tls_io(ssl, s, std::chrono::steady_clock::now() + std::chrono::milliseconds(budget_ms), op, error, fallback);
    };
    if (io([&] { return SSL_connect(ssl); }, 10000, "TLS handshake failed") != 1) {
        t.err = error.empty() ? "TLS handshake closed" : error;
        return done(VolumeTrace::End::Failed);
    }
    t.tls_ok = true;
    // same header set as the https probe; nothing new for the node to see
    const string authority = http_authority(host.empty() ? ip : host, port);
    const string req = "GET " + path + " HTTP/1.1\r\nHost: " + authority + "\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    if (io([&] { return SSL_write(ssl, req.data(), (int)req.size()); }, 10000, "request write failed") != (int)req.size()) {
        t.err = error.empty() ? "request not written" : error;
        return done(VolumeTrace::End::Failed);
    }
    string head;
    bool in_body = false;
    char buf[16384];
    for (;;) {
        if (ms() > VOLUME_TOTAL_MS) { t.err = "transfer exceeded 45 s"; return done(VolumeTrace::End::Failed); }
        error.clear();
        const int n = io([&] { return SSL_read(ssl, buf, (int)sizeof(buf)); }, VOLUME_STALL_MS, "read failed");
        if (n > 0) {
            if (t.first_byte_ms < 0) t.first_byte_ms = ms();
            t.last_byte_ms = ms();
            if (!in_body) {
                head.append(buf, n);
                const size_t end = head.find("\r\n\r\n");
                if (end == string::npos) {
                    if (head.size() > 65536) { t.err = "response head over 64 KB"; return done(VolumeTrace::End::Failed); }
                    continue;
                }
                in_body = true;
                if (head.rfind("HTTP/1.", 0) == 0 && head.size() > 12) {
                    t.response = true;
                    t.status = std::atoi(head.c_str() + 9);
                }
                t.content_length = header_length(head.substr(0, end + 2));
                t.body = (long long)(head.size() - (end + 4));
            } else {
                t.body += n;
            }
            if (t.content_length >= 0 && t.body >= t.content_length) return done(VolumeTrace::End::Complete);
            if (t.body >= VOLUME_CAP) return done(VolumeTrace::End::Cap);
            continue;
        }
        if (n == 0) return done(in_body && t.content_length < 0 ? VolumeTrace::End::Complete : VolumeTrace::End::Closed);
        if (error.find("deadline") != string::npos) return done(VolumeTrace::End::Stall);
        const int werr = WSAGetLastError();
        t.err = error;
        // eof without close_notify is a close, not a reset
        if (werr == WSAECONNRESET || error.find("reset") != string::npos) return done(VolumeTrace::End::Reset);
        if (in_body && t.content_length < 0 && error.find("unexpected eof") != string::npos)
            return done(VolumeTrace::End::Complete);
        return done(VolumeTrace::End::Closed);
    }
}
