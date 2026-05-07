#include "fingerprint.h"
#include "../common/winhdr.h"
#include "../common/util.h"
#include "../common/config.h"
#include "../common/tspu.h"
#include "../net/tcp.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstring>

using std::string;

FpResult fp_http_plain(const string& host, int port) {
    FpResult f; f.service = "HTTP?";
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    string req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    tcp_send_all(s, req.data(), (int)req.size());
    char buf[2048]; int n = tcp_recv_to(s, buf, sizeof(buf) - 1, 1500);
    closesocket(s);
    if (n <= 0) { f.silent = true; return f; }
    buf[n] = 0; string resp(buf, n);
    string first = resp.substr(0, resp.find('\n'));
    string server;
    size_t sv = tolower_s(resp).find("server:");
    if (sv != string::npos) {
        size_t e = resp.find('\r', sv);
        if (e == string::npos) e = resp.find('\n', sv);
        server = trim(resp.substr(sv + 7, e - (sv + 7)));
    }
    f.service = "HTTP";
    f.details = trim(first);
    if (!server.empty()) f.details += "  | Server: " + server;

    // tspu redirect detection: 302 Location: <warning page>
    {
        string loresp = tolower_s(resp);
        size_t lp = loresp.find("\nlocation:");
        if (lp != string::npos) {
            size_t vs = lp + 10;
            size_t ve = resp.find('\r', vs);
            if (ve == string::npos) ve = resp.find('\n', vs);
            if (ve != string::npos && ve > vs && ve - vs < 512) {
                string location = trim(resp.substr(vs, ve - vs));
                const char* marker = looks_like_tspu_redirect(location);
                if (marker) {
                    f.tspu_redirect   = true;
                    f.redirect_target = location;
                    f.redirect_marker = marker;
                    f.details += string("  [!tspu-redirect to ") + marker + "]";
                }
            }
        }
    }
    string rl = tolower_s(server);
    if (contains(rl, "caddy"))           f.details += "  %[caddy-fronted - common Xray/Reality fallback]";
    else if (contains(rl, "nginx"))      f.details += "  %[nginx - fallback host?]";
    else if (contains(rl, "cloudflare")) f.details += "  %[cloudflare]";
    return f;
}

FpResult fp_ssh(const string& banner_hint, const string& host, int port) {
    FpResult f; f.service = "SSH?";
    string b = banner_hint;
    if (b.empty() || b.substr(0, 4) != "SSH-") {
        string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
        if (s != INVALID_SOCKET) {
            char buf[256]; int n = tcp_recv_to(s, buf, sizeof(buf) - 1, 1500);
            closesocket(s);
            if (n > 0) { buf[n] = 0; b.assign(buf, n); }
        }
    }
    if (b.substr(0, 4) == "SSH-") {
        f.service = "SSH";
        while (!b.empty() && (b.back() == '\r' || b.back() == '\n')) b.pop_back();
        f.details = b;
    } else {
        f.details = "no SSH banner (but port open)";
    }
    return f;
}

FpResult fp_socks5(const string& host, int port) {
    FpResult f; f.service = "SOCKS?";
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    unsigned char greet[] = {0x05, 0x02, 0x00, 0x02};
    tcp_send_all(s, greet, sizeof(greet));
    unsigned char reply[8]; int n = tcp_recv_to(s, (char*)reply, sizeof(reply), 1200);
    closesocket(s);
    if (n <= 0) { f.silent = true; return f; }
    if (reply[0] == 0x05 && n >= 2) {
        f.service = "SOCKS5";
        f.details = "methods=0x" + hex_s(reply + 1, 1);
        if      (reply[1] == 0x00) f.details += " (no-auth)";
        else if (reply[1] == 0x02) f.details += " (user/pass)";
        else if (reply[1] == 0xFF) f.details += " (no acceptable)";
        f.is_vpn_like = true;
    } else if (reply[0] == 0x05) {
        f.service = "SOCKS5"; f.details = "short greeting"; f.is_vpn_like = true;
    } else if (reply[0] == 0x04) {
        f.service = "SOCKS4"; f.is_vpn_like = true;
    } else {
        f.details = "reply=" + hex_s(reply, std::min(4, n));
    }
    return f;
}

FpResult fp_http_connect(const string& host, int port) {
    FpResult f; f.service = "HTTP-PROXY?";
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    string req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    tcp_send_all(s, req.data(), (int)req.size());
    char buf[512]; int n = tcp_recv_to(s, buf, sizeof(buf) - 1, 1500);
    closesocket(s);
    if (n <= 0) { f.silent = true; return f; }
    buf[n] = 0;
    string line(buf, buf + std::min(n, 120));
    if (starts_with(line, "HTTP/")) {
        f.service = "HTTP-PROXY";
        f.details = trim(line.substr(0, line.find('\n')));
        f.is_vpn_like = true;
    } else {
        f.details = printable_prefix(line);
    }
    return f;
}

FpResult fp_shadowsocks(const string& host, int port) {
    FpResult f; f.service = "SS?";
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    // 64 truly-random bytes via OpenSSL CSPRNG — NOT rand()/time() seeded.
    // a deterministic LCG would leak "generated by tool at ~time T".
    unsigned char rnd[64];
    RAND_bytes(rnd, 64);
    tcp_send_all(s, rnd, 64);
    char buf[256]; int n = tcp_recv_to(s, buf, sizeof(buf), 800);
    closesocket(s);
    if (n <= 0) {
        f.service = "silent-on-junk";
        f.details = "accepts random bytes but never replies (ambiguous: Shadowsocks AEAD, Trojan, Reality hidden-mode, or any firewalled service)";
    } else {
        f.details = "responded " + std::to_string(n) + "B: " + printable_prefix(string(buf, n));
    }
    return f;
}

FpResult sstp_probe(const string& host, int port) {
    FpResult f; f.service = "SSTP?";
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)s);
    SSL_set_tlsext_host_name(ssl, host.c_str());
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
        f.details = "TLS handshake failed (not HTTPS)"; f.silent = true; return f;
    }
    string req =
        "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "Content-Length: 18446744073709551615\r\n"
        "SSTPCORRELATIONID: {00000000-0000-0000-0000-000000000000}\r\n"
        "\r\n";
    SSL_write(ssl, req.data(), (int)req.size());
    char buf[1024];
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
    if (n <= 0) { f.details = "TLS ok but SSTP request got no reply"; return f; }
    buf[n] = 0;
    string body(buf, n);
    if (body.find("HTTP/1.1 200") != string::npos &&
        body.find("18446744073709551615") != string::npos) {
        f.service = "SSTP";
        f.details = "Microsoft SSTP VPN endpoint (Content-Length: 2^64-1 match)";
        f.is_vpn_like = true;
    } else if (body.find("SSTP") != string::npos) {
        f.service = "SSTP";
        f.details = "SSTP-aware server: " + printable_prefix(body.substr(0, body.find('\n')), 80);
        f.is_vpn_like = true;
    } else {
        size_t nl = body.find('\n');
        f.details = "not SSTP: " + printable_prefix(body.substr(0, nl), 80);
    }
    return f;
}
