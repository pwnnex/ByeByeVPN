#include "service_probes.h"
#include "tcp_scanner.h"
#include "../analysis/tspu.h"
#include "../core/utils.h"
#include <openssl/rand.h>

std::string printable_prefix(const std::string& s, size_t lim) {
    std::string out;
    for (size_t i=0;i<s.size() && out.size()<lim;++i) {
        char c = s[i];
        if (c>=32 && c<127) out += c;
        else if (c=='\r') out += "\\r";
        else if (c=='\n') out += "\\n";
        else out += '.';
    }
    return out;
}

FpResult fp_http_plain(const std::string& host, int port) {
    FpResult f; f.service = "HTTP?";
    std::string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    std::string req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    tcp_send_all(s, req.data(), (int)req.size());
    char buf[2048]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 1500);
    closesocket(s);
    if (n <= 0) { f.silent = true; return f; }
    buf[n]=0; std::string resp(buf, n);
    std::string first = resp.substr(0, resp.find('\n'));
    std::string server;
    size_t sv = tolower_s(resp).find("server:");
    if (sv != std::string::npos) {
        size_t e = resp.find('\r', sv);
        if (e == std::string::npos) e = resp.find('\n', sv);
        server = trim(resp.substr(sv+7, e-(sv+7)));
    }
    f.service = "HTTP";
    f.details = trim(first);
    if (!server.empty()) f.details += "  | Server: " + server;
    
    std::string loresp = tolower_s(resp);
    size_t lp = loresp.find("\nlocation:");
    if (lp != std::string::npos) {
        size_t vs = lp + 10;
        size_t ve = resp.find('\r', vs);
        if (ve == std::string::npos) ve = resp.find('\n', vs);
        if (ve != std::string::npos && ve > vs && ve - vs < 512) {
            std::string location = trim(resp.substr(vs, ve - vs));
            const char* marker = looks_like_tspu_redirect(location);
            if (marker) {
                f.tspu_redirect   = true;
                f.redirect_target = location;
                f.redirect_marker = marker;
                f.details += std::string("  [!tspu-redirect to ") + marker + "]";
            }
        }
    }
    
    std::string rl = tolower_s(server);
    if (contains(rl, "caddy"))     f.details += "  %[caddy-fronted - common Xray/Reality fallback]";
    else if (contains(rl, "nginx")) f.details += "  %[nginx - fallback host?]";
    else if (contains(rl, "cloudflare")) f.details += "  %[cloudflare]";
    return f;
}

FpResult fp_ssh(const std::string& banner_hint, const std::string& host, int port) {
    FpResult f; f.service = "SSH?";
    std::string b = banner_hint;
    if (b.empty() || b.substr(0,4) != "SSH-") {
        std::string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
        if (s != INVALID_SOCKET) {
            char buf[256]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 1500);
            closesocket(s);
            if (n > 0) { buf[n]=0; b.assign(buf,n); }
        }
    }
    if (b.substr(0,4) == "SSH-") {
        f.service = "SSH";
        while (!b.empty() && (b.back()=='\r'||b.back()=='\n')) b.pop_back();
        f.details = b;
    } else {
        f.details = "no SSH banner (but port open)";
    }
    return f;
}

FpResult fp_socks5(const std::string& host, int port) {
    FpResult f; f.service = "SOCKS?";
    std::string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    unsigned char greet[] = {0x05, 0x02, 0x00, 0x02};
    tcp_send_all(s, greet, sizeof(greet));
    unsigned char reply[8]; int n = tcp_recv_to(s, (char*)reply, sizeof(reply), 1200);
    closesocket(s);
    if (n <= 0) { f.silent = true; return f; }
    if (reply[0] == 0x05 && n >= 2) {
        f.service = "SOCKS5";
        f.details = "methods=0x" + hex_s(reply+1, 1);
        if (reply[1] == 0x00) f.details += " (no-auth)";
        else if (reply[1] == 0x02) f.details += " (user/pass)";
        else if (reply[1] == 0xFF) f.details += " (no acceptable)";
        f.is_vpn_like = true;
    } else if (reply[0] == 0x05) {
        f.service = "SOCKS5"; f.details = "short greeting"; f.is_vpn_like = true;
    } else if (reply[0] == 0x04) {
        f.service = "SOCKS4"; f.is_vpn_like = true;
    } else {
        f.details = "reply=" + hex_s(reply, std::min(4,n));
    }
    return f;
}

FpResult fp_http_connect(const std::string& host, int port) {
    FpResult f; f.service = "HTTP-PROXY?";
    std::string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    std::string req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    tcp_send_all(s, req.data(), (int)req.size());
    char buf[512]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 1500);
    closesocket(s);
    if (n <= 0) { f.silent = true; return f; }
    buf[n]=0;
    std::string line(buf, buf + std::min(n, 120));
    if (starts_with(line, "HTTP/")) {
        f.service = "HTTP-PROXY";
        f.details = trim(line.substr(0, line.find('\n')));
        f.is_vpn_like = true;
    } else {
        f.details = printable_prefix(line);
    }
    return f;
}

FpResult fp_shadowsocks(const std::string& host, int port) {
    FpResult f; f.service = "SS?";
    std::string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    unsigned char rnd[64];
    RAND_bytes(rnd, 64);
    tcp_send_all(s, rnd, 64);
    char buf[256]; int n = tcp_recv_to(s, buf, sizeof(buf), 800);
    closesocket(s);
    if (n <= 0) {
        f.service = "silent-on-junk";
        f.details = "accepts random bytes but never replies (ambiguous: Shadowsocks AEAD, Trojan, Reality hidden-mode, or any firewalled service)";
    } else {
        f.details = "responded "+std::to_string(n)+"B: "+printable_prefix(std::string(buf,n));
    }
    return f;
}