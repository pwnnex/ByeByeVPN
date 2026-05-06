#include "vpn_probes2.h"
#include "vpn_probes.h"
#include "tcp_scanner.h"
#include "../core/utils.h"
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <cstring>

UdpResult hysteria2_probe(const std::string& host, int port) {
    unsigned char pkt[] = {
        0xc0, 0x00,0x00,0x00,0x01, 0x08,
        0,0,0,0,0,0,0,0,             
        0x00, 0x00, 0x44,0x40
    };
    RAND_bytes(pkt + 6, 8);          
    std::vector<unsigned char> full(1200, 0x00);
    memcpy(full.data(), pkt, sizeof(pkt));
    return udp_probe(host, port, full.data(), (int)full.size(), 1500);
}

UdpResult tuic_probe(const std::string& host, int port) {
    return quic_probe(host, port);
}

UdpResult l2tp_probe(const std::string& host, int port) {
    unsigned char pkt[] = {
        0xC8,0x02,       
        0x00,0x2D,       
        0x00,0x00,       
        0x00,0x00,       
        0x00,0x00,       
        0x00,0x00,       
        0x80,0x08, 0x00,0x00, 0x00,0x00, 0x00,0x01,
        0x80,0x08, 0x00,0x00, 0x00,0x02, 0x01,0x00,
        0x80,0x0A, 0x00,0x00, 0x00,0x03, 0x00,0x00,0x00,0x03,
        0x80,0x0B, 0x00,0x00, 0x00,0x07, 'l','a','c',
        0x80,0x08, 0x00,0x00, 0x00,0x09, 0,0
    };
    unsigned char tid[2];
    do { RAND_bytes(tid, 2); } while (tid[0] == 0 && tid[1] == 0);
    pkt[sizeof(pkt)-2] = tid[0];
    pkt[sizeof(pkt)-1] = tid[1];
    return udp_probe(host, port, pkt, sizeof(pkt), 1500);
}

UdpResult amneziawg_probe(const std::string& host, int port) {
    unsigned char pkt[148 + 8] = {0};
    RAND_bytes(pkt, 8);              
    pkt[8] = 0x01;                   
    RAND_bytes(pkt + 12, 140);       
    return udp_probe(host, port, pkt, sizeof(pkt), 1500);
}

FpResult sstp_probe(const std::string& host, int port) {
    FpResult f; f.service = "SSTP?";
    std::string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
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
    std::string req =
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
    std::string body(buf, n);
    if (body.find("HTTP/1.1 200") != std::string::npos &&
        body.find("18446744073709551615") != std::string::npos) {
        f.service = "SSTP";
        f.details = "Microsoft SSTP VPN endpoint (Content-Length: 2^64-1 match)";
        f.is_vpn_like = true;
    } else if (body.find("SSTP") != std::string::npos) {
        f.service = "SSTP";
        f.details = "SSTP-aware server: " + printable_prefix(body.substr(0, body.find('\n')), 80);
        f.is_vpn_like = true;
    } else {
        size_t nl = body.find('\n');
        f.details = "not SSTP: " + printable_prefix(body.substr(0, nl), 80);
    }
    return f;
}