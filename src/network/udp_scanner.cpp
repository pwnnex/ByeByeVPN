#include "udp_scanner.h"
#include "../core/utils.h"
#include <chrono>
#include <openssl/rand.h>

UdpResult udp_probe(const std::string& host, int port, const unsigned char* payload, int plen, int timeout_ms) {
    UdpResult r;
    if (g_udp_jitter) {
        unsigned char jb = 0;
        RAND_bytes(&jb, 1);
        Sleep(50 + (jb % 251));
    }
    auto t0 = std::chrono::steady_clock::now();
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM;
    addrinfo* ai = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &ai) != 0) {
        r.err = "dns"; return r;
    }
    addrinfo* chosen = nullptr;
    for (auto* p = ai; p; p = p->ai_next) if (p->ai_family == AF_INET)  { chosen = p; break; }
    if (!chosen)
        for (auto* p = ai; p; p = p->ai_next) if (p->ai_family == AF_INET6) { chosen = p; break; }
    if (!chosen) { freeaddrinfo(ai); r.err = "dns"; return r; }
    SOCKET s = socket(chosen->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { freeaddrinfo(ai); r.err = "socket"; return r; }
    
#ifdef _WIN32
    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif

    int rc = sendto(s, (const char*)payload, plen, 0, chosen->ai_addr, (int)chosen->ai_addrlen);
    freeaddrinfo(ai);
    if (rc <= 0) { closesocket(s); r.err = "send"; return r; }
    char buf[2048];
    int got = recv(s, buf, sizeof(buf), 0);
    closesocket(s);
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
             
    int werr = WSAGetLastError();
#ifndef _WIN32
    if (werr == EAGAIN) werr = WSAETIMEDOUT;
#endif

    if (got > 0) {
        r.responded = true; r.bytes = got;
        r.reply_hex = hex_s((unsigned char*)buf, std::min(32, got), true);
    } else if (werr == WSAETIMEDOUT || werr == 0) {
        r.err = "no-reply / filtered";
    } else if (werr == WSAECONNRESET) {
        r.err = "ICMP port-unreachable (port closed)";
    } else {
        r.err = "wsa " + std::to_string(werr);
    }
    return r;
}