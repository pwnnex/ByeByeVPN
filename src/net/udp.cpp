#include "udp.h"
#include "../common/winhdr.h"
#include "../common/util.h"
#include "../common/config.h"

#include <openssl/rand.h>

#include <algorithm>
#include <chrono>

using std::string;

UdpResult udp_probe(const string& host, int port,
                    const unsigned char* payload, int plen,
                    int timeout_ms) {
    UdpResult r;
    // optional jitter. without it every scan emits all VPN-ish UDP probes
    // within ~2s, which is itself a scanner signature. 50-300ms random
    // delay smears the burst.
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
    // prefer v4 over v6 for UDP too (same DNS-ordering trap as TCP)
    addrinfo* chosen = nullptr;
    for (auto* p = ai; p; p = p->ai_next) if (p->ai_family == AF_INET)  { chosen = p; break; }
    if (!chosen)
        for (auto* p = ai; p; p = p->ai_next) if (p->ai_family == AF_INET6) { chosen = p; break; }
    if (!chosen) { freeaddrinfo(ai); r.err = "dns"; return r; }

    SOCKET s = socket(chosen->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { freeaddrinfo(ai); r.err = "socket"; return r; }
    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof(to));
    int rc = sendto(s, (const char*)payload, plen, 0, chosen->ai_addr, (int)chosen->ai_addrlen);
    freeaddrinfo(ai);
    if (rc <= 0) { closesocket(s); r.err = "send"; return r; }
    char buf[2048];
    int got = recv(s, buf, sizeof(buf), 0);
    closesocket(s);
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    int werr = WSAGetLastError();
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
