// SPDX-License-Identifier: GPL-3.0-or-later
#include "udp.h"
#include "../common/winhdr.h"
#include "../common/util.h"
#include "../common/config.h"

#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cstring>

using std::string;

UdpResult udp_probe(const string& host, int port,
                    const unsigned char* payload, int plen,
                    int timeout_ms) {
    UdpResult r;
    if (port < 1 || port > 65535 || plen < 0 || plen > 65507 ||
        (plen > 0 && payload == nullptr) || timeout_ms < 1) {
        r.err = "invalid probe arguments";
        return r;
    }
    // optional jitter. without it every scan emits all vpn-ish udp probes
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
    // prefer v4 over v6 for udp too (same dns-ordering trap as tcp)
    addrinfo* chosen = nullptr;
    for (auto* p = ai; p; p = p->ai_next) if (p->ai_family == AF_INET)  { chosen = p; break; }
    if (!chosen)
        for (auto* p = ai; p; p = p->ai_next) if (p->ai_family == AF_INET6) { chosen = p; break; }
    if (!chosen) { freeaddrinfo(ai); r.err = "dns"; return r; }

    SOCKET s = socket(chosen->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { freeaddrinfo(ai); r.err = "socket"; return r; }
    DWORD to = (DWORD)timeout_ms;
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof(to)) != 0 ||
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&to, sizeof(to)) != 0) {
        freeaddrinfo(ai); closesocket(s); r.err = "socket timeout setup"; return r;
    }
    // a connected udp socket accepts replies only from the probed endpoint.
    int rc = connect(s, chosen->ai_addr, (int)chosen->ai_addrlen);
    freeaddrinfo(ai);
    if (rc != 0) { closesocket(s); r.err = "connect"; return r; }
    rc = send(s, (const char*)payload, plen, 0);
    if (rc != plen) { closesocket(s); r.err = "send"; return r; }
    char buf[2048];
    int got = recv(s, buf, sizeof(buf), 0);
    const int werr = got == SOCKET_ERROR ? WSAGetLastError() : 0;
    closesocket(s);
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    if (werr == WSAEMSGSIZE) {
        got = sizeof(buf);
        r.err = "reply truncated to 2048 bytes";
    }
    if (got >= 0) {
        r.responded = true; r.bytes = got;
        r.reply_hex = hex_s((unsigned char*)buf, std::min(32, got), true);
        // keep the whole datagram so validators can check it is complete.
        r.reply.assign((unsigned char*)buf, (unsigned char*)buf + got);
        // echo detection. every payload we send starts with >= 16 bytes of
        // csprng material (wg ephemeral, junk prefix, quic dcid), so a reply
        // that reproduces our own leading bytes is a reflector, not a peer.
        // 16 bytes of agreement by chance is 2^-128.
        int cmp = std::min({ got, plen, 64 });
        if (cmp >= 16 && std::memcmp(buf, payload, (size_t)cmp) == 0)
            r.echoed = true;
    } else if (werr == WSAETIMEDOUT) {
        r.err = "no-reply / filtered";
    } else if (werr == WSAECONNRESET) {
        r.err = "ICMP port-unreachable received";
    } else {
        r.err = "wsa " + std::to_string(werr);
    }
    return r;
}
