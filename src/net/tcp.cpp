// SPDX-License-Identifier: GPL-3.0-or-later
#include "tcp.h"

#include <string>
#include <vector>

using std::string;
using std::vector;

SOCKET tcp_connect(const string& host, int port, int timeout_ms, string& err) {
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    addrinfo* ai = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &ai) != 0) {
        err = "dns"; return INVALID_SOCKET;
    }
    // iterate v4 first, then v6. avoids the happy-eyeballs trap.
    vector<addrinfo*> ordered;
    for (auto* p = ai; p; p = p->ai_next) if (p->ai_family == AF_INET)  ordered.push_back(p);
    for (auto* p = ai; p; p = p->ai_next) if (p->ai_family == AF_INET6) ordered.push_back(p);
    SOCKET s = INVALID_SOCKET;
    // we only need to distinguish refused / timeout / other for the err
    // string; "other" is the fallthrough so it needs no explicit flag.
    bool saw_timeout = false, saw_refused = false;
    for (auto* p: ordered) {
        s = socket(p->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) continue;
        u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
        int rc = connect(s, p->ai_addr, (int)p->ai_addrlen);
        if (rc == 0) { u_long bl = 0; ioctlsocket(s, FIONBIO, &bl); break; }
        if (WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set wr, ex; FD_ZERO(&wr); FD_SET(s, &wr); FD_ZERO(&ex); FD_SET(s, &ex);
            timeval tv{}; tv.tv_sec = timeout_ms / 1000; tv.tv_usec = (timeout_ms % 1000) * 1000;
            int sr = select(0, nullptr, &wr, &ex, &tv);
            if (sr > 0 && FD_ISSET(s, &wr)) {
                int se = 0; int sl = sizeof(se);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&se, &sl);
                if (se == 0) { u_long bl = 0; ioctlsocket(s, FIONBIO, &bl); break; }
                if (se == WSAECONNREFUSED) saw_refused = true;
            } else if (sr == 0) {
                saw_timeout = true;
            }
        } else {
            if (WSAGetLastError() == WSAECONNREFUSED) saw_refused = true;
        }
        closesocket(s); s = INVALID_SOCKET;
    }
    freeaddrinfo(ai);
    if (s == INVALID_SOCKET) {
        if (saw_refused)      err = "refused";
        else if (saw_timeout) err = "timeout";
        else                  err = "other";
    }
    return s;
}

int tcp_recv_to(SOCKET s, char* buf, int max, int timeout_ms) {
    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof(to));
    return recv(s, buf, max, 0);
}

int tcp_send_all(SOCKET s, const void* data, int n) {
    const char* p = (const char*)data; int left = n;
    while (left > 0) {
        int rc = send(s, p, left, 0);
        if (rc <= 0) return rc;
        p += rc; left -= rc;
    }
    return n;
}