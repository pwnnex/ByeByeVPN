// SPDX-License-Identifier: GPL-3.0-or-later
#include "tcp.h"

#include <mstcpip.h>

#include <algorithm>
#include <string>
#include <vector>

using std::string;
using std::vector;

namespace {

// windows retries syn after rst
// refused: 2030 ms without, 1 ms with
void no_syn_retransmit(SOCKET s) {
    TCP_INITIAL_RTO_PARAMETERS p{};
    p.Rtt = TCP_INITIAL_RTO_UNSPECIFIED_RTT;
    p.MaxSynRetransmissions = TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS;
    DWORD out = 0;
    // pre-1703 rejects it, keeps old timing
    WSAIoctl(s, SIO_TCP_INITIAL_RTO, &p, sizeof(p), nullptr, 0, &out, nullptr, nullptr);
}

bool is_unreachable(int e) {
    return e == WSAEHOSTUNREACH || e == WSAENETUNREACH;
}

} // namespace

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
    bool saw_timeout = false, saw_refused = false, saw_unreach = false;
    for (auto* p: ordered) {
        s = socket(p->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) continue;
        no_syn_retransmit(s);
        u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
        int rc = connect(s, p->ai_addr, (int)p->ai_addrlen);
        if (rc == 0) { u_long bl = 0; ioctlsocket(s, FIONBIO, &bl); break; }
        const int ce = WSAGetLastError();
        if (ce == WSAEWOULDBLOCK) {
            fd_set wr, ex; FD_ZERO(&wr); FD_SET(s, &wr); FD_ZERO(&ex); FD_SET(s, &ex);
            timeval tv{}; tv.tv_sec = timeout_ms / 1000; tv.tv_usec = (timeout_ms % 1000) * 1000;
            int sr = select(0, nullptr, &wr, &ex, &tv);
            if (sr > 0 && (FD_ISSET(s, &wr) || FD_ISSET(s, &ex))) {
                int se = 0; int sl = sizeof(se);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&se, &sl);
                if (se == 0) { u_long bl = 0; ioctlsocket(s, FIONBIO, &bl); break; }
                if (se == WSAECONNREFUSED) saw_refused = true;
                else if (is_unreachable(se)) saw_unreach = true;
            } else if (sr == 0) {
                saw_timeout = true;
            }
        } else if (ce == WSAECONNREFUSED) {
            saw_refused = true;
        } else if (is_unreachable(ce)) {
            saw_unreach = true;
        }
        closesocket(s); s = INVALID_SOCKET;
    }
    freeaddrinfo(ai);
    if (s == INVALID_SOCKET) {
        if (saw_refused)      err = "refused";
        else if (saw_unreach) err = "unreachable";
        else if (saw_timeout) err = "timeout";
        else                  err = "other";
    }
    if (s != INVALID_SOCKET) {
        DWORD timeout = (DWORD)std::max(1, timeout_ms);
        if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) != 0 ||
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)) != 0) {
            closesocket(s);
            err = "socket timeout setup";
            return INVALID_SOCKET;
        }
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

ReadEnd classify_recv(int rc, int wsa_error) {
    if (rc > 0) return ReadEnd::Data;
    if (rc == 0) return ReadEnd::Fin;
    if (wsa_error == WSAECONNRESET || wsa_error == WSAECONNABORTED) return ReadEnd::Reset;
    if (wsa_error == WSAETIMEDOUT) return ReadEnd::Held;
    return ReadEnd::Error;
}
