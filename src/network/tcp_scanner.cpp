#include "tcp_scanner.h"
#include <chrono>
#include <vector>

#ifndef _WIN32
static void set_nonblocking(SOCKET s, bool nb) {
    int flags = fcntl(s, F_GETFL, 0);
    if (nb) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    fcntl(s, F_SETFL, flags);
}
#endif

SOCKET tcp_connect(const std::string& host, int port, int timeout_ms, std::string& err) {
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    addrinfo* ai = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &ai) != 0) {
        err = "dns"; return INVALID_SOCKET;
    }
    std::vector<addrinfo*> ordered;
    for (auto* p = ai; p; p = p->ai_next) if (p->ai_family == AF_INET)  ordered.push_back(p);
    for (auto* p = ai; p; p = p->ai_next) if (p->ai_family == AF_INET6) ordered.push_back(p);
    SOCKET s = INVALID_SOCKET;
    bool saw_timeout = false, saw_refused = false, saw_other = false;
    for (auto* p: ordered) {
        s = socket(p->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) { saw_other = true; continue; }
#ifdef _WIN32
        u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
#else
        set_nonblocking(s, true);
#endif
        int rc = connect(s, p->ai_addr, (int)p->ai_addrlen);
        if (rc == 0) { 
#ifdef _WIN32
            u_long bl=0; ioctlsocket(s,FIONBIO,&bl); 
#else
            set_nonblocking(s, false);
#endif
            break; 
        }
        
        int werr = WSAGetLastError();
#ifndef _WIN32
        if (werr == EINPROGRESS) werr = WSAEWOULDBLOCK;
#endif

        if (werr == WSAEWOULDBLOCK) {
            fd_set wr, ex; FD_ZERO(&wr); FD_SET(s, &wr); FD_ZERO(&ex); FD_SET(s, &ex);
            timeval tv{}; tv.tv_sec = timeout_ms/1000; tv.tv_usec = (timeout_ms%1000)*1000;
            int sr = select((int)s + 1, nullptr, &wr, &ex, &tv);
            if (sr > 0 && FD_ISSET(s, &wr)) {
                int se = 0; socklen_t sl = sizeof(se);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&se, &sl);
                if (se == 0) { 
#ifdef _WIN32
                    u_long bl=0; ioctlsocket(s,FIONBIO,&bl); 
#else
                    set_nonblocking(s, false);
#endif
                    break; 
                }
                if (se == WSAECONNREFUSED) saw_refused = true;
                else saw_other = true;
            } else if (sr == 0) {
                saw_timeout = true;
            } else {
                saw_other = true;
            }
        } else {
            if (werr == WSAECONNREFUSED) saw_refused = true;
            else saw_other = true;
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
#ifdef _WIN32
    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif
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