// SPDX-License-Identifier: GPL-3.0-or-later
// Minimal platform abstraction used by shared networking code.
#pragma once

struct SocketTcpInfo {
    unsigned int mss = 0;
    unsigned int send_window = 0;
};

#ifdef _WIN32

#include "winhdr.h"

using socket_len_t = int;

inline void platform_startup() {
    WSADATA data{};
    WSAStartup(MAKEWORD(2, 2), &data);
}

inline void platform_cleanup() { WSACleanup(); }

inline void platform_enable_virtual_terminal() {
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(output, &mode))
        SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleOutputCP(CP_UTF8);
}

namespace platform_detail {

#ifndef SIO_TCP_INFO
#define SIO_TCP_INFO _WSAIORW(IOC_VENDOR, 39)
#endif

struct WindowsTcpInfoV0 {
    unsigned int State;
    unsigned int Mss;
    unsigned long long ConnectionTimeMs;
    unsigned char TimestampsEnabled;
    unsigned int RttUs;
    unsigned int MinRttUs;
    unsigned int BytesInFlight;
    unsigned int Cwnd;
    unsigned int SndWnd;
    unsigned int RcvWnd;
    unsigned int RcvBuf;
    unsigned long long BytesOut;
    unsigned long long BytesIn;
    unsigned int BytesReordered;
    unsigned int BytesRetrans;
    unsigned int FastRetrans;
    unsigned int DupAcksIn;
    unsigned int TimeoutEpisodes;
    unsigned char SynRetrans;
};

} // namespace platform_detail

inline bool query_socket_tcp_info(SOCKET socket, SocketTcpInfo& output) {
    platform_detail::WindowsTcpInfoV0 info{};
    DWORD version = 0;
    DWORD bytes_returned = 0;
    int result = WSAIoctl(socket, SIO_TCP_INFO, &version, sizeof(version),
                          &info, sizeof(info), &bytes_returned, nullptr, nullptr);
    if (result != 0 || bytes_returned < sizeof(unsigned int) * 4) return false;
    output.mss = info.Mss;
    output.send_window = info.SndWnd;
    return true;
}

inline bool console_skip_supported() { return true; }

inline void discard_console_keys() {
    while (_kbhit()) _getch();
}

inline bool console_skip_requested() {
    if (!_kbhit()) return false;
    int key = _getch();
    return key == 'q' || key == 'Q' || key == 27;
}

inline void set_socket_recv_timeout(SOCKET socket, int timeout_ms) {
    DWORD timeout = static_cast<DWORD>(timeout_ms);
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));
}

#else

#include <cerrno>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>

using SOCKET = int;
using socket_len_t = socklen_t;

inline void platform_startup() {}
inline void platform_cleanup() {}
inline void platform_enable_virtual_terminal() {}

constexpr SOCKET INVALID_SOCKET = -1;
constexpr int SOCKET_ERROR = -1;

#define closesocket close
#define ioctlsocket ioctl
#define WSAGetLastError() errno
#define WSAEWOULDBLOCK EINPROGRESS
#define WSAECONNREFUSED ECONNREFUSED
#define WSAECONNRESET ECONNRESET
#define WSAETIMEDOUT ETIMEDOUT
#define InetNtopA inet_ntop
#define gai_strerrorA gai_strerror
#define _stricmp strcasecmp

inline void Sleep(unsigned milliseconds) {
    usleep(static_cast<useconds_t>(milliseconds) * 1000);
}

inline void set_socket_recv_timeout(SOCKET socket, int timeout_ms) {
    timeval timeout{};
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

inline bool query_socket_tcp_info(SOCKET socket, SocketTcpInfo& output) {
#ifdef __APPLE__
    tcp_connection_info info{};
    socklen_t size = sizeof(info);
    if (getsockopt(socket, IPPROTO_TCP, TCP_CONNECTION_INFO, &info, &size) != 0)
        return false;
    output.mss = info.tcpi_maxseg;
    output.send_window = info.tcpi_snd_wnd;
    return true;
#else
    (void)socket;
    (void)output;
    return false;
#endif
}

inline bool console_skip_supported() { return false; }
inline void discard_console_keys() {}
inline bool console_skip_requested() { return false; }

#endif
