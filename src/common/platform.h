// SPDX-License-Identifier: GPL-3.0-or-later
// Small OS boundary shared by networking and console code.
#pragma once

#include <string>

#ifdef _WIN32
#include "winhdr.h"
using socket_len_t = int;
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

constexpr SOCKET INVALID_SOCKET = -1;
constexpr int SOCKET_ERROR = -1;

#define closesocket close
#define ioctlsocket ioctl
#define WSAGetLastError() errno
#define WSAEWOULDBLOCK EINPROGRESS
#define WSAECONNREFUSED ECONNREFUSED
#define WSAECONNRESET ECONNRESET
#define WSAECONNABORTED ECONNABORTED
#define WSAETIMEDOUT ETIMEDOUT
#define WSAEHOSTUNREACH EHOSTUNREACH
#define WSAENETUNREACH ENETUNREACH
#define WSAEMSGSIZE EMSGSIZE
#define InetNtopA inet_ntop
#define gai_strerrorA gai_strerror
#define _stricmp strcasecmp
#endif

struct SocketTcpInfo {
    unsigned int mss = 0;
    unsigned int send_window = 0;
};

void platform_startup();
void platform_cleanup();
void platform_enable_virtual_terminal();
void platform_disable_syn_retransmit(SOCKET socket);
void sleep_ms(unsigned milliseconds);

bool query_socket_tcp_info(SOCKET socket, SocketTcpInfo& output);
bool console_skip_supported();
void discard_console_keys();
bool console_skip_requested();
void set_socket_recv_timeout(SOCKET socket, int timeout_ms);
bool set_socket_timeouts(SOCKET socket, int timeout_ms);

std::string platform_system_proxy();
