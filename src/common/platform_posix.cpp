// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform.h"

#include <chrono>
#include <thread>

void platform_startup() {}
void platform_cleanup() {}
void platform_enable_virtual_terminal() {}
void platform_disable_syn_retransmit(SOCKET) {}

void sleep_ms(unsigned milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

bool query_socket_tcp_info(SOCKET socket, SocketTcpInfo& output) {
#ifdef __APPLE__
    tcp_connection_info info{};
    socklen_t size = sizeof(info);
    if (getsockopt(socket, IPPROTO_TCP, TCP_CONNECTION_INFO, &info, &size) != 0) return false;
    output.mss = info.tcpi_maxseg;
    output.send_window = info.tcpi_snd_wnd;
    return true;
#else
    (void)socket;
    (void)output;
    return false;
#endif
}

bool console_skip_supported() { return false; }
void discard_console_keys() {}
bool console_skip_requested() { return false; }

void set_socket_recv_timeout(SOCKET socket, int timeout_ms) {
    timeval timeout{};
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

bool set_socket_timeouts(SOCKET socket, int timeout_ms) {
    timeval timeout{};
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
           setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0;
}

std::string platform_system_proxy() { return {}; }
