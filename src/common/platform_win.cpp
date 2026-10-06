// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform.h"

#include <mstcpip.h>

namespace {

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

std::string registry_string(HKEY root, const char* path, const char* name) {
    char value[1024]{};
    DWORD size = sizeof(value) - 1;
    DWORD type = 0;
    if (RegGetValueA(root, path, name, RRF_RT_REG_SZ, &type, value, &size) != ERROR_SUCCESS) return {};
    return value;
}

DWORD registry_dword(HKEY root, const char* path, const char* name) {
    DWORD value = 0;
    DWORD size = sizeof(value);
    if (RegGetValueA(root, path, name, RRF_RT_REG_DWORD, nullptr, &value, &size) != ERROR_SUCCESS) return 0;
    return value;
}

} // namespace

void platform_startup() {
    WSADATA data{};
    WSAStartup(MAKEWORD(2, 2), &data);
}

void platform_cleanup() { WSACleanup(); }

void platform_enable_virtual_terminal() {
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(output, &mode))
        SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleOutputCP(CP_UTF8);
}

void platform_disable_syn_retransmit(SOCKET socket) {
    TCP_INITIAL_RTO_PARAMETERS parameters{};
    parameters.Rtt = TCP_INITIAL_RTO_UNSPECIFIED_RTT;
    parameters.MaxSynRetransmissions = TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS;
    DWORD returned = 0;
    WSAIoctl(socket, SIO_TCP_INITIAL_RTO, &parameters, sizeof(parameters),
             nullptr, 0, &returned, nullptr, nullptr);
}

void sleep_ms(unsigned milliseconds) { Sleep(milliseconds); }

bool query_socket_tcp_info(SOCKET socket, SocketTcpInfo& output) {
    WindowsTcpInfoV0 info{};
    DWORD version = 0;
    DWORD bytes_returned = 0;
    const int result = WSAIoctl(socket, SIO_TCP_INFO, &version, sizeof(version),
                                &info, sizeof(info), &bytes_returned, nullptr, nullptr);
    if (result != 0 || bytes_returned < sizeof(unsigned int) * 4) return false;
    output.mss = info.Mss;
    output.send_window = info.SndWnd;
    return true;
}

bool console_skip_supported() { return true; }
void discard_console_keys() { while (_kbhit()) _getch(); }

bool console_skip_requested() {
    if (!_kbhit()) return false;
    const int key = _getch();
    return key == 'q' || key == 'Q' || key == 27;
}

void set_socket_recv_timeout(SOCKET socket, int timeout_ms) {
    const DWORD timeout = static_cast<DWORD>(timeout_ms);
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));
}

bool set_socket_timeouts(SOCKET socket, int timeout_ms) {
    const DWORD timeout = static_cast<DWORD>(timeout_ms);
    return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                      reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0 &&
           setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO,
                      reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0;
}

std::string platform_system_proxy() {
    constexpr const char* key = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    std::string result;
    if (registry_dword(HKEY_CURRENT_USER, key, "ProxyEnable"))
        result = registry_string(HKEY_CURRENT_USER, key, "ProxyServer");
    const std::string pac = registry_string(HKEY_CURRENT_USER, key, "AutoConfigURL");
    if (!pac.empty()) result += (result.empty() ? "" : ", ") + std::string("PAC ") + pac;
    return result;
}
