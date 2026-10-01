// SPDX-License-Identifier: GPL-3.0-or-later
// loopback-only driver for test_udp_socket.py.
#include "../src/common/winhdr.h"
#include "../src/net/udp.h"
#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv) {
    if (argc != 2) return 64;
    WSADATA ws{};
    if (WSAStartup(MAKEWORD(2, 2), &ws) != 0) return 1;
    const unsigned char payload[] = "0123456789abcdef";
    const auto r = udp_probe("127.0.0.1", std::atoi(argv[1]), payload, 16, 500);
    std::printf("%d %d %d\n%s\n%s\n", r.responded, r.bytes, r.echoed, r.reply_hex.c_str(), r.err.c_str());
    WSACleanup();
    return 0;
}
