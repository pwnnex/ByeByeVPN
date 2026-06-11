// SPDX-License-Identifier: GPL-3.0-or-later
// generic UDP send-and-wait probe. caller supplies the payload; this just
// fires-and-receives with a timeout, classifies the reply type.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct UdpResult {
    bool        responded = false;
    int         bytes     = 0;
    std::string reply_hex;        // first 32 bytes of reply, hex with spaces
    std::vector<uint8_t> reply;   // first up-to-256 raw reply bytes (for QUIC parse)
    long long   ms        = 0;
    std::string err;
};

UdpResult udp_probe(const std::string& host, int port,
                    const unsigned char* payload, int plen,
                    int timeout_ms);