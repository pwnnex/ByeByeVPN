// SPDX-License-Identifier: GPL-3.0-or-later
// generic udp send-and-wait probe. caller supplies the payload; this just
// fires-and-receives with a timeout, classifies the reply type.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct UdpResult {
    bool        responded = false;
    int         bytes     = 0;
    std::string reply_hex;        // first 32 bytes of reply, hex with spaces
    std::vector<uint8_t> reply;   // the whole reply datagram (up to the 2048-byte buffer)
    long long   ms        = 0;
    std::string err;
    // the reply is a verbatim copy of what we sent. a udp echo service, a
    // reflector, or a middlebox bouncing the datagram back all produce this,
    // and none of them is the protocol we probed for - so every protocol
    // verdict has to exclude it before calling a reply a handshake.
    bool        echoed    = false;
    // set by the quic probes: the source connection id we sent. a genuine
    // quic reply is addressed to it (its dcid), so validation can require it.
    std::vector<uint8_t> expect_dcid;
    // wg probes: our sender index, which a real response echoes back
    std::vector<uint8_t> expect_receiver;
};

UdpResult udp_probe(const std::string& host, int port,
                    const unsigned char* payload, int plen,
                    int timeout_ms);