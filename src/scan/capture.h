// SPDX-License-Identifier: GPL-3.0-or-later
// pcap and pcapng walking shared by awg-entropy and the pcap command, plus a
// decoder down to tcp and udp payloads. files only; nothing is captured here.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

// one link-layer frame: bytes, link type, time, "section:interface"
using FrameFn = std::function<void(const uint8_t*, size_t, uint32_t, uint64_t, const std::string&)>;

// walks every frame; throws std::runtime_error on a malformed container.
// counts records it had to skip (no timestamp, unsupported link).
void capture_walk(const std::vector<uint8_t>& bytes, const FrameFn& frame, size_t& records, size_t& skipped);

bool capture_read_file(const std::string& path, std::vector<uint8_t>& bytes, std::string& error);

constexpr size_t CAPTURE_MAX_FILE = size_t(64) * 1024 * 1024;

struct Decoded {
    uint64_t    time_ns = 0;
    std::string src, dst;     // address only, v6 in brackets
    uint16_t    sport = 0, dport = 0;
    uint8_t     proto = 0;    // 6 tcp, 17 udp
    uint32_t    seq = 0;      // tcp only
    uint8_t     flags = 0;    // tcp flags byte
    std::vector<uint8_t> payload;
};

// ethernet (vlan), linux cooked v1/v2, raw ip, null/loop. false for anything
// else, fragments and truncated frames.
bool capture_decode(const uint8_t* p, size_t n, uint32_t link, Decoded& out);
