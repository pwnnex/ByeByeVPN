// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// observations of real udp traffic, never the scanner's own random probes.
struct AwgPacket {
    uint64_t time_ns = 0;
    std::string src, dst, scope;
    size_t payload_size = 0;
    double byte_entropy = 0, nibble_entropy = 0;
    bool random_like = false;
    enum class Marker { None, WireGuard, QuicLong, Dtls, Stun, Dns };
    Marker marker = Marker::None;
};
AwgPacket awg_observe(const uint8_t* payload, size_t size);

struct AwgFlow {
    std::string endpoint_a, endpoint_b, scope;
    std::string verdict = "INSUFFICIENT_DATA";
    std::string version = "unknown";
    size_t packets = 0, a_to_b = 0, b_to_a = 0, sampled = 0;
    size_t random_packets = 0, candidate_bursts = 0;
    double mean_byte_entropy = 0, mean_nibble_entropy = 0;
    bool competing_protocol = false;
    std::vector<std::string> evidence;
};
// heuristic compatibility, not authenticated identification or a probability.
std::vector<AwgFlow> awg_analyze(const std::vector<AwgPacket>& packets);

struct AwgCapture {
    bool ok = false;
    std::string error;
    size_t records = 0, skipped = 0;
    std::vector<AwgPacket> packets;
};
// classic pcap and pcapng (epb). limits are errors, never a silent partial pass.
AwgCapture awg_read_capture(const std::vector<uint8_t>& bytes);
AwgCapture awg_read_capture_file(const std::string& path);
std::string awg_capture_json(const AwgCapture& capture, const std::vector<AwgFlow>& flows);
