// SPDX-License-Identifier: GPL-3.0-or-later
#include "grpc.h"

namespace {
void hpack_string(std::vector<uint8_t>& out, const std::string& value) {
    size_t size = value.size();
    if (size < 127) out.push_back(static_cast<uint8_t>(size));
    else {
        out.push_back(127);
        size -= 127;
        while (size >= 128) { out.push_back(static_cast<uint8_t>((size & 127) | 128)); size >>= 7; }
        out.push_back(static_cast<uint8_t>(size));
    }
    out.insert(out.end(), value.begin(), value.end());
}
uint32_t u32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}
}

std::vector<uint8_t> grpc_request_headers(const std::string& authority, const std::string& path) {
    if (authority.empty() || authority.size() > 1024 || path.empty() || path.size() > 4096) return {};
    std::vector<uint8_t> h{0x83, 0x87, 0x41};
    hpack_string(h, authority);
    h.push_back(0x44); hpack_string(h, path);
    h.push_back(0x5f); hpack_string(h, "application/grpc");
    h.push_back(0x40); hpack_string(h, "te"); hpack_string(h, "trailers");
    return h;
}

void analyze_h2_response(const std::vector<uint8_t>& bytes, GrpcProbe& r) {
    r.h2_frames = r.headers_resp = r.stream_reset = r.goaway = r.grpc_marker = false;
    r.err.clear();
    size_t pos = 0;
    uint32_t continuation = 0;
    bool header_block = false;
    while (pos < bytes.size()) {
        if (bytes.size() - pos < 9) { r.err = "incomplete HTTP/2 frame header"; break; }
        const auto* p = bytes.data() + pos;
        const size_t length = (size_t(p[0]) << 16) | (size_t(p[1]) << 8) | p[2];
        const uint8_t type = p[3], flags = p[4];
        const uint32_t stream = u32(p + 5) & 0x7fffffff;
        if (length > 16384) { r.err = "HTTP/2 frame exceeds advertised maximum"; break; }
        if (length > bytes.size() - pos - 9) { r.err = "incomplete HTTP/2 frame payload"; break; }
        bool valid = true;
        if (pos == 0 && (type != 4 || stream != 0 || (flags & 1))) valid = false;
        if (continuation && (type != 9 || stream != continuation)) valid = false;
        if (!continuation && type == 9) valid = false;
        if (type == 0 || type == 1 || type == 5) {
            if (!stream) valid = false;
            size_t overhead = 0;
            if (flags & 8) {
                if (!length) valid = false;
                else overhead = size_t(p[9]) + 1;
            }
            if (type == 1 && (flags & 32)) overhead += 5;
            if (type == 5) overhead += 4;
            if (overhead > length) valid = false;
        } else if (type == 2) valid = valid && stream != 0 && length == 5;
        else if (type == 3) valid = valid && stream != 0 && length == 4;
        else if (type == 4) valid = valid && stream == 0 && length % 6 == 0 && (!(flags & 1) || length == 0);
        else if (type == 6) valid = valid && stream == 0 && length == 8;
        else if (type == 7) valid = valid && stream == 0 && length >= 8;
        else if (type == 8) valid = valid && length == 4 && (u32(p + 9) & 0x7fffffff) != 0;
        if (!valid) { r.err = "invalid HTTP/2 frame structure or sequence"; break; }
        r.h2_frames = true;
        if (type == 1 || type == 5) {
            header_block = type == 1;
            if (flags & 4) {
                if (header_block && stream == 1) r.headers_resp = true;
            } else continuation = stream;
        }
        if (type == 9 && (flags & 4)) {
            if (header_block && stream == 1) r.headers_resp = true;
            continuation = 0;
        }
        if (type == 3 && stream == 1) r.stream_reset = true;
        if (type == 7) r.goaway = true;
        pos += 9 + length;
    }
    if (continuation && r.err.empty()) r.err = "incomplete HTTP/2 header block";
    if (!r.err.empty()) r.note = r.err + "; gRPC and VPN protocols unconfirmed";
    else if (r.headers_resp) r.note = "HTTP/2 header block on our stream; HPACK and gRPC status are not decoded";
    else if (r.stream_reset) r.note = "HTTP/2 reset our stream; this does not identify a VPN transport";
    else if (r.goaway) r.note = "HTTP/2 connection closed with GOAWAY; service unconfirmed";
    else if (r.h2_frames) r.note = "HTTP/2 frames observed without an application response";
    else r.note = "no complete HTTP/2 frames observed; service unconfirmed";
}
