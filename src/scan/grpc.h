// SPDX-License-Identifier: GPL-3.0-or-later
// http/2 + grpc transport probe. grpc requires http/2 (alpn "h2"), so a
// vless-grpc / vmess-grpc inbound negotiates h2 and routes a specific grpc
// service path. this probe negotiates h2, then sends a real http/2 grpc-shaped
// request (connection preface + settings + a headers frame for a grpc method)
// and classifies the reaction: a headers response, a stream RST, a goaway, or
// silence. combined with "h2-only + plain HTTP/1.1 over TLS gets nothing", it's
// the grpc-transport-proxy tell.
#pragma once

#include <string>
#include <vector>
#include <cstdint>

struct GrpcProbe {
    bool        tls_ok = false;
    bool        alpn_h2 = false;          // server negotiated http/2
    std::string alpn;                     // whatever alpn was negotiated
    bool        h2_frames = false;        // we received valid http/2 frames
    bool        headers_resp = false;     // server answered our stream with headers
    bool        stream_reset = false;     // rst_stream on our stream
    bool        goaway = false;           // connection-level goaway
    bool        grpc_marker = false;      // "grpc" seen in the (uncompressed) reply
    std::string note;                     // human-readable summary
    std::string err;
};

GrpcProbe grpc_probe(const std::string& ip, int port,
                     const std::string& sni, int to_ms = 2500);
std::vector<uint8_t> grpc_request_headers(const std::string& authority, const std::string& path);
void analyze_h2_response(const std::vector<uint8_t>& bytes, GrpcProbe& result);
