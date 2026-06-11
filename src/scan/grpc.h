// SPDX-License-Identifier: GPL-3.0-or-later
// HTTP/2 + gRPC transport probe. gRPC requires HTTP/2 (ALPN "h2"), so a
// VLESS-gRPC / VMess-gRPC inbound negotiates h2 and routes a specific gRPC
// service path. this probe negotiates h2, then sends a real HTTP/2 gRPC-shaped
// request (connection preface + SETTINGS + a HEADERS frame for a gRPC method)
// and classifies the reaction: a HEADERS response, a stream RST, a GOAWAY, or
// silence. combined with "h2-only + plain HTTP/1.1 over TLS gets nothing", it's
// the gRPC-transport-proxy tell.
#pragma once

#include <string>

struct GrpcProbe {
    bool        tls_ok = false;
    bool        alpn_h2 = false;          // server negotiated HTTP/2
    std::string alpn;                     // whatever ALPN was negotiated
    bool        h2_frames = false;        // we received valid HTTP/2 frames
    bool        headers_resp = false;     // server answered our stream with HEADERS
    bool        stream_reset = false;     // RST_STREAM on our stream
    bool        goaway = false;           // connection-level GOAWAY
    bool        grpc_marker = false;      // "grpc" seen in the (uncompressed) reply
    std::string note;                     // human-readable summary
    std::string err;
};

GrpcProbe grpc_probe(const std::string& ip, int port,
                     const std::string& sni, int to_ms = 2500);
