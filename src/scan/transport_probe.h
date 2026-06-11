// SPDX-License-Identifier: GPL-3.0-or-later
// extra TLS-transport probes:
//   * ws_probe   — VLESS/VMess-WebSocket: a WebSocket Upgrade over TLS; a 101
//                  on a guessed path means an open WS endpoint (ws-transport).
//   * naive_probe — NaiveProxy / Caddy forward_proxy: a proxy-style request
//                  over TLS draws a 407 Proxy-Authenticate from the forward
//                  proxy, where a normal web server just 400s.
#pragma once

#include <string>

struct WsProbe {
    bool        tls_ok = false;
    bool        ws_upgrade = false;   // got HTTP/1.1 101 Switching Protocols
    std::string path_hit;             // the path that upgraded
    std::string first_line;
    std::string err;
};

// try a WebSocket Upgrade over TLS on a few common VLESS/VMess-ws paths.
WsProbe ws_probe(const std::string& ip, int port, const std::string& sni, int to_ms = 2500);

struct NaiveProbe {
    bool        tls_ok = false;
    bool        proxy_auth_required = false;  // 407 + Proxy-Authenticate
    int         status = 0;
    std::string proxy_authenticate;
    std::string first_line;
    std::string err;
};

// send a proxy-style absolute-URI request over TLS; NaiveProxy / forward_proxy
// answers 407 with a Proxy-Authenticate header.
NaiveProbe naive_probe(const std::string& ip, int port, const std::string& sni, int to_ms = 2500);
