// SPDX-License-Identifier: GPL-3.0-or-later
// extra TLS-transport probes:
//   * ws_probe   — VLESS/VMess-WebSocket: a WebSocket Upgrade over TLS; a 101
//                  on a guessed path means an open WS endpoint (ws-transport).
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
