// SPDX-License-Identifier: GPL-3.0-or-later
// websocket opening handshake; does not identify a tunnel protocol.
#pragma once

#include <string>
#include "https_probe.h"

struct WsProbe {
    bool        tls_ok = false;
    bool        ws_upgrade = false;   // validated headers and accept challenge
    std::string path_hit;             // the path that upgraded
    std::string first_line;
    std::string err;
};

// try a websocket upgrade over tls on a few common vless/vmess-ws paths.
WsProbe ws_probe(const std::string& ip, int port, const std::string& sni, int to_ms = 2500);
bool websocket_upgrade_valid(const HttpsProbe& response, const std::string& key);
std::string websocket_accept(const std::string& key);
