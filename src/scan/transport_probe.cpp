// SPDX-License-Identifier: GPL-3.0-or-later
#include "transport_probe.h"
#include "../common/util.h"
#include <openssl/rand.h>
#include <openssl/evp.h>

WsProbe ws_probe(const std::string& ip, int port, const std::string& sni, int to_ms) {
    WsProbe r;
    const auto authority = http_authority(sni.empty() ? ip : sni, port);
    if (authority.empty()) { r.err = "invalid HTTP authority"; return r; }
    static const char* paths[] = {"/", "/ws", "/vless", "/vmess", "/websocket", "/ray"};
    bool first = true;
    for (const char* path : paths) {
        if (!first) stealth_sleep_ms(200, 1200);
        first = false;
        unsigned char nonce[16]{}, encoded[25]{};
        if (RAND_bytes(nonce, sizeof(nonce)) != 1) { r.err = "websocket nonce generation failed"; return r; }
        const int length = EVP_EncodeBlock(encoded, nonce, sizeof(nonce));
        const std::string key(reinterpret_cast<char*>(encoded), length);
        const std::string request = std::string("GET ") + path + " HTTP/1.1\r\nHost: " + authority +
            "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key +
            "\r\nSec-WebSocket-Version: 13\r\n\r\n";
        const auto response = https_exchange(ip, port, sni, request, to_ms);
        r.tls_ok = r.tls_ok || response.tls_ok;
        if (r.first_line.empty()) r.first_line = response.first_line;
        if (websocket_upgrade_valid(response, key)) {
            r.ws_upgrade = true;
            r.path_hit = path;
            r.first_line = response.first_line;
            r.err.clear();
            return r;
        }
        r.err = response.http_valid ? "no valid WebSocket opening handshake on tested paths" : response.err;
    }
    return r;
}
