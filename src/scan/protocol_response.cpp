// SPDX-License-Identifier: GPL-3.0-or-later
#include "transport_probe.h"
#include "fingerprint.h"
#include "../common/util.h"
#include "../common/tspu.h"
#include <openssl/evp.h>
#include <cstdio>

namespace {
std::string field(const HttpsProbe& r, const char* name) {
    auto it = r.headers.find(name);
    return it == r.headers.end() ? "" : it->second;
}
bool token(const std::string& value, const char* wanted) {
    for (const auto& part : split(value, ',')) if (tolower_s(trim(part)) == wanted) return true;
    return false;
}
}

std::string websocket_accept(const std::string& key) {
    if (key.empty() || key.size() > 128) return {};
    const auto input = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    unsigned char digest[EVP_MAX_MD_SIZE]{}, encoded[32]{};
    unsigned int size = 0;
    if (EVP_Digest(input.data(), input.size(), digest, &size, EVP_sha1(), nullptr) != 1 || size != 20) return {};
    const int length = EVP_EncodeBlock(encoded, digest, size);
    return length > 0 ? std::string(reinterpret_cast<char*>(encoded), length) : "";
}

bool websocket_upgrade_valid(const HttpsProbe& r, const std::string& key) {
    const auto accept = websocket_accept(key);
    return r.http_valid && r.http_version == "HTTP/1.1" && r.status_code == 101 &&
        !accept.empty() && field(r, "sec-websocket-accept") == accept &&
        token(field(r, "upgrade"), "websocket") && token(field(r, "connection"), "upgrade") &&
        !r.headers.count("sec-websocket-extensions") && !r.headers.count("sec-websocket-protocol");
}

FpResult http_fingerprint_response(const HttpsProbe& r, bool connect_probe) {
    FpResult f;
    f.service = connect_probe ? "HTTP-PROXY?" : "HTTP?";
    f.silent = !r.responded;
    if (!r.http_valid) { f.details = r.err; return f; }
    f.service = "HTTP";
    f.details = printable_prefix(r.first_line, 160);
    if (connect_probe) {
        f.connect_accepted = r.status_code >= 200 && r.status_code < 300;
        f.details += f.connect_accepted ? "; CONNECT accepted; relay access untested" : "; CONNECT was not accepted";
        return f;
    }
    if (!r.server_hdr.empty()) f.details += " | Server: " + printable_prefix(r.server_hdr, 100);
    // only redirect statuses and the actual location authority count.
    if (r.status_code == 301 || r.status_code == 302 || r.status_code == 303 || r.status_code == 307 || r.status_code == 308) {
        const auto location = field(r, "location");
        if (const char* marker = looks_like_tspu_redirect(location)) {
            f.tspu_redirect = true;
            f.redirect_target = location;
            f.redirect_marker = marker;
            f.details += "; warning-page destination observed";
        }
    }
    return f;
}

FpResult sstp_response(const HttpsProbe& r) {
    FpResult f;
    f.service = "SSTP?";
    f.silent = !r.responded;
    if (r.http_valid && r.http_version == "HTTP/1.1" && r.status_code == 200 &&
        field(r, "content-length") == "18446744073709551615" && !r.headers.count("transfer-encoding")) {
        f.service = "SSTP";
        f.is_vpn_like = true;
        f.outcome = Outcome::Positive;
        f.details = "SSTP-compatible HTTP setup response; control exchange and authentication untested";
    } else if (r.http_valid) {
        // a real http answer that refuses the setup
        f.outcome = Outcome::Negative;
        f.details = "SSTP setup not established: " + printable_prefix(r.first_line, 100);
    } else {
        f.details = r.err.empty() ? "no HTTP response to the setup request" : r.err;
    }
    return f;
}

Outcome socks5_reply_outcome(const unsigned char* reply, int n, ReadEnd end) {
    // rfc 1928 3: ver 5, method we offered or ff
    if (n == 2 && reply[0] == 0x05 && (reply[1] == 0x00 || reply[1] == 0x02 || reply[1] == 0xFF))
        return Outcome::Positive;
    // other bytes: something else speaks here
    if (n > 0) return Outcome::Negative;
    (void)end;
    return Outcome::Inconclusive;
}

std::string sstp_setup_request(const std::string& authority, const unsigned char g[16]) {
    // ms-sstp 2.2.1; windows sends a fresh uppercase guid
    char id[40];
    std::snprintf(id, sizeof(id), "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                  g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
    return "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\nHost: " + authority +
           "\r\nContent-Length: 18446744073709551615\r\nSSTPCORRELATIONID: {" + id + "}\r\n\r\n";
}
