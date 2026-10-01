// SPDX-License-Identifier: GPL-3.0-or-later
#include "https_probe.h"
#include "../common/util.h"
#include <algorithm>
#include <map>

namespace {
bool field_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           std::string("!#$%&'*+-.^_`|~").find(static_cast<char>(c)) != std::string::npos;
}
}

HttpsProbe parse_https_response(const std::string& bytes) {
    HttpsProbe r;
    r.responded = !bytes.empty();
    r.bytes = static_cast<int>(std::min(bytes.size(), HTTPS_HEADER_LIMIT));
    size_t pos = 0;
    for (int response = 0; response < 9; ++response) {
        const size_t end = bytes.find('\n', pos);
        if (end == std::string::npos || end >= HTTPS_HEADER_LIMIT) {
            r.err = bytes.size() >= HTTPS_HEADER_LIMIT ? "HTTP headers exceed 16 KiB" : "incomplete HTTP status line";
            return r;
        }
        std::string line = bytes.substr(pos, end - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        r.first_line = line;
        const size_t space = line.find(' ');
        if (line.rfind("HTTP/", 0) != 0 || space == std::string::npos) {
            r.err = "response is not an HTTP/1.x status line";
            return r;
        }
        r.http_version = line.substr(0, space);
        if (r.http_version != "HTTP/1.0" && r.http_version != "HTTP/1.1") {
            r.version_anomaly = true;
            r.err = "unexpected HTTP version for an HTTP/1.1 probe";
            return r;
        }
        const auto code = line.substr(space + 1, 3);
        if (code.size() != 3 || !std::all_of(code.begin(), code.end(), [](char c) { return c >= '0' && c <= '9'; }) ||
            (line.size() > space + 4 && line[space + 4] != ' ') || code[0] < '1' || code[0] > '5') {
            r.err = "invalid HTTP status code";
            return r;
        }
        for (unsigned char c : line) if ((c < 32 && c != '\t') || c == 127) {
            r.err = "control byte in HTTP status line";
            return r;
        }
        const int status = (code[0] - '0') * 100 + (code[1] - '0') * 10 + code[2] - '0';
        pos = end + 1;
        std::map<std::string, std::string> headers;
        for (;;) {
            const size_t eol = bytes.find('\n', pos);
            if (eol == std::string::npos || eol >= HTTPS_HEADER_LIMIT) {
                r.err = bytes.size() >= HTTPS_HEADER_LIMIT ? "HTTP headers exceed 16 KiB" : "incomplete HTTP headers";
                return r;
            }
            line = bytes.substr(pos, eol - pos);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            pos = eol + 1;
            if (line.empty()) break;
            const size_t colon = line.find(':');
            if (colon == 0 || colon == std::string::npos ||
                !std::all_of(line.begin(), line.begin() + colon, field_char)) {
                r.err = "invalid HTTP header field name";
                return r;
            }
            for (unsigned char c : line) if ((c < 32 && c != '\t') || c == 127) {
                r.err = "control byte in HTTP header";
                return r;
            }
            auto [it, inserted] = headers.try_emplace(tolower_s(line.substr(0, colon)));
            auto& value = it->second;
            if (!inserted) value += ", ";
            value += trim(line.substr(colon + 1));
        }
        // 101 is terminal; other 1xx blocks precede the actual response.
        if (status < 200 && status != 101) continue;
        r.status_code = status;
        r.headers_complete = true;
        r.http_valid = true;
        r.server_hdr = headers["server"];
        r.via_hdr = headers["via"];
        r.forwarded_hdr = headers["forwarded"];
        r.xff_hdr = headers["x-forwarded-for"];
        r.xreal_ip_hdr = headers["x-real-ip"];
        r.x_forwarded_proto = headers["x-forwarded-proto"];
        r.x_forwarded_host = headers["x-forwarded-host"];
        r.cf_ray_hdr = headers["cf-ray"];
        r.cf_cache_status = headers["cf-cache-status"];
        r.x_amz_cf_id = headers["x-amz-cf-id"];
        r.x_amz_cf_pop = headers["x-amz-cf-pop"];
        r.x_azure_ref = headers["x-azure-ref"];
        r.x_azure_clientip = headers["x-azure-clientip"];
        r.x_cache = headers["x-cache"];
        r.x_served_by = headers["x-served-by"];
        r.alt_svc = headers["alt-svc"];
        r.has_proxy_leak = !r.via_hdr.empty() || !r.forwarded_hdr.empty() || !r.xff_hdr.empty() || !r.xreal_ip_hdr.empty();
        r.has_cdn_hdr = !r.cf_ray_hdr.empty() || !r.x_amz_cf_id.empty() || !r.x_azure_ref.empty() || !r.x_served_by.empty();
        r.headers = std::move(headers);
        return r;
    }
    r.err = "too many interim HTTP responses";
    return r;
}

std::string http_authority(const std::string& host, int port, int default_port) {
    if (host.empty() || port < 1 || port > 65535) return {};
    for (unsigned char c : host) if (c <= 32 || c == 127 || c == '/' || c == '\\' || c == '@') return {};
    std::string out = host;
    if (host.find(':') != std::string::npos && host.front() != '[') out = "[" + host + "]";
    if (port != default_port) out += ":" + std::to_string(port);
    return out;
}
