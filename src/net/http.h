// SPDX-License-Identifier: GPL-3.0-or-later
// minimal WinHTTP GET wrapper used by GeoIP + crt.sh + DoH.
// no UA string — bare GET against JSON endpoints. an optional Accept header is
// supported for content-negotiating endpoints (e.g. Cloudflare DoH, which needs
// `Accept: application/dns-json`); it is empty for every other caller so the
// bare-GET on-the-wire posture is unchanged.
#pragma once

#include <string>

struct HttpResp {
    int         status = 0;
    std::string body;
    std::string err;
    long long   ms = 0;
    bool ok() const { return status >= 200 && status < 400; }
};

HttpResp http_get(const std::string& url, int timeout_ms = 7000,
                  const std::string& accept = "");