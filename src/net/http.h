// SPDX-License-Identifier: GPL-3.0-or-later
// minimal winhttp get wrapper used by geoip + crt.sh + doh.
// no ua string - bare get against json endpoints. an optional accept header is
// supported for content-negotiating endpoints (e.g. cloudflare doh, which needs
// `Accept: application/dns-json`); it is empty for every other caller so the
// bare-get on-the-wire posture is unchanged.
#pragma once

#include <string>

struct HttpResp {
    int         status = 0;
    std::string body;
    std::string err;
    long long   ms = 0;
    bool ok() const { return status >= 200 && status < 300 && err.empty(); }
};

HttpResp http_get(const std::string& url, int timeout_ms = 7000,
                  const std::string& accept = "");
