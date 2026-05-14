// SPDX-License-Identifier: GPL-3.0-or-later
// minimal WinHTTP GET wrapper used by GeoIP + crt.sh.
// no UA string, no extra headers — bare GET against JSON endpoints.
#pragma once

#include <string>

struct HttpResp {
    int         status = 0;
    std::string body;
    std::string err;
    long long   ms = 0;
    bool ok() const { return status >= 200 && status < 400; }
};

HttpResp http_get(const std::string& url, int timeout_ms = 7000);