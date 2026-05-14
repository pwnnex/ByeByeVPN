// SPDX-License-Identifier: GPL-3.0-or-later
#include "ct.h"
#include "../net/http.h"
#include "../common/util.h"

using std::string;

CtCheck ct_check(const string& cert_sha256) {
    CtCheck r;
    if (cert_sha256.size() < 32) { r.err = "no sha256"; return r; }
    r.queried = true;
    string url = "https://crt.sh/?q=" + cert_sha256 + "&output=json";
    auto h = http_get(url, 5000);
    if (!h.ok()) { r.err = "http " + std::to_string(h.status); return r; }
    if (h.body.size() >= 2) {
        string b = trim(h.body);
        if (b.size() >= 2 && b[0] == '[' && b[1] == ']') {
            r.found = false;
            r.log_entries = 0;
        } else {
            r.found = true;
            int cnt = 0;
            size_t p = 0;
            while ((p = h.body.find("\"id\"", p)) != string::npos) {
                ++cnt; ++p; if (cnt > 50) break;
            }
            r.log_entries = cnt;
        }
    }
    return r;
}