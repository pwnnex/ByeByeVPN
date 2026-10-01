// SPDX-License-Identifier: GPL-3.0-or-later
#include "ct.h"
#include "../net/http.h"
#include "../common/util.h"

using std::string;

CtCheck ct_check(const string& cert_sha256) {
    CtCheck r;
    // need a full 64-char hex digest
    // a bad query returning [] doesn't mean the cert is missing from ct
    if (cert_sha256.size() != 64) { r.err = "no sha256"; return r; }
    for (char c : cert_sha256) {
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) { r.err = "malformed sha256"; return r; }
    }
    r.queried = true;
    string url = "https://crt.sh/?q=" + cert_sha256 + "&output=json";
    auto h = http_get(url, 5000);
    if (!h.ok()) {
        r.err = h.err.empty() ? "http " + std::to_string(h.status) : h.err;
        return r;
    }
    return parse_ct_response(h.body);
}
