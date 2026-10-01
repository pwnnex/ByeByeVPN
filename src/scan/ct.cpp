// SPDX-License-Identifier: GPL-3.0-or-later
#include "ct.h"
#include "../net/http.h"
#include "../common/util.h"

using std::string;

string ct_names_fetch(const string& domain, string& err) {
    // %25 is the crt.sh wildcard; deduplicate drops precertificate twins
    const string url = "https://crt.sh/?q=%25." + domain + "&output=json&deduplicate=Y";
    auto h = http_get(url, 20000);
    // crt.sh often answers 502/503 under load; one retry
    if (h.status >= 500) h = http_get(url, 20000);
    if (!h.ok()) {
        err = h.err.empty() ? "crt.sh answered HTTP " + std::to_string(h.status) : "crt.sh: " + h.err;
        if (h.err.find("512 KiB") != string::npos)
            err += "; too many certificates, query a subdomain or save the JSON and use --ct-file";
        return {};
    }
    return h.body;
}

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
