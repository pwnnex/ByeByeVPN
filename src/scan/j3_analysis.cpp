// SPDX-License-Identifier: GPL-3.0-or-later
#include "j3.h"
#include "https_probe.h"
#include <cstring>
using std::string;
using std::vector;

static bool looks_like_http_line(const string& first_line, bool* bad_version_out = nullptr) {
    if (first_line.rfind("HTTP/", 0) != 0) return false;
    auto parsed = parse_https_response(first_line + "\r\n\r\n");
    if (bad_version_out) *bad_version_out = !parsed.http_valid;
    return true;
}

// tls record prefix only; an alert does not identify the server's protocol.
static bool looks_like_tls_record(const string& hex_head) {
    if (hex_head.size() < 5) return false;
    string ct = hex_head.substr(0, 2);
    if (ct != "14" && ct != "15" && ct != "16" && ct != "17") return false;
    return hex_head.compare(3, 2, "03") == 0;
}

J3Analysis j3_analyze(const vector<J3Result>& probes) {
    J3Analysis a;
    struct KeyEntry { string line; int bytes; const char* name; };
    vector<KeyEntry> keys;
    for (auto& p: probes) {
        if (p.responded) {
            ++a.resp;
            keys.push_back({p.first_line, p.bytes, p.name.c_str()});
            bool bad_v = false;
            bool is_http = looks_like_http_line(p.first_line, &bad_v);
            if (is_http && !bad_v)               ++a.http_real;
            else if (is_http && bad_v)           ++a.http_bad_version;
            else if (looks_like_tls_record(p.hex_head)) { /* legit tls reply, not proxy framing */ }
            else                                 ++a.raw_non_http;
        } else {
            ++a.silent;
        }
        switch (p.end) {
        case ReadEnd::Fin:       ++a.closed; break;
        case ReadEnd::Reset:     ++a.reset; break;
        case ReadEnd::Held:      ++a.held; break;
        case ReadEnd::NoConnect: ++a.no_connect; break;
        default: break;
        }
    }
    auto is_valid_http_probe = [](const char* n) {
        if (!n) return false;
        return std::strstr(n, "HTTP GET /") != nullptr ||
               std::strstr(n, "HTTP abs-URI") != nullptr;
    };
    for (size_t i = 0; i < keys.size(); ++i) {
        int count = 0;
        bool has_valid_http = false, has_garbage = false;
        for (size_t j = 0; j < keys.size(); ++j) {
            if (keys[i].line == keys[j].line && keys[i].bytes == keys[j].bytes) {
                ++count;
                if (is_valid_http_probe(keys[j].name)) has_valid_http = true;
                else                                   has_garbage = true;
            }
        }
        // first line and captured length only; this is not a whole-body comparison.
        if (count >= 2 && count > a.canned_identical && keys[i].line.size() > 3 && has_valid_http && has_garbage) {
            a.canned_identical = count;
            a.canned_line      = keys[i].line;
            a.canned_bytes     = keys[i].bytes;
        }
    }
    return a;
}
