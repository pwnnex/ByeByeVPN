#include "ct_check.h"
#include "../network/http_client.h"
#include "../core/utils.h"

CtCheck ct_check(const std::string& cert_sha256) {
    CtCheck r;
    if (cert_sha256.size() < 32) { r.err = "no sha256"; return r; }
    r.queried = true;
    std::string url = "https://crt.sh/?q=" + cert_sha256 + "&output=json";
    auto h = http_get(url, 5000);
    if (!h.ok()) { r.err = "http " + std::to_string(h.status); return r; }
    if (h.body.size() >= 2) {
        std::string b = trim(h.body);
        if (b.size() >= 2 && b[0] == '[' && b[1] == ']') {
            r.found = false;
            r.log_entries = 0;
        } else {
            r.found = true;
            int cnt = 0;
            size_t p = 0;
            while ((p = h.body.find("\"id\"", p)) != std::string::npos) {
                ++cnt; ++p; if (cnt > 50) break;
            }
            r.log_entries = cnt;
        }
    }
    return r;
}