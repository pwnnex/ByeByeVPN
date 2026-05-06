#include "tspu.h"
#include <cstdio>
#include <cctype>

bool looks_like_tspu_hop(const std::string& addr) {
    if (addr.size() < 8 || addr.size() > 15) return false;
    if (addr.compare(0, 3, "10.") != 0) return false;
    unsigned a = 0, b = 0, c = 0;
    if (sscanf(addr.c_str(), "10.%u.%u.%u", &a, &b, &c) != 3) return false;
    if (a > 255 || b > 255 || c > 255) return false;
    if (c >= 131 && c <= 235) return true;
    if (c >= 241 && c <= 245) return true;
    if (c == 254) return true;
    return false;
}

static const char* TSPU_REDIRECT_MARKERS[] = {
    "rkn.gov.ru",
    "warning.rt.ru",
    "nt.rtk.ru",
    "blocked.rt.ru",
    "blocked.ruvds.com",
    "blocked.tattelecom.ru",
    "blocked.yota.ru",
    "zapret.gov.ru",
    "eais.rkn.gov.ru",
    "185.76.180.75",
    "185.76.180.76",
    "185.76.180.77",
    nullptr
};

const char* looks_like_tspu_redirect(const std::string& location) {
    if (location.empty() || location.size() > 512) return nullptr;
    std::string ll = location;
    for (auto& ch: ll) ch = (char)std::tolower((unsigned char)ch);
    for (const char** p = TSPU_REDIRECT_MARKERS; *p; ++p) {
        if (ll.find(*p) != std::string::npos) return *p;
    }
    return nullptr;
}