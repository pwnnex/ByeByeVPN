// SPDX-License-Identifier: GPL-3.0-or-later
#include "tspu.h"

#include <cctype>
#include <cstdio>

using std::string;

// 10.<region>.<site>.z layout (tspu-docs ch. 10):
//   .131-.140 balancers, .141-.150 bmc, .151-.190 filters,
//   .191-.230 ipmi, .231-.235 spfs, .241-.245 spxd, .254 kontinent gw.
bool looks_like_tspu_hop(const string& addr) {
    if (addr.size() < 8 || addr.size() > 15) return false;
    if (addr.compare(0, 3, "10.") != 0) return false;
    unsigned a = 0, b = 0, c = 0;
    if (std::sscanf(addr.c_str(), "10.%u.%u.%u", &a, &b, &c) != 3) return false;
    if (a > 255 || b > 255 || c > 255) return false;
    if (c >= 131 && c <= 235) return true;
    if (c >= 241 && c <= 245) return true;
    if (c == 254) return true;
    return false;
}

// known tspu-operator block/warning redirect destinations (http 302 location).
// source: public observations + tspu-docs ch. 5.1.5
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
    "185.76.180.75",      // rostelecom warning page
    "185.76.180.76",
    "185.76.180.77",
    nullptr
};

const char* looks_like_tspu_redirect(const string& location) {
    if (location.empty() || location.size() > 512) return nullptr;
    string ll = location;
    for (auto& ch: ll) {
        const auto c = static_cast<unsigned char>(ch);
        if (c <= 32 || c == 127 || c == '\\') return nullptr;
        ch = (char)std::tolower(c);
    }
    size_t start = 0;
    if (ll.rfind("https://", 0) == 0) start = 8;
    else if (ll.rfind("http://", 0) == 0) start = 7;
    else if (ll.rfind("//", 0) == 0) start = 2;
    else return nullptr;
    string authority = ll.substr(start, ll.find_first_of("/?#", start) - start);
    if (authority.empty() || authority.find_first_of("@%[],") != string::npos) return nullptr;
    const auto colon = authority.find(':');
    if (colon != string::npos) {
        unsigned port = 0;
        const auto digits = authority.substr(colon + 1);
        if (digits.empty() || digits.size() > 5) return nullptr;
        for (char c : digits) {
            if (c < '0' || c > '9') return nullptr;
            port = port * 10 + c - '0';
        }
        if (port == 0 || port > 65535) return nullptr;
        authority.resize(colon);
    }
    if (!authority.empty() && authority.back() == '.') authority.pop_back();
    for (const char** p = TSPU_REDIRECT_MARKERS; *p; ++p) {
        const string marker = *p;
        if (authority == marker) return *p;
        if (marker.front() >= '0' && marker.front() <= '9') continue;
        if (authority.size() > marker.size() && authority.ends_with("." + marker)) return *p;
    }
    return nullptr;
}
