// SPDX-License-Identifier: GPL-3.0-or-later
#include "util.h"
#include "platform.h"

// string helpers shared by the cli and tests
// platform-specific conversions stay behind _WIN32
#ifdef _WIN32
#else
#include <strings.h>
#endif

#include "config.h"

#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>

using std::string;
using std::vector;

// portable case-insensitive C-string compare.
static int ci_strcmp(const char* a, const char* b) {
#ifdef _WIN32
    return _stricmp(a, b);
#else
    return strcasecmp(a, b);
#endif
}

string tolower_s(string s) {
    for (auto& c: s) c = (char)std::tolower((unsigned char)c);
    return s;
}

bool contains(const string& h, const string& n) { return h.find(n) != string::npos; }

bool starts_with(const string& s, const string& p) {
    return s.size() >= p.size() && std::memcmp(s.data(), p.data(), p.size()) == 0;
}

string trim(const string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a, b - a);
}

vector<string> split(const string& s, char sep) {
    vector<string> r; string cur;
    for (char c: s) {
        if (c == sep) { r.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    r.push_back(cur);
    return r;
}

string hex_s(const unsigned char* d, size_t n, bool spaces) {
    static const char* hex = "0123456789abcdef";
    string s; s.reserve(n * (spaces ? 3 : 2));
    for (size_t i = 0; i < n; ++i) {
        s += hex[(d[i] >> 4) & 0xF];
        s += hex[d[i] & 0xF];
        if (spaces && i + 1 < n) s += ' ';
    }
    return s;
}

// wide-char <-> utf-8 glue. only the windows networking / adapter code
// uses these; on other platforms they are unreachable stubs that exist
// purely so the file links in the cross-platform test build.
#ifdef _WIN32
string ws2s(const wchar_t* w) {
    if (!w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    string s((size_t)n - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring s2ws(const string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring w((size_t)n - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}
#else
string      ws2s(const wchar_t*) { return {}; }
std::wstring s2ws(const string&) { return {}; }
#endif

// grab a scalar by key from geoip json
// check both sides of the token so a value like "asn" can't pass as a key
// not a full json parser; objects and arrays return an empty string
string json_get_str(const string& body, const string& key) {
    string pat = "\"" + key + "\"";
    size_t p = 0;
    while ((p = body.find(pat, p)) != string::npos) {
        // left side: the nearest non-space char before the token must open an
        // object or separate members, otherwise this is a value, not a key.
        size_t b = p;
        while (b > 0 && std::isspace((unsigned char)body[b - 1])) --b;
        bool key_position = (b > 0 && (body[b - 1] == '{' || body[b - 1] == ','));
        if (!key_position) { p += pat.size(); continue; }

        // right side: optional whitespace, then the ':' separator.
        size_t q = p + pat.size();
        while (q < body.size() && (body[q] == ' ' || body[q] == '\t')) ++q;
        if (q >= body.size() || body[q] != ':') { p += pat.size(); continue; }
        ++q;
        // a pretty-printer is allowed to put the value on the next line, so
        // skip every kind of whitespace here, not just spaces and tabs.
        while (q < body.size() && std::isspace((unsigned char)body[q])) ++q;
        if (q >= body.size()) return {};

        if (body[q] == '"') {
            size_t e = q + 1;
            string v;
            while (e < body.size() && body[e] != '"') {
                if (body[e] == '\\' && e + 1 < body.size()) { v += body[e+1]; e += 2; }
                else { v += body[e]; ++e; }
            }
            return v;
        }
        // a nested object/array has no scalar text to hand back. the bare scan
        // below would have chopped it at the first ',' and returned a shard
        // like `{"asn":13335` - ipapi.is, whose "asn" is an object, hit exactly
        // that on its fallback path. report "absent" instead; callers that want
        // the inner fields already slice the sub-object out first.
        if (body[q] == '{' || body[q] == '[') return {};
        size_t e = q;
        while (e < body.size() && body[e] != ',' && body[e] != '}' && body[e] != '\n') ++e;
        return trim(body.substr(q, e - q));
    }
    return {};
}

bool icontains(const string& hay, const char* needle) {
    if (!needle || !*needle) return false;
    // walk hay manually with case-insensitive compare. avoids two
    // tolower copies per call (the previous version allocated twice).
    size_t nlen = std::strlen(needle);
    if (nlen == 0 || hay.size() < nlen) return false;
    for (size_t i = 0; i + nlen <= hay.size(); ++i) {
        size_t j = 0;
        for (; j < nlen; ++j) {
            unsigned char a = (unsigned char)hay[i + j];
            unsigned char b = (unsigned char)needle[j];
            if (std::tolower(a) != std::tolower(b)) break;
        }
        if (j == nlen) return true;
    }
    return false;
}

string printable_prefix(const string& s, size_t lim) {
    string out;
    out.reserve(std::min(s.size(), lim));
    for (size_t i = 0; i < s.size() && out.size() < lim; ++i) {
        char c = s[i];
        if (c >= 32 && c < 127) out += c;
        else if (c == '\r') out += "\\r";
        else if (c == '\n') out += "\\n";
        else out += '.';
    }
    return out;
}

double percentile(vector<double> v, double pct) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    size_t n = v.size();
    double idx = pct * static_cast<double>(n - 1);
    size_t lo = (size_t)std::floor(idx);
    size_t hi = (size_t)std::ceil(idx);
    if (lo == hi) return v[lo];
    double frac = idx - static_cast<double>(lo);
    return v[lo] * (1 - frac) + v[hi] * frac;
}

string mac_to_str(const unsigned char* mac, int len) {
    char buf[64]; buf[0] = 0;
    for (int i = 0; i < len; ++i)
        std::sprintf(buf + std::strlen(buf), "%02X%s", mac[i], i < len-1 ? ":" : "");
    return buf;
}

bool is_ip_literal(const string& s) {
    if (s.empty()) return false;
    if (s.find(':') != string::npos) return true;
    int dots = 0;
    for (unsigned char c : s) {
        if (c == '.') ++dots;
        else if (!std::isdigit(c)) return false;
    }
    return dots == 3;
}

bool dns_name_match(const string& name, const string& pat) {
    if (name.empty() || pat.empty()) return false;
    if (pat.size() > 2 && pat[0] == '*' && pat[1] == '.') {
        string suffix = pat.substr(1); // ".example.com"
        if (name.size() <= suffix.size()) return false;
        size_t off = name.size() - suffix.size();
        return ci_strcmp(name.c_str() + off, suffix.c_str()) == 0 &&
               name.find('.') == off;
    }
    return ci_strcmp(name.c_str(), pat.c_str()) == 0;
}

string extract_cn(const string& subject_oneline) {
    size_t pos = subject_oneline.find("/CN=");
    if (pos == string::npos) return "";
    size_t end = subject_oneline.find('/', pos + 4);
    return subject_oneline.substr(pos + 4,
        end == string::npos ? string::npos : end - pos - 4);
}

string extract_cn_from_subject(const string& subj) {
    size_t p = subj.find("CN=");
    if (p == string::npos) return {};
    p += 3;
    size_t e = subj.find_first_of("/,", p);
    return subj.substr(p, e == string::npos ? string::npos : e - p);
}

// shared csprng byte filler - tiny wrapper so callers don't have to pull in
// <openssl/rand.h> just to seed a shuffle.
void csprng_bytes(unsigned char* buf, int n) { RAND_bytes(buf, n); }

void stealth_sleep_ms(int min_ms, int max_ms) {
    if (!g_stealth) return;
    if (max_ms <= min_ms) {
        sleep_ms((unsigned)min_ms);
        return;
    }
    unsigned char r[2];
    csprng_bytes(r, 2);
    unsigned span = (unsigned)(max_ms - min_ms + 1);
    unsigned pick = (((unsigned)r[0] << 8) | r[1]) % span;
    unsigned ms = (unsigned)min_ms + pick;
    sleep_ms(ms);
}
