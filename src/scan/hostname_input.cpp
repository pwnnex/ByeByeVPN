// SPDX-License-Identifier: GPL-3.0-or-later
#include "hostname_input.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <cstdint>
#include <limits>

namespace {
bool label_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

void append_utf8(std::string& out, uint32_t c) {
    if (c < 0x80) out += static_cast<char>(c);
    else if (c < 0x800) {
        out += static_cast<char>(0xc0 | (c >> 6));
        out += static_cast<char>(0x80 | (c & 63));
    } else if (c < 0x10000) {
        out += static_cast<char>(0xe0 | (c >> 12));
        out += static_cast<char>(0x80 | ((c >> 6) & 63));
        out += static_cast<char>(0x80 | (c & 63));
    } else {
        out += static_cast<char>(0xf0 | (c >> 18));
        out += static_cast<char>(0x80 | ((c >> 12) & 63));
        out += static_cast<char>(0x80 | ((c >> 6) & 63));
        out += static_cast<char>(0x80 | (c & 63));
    }
}

// rfc 3492 section 6.2, with bounded arithmetic and unicode scalar checks.
bool decode_punycode(const std::string& label, std::string& out) {
    const std::string text = label.substr(4);
    std::vector<uint32_t> points;
    size_t pos = 0;
    const size_t delim = text.rfind('-');
    if (delim != std::string::npos) {
        for (size_t p = 0; p < delim; ++p) {
            if (!label_char(text[p]) || text[p] == '_') return false;
            points.push_back(static_cast<unsigned char>(text[p]));
        }
        pos = delim + 1;
    }
    if (pos == text.size()) return false;
    constexpr uint64_t limit = std::numeric_limits<uint32_t>::max();
    uint64_t n = 128, i = 0, bias = 72;
    while (pos < text.size()) {
        const uint64_t old = i;
        uint64_t weight = 1;
        for (uint64_t k = 36;; k += 36) {
            if (pos == text.size()) return false;
            const char c = text[pos++];
            const uint64_t digit = c >= 'a' && c <= 'z' ? c - 'a'
                                 : c >= '0' && c <= '9' ? c - '0' + 26 : 36;
            if (digit >= 36 || digit > (limit - i) / weight) return false;
            i += digit * weight;
            const uint64_t t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
            if (digit < t) break;
            if (weight > limit / (36 - t)) return false;
            weight *= 36 - t;
        }
        const uint64_t count = points.size() + 1;
        uint64_t delta = (i - old) / (old == 0 ? 700 : 2);
        delta += delta / count;
        uint64_t k = 0;
        while (delta > 455) { delta /= 35; k += 36; }
        bias = k + 36 * delta / (delta + 38);
        n += i / count;
        i %= count;
        if (n < 0xa0 || n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff) ||
            (n >= 0x2000 && n <= 0x206f) || n == 0xfeff || n == 0x3002 ||
            n == 0xff0e || n == 0xff61 || n == 0xad || (n & 0xffff) >= 0xfffe)
            return false;
        points.insert(points.begin() + static_cast<size_t>(i), static_cast<uint32_t>(n));
        ++i;
    }
    for (auto c : points) append_utf8(out, c);
    return !out.empty();
}
}

HostnameInput parse_hostname(const std::string& host) {
    HostnameInput r;
    auto invalid = [&](const char* why) {
        r.status = HostnameInput::Status::Invalid;
        r.error = why;
        r.labels.clear();
        r.decoded_labels.clear();
        r.canonical.clear();
        return r;
    };
    if (host.empty() || host.size() > 254) return invalid("empty name or name too long");
    std::string name = host;
    for (auto& c : name) {
        const auto b = static_cast<unsigned char>(c);
        if (b >= 128) return invalid("use the ASCII/Punycode spelling for international names");
        if (b <= 32 || b == 127) return invalid("whitespace or control byte in hostname");
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    }
    if (name.back() == '.') name.pop_back();
    if (name.size() > 253) return invalid("name too long");
    std::string ip = name;
    if (ip.size() > 2 && ip.front() == '[' && ip.back() == ']') ip = ip.substr(1, ip.size() - 2);
    unsigned char address[16]{};
    if (inet_pton(AF_INET, ip.c_str(), address) == 1 || inet_pton(AF_INET6, ip.c_str(), address) == 1) {
        r.status = HostnameInput::Status::IpLiteral;
        r.canonical = ip;
        return r;
    }
    if (name.rfind("*.", 0) == 0) { r.wildcard = true; name.erase(0, 2); }
    if (name.empty() || name.size() > 253) return invalid("empty name or name too long");
    bool numeric = true;
    for (unsigned char c : name) if ((c < '0' || c > '9') && c != '.') numeric = false;
    if (numeric) return invalid("invalid IP literal");
    size_t start = 0;
    while (start < name.size()) {
        const size_t dot = name.find('.', start);
        const auto label = name.substr(start, dot == std::string::npos ? dot : dot - start);
        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-')
            return invalid("invalid DNS label length or hyphen position");
        for (unsigned char c : label) if (!label_char(c)) return invalid("expected a hostname, not a URL or host:port");
        std::string decoded = label;
        if (label.rfind("xn--", 0) == 0) {
            decoded.clear();
            if (!decode_punycode(label, decoded)) return invalid("invalid or unsupported Punycode label");
        }
        r.labels.push_back(label);
        r.decoded_labels.push_back(decoded);
        if (dot == std::string::npos) break;
        start = dot + 1;
        if (start == name.size()) return invalid("empty DNS label");
    }
    r.status = HostnameInput::Status::Hostname;
    r.canonical = (r.wildcard ? "*." : "") + name;
    return r;
}
