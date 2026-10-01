// SPDX-License-Identifier: GPL-3.0-or-later
#include "json.h"
#include <cstdio>

#include <cstdlib>
#include <cmath>
#include <climits>
#include <set>

using std::string;

int JsonValue::as_int(int def) const {
    double v = as_num((double)def);
    return std::isfinite(v) && v >= INT_MIN && v <= INT_MAX ? (int)v : def;
}

// safe accessors

static const JsonValue& null_value() {
    static const JsonValue kNull;   // type defaults to Null
    return kNull;
}

string JsonValue::as_str(const string& def) const {
    if (type == Type::Str) return str;
    return def;
}

double JsonValue::as_num(double def) const {
    if (type == Type::Num)  return num;
    if (type == Type::Bool) return b ? 1.0 : 0.0;
    return def;
}

bool JsonValue::as_bool(bool def) const {
    if (type == Type::Bool) return b;
    if (type == Type::Num)  return num != 0.0;
    return def;
}

const JsonValue& JsonValue::operator[](const string& key) const {
    if (type == Type::Obj)
        for (size_t i = 0; i < keys.size(); ++i)
            if (keys[i] == key) return vals[i];
    return null_value();
}

const JsonValue& JsonValue::at(size_t i) const {
    if (type == Type::Arr && i < arr.size()) return arr[i];
    return null_value();
}

size_t JsonValue::size() const {
    if (type == Type::Arr) return arr.size();
    if (type == Type::Obj) return keys.size();
    return 0;
}

bool JsonValue::has(const string& key) const {
    if (type != Type::Obj) return false;
    for (auto& k : keys) if (k == key) return true;
    return false;
}

// parser

namespace {

struct Parser {
    const char* p;
    const char* end;
    bool ok = true;
    int  depth = 0;
    static const int kMaxDepth = 64;   // hostile-input stack guard

    explicit Parser(const string& s) : p(s.data()), end(s.data() + s.size()) {}

    void skip_ws() {
        while (p < end) {
            char c = *p;
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') { ++p; continue; }
            // tolerate // and /* */ comments - sing-box / some xray configs
            // are edited by humans and occasionally carry them.
            if (c == '/' && p + 1 < end && p[1] == '/') {
                p += 2;
                while (p < end && *p != '\n') ++p;
                continue;
            }
            if (c == '/' && p + 1 < end && p[1] == '*') {
                p += 2;
                while (end - p >= 2 && !(p[0] == '*' && p[1] == '/')) ++p;
                if (end - p >= 2) p += 2;
                else { p = end; fail(); }
                continue;
            }
            break;
        }
    }

    void fail() { ok = false; }

    JsonValue parse_value() {
        if (!ok) return {};
        if (depth > kMaxDepth) { fail(); return {}; }
        skip_ws();
        if (p >= end) { fail(); return {}; }
        char c = *p;
        switch (c) {
            case '{': return parse_object();
            case '[': return parse_array();
            case '"': return parse_string_value();
            case 't': case 'f': return parse_bool();
            case 'n': return parse_null();
            default:
                if (c == '-' || (c >= '0' && c <= '9')) return parse_number();
                fail();
                return {};
        }
    }

    // balance the depth counter on every return, including parse errors
    struct DepthGuard {
        int& d;
        explicit DepthGuard(int& x) : d(x) { ++d; }
        ~DepthGuard() { --d; }
    };

    JsonValue parse_object() {
        JsonValue v; v.type = JsonValue::Type::Obj;
        ++p; // consume '{'
        DepthGuard dg(depth);
        std::set<string> seen;
        skip_ws();
        if (p < end && *p == '}') { ++p; return v; }
        while (ok && p < end) {
            skip_ws();
            if (p >= end || *p != '"') { fail(); break; }
            string key = parse_string_raw();
            if (!ok) break;
            // go json keeps the last dup, we'd read the first. just refuse
            if (!seen.insert(key).second) { fail(); break; }
            skip_ws();
            if (p >= end || *p != ':') { fail(); break; }
            ++p; // consume ':'
            JsonValue child = parse_value();
            if (!ok) break;
            v.keys.push_back(std::move(key));
            v.vals.push_back(std::move(child));
            skip_ws();
            if (p >= end) { fail(); break; }
            if (*p == ',') { ++p; continue; }
            if (*p == '}') { ++p; return v; }
            fail();
            break;
        }
        if (ok) fail();
        return v;
    }

    JsonValue parse_array() {
        JsonValue v; v.type = JsonValue::Type::Arr;
        ++p; // consume '['
        DepthGuard dg(depth);
        skip_ws();
        if (p < end && *p == ']') { ++p; return v; }
        while (ok && p < end) {
            JsonValue child = parse_value();
            if (!ok) break;
            v.arr.push_back(std::move(child));
            skip_ws();
            if (p >= end) { fail(); break; }
            if (*p == ',') { ++p; continue; }
            if (*p == ']') { ++p; return v; }
            fail();
            break;
        }
        if (ok) fail();
        return v;
    }

    // parse a json string token (assumes *p == '"'), returns the decoded text.
    string parse_string_raw() {
        string out;
        ++p; // consume opening quote
        while (p < end) {
            char c = *p++;
            if (c == '"') return out;
            if (c == '\\') {
                if (p >= end) break;
                char e = *p++;
                switch (e) {
                    case '"':  out += '"';  break;
                    case '\\': out += '\\'; break;
                    case '/':  out += '/';  break;
                    case 'b':  out += '\b'; break;
                    case 'f':  out += '\f'; break;
                    case 'n':  out += '\n'; break;
                    case 'r':  out += '\r'; break;
                    case 't':  out += '\t'; break;
                    case 'u': {
                        // decode utf-16 escapes, including surrogate pairs.
                        if (end - p < 4) { fail(); return out; }
                        unsigned cp = 0;
                        for (int i = 0; i < 4; ++i) {
                            char h = *p++;
                            cp <<= 4;
                            if      (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                            else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                            else { fail(); return out; }
                        }
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            if (end - p < 6 || p[0] != '\\' || p[1] != 'u') { fail(); return out; }
                            p += 2;
                            unsigned low = 0;
                            for (int i = 0; i < 4; ++i) {
                                char h = *p++;
                                low <<= 4;
                                if (h >= '0' && h <= '9') low |= h - '0';
                                else if (h >= 'a' && h <= 'f') low |= h - 'a' + 10;
                                else if (h >= 'A' && h <= 'F') low |= h - 'A' + 10;
                                else { fail(); return out; }
                            }
                            if (low < 0xDC00 || low > 0xDFFF) { fail(); return out; }
                            cp = 0x10000 + ((cp - 0xD800) << 10) + low - 0xDC00;
                        } else if (cp >= 0xDC00 && cp <= 0xDFFF) { fail(); return out; }
                        if (cp >= 0x10000) {
                            out += (char)(0xF0 | (cp >> 18));
                            out += (char)(0x80 | ((cp >> 12) & 0x3F));
                            out += (char)(0x80 | ((cp >> 6) & 0x3F));
                            out += (char)(0x80 | (cp & 0x3F));
                        } else if (cp < 0x80) {
                            out += (char)cp;
                        } else if (cp < 0x800) {
                            out += (char)(0xC0 | (cp >> 6));
                            out += (char)(0x80 | (cp & 0x3F));
                        } else {
                            out += (char)(0xE0 | (cp >> 12));
                            out += (char)(0x80 | ((cp >> 6) & 0x3F));
                            out += (char)(0x80 | (cp & 0x3F));
                        }
                        break;
                    }
                    default: fail(); return out;
                }
            } else {
                if ((unsigned char)c < 0x20) { fail(); return out; }
                out += c;
            }
        }
        fail();
        return out;
    }

    JsonValue parse_string_value() {
        JsonValue v; v.type = JsonValue::Type::Str;
        v.str = parse_string_raw();
        return v;
    }

    JsonValue parse_number() {
        const char* start = p;
        if (p < end && *p == '-') ++p;
        auto digit = [&] { return p < end && *p >= '0' && *p <= '9'; };
        if (!digit()) { fail(); return {}; }
        if (*p == '0') ++p;
        else while (digit()) ++p;
        if (p < end && *p == '.') {
            ++p;
            if (!digit()) { fail(); return {}; }
            while (digit()) ++p;
        }
        if (p < end && (*p == 'e' || *p == 'E')) {
            ++p;
            if (p < end && (*p == '+' || *p == '-')) ++p;
            if (!digit()) { fail(); return {}; }
            while (digit()) ++p;
        }
        JsonValue v; v.type = JsonValue::Type::Num;
        string tok(start, (size_t)(p - start));
        char* tail = nullptr;
        v.num = std::strtod(tok.c_str(), &tail);
        if (tail != tok.c_str() + tok.size() || !std::isfinite(v.num)) fail();
        return v;
    }

    JsonValue parse_bool() {
        JsonValue v; v.type = JsonValue::Type::Bool;
        if (end - p >= 4 && string(p, 4) == "true")  { p += 4; v.b = true;  return v; }
        if (end - p >= 5 && string(p, 5) == "false") { p += 5; v.b = false; return v; }
        fail();
        return v;
    }

    JsonValue parse_null() {
        if (end - p >= 4 && string(p, 4) == "null") { p += 4; return {}; }
        fail();
        return {};
    }
};

} // namespace

string json_escape_string(const string& text) {
    string out;
    out.reserve(text.size() + 8);
    const auto* s = reinterpret_cast<const unsigned char*>(text.data());
    const size_t n = text.size();
    size_t i = 0;
    while (i < n) {
        const unsigned char c = s[i];
        if (c < 0x80) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b";  break;
                case '\f': out += "\\f";  break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:
                    if (c < 0x20) {
                        char b[8];
                        std::snprintf(b, sizeof(b), "\\u%04x", c);
                        out += b;
                    } else {
                        out += static_cast<char>(c);
                    }
            }
            ++i;
            continue;
        }
        // one utf-8 scalar; overlongs, surrogates and > U+10FFFF are invalid.
        size_t len = 0;
        unsigned cp = 0, min = 0;
        if      (c >= 0xC2 && c <= 0xDF) { len = 2; cp = c & 0x1Fu; min = 0x80; }
        else if (c >= 0xE0 && c <= 0xEF) { len = 3; cp = c & 0x0Fu; min = 0x800; }
        else if (c >= 0xF0 && c <= 0xF4) { len = 4; cp = c & 0x07u; min = 0x10000; }
        bool valid = len != 0 && n - i >= len;
        for (size_t k = 1; valid && k < len; ++k) {
            if ((s[i + k] & 0xC0) != 0x80) valid = false;
            else cp = (cp << 6) | (s[i + k] & 0x3Fu);
        }
        if (valid && (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))) valid = false;
        if (valid) {
            out.append(text, i, len);
            i += len;
        } else {
            out += "\xEF\xBF\xBD";   // U+FFFD, one per invalid byte
            ++i;
        }
    }
    return out;
}

JsonValue json_parse(const string& text, bool* ok) {
    Parser ps(text);
    JsonValue root = ps.parse_value();
    // a document must be one value. without this check a truncated or
    // concatenated config ("{...}{...}", or a json object followed by a shell
    // heredoc marker) parsed "successfully" from its prefix, and audit-config
    // then reported findings for half a file as if it had read all of it.
    if (ps.ok) {
        ps.skip_ws();
        if (ps.p != ps.end) ps.fail();
    }
    if (ok) *ok = ps.ok;
    if (!ps.ok) return {};
    return root;
}
