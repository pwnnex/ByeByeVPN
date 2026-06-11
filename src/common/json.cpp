// SPDX-License-Identifier: GPL-3.0-or-later
#include "json.h"

#include <cstdlib>

using std::string;

// ---- safe accessors --------------------------------------------------------

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

// ---- parser ----------------------------------------------------------------

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
            // tolerate // and /* */ comments — sing-box / some Xray configs
            // are edited by humans and occasionally carry them.
            if (c == '/' && p + 1 < end && p[1] == '/') {
                p += 2;
                while (p < end && *p != '\n') ++p;
                continue;
            }
            if (c == '/' && p + 1 < end && p[1] == '*') {
                p += 2;
                while (p + 1 < end && !(p[0] == '*' && p[1] == '/')) ++p;
                if (p + 1 < end) p += 2; else p = end;
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

    JsonValue parse_object() {
        JsonValue v; v.type = JsonValue::Type::Obj;
        ++p; // consume '{'
        ++depth;
        skip_ws();
        if (p < end && *p == '}') { ++p; --depth; return v; }
        while (ok && p < end) {
            skip_ws();
            if (p >= end || *p != '"') { fail(); break; }
            string key = parse_string_raw();
            if (!ok) break;
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
            if (*p == '}') { ++p; --depth; return v; }
            fail();
            break;
        }
        if (ok) fail();
        return v;
    }

    JsonValue parse_array() {
        JsonValue v; v.type = JsonValue::Type::Arr;
        ++p; // consume '['
        ++depth;
        skip_ws();
        if (p < end && *p == ']') { ++p; --depth; return v; }
        while (ok && p < end) {
            JsonValue child = parse_value();
            if (!ok) break;
            v.arr.push_back(std::move(child));
            skip_ws();
            if (p >= end) { fail(); break; }
            if (*p == ',') { ++p; continue; }
            if (*p == ']') { ++p; --depth; return v; }
            fail();
            break;
        }
        if (ok) fail();
        return v;
    }

    // parse a JSON string token (assumes *p == '"'), returns the decoded text.
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
                        // decode \uXXXX to UTF-8. surrogate pairs are decoded
                        // as two separate code units (good enough for configs,
                        // which are ASCII-dominant).
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
                        if (cp < 0x80) {
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
                    default: out += e; break;
                }
            } else {
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
        while (p < end && ((*p >= '0' && *p <= '9') || *p == '.' ||
                           *p == 'e' || *p == 'E' || *p == '+' || *p == '-')) ++p;
        JsonValue v; v.type = JsonValue::Type::Num;
        string tok(start, (size_t)(p - start));
        v.num = std::strtod(tok.c_str(), nullptr);
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

JsonValue json_parse(const string& text, bool* ok) {
    Parser ps(text);
    JsonValue root = ps.parse_value();
    if (ok) *ok = ps.ok;
    if (!ps.ok) return {};
    return root;
}
