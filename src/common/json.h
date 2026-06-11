// SPDX-License-Identifier: GPL-3.0-or-later
// minimal, dependency-free JSON value + parser. just enough to walk an
// Xray / sing-box config tree for the `audit-config` advisor. it is NOT a
// spec-perfect JSON implementation: it accepts the subset real configs use
// (objects, arrays, strings, numbers, bools, null), tolerates trailing junk,
// and is hardened against malformed / hostile input (bounded recursion, never
// throws, never reads out of bounds). this file is platform-agnostic and is
// compiled into the Linux unit-test build.
#pragma once

#include <string>
#include <vector>

struct JsonValue {
    enum class Type { Null, Bool, Num, Str, Arr, Obj };
    Type type = Type::Null;

    bool        b = false;
    double      num = 0.0;
    std::string str;
    // recursive members: std::vector<IncompleteType> is explicitly allowed
    // (C++17, P0033), but std::pair<.., IncompleteType> is NOT — it requires
    // complete types and clang rejects it. so objects are stored as two
    // parallel vectors (keys[i] -> vals[i]) instead of a vector<pair>.
    std::vector<JsonValue>   arr;    // array elements
    std::vector<std::string> keys;   // object keys
    std::vector<JsonValue>   vals;   // object values, parallel to keys

    bool is_null() const { return type == Type::Null; }
    bool is_bool() const { return type == Type::Bool; }
    bool is_num()  const { return type == Type::Num;  }
    bool is_str()  const { return type == Type::Str;  }
    bool is_arr()  const { return type == Type::Arr;  }
    bool is_obj()  const { return type == Type::Obj;  }

    // safe accessors — never throw. on a type mismatch they return a default.
    // as_str returns by value so a caller binding the result to a reference
    // can never end up pointing at the default temporary.
    std::string as_str(const std::string& def = std::string()) const;
    double as_num(double def = 0.0) const;
    bool   as_bool(bool def = false) const;
    int    as_int(int def = 0) const { return (int)as_num((double)def); }

    // object lookup by key. returns a reference to a shared Null value when
    // the key is absent or this is not an object, so chaining `a["x"]["y"]`
    // never crashes on a missing path.
    const JsonValue& operator[](const std::string& key) const;

    // array element by index. out-of-range / non-array -> shared Null.
    const JsonValue& at(size_t i) const;

    // element count: array length, object key count, else 0.
    size_t size() const;

    // true iff this is an object that has `key`.
    bool has(const std::string& key) const;
};

// parse `text`. on success returns the root value and sets *ok = true (if ok
// is non-null). on any parse error returns a Null value and sets *ok = false.
JsonValue json_parse(const std::string& text, bool* ok = nullptr);
