// SPDX-License-Identifier: GPL-3.0-or-later
// unit tests for src/common/json.cpp (the minimal config-audit JSON parser).
#include "doctest.h"
#include "../src/common/json.h"

#include <string>

TEST_CASE("json_parse handles scalars, objects, arrays") {
    bool ok = false;
    JsonValue v = json_parse(R"({"a":1,"b":"hi","c":true,"d":null,"e":[1,2,3]})", &ok);
    CHECK(ok);
    CHECK(v.is_obj());
    CHECK(v["a"].as_int() == 1);
    CHECK(v["b"].as_str() == "hi");
    CHECK(v["c"].as_bool() == true);
    CHECK(v["d"].is_null());
    CHECK(v["e"].is_arr());
    CHECK(v["e"].size() == 3);
    CHECK(v["e"].at(1).as_int() == 2);
}

TEST_CASE("json_parse: missing keys and bad indexes return Null, never crash") {
    JsonValue v = json_parse(R"({"x":{"y":42}})");
    CHECK(v["x"]["y"].as_int() == 42);
    // deep missing chain stays Null instead of throwing
    CHECK(v["nope"]["deeper"]["leaf"].is_null());
    CHECK(v["x"].at(9).is_null());
    CHECK(v["x"]["y"].at(0).is_null());
    CHECK(v.has("x"));
    CHECK_FALSE(v.has("nope"));
}

TEST_CASE("json_parse: nested arrays of objects (config-shaped)") {
    bool ok = false;
    JsonValue v = json_parse(
        R"({"inbounds":[{"protocol":"vless","port":443},{"protocol":"trojan","port":8443}]})",
        &ok);
    CHECK(ok);
    const JsonValue& ib = v["inbounds"];
    REQUIRE(ib.is_arr());
    REQUIRE(ib.size() == 2);
    CHECK(ib.at(0)["protocol"].as_str() == "vless");
    CHECK(ib.at(1)["port"].as_int() == 8443);
}

TEST_CASE("json_parse: string escapes and \\u decoding") {
    JsonValue v = json_parse(R"({"s":"a\tb\n\"q\"A"})");
    CHECK(v["s"].as_str() == "a\tb\n\"q\"A");
}

TEST_CASE("json_parse: tolerates // and /* */ comments") {
    bool ok = false;
    JsonValue v = json_parse(
        "{\n  // leading comment\n  \"a\": 1, /* inline */ \"b\": 2\n}", &ok);
    CHECK(ok);
    CHECK(v["a"].as_int() == 1);
    CHECK(v["b"].as_int() == 2);
}

TEST_CASE("json_parse: malformed input fails cleanly") {
    bool ok = true;
    JsonValue v = json_parse(R"({"a":)", &ok);
    CHECK_FALSE(ok);
    CHECK(v.is_null());

    ok = true;
    json_parse(R"({"a":1,)", &ok);
    CHECK_FALSE(ok);

    ok = true;
    json_parse("not json at all", &ok);
    CHECK_FALSE(ok);
}

TEST_CASE("json_parse: number forms") {
    JsonValue v = json_parse(R"({"i":443,"neg":-5,"f":1.5,"e":2e3})");
    CHECK(v["i"].as_int() == 443);
    CHECK(v["neg"].as_int() == -5);
    CHECK(v["f"].as_num() == doctest::Approx(1.5));
    CHECK(v["e"].as_num() == doctest::Approx(2000.0));
}
