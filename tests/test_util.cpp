// SPDX-License-Identifier: GPL-3.0-or-later
// unit tests for src/common/util.cpp string + parsing helpers.
#include "doctest.h"
#include "../src/common/util.h"

#include <vector>

TEST_CASE("trim strips leading/trailing whitespace") {
    CHECK(trim("  hello  ") == "hello");
    CHECK(trim("\t\n x \r\n") == "x");
    CHECK(trim("") == "");
    CHECK(trim("   ") == "");
    CHECK(trim("no-ws") == "no-ws");
}

TEST_CASE("split breaks on separator and keeps empties") {
    auto a = split("a,b,c", ',');
    REQUIRE(a.size() == 3);
    CHECK(a[0] == "a"); CHECK(a[1] == "b"); CHECK(a[2] == "c");

    auto b = split("a,,c", ',');
    REQUIRE(b.size() == 3);
    CHECK(b[1] == "");

    auto c = split("", ',');
    REQUIRE(c.size() == 1);
    CHECK(c[0] == "");

    auto d = split("trailing,", ',');
    REQUIRE(d.size() == 2);
    CHECK(d[1] == "");
}

TEST_CASE("tolower_s / starts_with / contains") {
    CHECK(tolower_s("MixedCASE 123") == "mixedcase 123");
    CHECK(starts_with("HTTP/1.1 200", "HTTP/"));
    CHECK_FALSE(starts_with("HTTP", "HTTP/1.1"));
    CHECK(starts_with("anything", ""));
    CHECK(contains("the quick brown fox", "quick"));
    CHECK_FALSE(contains("abc", "xyz"));
}

TEST_CASE("hex_s renders bytes with and without spaces") {
    unsigned char d[] = {0x00, 0xff, 0x1a, 0xb2};
    CHECK(hex_s(d, 4, false) == "00ff1ab2");
    CHECK(hex_s(d, 4, true)  == "00 ff 1a b2");
    CHECK(hex_s(d, 0, false) == "");
}

TEST_CASE("json_get_str pulls quoted and bare values") {
    std::string body = R"({"ip":"1.2.3.4","asn":13335,"is_vpn":true,"city":"Berlin"})";
    CHECK(json_get_str(body, "ip")     == "1.2.3.4");
    CHECK(json_get_str(body, "asn")    == "13335");
    CHECK(json_get_str(body, "is_vpn") == "true");
    CHECK(json_get_str(body, "city")   == "Berlin");
    CHECK(json_get_str(body, "absent") == "");
}

TEST_CASE("json_get_str handles escaped quote in value") {
    std::string body = R"({"name":"a\"b"})";
    CHECK(json_get_str(body, "name") == "a\"b");
}

TEST_CASE("icontains is case-insensitive substring") {
    CHECK(icontains("Cloudflare, Inc.", "cloudflare"));
    CHECK(icontains("HOSTKEY B.V.", "hostkey"));
    CHECK_FALSE(icontains("amazon", "aws"));
    CHECK_FALSE(icontains("short", "longerneedle"));
    CHECK_FALSE(icontains("anything", ""));
}

TEST_CASE("dns_name_match exact and wildcard") {
    CHECK(dns_name_match("www.example.com", "www.example.com"));
    CHECK(dns_name_match("WWW.EXAMPLE.COM", "www.example.com"));
    CHECK(dns_name_match("api.example.com", "*.example.com"));
    // wildcard matches exactly one label, not nested subdomains
    CHECK_FALSE(dns_name_match("a.b.example.com", "*.example.com"));
    // wildcard must not match the bare apex
    CHECK_FALSE(dns_name_match("example.com", "*.example.com"));
    CHECK_FALSE(dns_name_match("", "x"));
    CHECK_FALSE(dns_name_match("x", ""));
}

TEST_CASE("extract_cn from /CN= oneline subject") {
    CHECK(extract_cn("/C=US/O=Cloudflare/CN=cloudflare.com") == "cloudflare.com");
    CHECK(extract_cn("/C=US/CN=a.b.c/OU=x") == "a.b.c");
    CHECK(extract_cn("/C=US/O=NoCN") == "");
}

TEST_CASE("extract_cn_from_subject from CN= in mixed subject") {
    CHECK(extract_cn_from_subject("CN=foo.com,O=Bar") == "foo.com");
    CHECK(extract_cn_from_subject("O=Bar/CN=baz.net") == "baz.net");
    CHECK(extract_cn_from_subject("O=NoCommonName") == "");
}

TEST_CASE("printable_prefix escapes and bounds") {
    CHECK(printable_prefix("hello", 80) == "hello");
    CHECK(printable_prefix("a\r\nb", 80) == "a\\r\\nb");
    CHECK(printable_prefix("abcdef", 3) == "abc");
    std::string ctrl;
    ctrl.push_back((char)0x01);
    ctrl += "x";
    CHECK(printable_prefix(ctrl, 80) == ".x");
}

TEST_CASE("percentile interpolates") {
    std::vector<double> v = {10, 20, 30, 40, 50};
    CHECK(percentile(v, 0.0) == doctest::Approx(10));
    CHECK(percentile(v, 1.0) == doctest::Approx(50));
    CHECK(percentile(v, 0.5) == doctest::Approx(30));
    std::vector<double> empty;
    CHECK(percentile(empty, 0.5) == doctest::Approx(0.0));
}

TEST_CASE("mac_to_str formats colon-separated hex") {
    unsigned char mac[] = {0x08, 0x00, 0x27, 0x4e, 0xd3, 0x7f};
    CHECK(mac_to_str(mac, 6) == "08:00:27:4E:D3:7F");
}
