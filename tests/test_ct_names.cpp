// SPDX-License-Identifier: GPL-3.0-or-later
// names --ct: crt.sh answers parsed into the names under one domain, and
// which of them share an address. fixture shapes follow real crt.sh rows.
#include "doctest.h"
#include "../src/scan/ct_names.h"
#include "../src/common/json.h"

#include <algorithm>
#include <string>

namespace {

const char* CRT = R"([
  {"id": 101, "common_name": "example.com", "name_value": "example.com\nwww.example.com", "not_before": "2025-01-10T00:00:00"},
  {"id": 102, "common_name": "panel.example.com", "name_value": "panel.example.com\nsub.example.com", "not_before": "2025-03-01T00:00:00"},
  {"id": 103, "common_name": "*.example.com", "name_value": "*.example.com", "not_before": "2024-11-05T00:00:00"},
  {"id": 104, "common_name": "remnawave.example.com",
   "name_value": "remnawave.example.com\nadmin@example.com\nexample.com.evil.net\nnotexample.com\nSUBWAY.example.com.",
   "not_before": "2024-12-01T00:00:00"},
  {"id": 102, "common_name": "sub.example.com", "name_value": "sub.example.com", "not_before": "2025-03-01T00:00:00"}
])";

const CtName* find(const CtNames& ct, const std::string& n) {
    for (const auto& x : ct.names) if (x.name == n) return &x;
    return nullptr;
}

} // namespace

TEST_CASE("ct names: only host names under the domain, deduplicated by certificate") {
    const CtNames ct = parse_ct_names(CRT, "Example.com.");
    REQUIRE(ct.lookup_complete);
    CHECK(ct.domain == "example.com");
    CHECK(ct.certificates == 4);
    CHECK(ct.names.size() == 6);
    CHECK(find(ct, "admin@example.com") == nullptr);
    CHECK(find(ct, "example.com.evil.net") == nullptr);
    CHECK(find(ct, "notexample.com") == nullptr);
    REQUIRE(find(ct, "subway.example.com"));
    // word match: "subway" is not the "sub" convention
    CHECK_FALSE(find(ct, "subway.example.com")->marks.any());
    const CtName* apex = find(ct, "example.com");
    REQUIRE(apex);
    CHECK(apex->wildcard);
    CHECK(apex->first_seen == "2024-11-05");
    CHECK(find(ct, "sub.example.com")->certificates == 1);
    // strongest first
    CHECK(ct.names.front().name == "remnawave.example.com");
    CHECK(ct.names.front().marks.strong);
    CHECK(find(ct, "panel.example.com")->marks.moderate);
}

TEST_CASE("ct names: broken answers are errors, not empty results") {
    CHECK_FALSE(parse_ct_names("<html>rate limited</html>", "example.com").lookup_complete);
    CHECK_FALSE(parse_ct_names("{\"id\": 1}", "example.com").lookup_complete);
    CHECK_FALSE(parse_ct_names("[{\"name_value\": \"a.example.com\"}]", "example.com").lookup_complete);
    CHECK(parse_ct_names("[]", "example.com").lookup_complete);
    CHECK(parse_ct_names("[]", "example.com").names.empty());
    CHECK(parse_ct_names("[]", "203.0.113.5").err == "not a domain name");
    CHECK(parse_ct_names("[]", "*.example.com").err == "not a domain name");
}

TEST_CASE("ct names: shared addresses, the node always listed") {
    const CtNames ct = parse_ct_names(CRT, "example.com");
    const std::vector<std::pair<std::string, std::vector<std::string>>> dns = {
        {"example.com", {"203.0.113.5"}},
        {"panel.example.com", {"203.0.113.5"}},
        {"www.example.com", {"198.51.100.7"}},
        {"sub.example.com", {"198.51.100.9"}},
    };
    auto s = ct_shared_addresses(ct, dns, "203.0.113.5");
    REQUIRE(s.size() == 1);
    CHECK(s[0].ip == "203.0.113.5");
    CHECK(s[0].node);
    CHECK(s[0].marked);
    CHECK(s[0].names.size() == 2);
    // a lone name is listed only when it is the node
    s = ct_shared_addresses(ct, dns, "198.51.100.7");
    REQUIRE(s.size() == 2);
    CHECK(s[0].node);
    CHECK(s[0].names == std::vector<std::string>{"www.example.com"});
    CHECK_FALSE(s[0].marked);
    CHECK(ct_shared_addresses(ct, {}, "").empty());

    bool ok = false;
    const auto j = json_parse(ct_names_json(ct, s), &ok);
    REQUIRE(ok);
    CHECK(j["domain"].as_str() == "example.com");
    CHECK(j["names"].size() == 6);
    CHECK(j["shared_addresses"].size() == 2);
}
