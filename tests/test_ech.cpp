// SPDX-License-Identifier: GPL-3.0-or-later
// unit tests for src/scan/ech.cpp (the pure HTTPS-RR presentation parser).
#include "doctest.h"
#include "../src/scan/ech.h"

#include <string>

TEST_CASE("ech_parse extracts ech + alpn + ipv4hint (quoted values)") {
    std::string rr = "1 . alpn=\"h3,h2\" ipv4hint=104.16.132.229,104.16.133.229 "
                     "ech=\"AEX+DQBBdwAgACABcdEF\" ipv6hint=2606:4700::6810:84e5";
    EchInfo e = ech_parse(rr);
    CHECK(e.alpn == "h3,h2");
    CHECK(e.ipv4hint == "104.16.132.229,104.16.133.229");
    CHECK(e.ipv6hint == "2606:4700::6810:84e5");
    CHECK(e.has_ech);
    CHECK(e.ech_b64.rfind("AEX+DQBB", 0) == 0);
    CHECK(e.ech_len > 0);
}

TEST_CASE("ech_parse: bare (unquoted) values") {
    std::string rr = "1 . alpn=h2 ech=AEX+DQBBdwAg ipv4hint=1.2.3.4";
    EchInfo e = ech_parse(rr);
    CHECK(e.alpn == "h2");
    CHECK(e.ipv4hint == "1.2.3.4");
    CHECK(e.has_ech);
}

TEST_CASE("ech_parse: HTTPS RR without ECH") {
    std::string rr = "1 . alpn=\"h2\" ipv4hint=1.2.3.4";
    EchInfo e = ech_parse(rr);
    CHECK(e.alpn == "h2");
    CHECK_FALSE(e.has_ech);
    CHECK(e.ech_b64.empty());
}

TEST_CASE("ech_parse: empty / garbage / boundary") {
    CHECK_FALSE(ech_parse("").has_ech);
    CHECK_FALSE(ech_parse("garbage with no svcparams").has_ech);
    // a key must match at a token boundary, not as a substring of another token
    EchInfo e = ech_parse("1 . ipv4hint=9.9.9.9");
    CHECK(e.ipv4hint == "9.9.9.9");
    CHECK(e.alpn.empty());
    CHECK_FALSE(e.has_ech);
}

TEST_CASE("ech_parse: exact base64 decoded length (padded + unpadded)") {
    // 12 significant symbols -> floor(12*3/4) = 9 bytes
    EchInfo u = ech_parse("1 . ech=AEX+DQBBdwAg");
    CHECK(u.has_ech);
    CHECK(u.ech_len == 9);
    // padding '=' must not change the decoded length: 6 significant -> 4 bytes
    EchInfo p = ech_parse("1 . ech=\"QUJDRA==\"");
    CHECK(p.has_ech);
    CHECK(p.ech_len == 4);
}

TEST_CASE("ech_parse: generic RFC 3597 wire form (alpn + hints + ech)") {
    // SvcPriority=1, root target, then alpn(h3,h2) / ipv4hint / ech / ipv6hint.
    // whitespace inside the hex is tolerated; the leading rdlen is ignored.
    std::string rr =
        "\\# 49 0001 00 "
        "0001 0006 02 68 33 02 68 32 "          // alpn = h3,h2
        "0004 0004 68 10 84 e5 "                // ipv4hint = 104.16.132.229
        "0005 0004 fe 0d 00 03 "                // ech = 4 opaque bytes
        "0006 0010 26 06 47 00 00 00 00 00 00 00 00 00 68 10 84 e5"; // ipv6hint
    EchInfo e = ech_parse(rr);
    CHECK(e.alpn == "h3,h2");
    CHECK(e.ipv4hint == "104.16.132.229");
    CHECK(e.ipv6hint == "2606:4700:0:0:0:0:6810:84e5");
    CHECK(e.has_ech);
    CHECK(e.ech_len == 4);
}

TEST_CASE("ech_parse: generic wire form without an ech param") {
    EchInfo e = ech_parse("\\# 10 0001 00 0001 0003 02 68 32");  // alpn=h2 only
    CHECK(e.alpn == "h2");
    CHECK_FALSE(e.has_ech);
    CHECK(e.ipv4hint.empty());
}

TEST_CASE("ech_parse: malformed generic record is rejected safely") {
    EchInfo e = ech_parse("\\# 3 0001 0");   // dangling hex nibble
    CHECK_FALSE(e.has_ech);
    CHECK(e.alpn.empty());
    CHECK(e.ipv4hint.empty());
}
