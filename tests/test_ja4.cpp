// SPDX-License-Identifier: GPL-3.0-or-later
// unit tests for src/scan/ja4.cpp (byte parsers + JA4 builders) and
// src/scan/ja4s_db.cpp (JA4S classifier).
#include "doctest.h"
#include "../src/scan/ja4.h"
#include "../src/scan/ja4s_db.h"
#include "../src/scan/chrome_ch.h"

#include <cstdint>
#include <vector>

using std::vector;

// build a minimal but well-formed TLS 1.3 ClientHello handshake message,
// as SSL_set_msg_callback would hand it to parse_client_hello: it starts
// at the HandshakeType byte, then a uint24 length, then the body.
static vector<uint8_t> make_client_hello() {
    vector<uint8_t> body;
    auto u16 = [&](uint16_t v){ body.push_back(v >> 8); body.push_back(v & 0xff); };

    u16(0x0303);                          // legacy_version
    for (int i = 0; i < 32; ++i) body.push_back(0xAB);  // random
    body.push_back(0);                    // legacy_session_id length 0

    // cipher_suites: GREASE 0x0a0a + 1301 + 1302  (6 bytes)
    u16(6);
    u16(0x0a0a); u16(0x1301); u16(0x1302);

    body.push_back(1); body.push_back(0); // 1 compression method, null

    // extensions
    vector<uint8_t> ext;
    auto eu16 = [&](uint16_t v){ ext.push_back(v >> 8); ext.push_back(v & 0xff); };
    // SNI (0x0000): server_name_list { host_name(0) "ab" }
    eu16(0x0000); eu16(7);                // ext type, ext len
    eu16(5);                              // server_name_list len
    ext.push_back(0);                     // name type host_name
    eu16(2); ext.push_back('a'); ext.push_back('b');
    // supported_versions (0x002b): list = [0x0304]
    eu16(0x002b); eu16(3);
    ext.push_back(2); eu16(0x0304);
    // ALPN (0x0010): list = ["h2"]
    eu16(0x0010); eu16(5);
    eu16(3);                              // alpn protocol list length
    ext.push_back(2); ext.push_back('h'); ext.push_back('2');
    // signature_algorithms (0x000d): [0x0403, 0x0804]
    eu16(0x000d); eu16(6);
    eu16(4); eu16(0x0403); eu16(0x0804);

    u16((uint16_t)ext.size());
    body.insert(body.end(), ext.begin(), ext.end());

    // wrap: HandshakeType(1) + uint24 length + body
    vector<uint8_t> msg;
    msg.push_back(0x01);
    msg.push_back((body.size() >> 16) & 0xff);
    msg.push_back((body.size() >> 8) & 0xff);
    msg.push_back(body.size() & 0xff);
    msg.insert(msg.end(), body.begin(), body.end());
    return msg;
}

static vector<uint8_t> make_server_hello() {
    vector<uint8_t> body;
    auto u16 = [&](uint16_t v){ body.push_back(v >> 8); body.push_back(v & 0xff); };
    u16(0x0303);                          // legacy_version
    for (int i = 0; i < 32; ++i) body.push_back(0xCD);  // random
    body.push_back(0);                    // session_id_echo length 0
    u16(0x1302);                          // cipher_suite
    body.push_back(0);                    // compression method null

    vector<uint8_t> ext;
    auto eu16 = [&](uint16_t v){ ext.push_back(v >> 8); ext.push_back(v & 0xff); };
    eu16(0x002b); eu16(2); eu16(0x0304);  // supported_versions = 0x0304
    eu16(0x0033); eu16(2); ext.push_back(0); ext.push_back(0); // key_share stub
    u16((uint16_t)ext.size());
    body.insert(body.end(), ext.begin(), ext.end());

    vector<uint8_t> msg;
    msg.push_back(0x02);
    msg.push_back((body.size() >> 16) & 0xff);
    msg.push_back((body.size() >> 8) & 0xff);
    msg.push_back(body.size() & 0xff);
    msg.insert(msg.end(), body.begin(), body.end());
    return msg;
}

TEST_CASE("ja4_is_grease matches the 0x?A?A pattern") {
    CHECK(ja4_is_grease(0x0a0a));
    CHECK(ja4_is_grease(0x1a1a));
    CHECK(ja4_is_grease(0xfafa));
    CHECK_FALSE(ja4_is_grease(0x1301));
    CHECK_FALSE(ja4_is_grease(0x0000));
}

TEST_CASE("sha256_12 is a stable 12-hex-char digest") {
    std::string h = sha256_12("");
    CHECK(h.size() == 12);
    // sha256("") = e3b0c44298fc1c14...; first 12 hex chars are stable
    CHECK(h == "e3b0c44298fc");
    CHECK(sha256_12("abc") == sha256_12("abc"));   // deterministic
    CHECK(sha256_12("abc") != sha256_12("abd"));
}

TEST_CASE("parse_client_hello extracts the structural fields") {
    auto msg = make_client_hello();
    ClientHelloFp ch;
    REQUIRE(parse_client_hello(msg.data(), msg.size(), ch));
    REQUIRE(ch.ok);
    // GREASE cipher 0x0a0a is stripped, leaving 1301 + 1302
    REQUIRE(ch.ciphers.size() == 2);
    CHECK(ch.ciphers[0] == 0x1301);
    CHECK(ch.ciphers[1] == 0x1302);
    CHECK(ch.has_grease);
    CHECK(ch.has_sni);
    CHECK(ch.sni == "ab");
    CHECK(ch.alpn_first == "h2");
    CHECK(ch.real_version == 0x0304);    // from supported_versions
    REQUIRE(ch.sigalgs.size() == 2);
    CHECK(ch.sigalgs[0] == 0x0403);
}

TEST_CASE("parse_client_hello rejects truncated / wrong-type input") {
    ClientHelloFp ch;
    CHECK_FALSE(parse_client_hello(nullptr, 0, ch));
    uint8_t tiny[] = {0x01, 0x00};
    CHECK_FALSE(parse_client_hello(tiny, sizeof(tiny), ch));
    // a ServerHello (type 0x02) must not parse as a ClientHello
    auto sh = make_server_hello();
    CHECK_FALSE(parse_client_hello(sh.data(), sh.size(), ch));
    // claimed length longer than the buffer
    uint8_t badlen[] = {0x01, 0xff, 0xff, 0xff, 0x00};
    CHECK_FALSE(parse_client_hello(badlen, sizeof(badlen), ch));
}

TEST_CASE("ja4_client builds the canonical t..._..._... shape") {
    auto msg = make_client_hello();
    ClientHelloFp ch;
    REQUIRE(parse_client_hello(msg.data(), msg.size(), ch));
    std::string ja4 = ja4_client(ch);
    // a-part: t + 13 + d (SNI present) + 02 ciphers + 04 exts + h2
    CHECK(ja4.rfind("t13d0204h2_", 0) == 0);
    // total shape: 10-char header + "_" + 12 + "_" + 12
    CHECK(ja4.size() == 10 + 1 + 12 + 1 + 12);
    // deterministic
    ClientHelloFp ch2;
    parse_client_hello(msg.data(), msg.size(), ch2);
    CHECK(ja4_client(ch2) == ja4);
}

TEST_CASE("parse_server_hello + ja4s_server") {
    auto msg = make_server_hello();
    ServerHelloFp sh;
    REQUIRE(parse_server_hello(msg.data(), msg.size(), sh));
    REQUIRE(sh.ok);
    CHECK(sh.cipher == 0x1302);
    CHECK(sh.real_version == 0x0304);
    CHECK(sh.extensions.size() == 2);
    std::string ja4s = ja4s_server(sh);
    // a-part: t + 13 + 02 exts + 00 (no ALPN) ; b-part: cipher 1302
    CHECK(ja4s.rfind("t130200_1302_", 0) == 0);
}

TEST_CASE("ja4s_classify: exact seed hit vs structural fallback") {
    // exact: the Cloudflare-edge ext-hash seeded in ja4s_db.cpp
    Ja4sInfo cf = ja4s_classify("t130200_1301_a56c5b993250");
    CHECK(cf.confidence == "exact");
    CHECK(cf.family == "cloudflare-edge");

    // structural: unknown ext-hash, valid shape -> generic family
    Ja4sInfo st = ja4s_classify("t130203h2_1302_ffffffffffff");
    CHECK(st.confidence == "structural");
    CHECK(st.tls_version == 0x0304);
    CHECK(st.ok);

    // malformed input -> unknown, never crashes
    Ja4sInfo bad = ja4s_classify("not-a-ja4s");
    CHECK(bad.confidence == "unknown");
    Ja4sInfo empty = ja4s_classify("");
    CHECK(empty.confidence == "unknown");
}

TEST_CASE("build_chrome131_clienthello is a well-formed Chrome ClientHello") {
    auto rec = build_chrome131_clienthello("example.com");

    // TLS plaintext record header: handshake (0x16), legacy version 0x0301.
    REQUIRE(rec.size() > 5);
    CHECK(rec[0] == 0x16);
    CHECK(rec[1] == 0x03);
    CHECK(rec[2] == 0x01);
    size_t rec_len = ((size_t)rec[3] << 8) | rec[4];
    CHECK(rec_len == rec.size() - 5);

    // the handshake message (record payload) must parse as a ClientHello.
    const uint8_t* hs = rec.data() + 5;
    size_t hs_len = rec.size() - 5;
    CHECK(hs[0] == 0x01);  // HandshakeType client_hello

    ClientHelloFp ch;
    REQUIRE(parse_client_hello(hs, hs_len, ch));
    REQUIRE(ch.ok);

    // GREASE injected: the parser strips it but flags that it saw it.
    CHECK(ch.has_grease);
    CHECK(ch.has_sni);
    CHECK(ch.sni == "example.com");
    CHECK(ch.alpn_first == "h2");
    CHECK(ch.real_version == 0x0304);

    // 15 real cipher suites (GREASE-stripped) and 16 real extensions
    // (GREASE-stripped) -> the canonical recent-Chrome JA4 a-part.
    CHECK(ch.ciphers.size() == 15);
    CHECK(ch.extensions.size() == 16);

    std::string ja4 = ja4_client(ch);
    CHECK(ja4.rfind("t13d1516h2_", 0) == 0);

    // padding extension (0x0015) pushed the hello into Chrome's size band.
    CHECK(hs_len >= 256);

    // each call re-randomizes the GREASE / random / key_share, so two
    // builds differ byte-for-byte but yield the same JA4 (GREASE-stripped).
    auto rec2 = build_chrome131_clienthello("example.com");
    CHECK(rec2 != rec);
    ClientHelloFp ch2;
    REQUIRE(parse_client_hello(rec2.data() + 5, rec2.size() - 5, ch2));
    CHECK(ja4_client(ch2) == ja4);
}

TEST_CASE("build_chrome131_clienthello keeps the GREASE invariants") {
    // a KeyShareEntry MUST correspond to a group offered in supported_groups
    // (RFC 8446 4.2.8), so the GREASE group in key_share has to equal the
    // GREASE in supported_groups, and the two bookend GREASE extension types
    // must differ or it is a duplicate extension. a strict server (OpenSSL)
    // rejects either violation, so guard both here. checked over many builds
    // because the GREASE values are randomized per call.
    auto rd16 = [](const uint8_t* p){ return (uint16_t)((p[0] << 8) | p[1]); };

    for (int iter = 0; iter < 64; ++iter) {
        auto rec = build_chrome131_clienthello("a.example.com");
        REQUIRE(rec.size() > 5);
        const uint8_t* hs = rec.data() + 5;
        size_t hs_len = rec.size() - 5;

        // walk to the extensions block: 4 hs header + 2 ver + 32 random
        // + 1+sid + 2+ciphers + 2 compression.
        size_t p = 4 + 2 + 32;
        REQUIRE(p < hs_len);
        p += 1 + hs[p];                       // legacy_session_id
        REQUIRE(p + 2 <= hs_len);
        p += 2 + rd16(hs + p);                // cipher_suites
        REQUIRE(p + 1 <= hs_len);
        p += 1 + hs[p];                       // compression_methods
        REQUIRE(p + 2 <= hs_len);
        size_t ext_total = rd16(hs + p); p += 2;
        const uint8_t* e  = hs + p;
        const uint8_t* ee = e + ext_total;
        REQUIRE(ee <= hs + hs_len);

        uint16_t first_ext_type = 0xffff, second_last_ext_type = 0xffff;
        uint16_t sg_grease = 1, ks_grease = 2;   // start unequal
        int      ext_idx = 0;
        std::vector<uint16_t> ext_types;
        while (e < ee) {
            REQUIRE(ee - e >= 4);
            uint16_t et = rd16(e);
            uint16_t el = rd16(e + 2);
            const uint8_t* body = e + 4;
            REQUIRE(body + el <= ee);
            ext_types.push_back(et);
            if (ext_idx == 0) first_ext_type = et;
            if (et == 0x000a)                       // supported_groups
                sg_grease = rd16(body + 2);         // first entry after list len
            if (et == 0x0033)                       // key_share
                ks_grease = rd16(body + 2);         // first KeyShareEntry group
            e += 4 + el;
            ++ext_idx;
        }
        REQUIRE(ext_types.size() >= 3);
        second_last_ext_type = ext_types[ext_types.size() - 2];

        // GREASE group in key_share == GREASE in supported_groups
        CHECK(sg_grease == ks_grease);
        // leading and trailing bookend GREASE extension types differ
        CHECK(first_ext_type != second_last_ext_type);
    }
}
