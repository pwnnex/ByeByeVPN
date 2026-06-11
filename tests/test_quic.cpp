// SPDX-License-Identifier: GPL-3.0-or-later
// unit tests for src/scan/quic.cpp — verified byte-exact against the
// RFC 9001 Appendix A QUIC v1 test vectors.
#include "doctest.h"
#include "../src/scan/quic.h"

#include <cstdint>
#include <string>
#include <vector>

static std::vector<uint8_t> hx(const std::string& h) {
    std::vector<uint8_t> o;
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        o.push_back((uint8_t)((nib(h[i]) << 4) | nib(h[i + 1])));
    }
    return o;
}

static std::string hexs(const std::vector<uint8_t>& v) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (uint8_t b : v) { s += d[b >> 4]; s += d[b & 0xf]; }
    return s;
}

// RFC 9001 §A.1 — the canonical client/server Initial key schedule.
TEST_CASE("RFC 9001 A.1: QUIC v1 Initial key schedule (client)") {
    std::vector<uint8_t> dcid = hx("8394c8f03e515708");
    QuicInitialSecrets c = quic_initial_secrets(dcid, true);
    REQUIRE(c.ok);
    CHECK(hexs(c.secret) == "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    CHECK(hexs(c.key)    == "1f369613dd76d5467730efcbe3b1a22d");
    CHECK(hexs(c.iv)     == "fa044b2f42a3fd3b46fb255c");
    CHECK(hexs(c.hp)     == "9f50449e04a0e810283a1e9933adedd2");
}

TEST_CASE("RFC 9001 A.1: server Initial secret") {
    std::vector<uint8_t> dcid = hx("8394c8f03e515708");
    QuicInitialSecrets s = quic_initial_secrets(dcid, false);
    REQUIRE(s.ok);
    CHECK(hexs(s.secret) == "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");
}

TEST_CASE("RFC 9001 A.1: HKDF-Extract initial_secret") {
    // initial_secret = HKDF-Extract(initial_salt, dcid)
    std::vector<uint8_t> salt = hx("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    std::vector<uint8_t> dcid = hx("8394c8f03e515708");
    CHECK(hexs(hkdf_extract(salt, dcid)) ==
          "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");
}

// RFC 9001 §A.2 — header-protection sample -> mask for the client Initial.
TEST_CASE("RFC 9001 A.2: header-protection mask") {
    std::vector<uint8_t> dcid = hx("8394c8f03e515708");
    QuicInitialSecrets c = quic_initial_secrets(dcid, true);
    REQUIRE(c.ok);
    std::vector<uint8_t> sample = hx("d1b1c98dd7689fb8ec11d242b123dc9b");
    std::vector<uint8_t> mask = quic_hp_mask(c.hp, sample);
    REQUIRE(mask.size() >= 5);
    // first 5 mask bytes per RFC 9001 A.2
    CHECK(hexs(std::vector<uint8_t>(mask.begin(), mask.begin() + 5)) == "437b9aec36");
}

// RFC 9000 §16 — variable-length integer encodings.
TEST_CASE("RFC 9000 §16: varint encoding") {
    CHECK(hexs(quic_varint(37))                 == "25");
    CHECK(hexs(quic_varint(15293))              == "7bbd");
    CHECK(hexs(quic_varint(494878333))          == "9d7f3e7d");
    CHECK(hexs(quic_varint(151288809941952652ULL)) == "c2197c5eff14e88c");
    CHECK(hexs(quic_varint(0))                  == "00");
    CHECK(hexs(quic_varint(63))                 == "3f");
    CHECK(hexs(quic_varint(64))                 == "4040");
}

// build a real protected Initial, then deprotect+decrypt it back. exercises
// the full AEAD + header-protection pipeline end to end (the GCM tag check
// makes this fail loudly if the AAD / nonce / header are wrong).
TEST_CASE("client Initial build -> unprotect round-trip recovers the CRYPTO bytes") {
    std::vector<uint8_t> dcid = hx("0001020304050607");
    std::vector<uint8_t> scid = hx("0a0b0c0d");
    std::vector<uint8_t> crypto;
    for (int i = 0; i < 200; ++i) crypto.push_back((uint8_t)(i * 7 + 1));

    std::vector<uint8_t> dg = quic_build_client_initial(dcid, scid, crypto, 1);
    REQUIRE(dg.size() >= 1200);            // padded to the anti-amplification min
    CHECK((dg[0] & 0x80) != 0);            // long-header form bit set

    std::vector<uint8_t> recovered;
    REQUIRE(quic_unprotect_client_initial(dg, dcid, recovered));
    CHECK(recovered == crypto);
}

TEST_CASE("build is deterministic for a fixed DCID/SCID/crypto/pn") {
    std::vector<uint8_t> dcid = hx("8394c8f03e515708");
    std::vector<uint8_t> scid;
    std::vector<uint8_t> crypto = hx("0102030405");
    auto a = quic_build_client_initial(dcid, scid, crypto, 2);
    auto b = quic_build_client_initial(dcid, scid, crypto, 2);
    REQUIRE(!a.empty());
    CHECK(a == b);
}

static bool contains_seq(const std::vector<uint8_t>& hay, const std::vector<uint8_t>& nee) {
    if (nee.empty() || hay.size() < nee.size()) return false;
    for (size_t i = 0; i + nee.size() <= hay.size(); ++i) {
        bool ok = true;
        for (size_t j = 0; j < nee.size(); ++j) if (hay[i + j] != nee[j]) { ok = false; break; }
        if (ok) return true;
    }
    return false;
}

TEST_CASE("transport params carry initial_source_connection_id = scid") {
    std::vector<uint8_t> scid = hx("0a0b0c0d");
    auto tp = quic_transport_params(scid);
    REQUIRE(!tp.empty());
    // last parameter is id 0x0f, len 0x04, then the scid bytes
    std::vector<uint8_t> want = {0x0f, 0x04, 0x0a, 0x0b, 0x0c, 0x0d};
    CHECK(contains_seq(tp, want));
}

TEST_CASE("quic ClientHello is well-formed and carries ALPN h3 + transport params") {
    std::vector<uint8_t> scid = hx("0a0b0c0d");
    auto ch = quic_build_client_hello("example.com", scid);
    REQUIRE(ch.size() > 40);
    CHECK(ch[0] == 0x01);                              // HandshakeType client_hello
    uint32_t mlen = ((uint32_t)ch[1] << 16) | ((uint32_t)ch[2] << 8) | ch[3];
    CHECK(mlen + 4 == ch.size());                      // 24-bit length is consistent
    CHECK(contains_seq(ch, {0x00, 0x39}));             // quic_transport_parameters ext
    CHECK(contains_seq(ch, {0x02, 'h', '3'}));         // ALPN h3
    CHECK(contains_seq(ch, {'e','x','a','m','p','l','e','.','c','o','m'})); // SNI
}

TEST_CASE("VN probe sets a reserved version that forces Version-Negotiation") {
    std::vector<uint8_t> dcid = hx("0001020304050607");
    std::vector<uint8_t> scid = hx("0a0b0c0d");
    auto dg = quic_build_vn_probe(dcid, scid, hx("0102"));
    REQUIRE(dg.size() >= 1200);
    // version field (bytes 1..4) is the reserved 0x1a2a3a4a
    CHECK(dg[1] == 0x1a); CHECK(dg[2] == 0x2a); CHECK(dg[3] == 0x3a); CHECK(dg[4] == 0x4a);
}

TEST_CASE("quic_parse_response classifies VN / Retry / Initial / short-header") {
    // Version-Negotiation: version == 0, then a list of offered versions.
    std::vector<uint8_t> vn = {0x80, 0,0,0,0, 0x00, 0x00,
                               0x00,0x00,0x00,0x01,  0xff,0x00,0x00,0x1d};
    QuicResponse rv = quic_parse_response(vn);
    CHECK(rv.kind == QuicResponse::Kind::VersionNegotiation);
    REQUIRE(rv.versions.size() == 2);
    CHECK(rv.versions[0] == 0x00000001u);
    CHECK(rv.versions[1] == 0xff00001du);

    // Retry: long header, type bits = 3.
    std::vector<uint8_t> retry = {0xf0, 0,0,0,1, 0x00, 0x00, 0xde,0xad,0xbe,0xef};
    QuicResponse rr = quic_parse_response(retry);
    CHECK(rr.kind == QuicResponse::Kind::Retry);
    CHECK(rr.has_token);

    // Initial: long header, type bits = 0.
    std::vector<uint8_t> ini = {0xc0, 0,0,0,1, 0x00, 0x00, 0x00};
    CHECK(quic_parse_response(ini).kind == QuicResponse::Kind::Initial);

    // short header (high bit clear).
    std::vector<uint8_t> sh = {0x40, 0x11, 0x22};
    CHECK(quic_parse_response(sh).kind == QuicResponse::Kind::ShortHeader);

    // empty.
    CHECK(quic_parse_response({}).kind == QuicResponse::Kind::None);
}

TEST_CASE("real QUIC ClientHello round-trips through build/unprotect") {
    std::vector<uint8_t> dcid = hx("0001020304050607");
    std::vector<uint8_t> scid = hx("0a0b0c0d");
    auto ch = quic_build_client_hello("", scid);
    auto dg = quic_build_client_initial(dcid, scid, ch, 1);
    REQUIRE(dg.size() >= 1200);
    std::vector<uint8_t> recovered;
    REQUIRE(quic_unprotect_client_initial(dg, dcid, recovered));
    CHECK(recovered == ch);
}
