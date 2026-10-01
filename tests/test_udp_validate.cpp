// SPDX-License-Identifier: GPL-3.0-or-later
// unit tests for src/scan/udp_validate.cpp - the predicates that decide whether
// a udp reply is actually the protocol we probed for.
//
// the bug these guard against: the verdict engine used to treat any datagram
// coming back as a confirmed WireGuard / amneziawg / hysteria2 handshake, so a
// plain udp echo service was enough to produce an "IMMEDIATE BLOCK" verdict.
#include "doctest.h"
#include "../src/scan/udp_validate.h"

#include <cstdint>
#include <vector>

namespace {

UdpResult make_reply(const std::vector<uint8_t>& bytes, bool echoed = false) {
    UdpResult u;
    u.responded = true;
    u.bytes     = (int)bytes.size();
    u.reply     = bytes;
    u.echoed    = echoed;
    return u;
}

// a well-formed WireGuard messageresponse: type 0x02, 3 reserved zeros, 92B.
std::vector<uint8_t> wg_message_response(size_t junk_prefix = 0) {
    std::vector<uint8_t> v(junk_prefix, 0xAB);   // junk is arbitrary non-zero
    v.push_back(0x02); v.push_back(0); v.push_back(0); v.push_back(0);
    v.resize(junk_prefix + 92, 0x5A);            // sender/receiver/ephemeral/macs
    return v;
}

} // namespace

TEST_CASE("wg_response_valid accepts a real MessageResponse") {
    CHECK(wg_response_valid(make_reply(wg_message_response())));
}

TEST_CASE("wg_response_valid accepts a cookie reply") {
    std::vector<uint8_t> cookie(64, 0x11);
    cookie[0] = 0x03; cookie[1] = 0; cookie[2] = 0; cookie[3] = 0;
    CHECK(wg_response_valid(make_reply(cookie)));
}

TEST_CASE("wg_response_valid rejects the false positives that used to score") {
    // no answer at all
    UdpResult silent;
    CHECK_FALSE(wg_response_valid(silent));

    // an echo service mirroring our own messageinitiation back
    CHECK_FALSE(wg_response_valid(make_reply(wg_message_response(), /*echoed= */true)));

    // right length, wrong type byte (this is an initiation, not a response)
    std::vector<uint8_t> init(92, 0x5A);
    init[0] = 0x01; init[1] = 0; init[2] = 0; init[3] = 0;
    CHECK_FALSE(wg_response_valid(make_reply(init)));

    // right type byte, reserved bytes not zero
    std::vector<uint8_t> bad_reserved = wg_message_response();
    bad_reserved[2] = 0x07;
    CHECK_FALSE(wg_response_valid(make_reply(bad_reserved)));

    // right shape, wrong length
    std::vector<uint8_t> short_resp = wg_message_response();
    short_resp.resize(91);
    CHECK_FALSE(wg_response_valid(make_reply(short_resp)));

    // a generic chatty udp service
    std::vector<uint8_t> noise = {'H','E','L','L','O',' ','W','O','R','L','D'};
    CHECK_FALSE(wg_response_valid(make_reply(noise)));
}

TEST_CASE("awg_response_offset finds the MessageResponse behind a junk prefix") {
    CHECK(awg_response_offset(make_reply(wg_message_response(8)))  == 8);
    CHECK(awg_response_offset(make_reply(wg_message_response(24))) == 24);
    // offset 0 means it is plain WireGuard, not obfuscated
    CHECK(awg_response_offset(make_reply(wg_message_response(0)))  == 0);
}

TEST_CASE("awg_response_offset rejects replies with no MessageResponse in them") {
    std::vector<uint8_t> junk(160, 0xAB);       // long, but no 02 00 00 00
    CHECK(awg_response_offset(make_reply(junk)) == -1);

    // too short to hold a messageresponse at all
    CHECK(awg_response_offset(make_reply(std::vector<uint8_t>(40, 0x00))) == -1);

    // an echo is never an amneziawg reply
    CHECK(awg_response_offset(make_reply(wg_message_response(8), /*echoed= */true)) == -1);
}

TEST_CASE("awg_response_offset requires the datagram to be exactly prefix+92") {
    // a 02 00 00 00 that happens to appear inside a longer payload isn't a
    // messageresponse - without the exact-length rule, random bytes would hit
    // this roughly once per 4 billion, but a structured protocol far more often.
    std::vector<uint8_t> trailing = wg_message_response(8);
    trailing.push_back(0xFF);                   // one byte too many
    CHECK(awg_response_offset(make_reply(trailing)) == -1);
}

TEST_CASE("quic_response_valid accepts a long-header QUIC packet") {
    // long header (0x80 set), version 1, empty dcid/scid -> parsed as Initial
    std::vector<uint8_t> initial = {0xC0, 0x00,0x00,0x00,0x01, 0x00, 0x00, 0x00, 0x00};
    CHECK(quic_response_valid(make_reply(initial)));

    // version 0 == version-negotiation
    std::vector<uint8_t> vn = {0xC0, 0x00,0x00,0x00,0x00, 0x00, 0x00, 0x00,0x00,0x00,0x01};
    CHECK(quic_response_valid(make_reply(vn)));
}

TEST_CASE("quic_response_valid rejects non-QUIC and echoed replies") {
    // short header: can't be an answer to an Initial on a fresh connection
    std::vector<uint8_t> short_hdr = {0x40, 0x11, 0x22, 0x33};
    CHECK_FALSE(quic_response_valid(make_reply(short_hdr)));

    // an echo of our own Initial
    std::vector<uint8_t> initial = {0xC0, 0x00,0x00,0x00,0x01, 0x00, 0x00, 0x00, 0x00};
    CHECK_FALSE(quic_response_valid(make_reply(initial, /*echoed= */true)));

    // no reply
    CHECK_FALSE(quic_response_valid(UdpResult{}));

    // truncated long header
    CHECK_FALSE(quic_response_valid(make_reply({0xC0, 0x00, 0x00})));
}


TEST_CASE("QUIC rejects incomplete and inconsistent datagrams") {
    CHECK_FALSE(quic_response_valid(make_reply({0xc0,0,0,0,1,0,0})));
    CHECK_FALSE(quic_response_valid(make_reply({0xc0,0,0,0,1,0,255})));
    CHECK_FALSE(quic_response_valid(make_reply({0x80,0,0,0,0,0,0})));
    CHECK_FALSE(quic_response_valid(make_reply({0x80,0,0,0,0,0,0,0,0,0,1,0})));
    auto u = make_reply({0x80,0,0,0,0,0,0,0,0,0,1});
    u.bytes = 2048;
    CHECK_FALSE(quic_response_valid(u));
    u.bytes = (int)u.reply.size();
    u.err = "reply truncated to 2048 bytes";
    CHECK_FALSE(quic_response_valid(u));
}
