// SPDX-License-Identifier: GPL-3.0-or-later
// owner self-check: noise_ikpsk2 initiator against a spec-shaped responder
// written here from the same primitives, plus fixed vectors for the
// primitives. the lab (stand FK, a real wireguard-go) is the independent check.
#include "doctest.h"
#include "../src/scan/wg_handshake.h"
#include "../src/app/verdict.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

WgKey key_hex(const char* h) {
    WgKey k{};
    for (size_t i = 0; i < 32; ++i) {
        unsigned v = 0;
        std::sscanf(h + 2 * i, "%2x", &v);
        k[i] = uint8_t(v);
    }
    return k;
}

std::string hex(const uint8_t* p, size_t n) {
    std::string s;
    char b[3];
    for (size_t i = 0; i < n; ++i) { std::snprintf(b, sizeof(b), "%02x", p[i]); s += b; }
    return s;
}

// rfc 7748 section 6.1
const char* ALICE_PRIV = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const char* ALICE_PUB  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const char* BOB_PRIV   = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const char* BOB_PUB    = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const char* SHARED     = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

struct Lab {
    WgKey server_priv = key_hex(BOB_PRIV);
    WgKey client_priv = key_hex(ALICE_PRIV);
    WgKey resp_eph    = key_hex("a8abababababababababababababababababababababababababababababab6b");
    WgKeys keys;
    Lab() {
        keys.server_pub = key_hex(BOB_PUB);
        keys.client_priv = client_priv;
        keys.loaded = true;
    }
};

// whitepaper 5.4.2 and 5.4.3, responder side; empty vector when it would drop
std::vector<uint8_t> respond(const Lab& lab, const std::vector<uint8_t>& m, const WgKey& psk,
                             uint8_t ts_out[12] = nullptr) {
    if (m.size() != 148 || m[0] != 1) return {};
    WgKey spub_r, c, h, k, ss, epub_i, spub_i;
    wgc::pub(lab.server_priv, spub_r);
    uint8_t mac[16];
    if (!wgc::mac16(wgc::hash(wgc::LABEL_MAC1, 8, spub_r.data(), 32), m.data(), 116, mac) ||
        std::memcmp(mac, m.data() + 116, 16) != 0) return {};
    wgc::initial(c, h);
    h = wgc::hash(h.data(), 32, spub_r.data(), 32);
    std::copy(m.begin() + 8, m.begin() + 40, epub_i.begin());
    wgc::kdf(c, epub_i.data(), 32, &c, nullptr, nullptr);
    h = wgc::hash(h.data(), 32, epub_i.data(), 32);
    if (!wgc::dh(lab.server_priv, epub_i, ss)) return {};
    wgc::kdf(c, ss.data(), 32, &c, &k, nullptr);
    if (!wgc::aead_open(k, m.data() + 40, 48, h, spub_i.data())) return {};
    h = wgc::hash(h.data(), 32, m.data() + 40, 48);
    WgKey known;
    wgc::pub(lab.client_priv, known);
    if (spub_i != known) return {};   // unknown peer: silence
    if (!wgc::dh(lab.server_priv, spub_i, ss)) return {};
    wgc::kdf(c, ss.data(), 32, &c, &k, nullptr);
    uint8_t ts[12];
    if (!wgc::aead_open(k, m.data() + 88, 28, h, ts)) return {};
    if (ts_out) std::memcpy(ts_out, ts, 12);
    h = wgc::hash(h.data(), 32, m.data() + 88, 28);

    std::vector<uint8_t> r(92, 0);
    WgKey epub_r, tau;
    wgc::pub(lab.resp_eph, epub_r);
    r[0] = 2;
    r[4] = 0x11; r[5] = 0x22; r[6] = 0x33; r[7] = 0x44;
    std::copy(m.begin() + 4, m.begin() + 8, r.begin() + 8);
    std::copy(epub_r.begin(), epub_r.end(), r.begin() + 12);
    wgc::kdf(c, epub_r.data(), 32, &c, nullptr, nullptr);
    h = wgc::hash(h.data(), 32, epub_r.data(), 32);
    wgc::dh(lab.resp_eph, epub_i, ss);
    wgc::kdf(c, ss.data(), 32, &c, nullptr, nullptr);
    wgc::dh(lab.resp_eph, spub_i, ss);
    wgc::kdf(c, ss.data(), 32, &c, nullptr, nullptr);
    wgc::kdf(c, psk.data(), 32, &c, &tau, &k);
    h = wgc::hash(h.data(), 32, tau.data(), 32);
    wgc::aead_seal(k, nullptr, 0, h, r.data() + 44);
    wgc::mac16(wgc::hash(wgc::LABEL_MAC1, 8, spub_i.data(), 32), r.data(), 60, r.data() + 60);
    return r;
}

WgInitiation initiate(const Lab& lab) {
    WgInitiation st;
    const WgKey eph = key_hex("c8cececececececececececececececececececececececececececececece4e");
    const uint8_t ts[12] = {0x40, 0, 0, 0, 0x68, 0x00, 0x00, 0x0a, 0x12, 0, 0, 0};
    REQUIRE(wg_build_initiation(lab.keys, eph, {0xde, 0xad, 0xbe, 0xef}, ts, st));
    return st;
}

UdpResult replied(const std::vector<uint8_t>& r) {
    UdpResult u;
    u.responded = true;
    u.bytes = (int)r.size();
    u.reply = r;
    return u;
}

} // namespace

TEST_CASE("blake2s, x25519 and the noise constants match published values") {
    const uint8_t abc[] = {'a', 'b', 'c'};
    const WgKey h = wgc::hash(abc, 3, nullptr, 0);
    // rfc 7693 appendix b
    CHECK(hex(h.data(), 32) == "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    WgKey pub, shared;
    REQUIRE(wgc::pub(key_hex(ALICE_PRIV), pub));
    CHECK(hex(pub.data(), 32) == ALICE_PUB);
    REQUIRE(wgc::dh(key_hex(ALICE_PRIV), key_hex(BOB_PUB), shared));
    CHECK(hex(shared.data(), 32) == SHARED);
    // initial chaining key and hash, same constants as boringtun
    WgKey c, i;
    wgc::initial(c, i);
    CHECK(hex(c.data(), 32) == "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36");
    CHECK(hex(i.data(), 32) == "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3");
    // low-order point gives an all-zero secret and must be refused
    CHECK_FALSE(wgc::dh(key_hex(ALICE_PRIV), WgKey{}, shared));
}

TEST_CASE("wireguard keys parse from wg genkey text only") {
    WgKey k;
    REQUIRE(wg_key_from_base64("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=", k));
    CHECK(hex(k.data(), 32) == ALICE_PRIV);
    CHECK(wg_key_from_base64("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo", k));
    CHECK_FALSE(wg_key_from_base64("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=x", k));
    CHECK_FALSE(wg_key_from_base64("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LC", k));
    CHECK_FALSE(wg_key_from_base64("dwdtCnMYpX08FsFy*bJmRd9ML4frwJkqsXf7pR25LCo=", k));
    // nonzero spare bits would let two texts name one key
    CHECK_FALSE(wg_key_from_base64("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCp=", k));
    CHECK_FALSE(wg_key_from_base64("", k));
}

TEST_CASE("key loading needs both keys and never echoes key text") {
    WgKeys k;
    std::string err;
    CHECK_FALSE(wg_load_keys("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=", "", "", k, err));
    CHECK(err.find("--wg-key") != std::string::npos);
    CHECK_FALSE(k.loaded);
    const std::string path = "wg-test-key.tmp";
    FILE* f = std::fopen(path.c_str(), "wb");
    REQUIRE(f);
    std::fputs("not a key at all\n", f);
    std::fclose(f);
    CHECK_FALSE(wg_load_keys("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=", path, "", k, err));
    CHECK(err.find(path) != std::string::npos);
    CHECK(err.find("not a key") == std::string::npos);
    f = std::fopen(path.c_str(), "wb");
    REQUIRE(f);
    std::fputs("  dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=\r\n", f);
    std::fclose(f);
    CHECK(wg_load_keys("3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=", path, "", k, err));
    CHECK(k.loaded);
    CHECK(k.server_pub == key_hex(BOB_PUB));
    CHECK(k.client_priv == key_hex(ALICE_PRIV));
    CHECK(k.psk == WgKey{});
    k.wipe();
    CHECK_FALSE(k.loaded);
    CHECK(k.client_priv == WgKey{});
    std::remove(path.c_str());
}

TEST_CASE("tai64n clears the low 24 bits of nanoseconds") {
    uint8_t t[12];
    wg_tai64n(0, 0x12345678, t);
    CHECK(hex(t, 12) == "400000000000000a12000000");
    wg_tai64n(1700000000, 999999999, t);
    CHECK(hex(t, 12) == "400000006553f10a3b000000");
}

TEST_CASE("initiation is 148 bytes and a spec responder accepts it") {
    Lab lab;
    WgInitiation st = initiate(lab);
    REQUIRE(st.packet.size() == 148);
    CHECK(st.packet[0] == 1);
    CHECK(st.packet[1] == 0); CHECK(st.packet[2] == 0); CHECK(st.packet[3] == 0);
    CHECK(hex(st.packet.data() + 4, 4) == "deadbeef");
    // mac2 is zero without a cookie
    CHECK(std::all_of(st.packet.begin() + 132, st.packet.end(), [](uint8_t b) { return b == 0; }));
    uint8_t ts[12];
    const auto r = respond(lab, st.packet, WgKey{}, ts);
    REQUIRE(r.size() == 92);
    CHECK(hex(ts, 12) == "400000006800000a12000000");
    CHECK(wg_check_reply(lab.keys, st, r) == WgReply::Authenticated);
}

TEST_CASE("only the real responder with matching keys authenticates") {
    Lab lab;
    WgInitiation st = initiate(lab);
    const auto good = respond(lab, st.packet, WgKey{});
    REQUIRE(good.size() == 92);

    // wrong preshared key on our side: mac1 still proves the server key
    WgKeys psk = lab.keys;
    psk.psk[0] = 1;
    CHECK(wg_check_reply(psk, st, good) == WgReply::PskMismatch);

    // stand W: a responder that copies our index but has no key
    auto impostor = good;
    for (size_t i = 12; i < 92; ++i) impostor[i] ^= 0x5a;
    CHECK(wg_check_reply(lab.keys, st, impostor) == WgReply::Unauthenticated);

    // stand K: type 2 for another index
    auto other = good;
    other[8] ^= 0xff;
    CHECK(wg_check_reply(lab.keys, st, other) == WgReply::Unrelated);

    std::vector<uint8_t> cookie(64, 0x77);
    cookie[0] = 3; cookie[1] = cookie[2] = cookie[3] = 0;
    std::copy(st.packet.begin() + 4, st.packet.begin() + 8, cookie.begin() + 4);
    CHECK(wg_check_reply(lab.keys, st, cookie) == WgReply::Cookie);
    CHECK(wg_check_reply(lab.keys, st, std::vector<uint8_t>(91, 2)) == WgReply::Unrelated);

    // a responder with another server key never answers: mac1 fails first
    Lab other_server;
    other_server.server_priv = key_hex(ALICE_PRIV);
    CHECK(respond(other_server, st.packet, WgKey{}).empty());
    // and a peer it does not know gets silence, not an error
    Lab stranger;
    stranger.client_priv = key_hex("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe7f");
    CHECK(respond(stranger, st.packet, WgKey{}).empty());
}

TEST_CASE("keyed outcomes: positive only on server-authenticated bytes") {
    UdpResult silent; silent.err = "no-reply / filtered";
    CHECK(wg_keyed_outcome(silent, WgReply::Unrelated) == Outcome::Inconclusive);
    UdpResult echo = replied(std::vector<uint8_t>(148, 1)); echo.echoed = true;
    CHECK(wg_keyed_outcome(echo, WgReply::Unrelated) == Outcome::Negative);
    const UdpResult any = replied(std::vector<uint8_t>(92, 2));
    CHECK(wg_keyed_outcome(any, WgReply::Authenticated) == Outcome::Positive);
    CHECK(wg_keyed_outcome(any, WgReply::PskMismatch) == Outcome::Positive);
    CHECK(wg_keyed_outcome(any, WgReply::Cookie) == Outcome::Inconclusive);
    CHECK(wg_keyed_outcome(any, WgReply::Unauthenticated) == Outcome::Negative);
    CHECK(wg_keyed_outcome(any, WgReply::Unrelated) == Outcome::Negative);
}

TEST_CASE("wg-keyed needs two agreeing answers and shares one score with wg-family") {
    auto rec = [](Outcome o, bool responded) {
        UdpProbeRec r{51820, "wg-keyed", UdpResult{}};
        r.result.responded = responded;
        r.outcome = o;
        return r;
    };
    FullReport r; r.completed = true;
    r.udp_probes = {rec(Outcome::Positive, true)};
    evaluate_report(r);
    REQUIRE(r.checks.size() == 1);
    CHECK(r.checks[0].id == "wg-keyed");
    CHECK(r.checks[0].outcome == Outcome::Inconclusive);
    CHECK(r.scored.empty());

    r.udp_probes = {rec(Outcome::Inconclusive, false), rec(Outcome::Inconclusive, false)};
    evaluate_report(r);
    CHECK(r.checks[0].reason.find("wrong server or peer key") != std::string::npos);
    CHECK(r.label == "INCONCLUSIVE");

    r.udp_probes = {rec(Outcome::Positive, true), rec(Outcome::Positive, true)};
    evaluate_report(r);
    REQUIRE(r.scored.size() == 1);
    CHECK(r.scored[0].id == "wg-keyed");
    CHECK(r.score == 69);
    CHECK(r.tspu_a_hits == 1);

    // a layout positive on the same port is the same fact, scored once
    UdpResult layout;
    layout.responded = true; layout.bytes = 92;
    layout.reply.assign(92, 0x5a);
    layout.reply[0] = 2; layout.reply[1] = layout.reply[2] = layout.reply[3] = 0;
    layout.expect_receiver = {1, 2, 3, 4};
    std::copy(layout.expect_receiver.begin(), layout.expect_receiver.end(), layout.reply.begin() + 8);
    r.udp_probes.push_back({51820, "wg", layout});
    r.udp_probes.push_back({51820, "wg", layout});
    evaluate_report(r);
    CHECK(r.scored.size() == 1);
    CHECK(r.tspu_a_hits == 1);
    CHECK(r.score == 69);
    int positives = 0;
    for (const auto& c : r.checks) positives += c.outcome == Outcome::Positive;
    CHECK(positives == 2);
}
