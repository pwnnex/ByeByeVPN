// SPDX-License-Identifier: GPL-3.0-or-later
#include "udp_probes.h"
#include "quic.h"
#include "../common/winhdr.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using std::string;
using std::vector;

UdpResult wireguard_probe(const string& host, int port) {
    // rfc-shaped WireGuard messageinitiation: 1-byte type 0x01, 3 reserved
    // zero bytes, then 144 bytes of sender-index + ephemeral + encrypted
    // static + encrypted timestamp + mac1/mac2. all 144 are randomized:
    // to a passive observer the packet is indistinguishable from a real
    // client's first handshake message.
    unsigned char pkt[148] = {0};
    pkt[0] = 0x01;
    RAND_bytes(pkt + 4, 144);
    UdpResult r = udp_probe(host, port, pkt, sizeof(pkt), 1500);
    r.expect_receiver.assign(pkt + 4, pkt + 8);
    return r;
}

UdpResult amneziawg_probe(const string& host, int port) {
    // amneziawg obfuscation prepends sx junk bytes before the real wg
    // header and may shift the type byte. this probe uses the common
    // sx=8 layout: 8 random junk bytes, then 0x01 wg-init type at offset
    // 8, then 144 random bytes of the wg body. a vanilla wg listener
    // drops this (type byte not at offset 0); an amneziawg listener with
    // an 8-byte junk prefix accepts it. the verdict engine compares this
    // against the vanilla wireguard_probe result on the same port.
    unsigned char pkt[156] = {0};
    RAND_bytes(pkt, 8);          // sx=8 junk prefix
    pkt[8] = 0x01;              // wg handshake-initiation type
    RAND_bytes(pkt + 12, 144);
    UdpResult r = udp_probe(host, port, pkt, sizeof(pkt), 1500);
    r.expect_receiver.assign(pkt + 12, pkt + 16);
    return r;
}

UdpResult hysteria2_probe(const string& host, int port) {
    // hysteria2 rides quic v1. emit a *real* rfc 9001 protected client Initial
    // instead of an unprotected dummy: random connection ids, a tls
    // clienthello carried in a crypto frame, the payload aead-sealed and the
    // header masked with the Initial keys derived from the dcid, padded to the
    // 1200-byte anti-amplification minimum. a quic listener decrypts it and
    // answers (Initial / Retry / version-negotiation / connection_close); a
    // dead udp port or a non-quic service stays silent. the packet-protection
    // crypto is byte-exact against the rfc 9001 appendix A vectors
    // (tests/test_quic.cpp), so the server's tag check and header deprotection
    // succeed on what we send.
    unsigned char idb[16];
    RAND_bytes(idb, sizeof(idb));
    vector<uint8_t> dcid(idb, idb + 8);
    vector<uint8_t> scid(idb + 8, idb + 16);

    // a real quic clienthello (tls 1.3, alpn h3, quic_transport_parameters
    // ext 0x39) as the crypto payload - exactly what a genuine quic client
    // sends. sni is left empty so the target ip isn't echoed on the wire.
    vector<uint8_t> ch = quic_build_client_hello("", scid);
    vector<uint8_t> dg = quic_build_client_initial(dcid, scid, ch, 1);
    if (!dg.empty()) {
        UdpResult r = udp_probe(host, port, dg.data(), (int)dg.size(), 1500);
        r.expect_dcid = scid;
        return r;
    }

    // fallback: a minimal unprotected Initial (liveness only) if the aead
    // build failed for any reason - keeps the probe functional.
    unsigned char pkt[] = {
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x08, 0, 0, 0, 0, 0, 0, 0, 0,
        0x00, 0x00, 0x44, 0x40
    };
    RAND_bytes(pkt + 6, 8);
    vector<unsigned char> full(1200, 0x00);
    std::memcpy(full.data(), pkt, sizeof(pkt));
    return udp_probe(host, port, full.data(), (int)full.size(), 1500);
}

UdpResult hysteria2_vn_probe(const string& host, int port) {
    // a version-negotiation probe: a protected Initial whose version field is
    // a reserved value. a conformant quic server answers with a vn packet
    // listing every version it supports - a clean, cheap fingerprint of the
    // quic stack (quic-go / hysteria2 / others differ in the offered set).
    unsigned char idb[16];
    RAND_bytes(idb, sizeof(idb));
    vector<uint8_t> dcid(idb, idb + 8);
    vector<uint8_t> scid(idb + 8, idb + 16);
    vector<uint8_t> ch = quic_build_client_hello("", scid);
    vector<uint8_t> dg = quic_build_vn_probe(dcid, scid, ch);
    if (dg.empty()) return UdpResult{};
    UdpResult r = udp_probe(host, port, dg.data(), (int)dg.size(), 1500);
    r.expect_dcid = scid;   // a vn packet echoes our scid as its dcid
    return r;
}

UdpResult wireguard_keyed_probe(const string& host, int port, const WgKeys& keys, WgReply& reply) {
    reply = WgReply::Unrelated;
    UdpResult r;
    WgKey eph;
    std::array<uint8_t, 4> sender;
    if (RAND_bytes(eph.data(), (int)eph.size()) != 1 || RAND_bytes(sender.data(), (int)sender.size()) != 1) {
        r.err = "no randomness";
        return r;
    }
    const long long ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    uint8_t ts[12];
    wg_tai64n(uint64_t(ns / 1000000000), uint32_t(ns % 1000000000), ts);
    WgInitiation st;
    const bool built = wg_build_initiation(keys, eph, sender, ts, st);
    OPENSSL_cleanse(eph.data(), eph.size());
    if (!built) { r.err = "handshake build failed"; return r; }
    r = udp_probe(host, port, st.packet.data(), (int)st.packet.size(), 1500);
    r.expect_receiver.assign(sender.begin(), sender.end());
    if (r.responded && !r.echoed) reply = wg_check_reply(keys, st, r.reply);
    st.wipe();
    return r;
}

void wg_keyed_gap() {
    // wireguard-go drops an initiation within 20 ms of the last one, and the
    // timestamp moves in 2^24 ns steps; back-to-back probes lose the second
    unsigned char b = 0;
    RAND_bytes(&b, 1);
    Sleep(1000 + 2 * b);
}

string quic_reply_summary(const UdpResult& u) {
    if (!u.responded || u.reply.empty()) return {};
    // lab stand U: quic-shaped bytes for someone else's ids
    if (!quic_response_valid(u)) return "not a QUIC reply to this probe (connection ids or layout do not match)";
    QuicResponse q = quic_parse_response(u.reply);
    if (q.kind == QuicResponse::Kind::None || q.kind == QuicResponse::Kind::Unknown)
        return {};
    string s = "QUIC " + q.summary;
    if (q.kind == QuicResponse::Kind::VersionNegotiation && !q.versions.empty()) {
        s += " [";
        for (size_t i = 0; i < q.versions.size() && i < 8; ++i) {
            char b[12];
            std::snprintf(b, sizeof(b), "%08x", q.versions[i]);
            if (i) s += ",";
            s += b;
        }
        s += "]";
    }
    return s;
}
