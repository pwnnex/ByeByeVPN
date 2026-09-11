// SPDX-License-Identifier: GPL-3.0-or-later
#include "udp_probes.h"
#include "quic.h"
#include "../common/platform.h"

#include <openssl/rand.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using std::string;
using std::vector;

UdpResult wireguard_probe(const string& host, int port) {
    // RFC-shaped WireGuard MessageInitiation: 1-byte type 0x01, 3 reserved
    // zero bytes, then 144 bytes of sender-index + ephemeral + encrypted
    // static + encrypted timestamp + mac1/mac2. all 144 are randomized:
    // to a passive observer the packet is indistinguishable from a real
    // client's first handshake message.
    unsigned char pkt[148] = {0};
    pkt[0] = 0x01;
    RAND_bytes(pkt + 4, 144);
    return udp_probe(host, port, pkt, sizeof(pkt), 1500);
}

UdpResult amneziawg_probe(const string& host, int port) {
    // AmneziaWG obfuscation prepends Sx junk bytes before the real WG
    // header and may shift the type byte. this probe uses the common
    // Sx=8 layout: 8 random junk bytes, then 0x01 WG-init type at offset
    // 8, then 144 random bytes of the WG body. a vanilla WG listener
    // drops this (type byte not at offset 0); an AmneziaWG listener with
    // an 8-byte junk prefix accepts it. the verdict engine compares this
    // against the vanilla wireguard_probe result on the same port.
    unsigned char pkt[156] = {0};
    RAND_bytes(pkt, 8);          // Sx=8 junk prefix
    pkt[8] = 0x01;              // WG handshake-initiation type
    RAND_bytes(pkt + 12, 144);
    return udp_probe(host, port, pkt, sizeof(pkt), 1500);
}

UdpResult hysteria2_probe(const string& host, int port) {
    // Hysteria2 rides QUIC v1. emit a *real* RFC 9001 protected client Initial
    // instead of an unprotected dummy: random connection IDs, a TLS
    // ClientHello carried in a CRYPTO frame, the payload AEAD-sealed and the
    // header masked with the Initial keys derived from the DCID, padded to the
    // 1200-byte anti-amplification minimum. a QUIC listener decrypts it and
    // answers (Initial / Retry / version-negotiation / CONNECTION_CLOSE); a
    // dead UDP port or a non-QUIC service stays silent. the packet-protection
    // crypto is byte-exact against the RFC 9001 Appendix A vectors
    // (tests/test_quic.cpp), so the server's tag check and header deprotection
    // succeed on what we send.
    unsigned char idb[16];
    RAND_bytes(idb, sizeof(idb));
    vector<uint8_t> dcid(idb, idb + 8);
    vector<uint8_t> scid(idb + 8, idb + 16);

    // a real QUIC ClientHello (TLS 1.3, ALPN h3, quic_transport_parameters
    // ext 0x39) as the CRYPTO payload — exactly what a genuine QUIC client
    // sends. SNI is left empty so the target IP isn't echoed on the wire.
    vector<uint8_t> ch = quic_build_client_hello("", scid);
    vector<uint8_t> dg = quic_build_client_initial(dcid, scid, ch, 1);
    if (!dg.empty())
        return udp_probe(host, port, dg.data(), (int)dg.size(), 1500);

    // fallback: a minimal unprotected Initial (liveness only) if the AEAD
    // build failed for any reason — keeps the probe functional.
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
    // a Version-Negotiation probe: a protected Initial whose version field is
    // a reserved value. a conformant QUIC server answers with a VN packet
    // listing every version it supports — a clean, cheap fingerprint of the
    // QUIC stack (quic-go / Hysteria2 / others differ in the offered set).
    unsigned char idb[16];
    RAND_bytes(idb, sizeof(idb));
    vector<uint8_t> dcid(idb, idb + 8);
    vector<uint8_t> scid(idb + 8, idb + 16);
    vector<uint8_t> ch = quic_build_client_hello("", scid);
    vector<uint8_t> dg = quic_build_vn_probe(dcid, scid, ch);
    if (dg.empty()) return UdpResult{};
    return udp_probe(host, port, dg.data(), (int)dg.size(), 1500);
}

string quic_reply_summary(const UdpResult& u) {
    if (!u.responded || u.reply.empty()) return {};
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
