// SPDX-License-Identifier: GPL-3.0-or-later
#include "udp_probes.h"
#include "../common/winhdr.h"

#include <openssl/rand.h>

#include <cstring>
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
    // Hysteria2 rides QUIC v1. this is a well-formed QUIC v1 long-header
    // Initial packet (type 0xc0, version 0x00000001, 8-byte DCID, empty
    // SCID, empty token, 1088-byte length varint) padded to the 1200-byte
    // anti-amplification minimum. DCID is randomized so the packet looks
    // like a real client's first connection attempt. a Hysteria2 / QUIC
    // listener answers with a Retry or an encrypted Initial; a dead UDP
    // port stays silent.
    unsigned char pkt[] = {
        0xc0,                         // long header, Initial
        0x00, 0x00, 0x00, 0x01,       // QUIC version 1
        0x08,                         // DCID length
        0, 0, 0, 0, 0, 0, 0, 0,       // DCID (randomized below)
        0x00,                         // SCID length
        0x00,                         // token length
        0x44, 0x40                    // length varint (1088)
    };
    RAND_bytes(pkt + 6, 8);
    vector<unsigned char> full(1200, 0x00);
    std::memcpy(full.data(), pkt, sizeof(pkt));
    return udp_probe(host, port, full.data(), (int)full.size(), 1500);
}
