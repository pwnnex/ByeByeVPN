// SPDX-License-Identifier: GPL-3.0-or-later
// quic v1 (rfc 9000 / rfc 9001) Initial-packet machinery: hkdf key schedule,
// aead payload protection, and header protection. enough to emit a *real*
// protected client Initial - the bytes a genuine quic client (hysteria2 /
// tuic / quic-go / http3) puts on the wire - instead of an unprotected dummy.
//
// the crypto here is byte-exact against the rfc 9001 appendix A test vectors
// (see tests/test_quic.cpp), so a quic server's aead tag check and header
// deprotection succeed on what we send. this whole file is platform-agnostic
// (openssl only, no winsock); the datagram is handed to udp_probe() to send.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

// quic variable-length integer encoding (rfc 9000 §16). picks the shortest of
// the 1/2/4/8-byte forms that fits `v`.
std::vector<uint8_t> quic_varint(uint64_t v);

// hkdf-extract (rfc 5869) = HMAC-sha256(salt, ikm).
std::vector<uint8_t> hkdf_extract(const std::vector<uint8_t>& salt,
                                  const std::vector<uint8_t>& ikm);

// hkdf-expand-label (rfc 8446 §7.1) with sha-256 and the "tls13 " prefix.
std::vector<uint8_t> hkdf_expand_label(const std::vector<uint8_t>& secret,
                                       const std::string& label,
                                       const std::vector<uint8_t>& context,
                                       size_t length);

struct QuicInitialSecrets {
    bool ok = false;
    std::vector<uint8_t> secret;  // 32 - client/server_initial_secret
    std::vector<uint8_t> key;     // 16 - aead key (aes-128-gcm)
    std::vector<uint8_t> iv;      // 12 - aead nonce base
    std::vector<uint8_t> hp;      // 16 - header-protection key (aes-128-ecb)
};

// derive the client (is_client=true) or server Initial secrets for quic v1
// from the destination connection id, per rfc 9001 §5.2.
QuicInitialSecrets quic_initial_secrets(const std::vector<uint8_t>& dcid, bool is_client);

// aes-128-ecb single-block: mask = ecb(hp_key, sample). returns 16 bytes; the
// first 5 are the header-protection mask. (rfc 9001 §5.4.3)
std::vector<uint8_t> quic_hp_mask(const std::vector<uint8_t>& hp_key,
                                  const std::vector<uint8_t>& sample);

// build a fully protected quic client Initial datagram carrying `crypto`
// (tls handshake bytes) in a crypto frame, padded to >= 1200 bytes. `version`
// defaults to quic v1 (0x00000001); pass a reserved value (e.g. 0x1a2a3a4a) to
// force the peer into a version-negotiation response. on any crypto error
// returns an empty vector.
std::vector<uint8_t> quic_build_client_initial(const std::vector<uint8_t>& dcid,
                                               const std::vector<uint8_t>& scid,
                                               const std::vector<uint8_t>& crypto,
                                               uint32_t packet_number,
                                               uint32_t version = 0x00000001);

// build a version-negotiation probe: an Initial whose version field is a
// reserved value, which a conformant quic server answers with a vn packet
// listing the versions it supports (rfc 9000 §6). convenience wrapper.
std::vector<uint8_t> quic_build_vn_probe(const std::vector<uint8_t>& dcid,
                                         const std::vector<uint8_t>& scid,
                                         const std::vector<uint8_t>& crypto);

// quic transport-params extension body (the value of tls extension 0x39).
// includes initial_source_connection_id = scid plus a plausible flow-control
// set, so a server sees a complete quic clienthello.
std::vector<uint8_t> quic_transport_params(const std::vector<uint8_t>& scid);

// build a minimal valid tls 1.3 clienthello (handshake message, no record
// header) carrying alpn h3 and the quic transport_parameters extension -
// suitable as the crypto payload of a quic Initial.
std::vector<uint8_t> quic_build_client_hello(const std::string& sni,
                                             const std::vector<uint8_t>& scid);

// classification of a quic packet received from a peer.
struct QuicResponse {
    enum class Kind { None, VersionNegotiation, Retry, Initial, Handshake,
                      ZeroRTT, ShortHeader, Unknown };
    Kind                  kind = Kind::None;
    uint32_t              version = 0;        // long-header version field
    std::vector<uint32_t> versions;           // vn: the offered version list
    bool                  has_token = false;  // retry carries a token
    std::string           summary;            // human-readable one-liner
};

// parse the first quic packet in a datagram and classify it (long-header type,
// version-negotiation version list, Retry, short header). pure byte logic.
QuicResponse quic_parse_response(const std::vector<uint8_t>& datagram);

// reverse of the above for self-test: deprotect + aead-decrypt a datagram we
// (or a peer using the same dcid) built, recovering the crypto-frame bytes.
// returns false if header deprotection or the aead tag check fails.
bool quic_unprotect_client_initial(const std::vector<uint8_t>& datagram,
                                   const std::vector<uint8_t>& dcid,
                                   std::vector<uint8_t>& crypto_out);
