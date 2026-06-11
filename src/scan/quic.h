// SPDX-License-Identifier: GPL-3.0-or-later
// QUIC v1 (RFC 9000 / RFC 9001) Initial-packet machinery: HKDF key schedule,
// AEAD payload protection, and header protection. enough to emit a *real*
// protected client Initial — the bytes a genuine QUIC client (Hysteria2 /
// TUIC / quic-go / HTTP3) puts on the wire — instead of an unprotected dummy.
//
// the crypto here is byte-exact against the RFC 9001 Appendix A test vectors
// (see tests/test_quic.cpp), so a QUIC server's AEAD tag check and header
// deprotection succeed on what we send. this whole file is platform-agnostic
// (OpenSSL only, no winsock); the datagram is handed to udp_probe() to send.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

// QUIC variable-length integer encoding (RFC 9000 §16). picks the shortest of
// the 1/2/4/8-byte forms that fits `v`.
std::vector<uint8_t> quic_varint(uint64_t v);

// HKDF-Extract (RFC 5869) = HMAC-SHA256(salt, ikm).
std::vector<uint8_t> hkdf_extract(const std::vector<uint8_t>& salt,
                                  const std::vector<uint8_t>& ikm);

// HKDF-Expand-Label (RFC 8446 §7.1) with SHA-256 and the "tls13 " prefix.
std::vector<uint8_t> hkdf_expand_label(const std::vector<uint8_t>& secret,
                                       const std::string& label,
                                       const std::vector<uint8_t>& context,
                                       size_t length);

struct QuicInitialSecrets {
    bool ok = false;
    std::vector<uint8_t> secret;  // 32 — client/server_initial_secret
    std::vector<uint8_t> key;     // 16 — AEAD key (AES-128-GCM)
    std::vector<uint8_t> iv;      // 12 — AEAD nonce base
    std::vector<uint8_t> hp;      // 16 — header-protection key (AES-128-ECB)
};

// derive the client (is_client=true) or server Initial secrets for QUIC v1
// from the Destination Connection ID, per RFC 9001 §5.2.
QuicInitialSecrets quic_initial_secrets(const std::vector<uint8_t>& dcid, bool is_client);

// AES-128-ECB single-block: mask = ECB(hp_key, sample). returns 16 bytes; the
// first 5 are the header-protection mask. (RFC 9001 §5.4.3)
std::vector<uint8_t> quic_hp_mask(const std::vector<uint8_t>& hp_key,
                                  const std::vector<uint8_t>& sample);

// build a fully protected QUIC client Initial datagram carrying `crypto`
// (TLS handshake bytes) in a CRYPTO frame, padded to >= 1200 bytes. `version`
// defaults to QUIC v1 (0x00000001); pass a reserved value (e.g. 0x1a2a3a4a) to
// force the peer into a Version-Negotiation response. on any crypto error
// returns an empty vector.
std::vector<uint8_t> quic_build_client_initial(const std::vector<uint8_t>& dcid,
                                               const std::vector<uint8_t>& scid,
                                               const std::vector<uint8_t>& crypto,
                                               uint32_t packet_number,
                                               uint32_t version = 0x00000001);

// build a Version-Negotiation probe: an Initial whose version field is a
// reserved value, which a conformant QUIC server answers with a VN packet
// listing the versions it supports (RFC 9000 §6). convenience wrapper.
std::vector<uint8_t> quic_build_vn_probe(const std::vector<uint8_t>& dcid,
                                         const std::vector<uint8_t>& scid,
                                         const std::vector<uint8_t>& crypto);

// QUIC transport-parameters extension body (the value of TLS extension 0x39).
// includes initial_source_connection_id = scid plus a plausible flow-control
// set, so a server sees a complete QUIC ClientHello.
std::vector<uint8_t> quic_transport_params(const std::vector<uint8_t>& scid);

// build a minimal valid TLS 1.3 ClientHello (handshake message, no record
// header) carrying ALPN h3 and the QUIC transport_parameters extension —
// suitable as the CRYPTO payload of a QUIC Initial.
std::vector<uint8_t> quic_build_client_hello(const std::string& sni,
                                             const std::vector<uint8_t>& scid);

// classification of a QUIC packet received from a peer.
struct QuicResponse {
    enum class Kind { None, VersionNegotiation, Retry, Initial, Handshake,
                      ZeroRTT, ShortHeader, Unknown };
    Kind                  kind = Kind::None;
    uint32_t              version = 0;        // long-header version field
    std::vector<uint32_t> versions;           // VN: the offered version list
    bool                  has_token = false;  // Retry carries a token
    std::string           summary;            // human-readable one-liner
};

// parse the first QUIC packet in a datagram and classify it (long-header type,
// Version-Negotiation version list, Retry, short header). pure byte logic.
QuicResponse quic_parse_response(const std::vector<uint8_t>& datagram);

// reverse of the above for self-test: deprotect + AEAD-decrypt a datagram we
// (or a peer using the same DCID) built, recovering the CRYPTO-frame bytes.
// returns false if header deprotection or the AEAD tag check fails.
bool quic_unprotect_client_initial(const std::vector<uint8_t>& datagram,
                                   const std::vector<uint8_t>& dcid,
                                   std::vector<uint8_t>& crypto_out);
