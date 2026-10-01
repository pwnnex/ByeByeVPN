// SPDX-License-Identifier: GPL-3.0-or-later
// wireguard handshake initiator for the owner self-check (--wg-pubkey).
// noise_ikpsk2 as in the whitepaper section 5.4; byte logic only, no sockets.
// a responder answers only a peer it knows, so the check needs the server
// public key and a peer private key, both from the owner's own configs.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

using WgKey = std::array<uint8_t, 32>;

struct WgKeys {
    WgKey server_pub{};    // responder static public
    WgKey client_priv{};   // a configured peer's static private
    WgKey psk{};           // zero when the peer has none
    bool  loaded = false;
    void  wipe();
};

// wg genkey form; url-safe alphabet and missing padding accepted
bool wg_key_from_base64(const std::string& text, WgKey& out);

// pubkey: key text or a file holding it; key and psk: files only, so a
// private key never sits in argv. err names paths, never key material.
bool wg_load_keys(const std::string& pubkey, const std::string& key_path,
                  const std::string& psk_path, WgKeys& out, std::string& err);

// state kept between our initiation and the reply
struct WgInitiation {
    std::vector<uint8_t>   packet;   // 148 bytes, whitepaper 5.4.2
    std::array<uint8_t, 4> sender{};
    WgKey chain{}, hash{}, eph_priv{};
    void wipe();
};

// eph_priv and sender come from RAND_bytes at the call site
bool wg_build_initiation(const WgKeys& k, const WgKey& eph_priv,
                         const std::array<uint8_t, 4>& sender,
                         const uint8_t tai64n[12], WgInitiation& out);

enum class WgReply {
    Authenticated,    // mac1 and the empty aead both verify
    PskMismatch,      // mac1 proves the server key, the empty aead does not open
    Cookie,           // 64 B cookie reply to our index, responder under load
    Unauthenticated,  // type 2 to our index, mac1 does not verify
    Unrelated,        // anything else
};
WgReply     wg_check_reply(const WgKeys& k, const WgInitiation& st, const std::vector<uint8_t>& reply);
const char* wg_reply_name(WgReply r);

// low 24 bits of nanoseconds cleared, as wireguard-go and the linux module send
void wg_tai64n(uint64_t unix_sec, uint32_t nsec, uint8_t out[12]);

// primitives, exposed for the unit tests
namespace wgc {
WgKey hash(const uint8_t* a, size_t an, const uint8_t* b, size_t bn);   // blake2s-256(a || b)
void  kdf(const WgKey& key, const uint8_t* in, size_t n, WgKey* t1, WgKey* t2, WgKey* t3);
bool  mac16(const WgKey& key, const uint8_t* in, size_t n, uint8_t out[16]);
bool  aead_seal(const WgKey& key, const uint8_t* pt, size_t n, const WgKey& ad, uint8_t* out);
bool  aead_open(const WgKey& key, const uint8_t* ct, size_t n, const WgKey& ad, uint8_t* out);
bool  pub(const WgKey& priv, WgKey& out);
bool  dh(const WgKey& priv, const WgKey& peer, WgKey& out);
void  initial(WgKey& chain, WgKey& h);
extern const uint8_t LABEL_MAC1[8];
} // namespace wgc
