// SPDX-License-Identifier: GPL-3.0-or-later
#include "wg_handshake.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>

namespace {

// whitepaper 5.4, protocol name and identifier strings
const char CONSTRUCTION[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const char IDENTIFIER[]   = "WireGuard v1 zx2c4 Jason@zx2c4.com";

template <size_t N> void wipe(std::array<uint8_t, N>& a) { OPENSSL_cleanse(a.data(), N); }

int b64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

std::string trim_ws(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
    return a == std::string::npos ? std::string() : s.substr(a, b - a + 1);
}

bool read_small(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    // a key file is 45 bytes; anything large is the wrong file
    return !f.bad() && out.size() <= 4096;
}

bool key_from_file(const std::string& path, const char* what, WgKey& out, std::string& err) {
    std::string text;
    if (!read_small(path, text)) { err = std::string("cannot read ") + what + " file " + path; return false; }
    const bool ok = wg_key_from_base64(trim_ws(text), out);
    OPENSSL_cleanse(text.data(), text.size());
    if (!ok) err = std::string(what) + " file " + path + " does not hold one base64 key of 32 bytes";
    return ok;
}

} // namespace

void WgKeys::wipe() {
    ::wipe(server_pub); ::wipe(client_priv); ::wipe(psk);
    loaded = false;
}

void WgInitiation::wipe() {
    ::wipe(chain); ::wipe(hash); ::wipe(eph_priv); ::wipe(sender);
    OPENSSL_cleanse(packet.data(), packet.size());
    packet.clear();
}

bool wg_key_from_base64(const std::string& text, WgKey& out) {
    std::string s = text;
    while (!s.empty() && s.back() == '=') s.pop_back();
    // 32 bytes are 43 significant characters
    if (s.size() != 43) return false;
    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;
    for (char c : s) {
        const int v = b64_value(c);
        if (v < 0) return false;
        acc = (acc << 6) | uint32_t(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= out.size()) return false;
            out[n++] = uint8_t(acc >> bits);
        }
    }
    // the two spare bits must be zero, or two texts map to one key
    return n == out.size() && (acc & ((1u << bits) - 1)) == 0;
}

bool wg_load_keys(const std::string& pubkey, const std::string& key_path,
                  const std::string& psk_path, WgKeys& out, std::string& err) {
    out.wipe();
    if (pubkey.empty() || key_path.empty()) {
        err = "--wg-pubkey and --wg-key are both required: a responder drops initiations from peers it does not know";
        return false;
    }
    if (!wg_key_from_base64(trim_ws(pubkey), out.server_pub) &&
        !key_from_file(pubkey, "server public key", out.server_pub, err)) return false;
    if (!key_from_file(key_path, "peer private key", out.client_priv, err)) { out.wipe(); return false; }
    if (!psk_path.empty() && !key_from_file(psk_path, "preshared key", out.psk, err)) { out.wipe(); return false; }
    out.loaded = true;
    return true;
}

namespace wgc {

const uint8_t LABEL_MAC1[8] = {'m', 'a', 'c', '1', '-', '-', '-', '-'};

WgKey hash(const uint8_t* a, size_t an, const uint8_t* b, size_t bn) {
    WgKey out{};
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    unsigned int len = 0;
    if (c && EVP_DigestInit_ex(c, EVP_blake2s256(), nullptr) == 1 &&
        (an == 0 || EVP_DigestUpdate(c, a, an) == 1) &&
        (bn == 0 || EVP_DigestUpdate(c, b, bn) == 1))
        EVP_DigestFinal_ex(c, out.data(), &len);
    EVP_MD_CTX_free(c);
    return out;
}

namespace {
void hmac(const WgKey& key, const uint8_t* in, size_t n, WgKey& out) {
    unsigned int len = 0;
    static const uint8_t none = 0;
    HMAC(EVP_blake2s256(), key.data(), (int)key.size(), n ? in : &none, n, out.data(), &len);
}
} // namespace

void kdf(const WgKey& key, const uint8_t* in, size_t n, WgKey* t1, WgKey* t2, WgKey* t3) {
    // hkdf over hmac-blake2s, whitepaper 5.4 "KDF_n"
    WgKey t0, a, b, c;
    uint8_t buf[33];
    hmac(key, in, n, t0);
    buf[0] = 1;
    hmac(t0, buf, 1, a);
    std::memcpy(buf, a.data(), 32); buf[32] = 2;
    hmac(t0, buf, 33, b);
    std::memcpy(buf, b.data(), 32); buf[32] = 3;
    hmac(t0, buf, 33, c);
    // copy, not assign: cppcheck 2.13 reads *t = a as a pointer escape
    if (t1) std::copy(a.begin(), a.end(), t1->begin());
    if (t2) std::copy(b.begin(), b.end(), t2->begin());
    if (t3) std::copy(c.begin(), c.end(), t3->begin());
    ::wipe(t0); ::wipe(a); ::wipe(b); ::wipe(c);
    OPENSSL_cleanse(buf, sizeof(buf));
}

bool mac16(const WgKey& key, const uint8_t* in, size_t n, uint8_t out[16]) {
    // keyed blake2s with a 16-byte digest, not a truncated 32-byte one
    EVP_MAC* m = EVP_MAC_fetch(nullptr, "BLAKE2SMAC", nullptr);
    EVP_MAC_CTX* c = m ? EVP_MAC_CTX_new(m) : nullptr;
    size_t size = 16, got = 0;
    OSSL_PARAM p[] = {OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size), OSSL_PARAM_construct_end()};
    bool ok = c && EVP_MAC_init(c, key.data(), key.size(), p) == 1 &&
              EVP_MAC_update(c, in, n) == 1 && EVP_MAC_final(c, out, &got, 16) == 1 && got == 16;
    EVP_MAC_CTX_free(c);
    EVP_MAC_free(m);
    return ok;
}

namespace {
bool aead(bool enc, const WgKey& key, const uint8_t* in, size_t n, const WgKey& ad, uint8_t* out) {
    // chacha20-poly1305, counter 0: every handshake key is used once
    static const uint8_t nonce[12] = {0};
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    int len = 0;
    bool ok = c && EVP_CipherInit_ex(c, EVP_chacha20_poly1305(), nullptr, key.data(), nonce, enc ? 1 : 0) == 1 &&
              EVP_CipherUpdate(c, nullptr, &len, ad.data(), (int)ad.size()) == 1;
    const size_t body = enc ? n : n - 16;
    if (ok && body) ok = EVP_CipherUpdate(c, out, &len, in, (int)body) == 1;
    if (ok && !enc) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t*>(in + body)) == 1;
    uint8_t tail[16];
    if (ok) ok = EVP_CipherFinal_ex(c, tail, &len) == 1;
    if (ok && enc) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, out + n) == 1;
    EVP_CIPHER_CTX_free(c);
    return ok;
}
} // namespace

bool aead_seal(const WgKey& key, const uint8_t* pt, size_t n, const WgKey& ad, uint8_t* out) {
    return aead(true, key, pt, n, ad, out);
}

bool aead_open(const WgKey& key, const uint8_t* ct, size_t n, const WgKey& ad, uint8_t* out) {
    return n >= 16 && aead(false, key, ct, n, ad, out);
}

bool pub(const WgKey& priv, WgKey& out) {
    EVP_PKEY* k = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), priv.size());
    size_t len = out.size();
    const bool ok = k && EVP_PKEY_get_raw_public_key(k, out.data(), &len) == 1 && len == out.size();
    EVP_PKEY_free(k);
    return ok;
}

bool dh(const WgKey& priv, const WgKey& peer, WgKey& out) {
    EVP_PKEY* k = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), priv.size());
    EVP_PKEY* p = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer.data(), peer.size());
    EVP_PKEY_CTX* c = k ? EVP_PKEY_CTX_new(k, nullptr) : nullptr;
    size_t len = out.size();
    bool ok = c && p && EVP_PKEY_derive_init(c) == 1 && EVP_PKEY_derive_set_peer(c, p) == 1 &&
              EVP_PKEY_derive(c, out.data(), &len) == 1 && len == out.size();
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(p);
    EVP_PKEY_free(k);
    // low-order peer point, whitepaper 5.4 says reject
    static const WgKey zero{};
    return ok && CRYPTO_memcmp(out.data(), zero.data(), 32) != 0;
}

void initial(WgKey& chain, WgKey& h) {
    chain = hash((const uint8_t*)CONSTRUCTION, sizeof(CONSTRUCTION) - 1, nullptr, 0);
    h = hash(chain.data(), 32, (const uint8_t*)IDENTIFIER, sizeof(IDENTIFIER) - 1);
}

} // namespace wgc

bool wg_build_initiation(const WgKeys& k, const WgKey& eph_priv,
                         const std::array<uint8_t, 4>& sender,
                         const uint8_t tai64n[12], WgInitiation& out) {
    out.wipe();
    if (!k.loaded) return false;
    WgKey c, h, epub, spub, key, ss;
    std::vector<uint8_t> m(148, 0);
    bool ok = false;
    // offsets: type 0, sender 4, ephemeral 8, static 40, timestamp 88, mac1 116, mac2 132
    do {
        wgc::initial(c, h);
        h = wgc::hash(h.data(), 32, k.server_pub.data(), 32);
        if (!wgc::pub(eph_priv, epub) || !wgc::pub(k.client_priv, spub)) break;
        m[0] = 1;
        std::copy(sender.begin(), sender.end(), m.begin() + 4);
        std::copy(epub.begin(), epub.end(), m.begin() + 8);
        wgc::kdf(c, epub.data(), 32, &c, nullptr, nullptr);
        h = wgc::hash(h.data(), 32, epub.data(), 32);
        if (!wgc::dh(eph_priv, k.server_pub, ss)) break;
        wgc::kdf(c, ss.data(), 32, &c, &key, nullptr);
        if (!wgc::aead_seal(key, spub.data(), 32, h, m.data() + 40)) break;
        h = wgc::hash(h.data(), 32, m.data() + 40, 48);
        if (!wgc::dh(k.client_priv, k.server_pub, ss)) break;
        wgc::kdf(c, ss.data(), 32, &c, &key, nullptr);
        if (!wgc::aead_seal(key, tai64n, 12, h, m.data() + 88)) break;
        h = wgc::hash(h.data(), 32, m.data() + 88, 28);
        // mac1 needs server pubkey; mac2 stays zero without a cookie
        const WgKey mk = wgc::hash(wgc::LABEL_MAC1, 8, k.server_pub.data(), 32);
        if (!wgc::mac16(mk, m.data(), 116, m.data() + 116)) break;
        ok = true;
    } while (false);
    ::wipe(key); ::wipe(ss);
    if (!ok) { ::wipe(c); ::wipe(h); return false; }
    out.packet = std::move(m);
    out.sender = sender;
    out.chain = c;
    out.hash = h;
    out.eph_priv = eph_priv;
    ::wipe(c); ::wipe(h);
    return true;
}

WgReply wg_check_reply(const WgKeys& k, const WgInitiation& st, const std::vector<uint8_t>& r) {
    const auto to_us = [&](size_t at) { return std::equal(st.sender.begin(), st.sender.end(), r.begin() + at); };
    if (r.size() == 64 && r[0] == 3 && !r[1] && !r[2] && !r[3] && to_us(4)) return WgReply::Cookie;
    if (r.size() != 92 || r[0] != 2 || r[1] || r[2] || r[3] || !to_us(8)) return WgReply::Unrelated;
    WgKey spub;
    if (!k.loaded || !wgc::pub(k.client_priv, spub)) return WgReply::Unrelated;
    // mac1 over a response is keyed by our static key, which only the
    // holder of the server private key could decrypt from msg.static
    const WgKey mk = wgc::hash(wgc::LABEL_MAC1, 8, spub.data(), 32);
    uint8_t mac[16];
    if (!wgc::mac16(mk, r.data(), 60, mac) || CRYPTO_memcmp(mac, r.data() + 60, 16) != 0)
        return WgReply::Unauthenticated;
    // whitepaper 5.4.3 from the initiator side
    WgKey c = st.chain, h = st.hash, epr, ss, tau, key;
    std::copy(r.begin() + 12, r.begin() + 44, epr.begin());
    WgReply out = WgReply::Unauthenticated;
    do {
        wgc::kdf(c, epr.data(), 32, &c, nullptr, nullptr);
        h = wgc::hash(h.data(), 32, epr.data(), 32);
        if (!wgc::dh(st.eph_priv, epr, ss)) break;
        wgc::kdf(c, ss.data(), 32, &c, nullptr, nullptr);
        if (!wgc::dh(k.client_priv, epr, ss)) break;
        wgc::kdf(c, ss.data(), 32, &c, nullptr, nullptr);
        wgc::kdf(c, k.psk.data(), 32, &c, &tau, &key);
        h = wgc::hash(h.data(), 32, tau.data(), 32);
        uint8_t none[1];
        out = wgc::aead_open(key, r.data() + 44, 16, h, none) ? WgReply::Authenticated : WgReply::PskMismatch;
    } while (false);
    ::wipe(c); ::wipe(h); ::wipe(ss); ::wipe(tau); ::wipe(key);
    return out;
}

const char* wg_reply_name(WgReply r) {
    switch (r) {
    case WgReply::Authenticated:   return "handshake authenticated";
    case WgReply::PskMismatch:     return "server key proven by mac1, preshared key differs";
    case WgReply::Cookie:          return "cookie reply, responder under load";
    case WgReply::Unauthenticated: return "type-2 reply to our index, mac1 does not verify";
    default:                       return "reply is not a response to this initiation";
    }
}

void wg_tai64n(uint64_t unix_sec, uint32_t nsec, uint8_t out[12]) {
    // tai64 label 2^62 + 10, big endian
    const uint64_t s = 0x400000000000000aULL + unix_sec;
    const uint32_t n = nsec & ~uint32_t(0xffffff);
    for (int i = 0; i < 8; ++i) out[i] = uint8_t(s >> (56 - 8 * i));
    for (int i = 0; i < 4; ++i) out[8 + i] = uint8_t(n >> (24 - 8 * i));
}
