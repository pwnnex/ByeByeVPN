// SPDX-License-Identifier: GPL-3.0-or-later
#include "chrome_ch.h"

#include <openssl/rand.h>

using std::string;
using std::vector;

namespace {

// the 16 RFC 8701 GREASE values. Chrome picks one per slot, not necessarily
// the same one in every slot, so we draw fresh each time.
const uint16_t GREASE[16] = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
};

// CSPRNG-backed RNG. all randomness here goes through OpenSSL RAND_bytes so
// the ClientHello carries no observable PRNG pattern. RAND_bytes return is
// not checked: on a system where OpenSSL's RNG cannot seed at all, falling
// back to zeros still produces a syntactically valid ClientHello (the bytes
// in question are random-looking fields the peer does not validate against
// us; we are not running the TLS 1.3 key schedule on this path).
uint8_t rand_u8() {
    uint8_t b = 0;
    RAND_bytes(&b, 1);
    return b;
}

uint16_t grease_value() {
    return GREASE[rand_u8() & 0x0f];
}

// append-only byte builder with length-prefix backpatching.
struct B {
    vector<uint8_t> v;
    void u8(uint8_t x)   { v.push_back(x); }
    void u16(uint16_t x) { v.push_back((uint8_t)(x >> 8)); v.push_back((uint8_t)x); }
    void str(const string& s) { v.insert(v.end(), s.begin(), s.end()); }
    void blob(const vector<uint8_t>& b) { v.insert(v.end(), b.begin(), b.end()); }
    size_t mark16() { size_t o = v.size(); u16(0); return o; }
    void patch16(size_t o) {
        uint16_t n = (uint16_t)(v.size() - o - 2);
        v[o] = (uint8_t)(n >> 8); v[o + 1] = (uint8_t)n;
    }
    size_t mark24() { size_t o = v.size(); v.push_back(0); v.push_back(0); v.push_back(0); return o; }
    void patch24(size_t o) {
        uint32_t n = (uint32_t)(v.size() - o - 3);
        v[o] = (uint8_t)(n >> 16); v[o + 1] = (uint8_t)(n >> 8); v[o + 2] = (uint8_t)n;
    }
};

// emit one extension: 16-bit type, then a 16-bit length-prefixed body.
template <typename Fn>
void ext(B& b, uint16_t type, Fn&& body) {
    b.u16(type);
    size_t o = b.mark16();
    body();
    b.patch16(o);
}

} // namespace

std::vector<uint8_t> build_chrome131_clienthello(const string& sni) {
    auto rbyte = []{ return rand_u8(); };

    // GREASE values, drawn once up front. two constraints, both enforced by
    // a strict server (OpenSSL rejects violations):
    //   * the supported_groups GREASE and the key_share GREASE group MUST be
    //     the same value — a KeyShareEntry has to correspond to a group
    //     offered in supported_groups (RFC 8446 4.2.8). a mismatch is "bad
    //     key share".
    //   * the two bookend extension types MUST differ from each other, or it
    //     is a duplicate extension type.
    // the cipher-list and supported_versions GREASE values are unconstrained.
    const uint16_t g_cipher = grease_value();
    const uint16_t g_group  = grease_value();   // supported_groups + key_share
    const uint16_t g_ver    = grease_value();
    const uint16_t g_ext1   = grease_value();
    uint16_t g_ext2 = grease_value();
    while (g_ext2 == g_ext1) g_ext2 = grease_value();

    // ---- extensions block, built standalone so the padding extension can
    //      be sized against the finished pre-pad ClientHello length --------
    B ex;

    // GREASE (leading bookend) — empty body.
    ext(ex, g_ext1, []{});

    // server_name (0x0000)
    ext(ex, 0x0000, [&]{
        size_t lo = ex.mark16();      // ServerNameList length
        ex.u8(0x00);                  // name_type = host_name
        size_t no = ex.mark16();      // HostName length
        ex.str(sni);
        ex.patch16(no);
        ex.patch16(lo);
    });

    // extended_master_secret (0x0017) — empty.
    ext(ex, 0x0017, []{});

    // renegotiation_info (0xff01) — one zero byte (empty renegotiated_connection).
    ext(ex, 0xff01, [&]{ ex.u8(0x00); });

    // supported_groups (0x000a) — GREASE, x25519, secp256r1, secp384r1.
    ext(ex, 0x000a, [&]{
        size_t lo = ex.mark16();
        ex.u16(g_group);
        ex.u16(0x001d);  // x25519
        ex.u16(0x0017);  // secp256r1
        ex.u16(0x0018);  // secp384r1
        ex.patch16(lo);
    });

    // ec_point_formats (0x000b) — uncompressed only.
    ext(ex, 0x000b, [&]{ ex.u8(0x01); ex.u8(0x00); });

    // session_ticket (0x0023) — empty.
    ext(ex, 0x0023, []{});

    // ALPN (0x0010) — h2, http/1.1.
    ext(ex, 0x0010, [&]{
        size_t lo = ex.mark16();
        ex.u8(2); ex.str("h2");
        ex.u8(8); ex.str("http/1.1");
        ex.patch16(lo);
    });

    // status_request (0x0005) — OCSP, empty responder_id + extensions.
    ext(ex, 0x0005, [&]{ ex.u8(0x01); ex.u16(0x0000); ex.u16(0x0000); });

    // signature_algorithms (0x000d) — Chrome's 8-entry list, in order.
    ext(ex, 0x000d, [&]{
        size_t lo = ex.mark16();
        ex.u16(0x0403);  // ecdsa_secp256r1_sha256
        ex.u16(0x0804);  // rsa_pss_rsae_sha256
        ex.u16(0x0401);  // rsa_pkcs1_sha256
        ex.u16(0x0503);  // ecdsa_secp384r1_sha384
        ex.u16(0x0805);  // rsa_pss_rsae_sha384
        ex.u16(0x0501);  // rsa_pkcs1_sha384
        ex.u16(0x0806);  // rsa_pss_rsae_sha512
        ex.u16(0x0601);  // rsa_pkcs1_sha512
        ex.patch16(lo);
    });

    // signed_certificate_timestamp (0x0012) — empty.
    ext(ex, 0x0012, []{});

    // key_share (0x0033) — GREASE (1-byte key) + x25519 (32-byte key).
    // the GREASE group here MUST equal the supported_groups GREASE.
    ext(ex, 0x0033, [&]{
        size_t lo = ex.mark16();
        ex.u16(g_group); ex.u16(0x0001); ex.u8(0x00);
        ex.u16(0x001d); ex.u16(0x0020);
        for (int i = 0; i < 32; ++i) ex.u8(rbyte());
        ex.patch16(lo);
    });

    // psk_key_exchange_modes (0x002d) — psk_dhe_ke.
    ext(ex, 0x002d, [&]{ ex.u8(0x01); ex.u8(0x01); });

    // supported_versions (0x002b) — GREASE, TLS 1.3, TLS 1.2.
    ext(ex, 0x002b, [&]{
        size_t lo = ex.v.size(); ex.u8(0);
        ex.u16(g_ver);
        ex.u16(0x0304);
        ex.u16(0x0303);
        ex.v[lo] = (uint8_t)(ex.v.size() - lo - 1);
    });

    // compress_certificate (0x001b) — brotli.
    ext(ex, 0x001b, [&]{ ex.u8(0x02); ex.u16(0x0002); });

    // application_settings / ALPS (0x4469) — h2.
    ext(ex, 0x4469, [&]{
        size_t lo = ex.mark16();
        ex.u8(2); ex.str("h2");
        ex.patch16(lo);
    });

    // GREASE (trailing bookend) — Chrome's trailing GREASE ext carries a
    // single zero byte. its type must differ from the leading bookend.
    ext(ex, g_ext2, [&]{ ex.u8(0x00); });

    // ---- padding (0x0015) -------------------------------------------------
    // BoringSSL pads the ClientHello to 512 bytes when the handshake message
    // would otherwise land in [256, 512). kFixedPrefix is the byte count of
    // everything in the handshake message before the extensions block:
    //   1 type + 3 length + 2 legacy_version + 32 random
    //   + 1+32 session_id + 2+32 cipher_suites (GREASE + 15 suites)
    //   + 2 compression + 2 ext-block-length = 109
    const size_t kFixedPrefix = 109;
    size_t hs_total = kFixedPrefix + ex.v.size();
    if (hs_total >= 256 && hs_total < 512) {
        size_t pad = (hs_total + 4 <= 512) ? (512 - hs_total - 4) : 0;
        ext(ex, 0x0015, [&]{ for (size_t i = 0; i < pad; ++i) ex.u8(0x00); });
    }

    // ---- assemble the record + handshake message --------------------------
    B out;
    out.u8(0x16);             // record type: handshake
    out.u16(0x0301);          // record version: TLS 1.0 (legacy, like Chrome)
    size_t rec_len = out.mark16();

    out.u8(0x01);             // handshake type: ClientHello
    size_t hs_len = out.mark24();

    out.u16(0x0303);          // legacy_version: TLS 1.2
    for (int i = 0; i < 32; ++i) out.u8(rbyte());   // random
    out.u8(32);
    for (int i = 0; i < 32; ++i) out.u8(rbyte());   // legacy_session_id

    size_t cs = out.mark16();                       // cipher_suites
    out.u16(g_cipher);
    out.u16(0x1301); out.u16(0x1302); out.u16(0x1303);
    out.u16(0xc02b); out.u16(0xc02f); out.u16(0xc02c); out.u16(0xc030);
    out.u16(0xcca9); out.u16(0xcca8);
    out.u16(0xc013); out.u16(0xc014);
    out.u16(0x009c); out.u16(0x009d);
    out.u16(0x002f); out.u16(0x0035);
    out.patch16(cs);

    out.u8(0x01); out.u8(0x00);                     // compression: null

    size_t eb = out.mark16();                       // extensions block
    out.blob(ex.v);
    out.patch16(eb);

    out.patch24(hs_len);
    out.patch16(rec_len);
    return out.v;
}
