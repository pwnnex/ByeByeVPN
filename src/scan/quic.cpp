// SPDX-License-Identifier: GPL-3.0-or-later
#include "quic.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <cstring>

using std::string;
using std::vector;

namespace {

// QUIC v1 Initial salt (RFC 9001 §5.2).
const uint8_t INITIAL_SALT[20] = {
    0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,
    0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a
};

vector<uint8_t> hmac_sha256(const vector<uint8_t>& key, const uint8_t* data, size_t len) {
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int  ml = 0;
    HMAC(EVP_sha256(), key.data(), (int)key.size(), data, len, mac, &ml);
    return vector<uint8_t>(mac, mac + ml);
}

// AES-128-GCM seal. out = ciphertext || 16-byte tag. false on any EVP error.
bool gcm_encrypt(const vector<uint8_t>& key, const vector<uint8_t>& nonce,
                 const vector<uint8_t>& aad, const vector<uint8_t>& pt,
                 vector<uint8_t>& out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1) break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) break;
        int outl = 0;
        if (!aad.empty() &&
            EVP_EncryptUpdate(ctx, nullptr, &outl, aad.data(), (int)aad.size()) != 1) break;
        out.resize(pt.size() + 16);
        int n = 0;
        if (EVP_EncryptUpdate(ctx, out.data(), &outl, pt.data(), (int)pt.size()) != 1) break;
        n = outl;
        if (EVP_EncryptFinal_ex(ctx, out.data() + n, &outl) != 1) break;
        n += outl;
        uint8_t tag[16];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) break;
        std::memcpy(out.data() + n, tag, 16);
        out.resize((size_t)n + 16);
        ok = true;
    } while (false);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// AES-128-GCM open. ct_tag = ciphertext || 16-byte tag. false on tag mismatch.
bool gcm_decrypt(const vector<uint8_t>& key, const vector<uint8_t>& nonce,
                 const vector<uint8_t>& aad, const vector<uint8_t>& ct_tag,
                 vector<uint8_t>& out) {
    if (ct_tag.size() < 16) return false;
    size_t ct_len = ct_tag.size() - 16;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1) break;
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) break;
        int outl = 0;
        if (!aad.empty() &&
            EVP_DecryptUpdate(ctx, nullptr, &outl, aad.data(), (int)aad.size()) != 1) break;
        out.resize(ct_len);
        int n = 0;
        if (EVP_DecryptUpdate(ctx, out.data(), &outl, ct_tag.data(), (int)ct_len) != 1) break;
        n = outl;
        uint8_t tag[16];
        std::memcpy(tag, ct_tag.data() + ct_len, 16);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) break;
        if (EVP_DecryptFinal_ex(ctx, out.data() + n, &outl) != 1) break;  // tag check
        n += outl;
        out.resize((size_t)n);
        ok = true;
    } while (false);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool parse_varint(const vector<uint8_t>& d, size_t& pos, uint64_t& out) {
    if (pos >= d.size()) return false;
    uint8_t b = d[pos];
    int len = 1 << (b >> 6);                 // 1 / 2 / 4 / 8
    if (pos + (size_t)len > d.size()) return false;
    uint64_t v = b & 0x3f;
    for (int i = 1; i < len; ++i) v = (v << 8) | d[pos + (size_t)i];
    pos += (size_t)len;
    out = v;
    return true;
}

} // namespace

vector<uint8_t> quic_varint(uint64_t v) {
    vector<uint8_t> o;
    if (v <= 63) {
        o.push_back((uint8_t)v);
    } else if (v <= 16383) {
        o.push_back((uint8_t)(0x40 | (v >> 8)));
        o.push_back((uint8_t)v);
    } else if (v <= 1073741823ULL) {
        o.push_back((uint8_t)(0x80 | (v >> 24)));
        o.push_back((uint8_t)(v >> 16));
        o.push_back((uint8_t)(v >> 8));
        o.push_back((uint8_t)v);
    } else {
        o.push_back((uint8_t)(0xc0 | (v >> 56)));
        o.push_back((uint8_t)(v >> 48));
        o.push_back((uint8_t)(v >> 40));
        o.push_back((uint8_t)(v >> 32));
        o.push_back((uint8_t)(v >> 24));
        o.push_back((uint8_t)(v >> 16));
        o.push_back((uint8_t)(v >> 8));
        o.push_back((uint8_t)v);
    }
    return o;
}

vector<uint8_t> hkdf_extract(const vector<uint8_t>& salt, const vector<uint8_t>& ikm) {
    return hmac_sha256(salt, ikm.data(), ikm.size());
}

vector<uint8_t> hkdf_expand_label(const vector<uint8_t>& secret, const string& label,
                                  const vector<uint8_t>& context, size_t length) {
    // HkdfLabel = u16(length) | u8(len) "tls13 "+label | u8(len) context
    string full = "tls13 " + label;
    vector<uint8_t> info;
    info.push_back((uint8_t)(length >> 8));
    info.push_back((uint8_t)length);
    info.push_back((uint8_t)full.size());
    info.insert(info.end(), full.begin(), full.end());
    info.push_back((uint8_t)context.size());
    info.insert(info.end(), context.begin(), context.end());

    // HKDF-Expand (RFC 5869): T(i) = HMAC(secret, T(i-1) | info | i)
    vector<uint8_t> okm, prev;
    uint8_t counter = 1;
    while (okm.size() < length) {
        vector<uint8_t> msg = prev;
        msg.insert(msg.end(), info.begin(), info.end());
        msg.push_back(counter++);
        prev = hmac_sha256(secret, msg.data(), msg.size());
        okm.insert(okm.end(), prev.begin(), prev.end());
    }
    okm.resize(length);
    return okm;
}

QuicInitialSecrets quic_initial_secrets(const vector<uint8_t>& dcid, bool is_client) {
    QuicInitialSecrets s;
    vector<uint8_t> salt(INITIAL_SALT, INITIAL_SALT + sizeof(INITIAL_SALT));
    vector<uint8_t> init = hkdf_extract(salt, dcid);
    s.secret = hkdf_expand_label(init, is_client ? "client in" : "server in", {}, 32);
    s.key    = hkdf_expand_label(s.secret, "quic key", {}, 16);
    s.iv     = hkdf_expand_label(s.secret, "quic iv",  {}, 12);
    s.hp     = hkdf_expand_label(s.secret, "quic hp",  {}, 16);
    s.ok = (s.key.size() == 16 && s.iv.size() == 12 && s.hp.size() == 16);
    return s;
}

vector<uint8_t> quic_hp_mask(const vector<uint8_t>& hp_key, const vector<uint8_t>& sample) {
    vector<uint8_t> mask;
    if (hp_key.size() != 16 || sample.size() < 16) return mask;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return mask;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, hp_key.data(), nullptr) == 1) {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        mask.resize(32);
        int outl = 0;
        if (EVP_EncryptUpdate(ctx, mask.data(), &outl, sample.data(), 16) == 1)
            mask.resize((size_t)outl);
        else
            mask.clear();
    }
    EVP_CIPHER_CTX_free(ctx);
    return mask;
}

vector<uint8_t> quic_build_client_initial(const vector<uint8_t>& dcid,
                                          const vector<uint8_t>& scid,
                                          const vector<uint8_t>& crypto,
                                          uint32_t packet_number,
                                          uint32_t version) {
    // Initial keys are always derived with the QUIC v1 salt; for a forced-VN
    // probe (reserved version) the server never decrypts, so the v1 keys just
    // produce well-formed-looking bytes under a bogus version field.
    QuicInitialSecrets s = quic_initial_secrets(dcid, true);
    if (!s.ok) return {};
    const int pn_len = 4;

    // plaintext payload: one CRYPTO frame (type 0x06) carrying the TLS bytes.
    vector<uint8_t> pt;
    pt.push_back(0x06);
    { auto v = quic_varint(0);             pt.insert(pt.end(), v.begin(), v.end()); } // offset
    { auto v = quic_varint(crypto.size()); pt.insert(pt.end(), v.begin(), v.end()); } // length
    pt.insert(pt.end(), crypto.begin(), crypto.end());

    // unprotected header up to (but not including) the length field.
    vector<uint8_t> hdr;
    hdr.push_back((uint8_t)(0xC0 | (pn_len - 1)));     // long, fixed, Initial, pn_len-1
    hdr.push_back((uint8_t)(version >> 24));            // version (default v1)
    hdr.push_back((uint8_t)(version >> 16));
    hdr.push_back((uint8_t)(version >> 8));
    hdr.push_back((uint8_t)(version));
    hdr.push_back((uint8_t)dcid.size()); hdr.insert(hdr.end(), dcid.begin(), dcid.end());
    hdr.push_back((uint8_t)scid.size()); hdr.insert(hdr.end(), scid.begin(), scid.end());
    hdr.push_back(0x00);                              // token length = 0

    // pad with PADDING frames (0x00) so the datagram is >= 1200 bytes. the
    // length field is a fixed 2-byte varint (value < 16384 for a 1200B Initial).
    size_t header_len = hdr.size() + 2 /*length varint*/ + pn_len;
    size_t total = header_len + pt.size() + 16 /*tag*/;
    if (total < 1200) pt.resize(pt.size() + (1200 - total), 0x00);

    uint64_t length_val = (uint64_t)pn_len + pt.size() + 16;
    if (length_val >= 16384) return {};
    hdr.push_back((uint8_t)(0x40 | (length_val >> 8)));
    hdr.push_back((uint8_t)(length_val & 0xff));

    size_t pn_offset = hdr.size();
    hdr.push_back((uint8_t)(packet_number >> 24));
    hdr.push_back((uint8_t)(packet_number >> 16));
    hdr.push_back((uint8_t)(packet_number >> 8));
    hdr.push_back((uint8_t)(packet_number));

    // nonce = iv XOR left-padded packet number.
    vector<uint8_t> nonce = s.iv;
    nonce[8]  ^= (uint8_t)(packet_number >> 24);
    nonce[9]  ^= (uint8_t)(packet_number >> 16);
    nonce[10] ^= (uint8_t)(packet_number >> 8);
    nonce[11] ^= (uint8_t)(packet_number);

    vector<uint8_t> ct_tag;
    if (!gcm_encrypt(s.key, nonce, hdr, pt, ct_tag)) return {};

    vector<uint8_t> pkt = hdr;
    pkt.insert(pkt.end(), ct_tag.begin(), ct_tag.end());

    // header protection: sample 16 bytes starting 4 into the packet number.
    size_t sample_off = pn_offset + 4;
    if (sample_off + 16 > pkt.size()) return {};
    vector<uint8_t> sample(pkt.begin() + sample_off, pkt.begin() + sample_off + 16);
    vector<uint8_t> mask = quic_hp_mask(s.hp, sample);
    if (mask.size() < 5) return {};
    pkt[0] ^= (uint8_t)(mask[0] & 0x0f);              // long header: low 4 bits
    for (int i = 0; i < pn_len; ++i) pkt[pn_offset + (size_t)i] ^= mask[1 + (size_t)i];
    return pkt;
}

bool quic_unprotect_client_initial(const vector<uint8_t>& dg, const vector<uint8_t>& dcid,
                                   vector<uint8_t>& crypto_out) {
    QuicInitialSecrets s = quic_initial_secrets(dcid, true);
    if (!s.ok) return false;
    if (dg.size() < 7) return false;

    size_t pos = 1;                                   // skip first byte
    pos += 4;                                         // version
    if (pos >= dg.size()) return false;
    uint8_t dl = dg[pos++]; pos += dl;                // DCID
    if (pos >= dg.size()) return false;
    uint8_t sl = dg[pos++]; pos += sl;                // SCID
    uint64_t token_len = 0;
    if (!parse_varint(dg, pos, token_len)) return false;
    pos += token_len;                                 // token
    uint64_t length_val = 0;
    if (!parse_varint(dg, pos, length_val)) return false;
    size_t pn_offset = pos;

    size_t sample_off = pn_offset + 4;
    if (sample_off + 16 > dg.size()) return false;
    vector<uint8_t> sample(dg.begin() + sample_off, dg.begin() + sample_off + 16);
    vector<uint8_t> mask = quic_hp_mask(s.hp, sample);
    if (mask.size() < 5) return false;

    uint8_t first = dg[0] ^ (uint8_t)(mask[0] & 0x0f);
    int pn_len = (first & 0x03) + 1;
    if (pn_offset + (size_t)pn_len > dg.size()) return false;

    vector<uint8_t> hdr(dg.begin(), dg.begin() + pn_offset + (size_t)pn_len);
    hdr[0] = first;
    uint32_t pn = 0;
    for (int i = 0; i < pn_len; ++i) {
        uint8_t b = dg[pn_offset + (size_t)i] ^ mask[1 + (size_t)i];
        hdr[pn_offset + (size_t)i] = b;
        pn = (pn << 8) | b;
    }

    // payload spans length_val bytes from pn_offset (pn + ciphertext + tag).
    if (pn_offset + (size_t)length_val > dg.size()) return false;
    size_t ct_start = pn_offset + (size_t)pn_len;
    size_t ct_len = (size_t)length_val - (size_t)pn_len;
    vector<uint8_t> ct_tag(dg.begin() + ct_start, dg.begin() + ct_start + ct_len);

    vector<uint8_t> nonce = s.iv;
    nonce[8]  ^= (uint8_t)(pn >> 24);
    nonce[9]  ^= (uint8_t)(pn >> 16);
    nonce[10] ^= (uint8_t)(pn >> 8);
    nonce[11] ^= (uint8_t)(pn);

    vector<uint8_t> pt;
    if (!gcm_decrypt(s.key, nonce, hdr, ct_tag, pt)) return false;

    // walk frames, skip PADDING (0x00), return the first CRYPTO (0x06) data.
    size_t p = 0;
    while (p < pt.size()) {
        uint8_t ft = pt[p];
        if (ft == 0x00) { ++p; continue; }            // PADDING
        if (ft == 0x06) {                             // CRYPTO
            ++p;
            uint64_t off = 0, clen = 0;
            if (!parse_varint(pt, p, off)) return false;
            if (!parse_varint(pt, p, clen)) return false;
            if (p + clen > pt.size()) return false;
            crypto_out.assign(pt.begin() + p, pt.begin() + p + clen);
            return true;
        }
        return false;                                 // unexpected frame
    }
    return false;
}

// ---- transport parameters + QUIC ClientHello -------------------------------

namespace {

void tp_int(vector<uint8_t>& o, uint64_t id, uint64_t val) {
    auto i = quic_varint(id);   o.insert(o.end(), i.begin(), i.end());
    auto v = quic_varint(val);
    auto l = quic_varint(v.size()); o.insert(o.end(), l.begin(), l.end());
    o.insert(o.end(), v.begin(), v.end());
}
void tp_bytes(vector<uint8_t>& o, uint64_t id, const vector<uint8_t>& val) {
    auto i = quic_varint(id);          o.insert(o.end(), i.begin(), i.end());
    auto l = quic_varint(val.size());  o.insert(o.end(), l.begin(), l.end());
    o.insert(o.end(), val.begin(), val.end());
}

// tiny length-prefix-backpatching byte builder for the ClientHello.
struct CHB {
    vector<uint8_t> v;
    void u8(uint8_t x)   { v.push_back(x); }
    void u16(uint16_t x) { v.push_back((uint8_t)(x >> 8)); v.push_back((uint8_t)x); }
    void raw(const uint8_t* p, size_t n) { v.insert(v.end(), p, p + n); }
    void raw(const vector<uint8_t>& b)   { v.insert(v.end(), b.begin(), b.end()); }
    void str(const string& s)            { v.insert(v.end(), s.begin(), s.end()); }
    size_t m16() { size_t o = v.size(); u16(0); return o; }
    void   p16(size_t o) { uint16_t n = (uint16_t)(v.size() - o - 2); v[o] = (uint8_t)(n >> 8); v[o + 1] = (uint8_t)n; }
    size_t m24() { size_t o = v.size(); v.push_back(0); v.push_back(0); v.push_back(0); return o; }
    void   p24(size_t o) { uint32_t n = (uint32_t)(v.size() - o - 3); v[o] = (uint8_t)(n >> 16); v[o + 1] = (uint8_t)(n >> 8); v[o + 2] = (uint8_t)n; }
};

} // namespace

vector<uint8_t> quic_transport_params(const vector<uint8_t>& scid) {
    vector<uint8_t> o;
    tp_int(o, 0x01, 30000);     // max_idle_timeout (ms)
    tp_int(o, 0x03, 1472);      // max_udp_payload_size
    tp_int(o, 0x04, 1048576);   // initial_max_data
    tp_int(o, 0x05, 262144);    // initial_max_stream_data_bidi_local
    tp_int(o, 0x06, 262144);    // initial_max_stream_data_bidi_remote
    tp_int(o, 0x07, 262144);    // initial_max_stream_data_uni
    tp_int(o, 0x08, 100);       // initial_max_streams_bidi
    tp_int(o, 0x09, 100);       // initial_max_streams_uni
    tp_bytes(o, 0x0f, scid);    // initial_source_connection_id
    return o;
}

vector<uint8_t> quic_build_client_hello(const string& sni, const vector<uint8_t>& scid) {
    CHB b;
    b.u8(0x01);                         // HandshakeType client_hello
    size_t hs = b.m24();
    b.u16(0x0303);                      // legacy_version TLS 1.2
    uint8_t rnd[32]; RAND_bytes(rnd, 32); b.raw(rnd, 32);
    b.u8(0x00);                         // legacy_session_id: empty (QUIC)

    size_t cs = b.m16();                // cipher_suites
    b.u16(0x1301); b.u16(0x1302); b.u16(0x1303);
    b.p16(cs);
    b.u8(0x01); b.u8(0x00);             // compression: null

    size_t eb = b.m16();                // extensions
    if (!sni.empty()) {                 // server_name
        b.u16(0x0000); size_t e = b.m16();
        size_t ln = b.m16(); b.u8(0x00); size_t hn = b.m16(); b.str(sni); b.p16(hn); b.p16(ln);
        b.p16(e);
    }
    b.u16(0x000a); { size_t e = b.m16(); size_t l = b.m16(); b.u16(0x001d); b.p16(l); b.p16(e); } // groups x25519
    b.u16(0x000d); { size_t e = b.m16(); size_t l = b.m16();                                       // sig algs
        b.u16(0x0403); b.u16(0x0804); b.u16(0x0401); b.u16(0x0503);
        b.u16(0x0805); b.u16(0x0501); b.u16(0x0806); b.u16(0x0601);
        b.p16(l); b.p16(e); }
    b.u16(0x002b); { size_t e = b.m16(); b.u8(0x02); b.u16(0x0304); b.p16(e); }                     // supported_versions 1.3
    b.u16(0x002d); { size_t e = b.m16(); b.u8(0x01); b.u8(0x01); b.p16(e); }                         // psk modes
    b.u16(0x0033); { size_t e = b.m16(); size_t l = b.m16(); b.u16(0x001d); b.u16(0x0020);           // key_share x25519
        uint8_t ks[32]; RAND_bytes(ks, 32); b.raw(ks, 32); b.p16(l); b.p16(e); }
    b.u16(0x0010); { size_t e = b.m16(); size_t l = b.m16(); b.u8(2); b.str("h3"); b.p16(l); b.p16(e); } // ALPN h3
    { vector<uint8_t> tp = quic_transport_params(scid);                                              // 0x39 transport params
      b.u16(0x0039); size_t e = b.m16(); b.raw(tp); b.p16(e); }
    b.p16(eb);
    b.p24(hs);
    return b.v;
}

vector<uint8_t> quic_build_vn_probe(const vector<uint8_t>& dcid,
                                    const vector<uint8_t>& scid,
                                    const vector<uint8_t>& crypto) {
    // a reserved version (0x?a?a?a?a pattern) forces Version-Negotiation.
    return quic_build_client_initial(dcid, scid, crypto, 1, 0x1a2a3a4aU);
}

QuicResponse quic_parse_response(const vector<uint8_t>& dg) {
    QuicResponse r;
    if (dg.empty()) { r.summary = "no datagram"; return r; }
    uint8_t first = dg[0];
    if ((first & 0x80) == 0) {
        r.kind = QuicResponse::Kind::ShortHeader;
        r.summary = "short-header (1-RTT) packet";
        return r;
    }
    if (dg.size() < 7) { r.kind = QuicResponse::Kind::Unknown; r.summary = "truncated long header"; return r; }
    r.version = ((uint32_t)dg[1] << 24) | ((uint32_t)dg[2] << 16) |
                ((uint32_t)dg[3] << 8)  | (uint32_t)dg[4];
    size_t pos = 5;
    uint8_t dl = dg[pos++]; pos += dl;
    if (pos >= dg.size()) { r.kind = QuicResponse::Kind::Unknown; return r; }
    uint8_t sl = dg[pos++]; pos += sl;

    if (r.version == 0) {                          // Version-Negotiation
        r.kind = QuicResponse::Kind::VersionNegotiation;
        while (pos + 4 <= dg.size()) {
            r.versions.push_back(((uint32_t)dg[pos] << 24) | ((uint32_t)dg[pos + 1] << 16) |
                                 ((uint32_t)dg[pos + 2] << 8) | (uint32_t)dg[pos + 3]);
            pos += 4;
        }
        r.summary = "Version-Negotiation, " + std::to_string(r.versions.size()) + " version(s) offered";
        return r;
    }
    switch ((first & 0x30) >> 4) {                 // long-header packet type (v1)
        case 0: r.kind = QuicResponse::Kind::Initial;   r.summary = "Initial packet"; break;
        case 1: r.kind = QuicResponse::Kind::ZeroRTT;   r.summary = "0-RTT packet"; break;
        case 2: r.kind = QuicResponse::Kind::Handshake; r.summary = "Handshake packet"; break;
        case 3: r.kind = QuicResponse::Kind::Retry;     r.has_token = true; r.summary = "Retry packet (token issued)"; break;
        default: r.kind = QuicResponse::Kind::Unknown;  break;
    }
    return r;
}
