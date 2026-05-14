// SPDX-License-Identifier: GPL-3.0-or-later
#include "ja4.h"

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

using std::string;
using std::vector;

bool ja4_is_grease(uint16_t v) {
    // RFC 8701 GREASE: 0x?A?A pattern (low nibble 'A' in both bytes).
    return (v & 0x0f0f) == 0x0a0a;
}

string sha256_12(const string& input) {
    unsigned char dgst[32];
    unsigned int  dl = 0;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) return {};
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, input.data(), input.size());
    EVP_DigestFinal_ex(mdctx, dgst, &dl);
    EVP_MD_CTX_free(mdctx);
    static const char hexd[] = "0123456789abcdef";
    string out; out.reserve(12);
    for (int i = 0; i < 6 && i < (int)dl; ++i) {
        out += hexd[(dgst[i] >> 4) & 0xF];
        out += hexd[dgst[i] & 0xF];
    }
    return out;
}

// raw byte readers ----------------------------------------------------------

namespace {

inline uint16_t rd16(const uint8_t* p) { return (uint16_t(p[0]) << 8) | p[1]; }
inline uint32_t rd24(const uint8_t* p) { return (uint32_t(p[0]) << 16) | (uint32_t(p[1]) << 8) | p[2]; }

const char* version_2digit(int ver) {
    switch (ver) {
        case 0x0304: return "13";
        case 0x0303: return "12";
        case 0x0302: return "11";
        case 0x0301: return "10";
        case 0x0300: return "s3";
        default:     return "00";
    }
}

string hex4(uint16_t v) {
    char b[5]; std::snprintf(b, sizeof(b), "%04x", v);
    return string(b, 4);
}

string join_csv(const vector<uint16_t>& vs, bool sort_first) {
    vector<uint16_t> v = vs;
    if (sort_first) std::sort(v.begin(), v.end());
    string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += ',';
        out += hex4(v[i]);
    }
    return out;
}

// scan extension block of a ClientHello. callback receives (ext_type, body_ptr, body_len).
// returns false on truncation.
template <typename Fn>
bool walk_exts(const uint8_t* p, const uint8_t* end, Fn&& fn) {
    if (end - p < 2) return false;
    uint16_t total = rd16(p); p += 2;
    if (end - p < total) return false;
    const uint8_t* ee = p + total;
    while (p < ee) {
        if (ee - p < 4) return false;
        uint16_t et = rd16(p);   p += 2;
        uint16_t el = rd16(p);   p += 2;
        if (ee - p < el) return false;
        fn(et, p, el);
        p += el;
    }
    return true;
}

} // namespace

// parsers -------------------------------------------------------------------

bool parse_client_hello(const uint8_t* data, size_t len, ClientHelloFp& out) {
    out = {};
    // SSL_set_msg_callback delivers handshake msg starting with the HandshakeType
    // byte and a uint24 length, followed by the ClientHello struct.
    if (len < 4) return false;
    if (data[0] != 0x01 /* HandshakeType client_hello */) return false;
    uint32_t mlen = rd24(data + 1);
    if (mlen + 4 > len) return false;
    const uint8_t* p   = data + 4;
    const uint8_t* end = data + 4 + mlen;

    // legacy_version (2)
    if (end - p < 2) return false;
    out.legacy_version = rd16(p); p += 2;

    // random (32)
    if (end - p < 32) return false;
    p += 32;

    // legacy_session_id <0..32>
    if (end - p < 1) return false;
    uint8_t sidlen = *p++;
    if (end - p < sidlen) return false;
    p += sidlen;

    // cipher_suites <2..2^16-2>
    if (end - p < 2) return false;
    uint16_t clen = rd16(p); p += 2;
    if (end - p < clen) return false;
    if (clen % 2 != 0) return false;
    for (int i = 0; i < clen; i += 2) {
        uint16_t cs = rd16(p + i);
        if (ja4_is_grease(cs)) { out.has_grease = true; continue; }
        out.ciphers.push_back(cs);
    }
    p += clen;

    // legacy_compression_methods <1..2^8-1>
    if (end - p < 1) return false;
    uint8_t cmplen = *p++;
    if (end - p < cmplen) return false;
    p += cmplen;

    // extensions <0..2^16-1>, may be absent in some TLS 1.0 hellos
    if (p == end) {
        out.real_version = out.legacy_version;
        out.ok = true;
        return true;
    }

    bool ok = walk_exts(p, end, [&](uint16_t et, const uint8_t* body, uint16_t bl){
        if (ja4_is_grease(et)) { out.has_grease = true; return; }
        out.extensions.push_back(et);
        switch (et) {
            case 0x0000: { // server_name
                // ServerNameList: <2..2^16-1>; entry: 1 byte type + <1..2^16-1>
                if (bl < 5) break;
                uint16_t snl = rd16(body);
                if (snl + 2 > bl) break;
                const uint8_t* q = body + 2;
                const uint8_t* qe = q + snl;
                while (q < qe) {
                    if (qe - q < 3) break;
                    uint8_t  nt = *q++;
                    uint16_t nl = rd16(q); q += 2;
                    if (qe - q < nl) break;
                    if (nt == 0 /* host_name */) {
                        out.has_sni = true;
                        out.sni.assign((const char*)q, (size_t)nl);
                        break;
                    }
                    q += nl;
                }
                break;
            }
            case 0x000a: { // supported_groups
                if (bl < 2) break;
                uint16_t gl = rd16(body);
                if (gl + 2 > bl || gl % 2 != 0) break;
                for (int i = 0; i < gl; i += 2) {
                    uint16_t g = rd16(body + 2 + i);
                    if (ja4_is_grease(g)) continue;
                    out.groups.push_back(g);
                }
                break;
            }
            case 0x000d: { // signature_algorithms
                if (bl < 2) break;
                uint16_t sl = rd16(body);
                if (sl + 2 > bl || sl % 2 != 0) break;
                for (int i = 0; i < sl; i += 2) {
                    out.sigalgs.push_back(rd16(body + 2 + i));
                }
                break;
            }
            case 0x0010: { // ALPN
                if (bl < 2) break;
                uint16_t al = rd16(body);
                if (al + 2 > bl) break;
                const uint8_t* q = body + 2;
                const uint8_t* qe = q + al;
                if (q < qe) {
                    uint8_t nl = *q++;
                    if (qe - q >= nl && out.alpn_first.empty()) {
                        out.alpn_first.assign((const char*)q, (size_t)nl);
                    }
                }
                break;
            }
            case 0x002b: { // supported_versions
                if (bl < 1) break;
                uint8_t vl = body[0];
                if (vl + 1 > bl || vl % 2 != 0) break;
                int best = 0;
                for (int i = 0; i < vl; i += 2) {
                    uint16_t v = rd16(body + 1 + i);
                    if (ja4_is_grease(v)) continue;
                    if (v > best) best = v;
                }
                out.real_version = best;
                break;
            }
            default: break;
        }
    });
    if (!ok) return false;
    if (!out.real_version) out.real_version = out.legacy_version;
    out.ok = true;
    return true;
}

bool parse_server_hello(const uint8_t* data, size_t len, ServerHelloFp& out) {
    out = {};
    if (len < 4) return false;
    if (data[0] != 0x02 /* server_hello */) return false;
    uint32_t mlen = rd24(data + 1);
    if (mlen + 4 > len) return false;
    const uint8_t* p   = data + 4;
    const uint8_t* end = data + 4 + mlen;

    // legacy_version (2)
    if (end - p < 2) return false;
    out.legacy_version = rd16(p); p += 2;

    // random (32)
    if (end - p < 32) return false;
    p += 32;

    // legacy_session_id_echo <0..32>
    if (end - p < 1) return false;
    uint8_t sidlen = *p++;
    if (end - p < sidlen) return false;
    p += sidlen;

    // cipher_suite (2)
    if (end - p < 2) return false;
    out.cipher = rd16(p); p += 2;

    // legacy_compression_method (1)
    if (end - p < 1) return false;
    p += 1;

    if (p == end) {
        out.real_version = out.legacy_version;
        out.ok = true;
        return true;
    }

    bool ok = walk_exts(p, end, [&](uint16_t et, const uint8_t* body, uint16_t bl){
        if (ja4_is_grease(et)) return;
        out.extensions.push_back(et);
        if (et == 0x0010 /* ALPN */) {
            if (bl < 3) return;
            uint16_t al = rd16(body);
            if (al + 2 > bl) return;
            const uint8_t* q = body + 2;
            const uint8_t* qe = q + al;
            if (q < qe) {
                uint8_t nl = *q++;
                if (qe - q >= nl) out.alpn_negotiated.assign((const char*)q, (size_t)nl);
            }
        } else if (et == 0x002b /* supported_versions */) {
            if (bl >= 2) out.real_version = rd16(body);
        }
    });
    if (!ok) return false;
    if (!out.real_version) out.real_version = out.legacy_version;
    out.ok = true;
    return true;
}

// builders ------------------------------------------------------------------

string ja4_client(const ClientHelloFp& ch) {
    if (!ch.ok) return {};
    char a[16]; // header is 10 fixed chars
    const char* ver = version_2digit(ch.real_version ? ch.real_version : ch.legacy_version);
    char snif = ch.has_sni ? 'd' : 'i';
    int cn = (int)std::min<size_t>(99, ch.ciphers.size());
    int en = (int)std::min<size_t>(99, ch.extensions.size());
    char alpn2[3] = {'0','0',0};
    if (ch.alpn_first.size() >= 2) {
        alpn2[0] = ch.alpn_first[0];
        alpn2[1] = ch.alpn_first[1];
    } else if (ch.alpn_first.size() == 1) {
        alpn2[0] = ch.alpn_first[0];
        alpn2[1] = '0';
    }
    std::snprintf(a, sizeof(a), "t%2s%c%02d%02d%c%c", ver, snif, cn, en, alpn2[0], alpn2[1]);

    // JA4_b: sha256 of comma-joined sorted ciphers (hex4, lowercase).
    string b = sha256_12(join_csv(ch.ciphers, true));

    // JA4_c: sorted exts EXCLUDING SNI (0x0000) and ALPN (0x0010), then "_"
    // and sigalgs in ORIGINAL order.
    vector<uint16_t> exts_for_c;
    exts_for_c.reserve(ch.extensions.size());
    for (auto e: ch.extensions) {
        if (e == 0x0000 || e == 0x0010) continue;
        exts_for_c.push_back(e);
    }
    std::sort(exts_for_c.begin(), exts_for_c.end());
    string c_in;
    for (size_t i = 0; i < exts_for_c.size(); ++i) {
        if (i) c_in += ',';
        c_in += hex4(exts_for_c[i]);
    }
    if (!ch.sigalgs.empty()) {
        c_in += '_';
        for (size_t i = 0; i < ch.sigalgs.size(); ++i) {
            if (i) c_in += ',';
            c_in += hex4(ch.sigalgs[i]);
        }
    }
    string c = sha256_12(c_in);

    string out = a;
    out += '_'; out += b;
    out += '_'; out += c;
    return out;
}

string ja4s_server(const ServerHelloFp& sh) {
    if (!sh.ok) return {};
    char a[16];
    const char* ver = version_2digit(sh.real_version ? sh.real_version : sh.legacy_version);
    int en = (int)std::min<size_t>(99, sh.extensions.size());
    char alpn2[3] = {'0','0',0};
    if (sh.alpn_negotiated.size() >= 2) {
        alpn2[0] = sh.alpn_negotiated[0];
        alpn2[1] = sh.alpn_negotiated[1];
    } else if (sh.alpn_negotiated.size() == 1) {
        alpn2[0] = sh.alpn_negotiated[0];
    }
    std::snprintf(a, sizeof(a), "t%2s%02d%c%c", ver, en, alpn2[0], alpn2[1]);

    string b = hex4(sh.cipher); // server picks one cipher, no sort

    // c: sha256 of sorted server-side extension list, no special exclusions
    vector<uint16_t> e = sh.extensions;
    std::sort(e.begin(), e.end());
    string c_in;
    for (size_t i = 0; i < e.size(); ++i) {
        if (i) c_in += ',';
        c_in += hex4(e[i]);
    }
    string c = sha256_12(c_in);

    string out = a;
    out += '_'; out += b;
    out += '_'; out += c;
    return out;
}

string ja4h(const Ja4hInput& in) {
    // method first 2 chars lowercased
    char m[3] = {'0','0',0};
    if (in.method.size() >= 1) m[0] = (char)std::tolower((unsigned char)in.method[0]);
    if (in.method.size() >= 2) m[1] = (char)std::tolower((unsigned char)in.method[1]);
    // http version: "11" or "20"
    const char* hv = "11";
    if (in.http_version == "2.0" || in.http_version == "2") hv = "20";
    else if (in.http_version == "1.0") hv = "10";
    char ck = in.has_cookie ? 'c' : 'n';
    char rf = in.has_referer ? 'r' : 'n';
    char l1 = '0', l2 = '0';
    if (in.accept_language.size() >= 1) l1 = (char)std::tolower((unsigned char)in.accept_language[0]);
    if (in.accept_language.size() >= 2) l2 = (char)std::tolower((unsigned char)in.accept_language[1]);
    char hcount[3];
    int hc = (int)std::min<size_t>(99, in.header_names_in_order.size());
    std::snprintf(hcount, sizeof(hcount), "%02d", hc);

    string a;
    a += m[0]; a += m[1];
    a += hv;
    a += ck; a += rf;
    a += hcount;
    a += l1; a += l2;

    // JA4H_b: header NAMES in order, comma-joined, sha256[:12]
    string b_in;
    for (size_t i = 0; i < in.header_names_in_order.size(); ++i) {
        if (i) b_in += ',';
        b_in += in.header_names_in_order[i];
    }
    string b = sha256_12(b_in);

    // JA4H_c: cookie names sorted, sha256[:12] (or "0" * 12 if no cookies)
    string c;
    if (in.cookie_names.empty()) {
        c = "000000000000";
    } else {
        vector<string> ns = in.cookie_names;
        std::sort(ns.begin(), ns.end());
        string cin;
        for (size_t i = 0; i < ns.size(); ++i) {
            if (i) cin += ',';
            cin += ns[i];
        }
        c = sha256_12(cin);
    }

    // JA4H_d: cookie name=value sorted by name, sha256[:12]
    string d;
    if (in.cookies_kv.empty()) {
        d = "000000000000";
    } else {
        vector<std::pair<string,string>> kv = in.cookies_kv;
        std::sort(kv.begin(), kv.end(),
                  [](const auto& x, const auto& y){ return x.first < y.first; });
        string din;
        for (size_t i = 0; i < kv.size(); ++i) {
            if (i) din += ',';
            din += kv[i].first; din += '='; din += kv[i].second;
        }
        d = sha256_12(din);
    }

    string out = a;
    out += '_'; out += b;
    out += '_'; out += c;
    out += '_'; out += d;
    return out;
}