// SPDX-License-Identifier: GPL-3.0-or-later
#include "udp_validate.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

// a WireGuard messageresponse header: type 0x02 then 3 reserved zero bytes.
// `n` is how many bytes remain from `p`.
bool is_wg_msg_response(const uint8_t* p, size_t n) {
    return n >= 4 && p[0] == 0x02 && p[1] == 0 && p[2] == 0 && p[3] == 0;
}

// reply must be addressed to our index
bool receiver_matches(const UdpResult& u, const uint8_t* at) {
    return u.expect_receiver.empty() ||
           (u.expect_receiver.size() == 4 && std::equal(u.expect_receiver.begin(), u.expect_receiver.end(), at));
}

} // namespace

bool wg_response_valid(const UdpResult& u) {
    if (!u.responded || u.echoed) return false;
    const std::vector<uint8_t>& r = u.reply;
    // messageresponse: exactly 92 bytes (type + 3 reserved + sender 4 +
    // receiver 4 + ephemeral 32 + empty 16 + mac1 16 + mac2 16).
    if (u.bytes == 92 && r.size() == 92 && is_wg_msg_response(r.data(), r.size()))
        return receiver_matches(u, r.data() + 8);
    // cookie reply: 64 bytes, type 0x03. a loaded or under-load responder
    // sends this instead of a messageresponse, and only WireGuard does.
    if (u.bytes == 64 && r.size() == 64 &&
        r[0] == 0x03 && r[1] == 0 && r[2] == 0 && r[3] == 0)
        return receiver_matches(u, r.data() + 4);
    return false;
}

int awg_response_offset(const UdpResult& u) {
    if (!u.responded || u.echoed) return -1;
    const std::vector<uint8_t>& r = u.reply;
    if (r.size() < 92) return -1;
    // udp_probe() keeps the whole datagram (up to its 2048-byte buffer). the
    // 128-byte scan window below bounds the s2 prefix we look behind;
    // amneziawg deployments cluster well under it, and a false negative is
    // the right failure direction for a detector that feeds a block verdict.
    //
    // s2 is configurable, so scan for the header rather than assuming a size.
    // two constraints keep random payload from satisfying this by chance:
    // the window must leave a full 92-byte messageresponse behind the header,
    // and the datagram must be exactly prefix + messageresponse.
    size_t max_off = r.size() - 92;
    if (max_off > 128) max_off = 128;
    for (size_t off = 0; off <= max_off; ++off) {
        if (is_wg_msg_response(r.data() + off, r.size() - off) &&
            (size_t)u.bytes == off + 92 && receiver_matches(u, r.data() + off + 8)) {
            return (int)off;
        }
    }
    return -1;
}

namespace {

// rfc 9000 §16 variable-length integer; false when it runs past the datagram.
bool read_varint(const std::vector<uint8_t>& d, size_t& pos, uint64_t& out) {
    if (pos >= d.size()) return false;
    const size_t len = size_t(1) << (d[pos] >> 6);
    if (d.size() - pos < len) return false;
    uint64_t v = d[pos] & 0x3f;
    for (size_t i = 1; i < len; ++i) v = (v << 8) | d[pos + i];
    pos += len;
    out = v;
    return true;
}

} // namespace

// the first long-header packet must be complete: connection ids, token and
// length fields inside the datagram, a version-negotiation list of whole
// 32-bit entries. a truncated or partially retained datagram proves nothing.
bool quic_response_valid(const UdpResult& u) {
    if (!u.responded || u.echoed || !u.err.empty() || u.reply.empty() ||
        u.bytes < 0 || static_cast<size_t>(u.bytes) != u.reply.size()) return false;
    const std::vector<uint8_t>& d = u.reply;
    // a short-header (1-rtt) packet can't answer an Initial for a connection
    // that doesn't exist yet.
    if (!(d[0] & 0x80) || d.size() < 7) return false;
    const uint32_t version = (uint32_t(d[1]) << 24) | (uint32_t(d[2]) << 16) |
                             (uint32_t(d[3]) << 8) | uint32_t(d[4]);
    size_t pos = 5;
    const size_t dcid_len = d[pos++];
    if (d.size() - pos < dcid_len) return false;
    const size_t dcid_at = pos;
    pos += dcid_len;
    if (pos >= d.size()) return false;
    const size_t scid_len = d[pos++];
    if (d.size() - pos < scid_len) return false;
    pos += scid_len;
    // a peer answers to the source connection id we chose; random bytes that
    // happen to parse as a long header don't carry it.
    if (!u.expect_dcid.empty() &&
        (dcid_len != u.expect_dcid.size() ||
         !std::equal(u.expect_dcid.begin(), u.expect_dcid.end(), d.begin() + dcid_at)))
        return false;
    if (version == 0) {                       // version negotiation (rfc 8999)
        const size_t rest = d.size() - pos;
        return rest >= 4 && rest % 4 == 0;
    }
    // our probes speak v1; v1 long headers carry the fixed bit and cids <= 20.
    if (version != 1 || !(d[0] & 0x40) || dcid_len > 20 || scid_len > 20) return false;
    uint64_t token = 0, length = 0;
    switch ((d[0] & 0x30) >> 4) {
        case 0:                               // initial: token, then length
            if (!read_varint(d, pos, token) || d.size() - pos < token) return false;
            pos += static_cast<size_t>(token);
            if (!read_varint(d, pos, length)) return false;
            return length <= d.size() - pos;
        case 2:                               // handshake: length only
            if (!read_varint(d, pos, length)) return false;
            return length <= d.size() - pos;
        case 3:                               // retry: nonempty token + 16-byte tag
            return d.size() - pos > 16;
        default:                              // 0-RTT is client-only
            return false;
    }
}
