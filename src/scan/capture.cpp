// SPDX-License-Identifier: GPL-3.0-or-later
#include "capture.h"

#include <cmath>
#include <fstream>
#include <locale>
#include <sstream>
#include <stdexcept>

namespace {

uint16_t u16(const uint8_t* p, bool le) {
    return le ? uint16_t(p[0] | (unsigned(p[1]) << 8)) : uint16_t((unsigned(p[0]) << 8) | p[1]);
}
uint32_t u32(const uint8_t* p, bool le) {
    return le ? uint32_t(u16(p, true)) | (uint32_t(u16(p + 2, true)) << 16)
              : (uint32_t(u16(p, false)) << 16) | u16(p + 2, false);
}
bool link_supported(uint32_t link) {
    return link == 1 || link == 101 || link == 228 || link == 229 || link == 113 || link == 276 || link == 0 || link == 108;
}
void require(bool yes, const char* error) { if (!yes) throw std::runtime_error(error); }

struct Interface {
    uint32_t link = 0, snap = 0;
    long double ns_per_tick = 1000, offset_seconds = 0;
};

std::string ip_text(const uint8_t* p, bool v6) {
    std::ostringstream s;
    s.imbue(std::locale::classic());
    if (v6) {
        s << '[' << std::hex;
        for (size_t i = 0; i < 8; ++i) { if (i) s << ':'; s << u16(p + 2 * i, false); }
        s << ']';
    } else {
        for (size_t i = 0; i < 4; ++i) { if (i) s << '.'; s << unsigned(p[i]); }
    }
    return s.str();
}

} // namespace

void capture_walk(const std::vector<uint8_t>& bytes, const FrameFn& frame, size_t& records, size_t& skipped) {
    require(bytes.size() <= CAPTURE_MAX_FILE, "capture exceeds 64 MiB; split the capture");
    require(bytes.size() >= 4, "truncated capture header");
    const uint8_t* d = bytes.data();
    uint32_t magic = u32(d, true);
    if (magic != 0x0a0d0d0a) {
        bool le = magic == 0xa1b2c3d4 || magic == 0xa1b23c4d;
        bool nano = magic == 0xa1b23c4d || magic == 0x4d3cb2a1;
        require(le || magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1, "not PCAP/PCAPNG");
        require(bytes.size() >= 24, "truncated PCAP header");
        require(u16(d + 4, le) == 2 && u16(d + 6, le) == 4, "unsupported PCAP version");
        uint32_t snap = u32(d + 16, le), link = u32(d + 20, le) & 0xffff;
        require(link_supported(link), "unsupported PCAP link type");
        size_t pos = 24;
        while (pos < bytes.size()) {
            require(bytes.size() - pos >= 16, "truncated PCAP record");
            const uint8_t* h = d + pos;
            uint32_t sec = u32(h, le), frac = u32(h + 4, le), cap = u32(h + 8, le), wire = u32(h + 12, le);
            pos += 16;
            require(frac < (nano ? 1000000000U : 1000000U), "invalid PCAP timestamp fraction");
            require(cap <= wire && cap <= snap && cap <= bytes.size() - pos, "invalid/truncated PCAP packet length");
            ++records;
            frame(d + pos, cap, link, uint64_t(sec) * 1000000000ULL + uint64_t(frac) * (nano ? 1 : 1000), "0:0");
            pos += cap;
        }
        return;
    }
    size_t pos = 0, section = 0;
    bool le = true, have_section = false;
    std::vector<Interface> interfaces;
    while (pos < bytes.size()) {
        require(bytes.size() - pos >= 12, "truncated PCAPNG block");
        const uint8_t* h = d + pos;
        bool shb = u32(h, true) == 0x0a0d0d0a;
        if (shb) {
            uint32_t bom = u32(h + 8, true);
            require(bom == 0x1a2b3c4d || bom == 0x4d3c2b1a, "invalid PCAPNG byte-order magic");
            le = bom == 0x1a2b3c4d;
        }
        uint32_t type = u32(h, le), len = u32(h + 4, le);
        require(len >= 12 && len % 4 == 0 && len <= bytes.size() - pos, "invalid/truncated PCAPNG block length");
        require(u32(h + len - 4, le) == len, "PCAPNG block trailer length mismatch");
        if (shb) {
            require(len >= 28 && u16(h + 12, le) == 1, "unsupported PCAPNG section");
            if (have_section) ++section;
            have_section = true;
            interfaces.clear();
        } else {
            require(have_section, "PCAPNG block before section");
            if (type == 1) {
                require(len >= 20 && interfaces.size() < 1024, "invalid/too many PCAPNG interfaces");
                Interface in;
                in.link = u16(h + 8, le);
                in.snap = u32(h + 12, le);
                size_t opt = 16;
                while (opt < len - 4) {
                    require(len - 4 - opt >= 4, "truncated PCAPNG option");
                    uint16_t code = u16(h + opt, le), sz = u16(h + opt + 2, le);
                    opt += 4;
                    require(size_t(sz) <= len - 4 - opt, "invalid PCAPNG option size");
                    if (!code) { require(!sz, "invalid end-of-options"); break; }
                    if (code == 9) {
                        require(sz == 1, "invalid if_tsresol");
                        unsigned v = h[opt];
                        in.ns_per_tick = 1e9L / std::pow(v & 128 ? 2.0L : 10.0L, int(v & 127));
                    } else if (code == 14) {
                        require(sz == 8, "invalid if_tsoffset");
                        uint64_t v = le ? uint64_t(u32(h + opt, true)) | (uint64_t(u32(h + opt + 4, true)) << 32)
                                        : (uint64_t(u32(h + opt, false)) << 32) | u32(h + opt + 4, false);
                        in.offset_seconds = (v >> 63) ? -static_cast<long double>((~v) + 1) : static_cast<long double>(v);
                    }
                    size_t padded = (size_t(sz) + 3) & ~size_t(3);
                    require(padded <= len - 4 - opt, "truncated PCAPNG option padding");
                    opt += padded;
                }
                interfaces.push_back(in);
            } else if (type == 6) {
                require(len >= 32, "short PCAPNG enhanced packet");
                uint32_t idx = u32(h + 8, le), cap = u32(h + 20, le), wire = u32(h + 24, le);
                require(idx < interfaces.size(), "PCAPNG unknown interface");
                auto in = interfaces[idx];
                require(cap <= wire && (!in.snap || cap <= in.snap) && cap <= len - 32, "invalid PCAPNG packet length");
                require(((size_t(cap) + 3) & ~size_t(3)) <= len - 32, "invalid PCAPNG packet padding");
                uint64_t ticks = (uint64_t(u32(h + 12, le)) << 32) | u32(h + 16, le);
                long double ns = static_cast<long double>(ticks) * in.ns_per_tick + in.offset_seconds * 1e9L;
                require(std::isfinite(ns) && ns >= 0 && ns < 18446744073709551616.0L, "PCAPNG timestamp out of range");
                ++records;
                if (link_supported(in.link)) frame(h + 28, cap, in.link, uint64_t(ns), std::to_string(section) + ":" + std::to_string(idx));
                else ++skipped;
            } else if (type == 3 || type == 2) {
                // timestamp-less or obsolete packet blocks
                ++records;
                ++skipped;
            }
        }
        pos += len;
    }
}

bool capture_read_file(const std::string& path, std::vector<uint8_t>& bytes, std::string& error) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) { error = "cannot open capture"; return false; }
    auto size = f.tellg();
    if (size < 0 || size > std::streamoff(CAPTURE_MAX_FILE)) { error = "capture exceeds 64 MiB or size unavailable"; return false; }
    bytes.resize(static_cast<size_t>(size));
    f.seekg(0);
    if (!f.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
        error = "cannot read complete capture";
        return false;
    }
    return true;
}

bool capture_decode(const uint8_t* p, size_t n, uint32_t link, Decoded& out) {
    size_t off = 0;
    uint16_t proto = 0;
    if (link == 1) {
        if (n < 14) return false;
        proto = u16(p + 12, false);
        off = 14;
        for (int tags = 0; proto == 0x8100 || proto == 0x88a8 || proto == 0x9100; ++tags) {
            if (tags >= 4 || n - off < 4) return false;
            proto = u16(p + off + 2, false);
            off += 4;
        }
    } else if (link == 113 || link == 276) {
        off = link == 113 ? 16 : 20;
        if (n < off) return false;
        proto = u16(p + (link == 113 ? 14 : 0), false);
    } else {
        if (link == 0 || link == 108) off = 4;
        if (n <= off) return false;
        proto = (p[off] >> 4) == 4 ? 0x0800 : (p[off] >> 4) == 6 ? 0x86dd : 0;
    }
    if (n <= off) return false;
    const uint8_t* ip = p + off;
    size_t left = n - off, l4 = 0, end = 0;
    uint8_t next = 0;
    bool v6 = false;
    const uint8_t *src = nullptr, *dst = nullptr;
    if (proto == 0x0800) {
        if (left < 20 || (ip[0] >> 4) != 4) return false;
        l4 = size_t(ip[0] & 15) * 4;
        end = u16(ip + 2, false);
        // fragments carry no complete header after the first
        if (l4 < 20 || end < l4 || end > left || (u16(ip + 6, false) & 0x3fff)) return false;
        next = ip[9];
        src = ip + 12;
        dst = ip + 16;
    } else if (proto == 0x86dd) {
        if (left < 40 || (ip[0] >> 4) != 6) return false;
        v6 = true;
        end = 40 + u16(ip + 4, false);
        if (end > left || end == 40) return false;
        src = ip + 8;
        dst = ip + 24;
        l4 = 40;
        next = ip[6];
        for (int count = 0; next != 6 && next != 17; ++count) {
            if (count >= 8 || l4 > end || end - l4 < 2) return false;
            if (next != 0 && next != 43 && next != 60 && next != 51) return false;
            size_t len = next == 51 ? (size_t(ip[l4 + 1]) + 2) * 4 : (size_t(ip[l4 + 1]) + 1) * 8;
            if (len > end - l4) return false;
            next = ip[l4];
            l4 += len;
        }
    } else {
        return false;
    }
    if (l4 > end) return false;
    const uint8_t* t = ip + l4;
    size_t tl = end - l4;
    out.src = ip_text(src, v6);
    out.dst = ip_text(dst, v6);
    if (next == 17) {
        if (tl < 8) return false;
        size_t length = u16(t + 4, false);
        if (length < 8 || length != tl) return false;
        out.proto = 17;
        out.sport = u16(t, false);
        out.dport = u16(t + 2, false);
        out.payload.assign(t + 8, t + length);
        return true;
    }
    if (next == 6) {
        if (tl < 20) return false;
        size_t hl = size_t(t[12] >> 4) * 4;
        if (hl < 20 || hl > tl) return false;
        out.proto = 6;
        out.sport = u16(t, false);
        out.dport = u16(t + 2, false);
        out.seq = u32(t + 4, false);
        out.flags = t[13];
        out.payload.assign(t + hl, t + tl);
        return true;
    }
    return false;
}
