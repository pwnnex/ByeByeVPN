// SPDX-License-Identifier: GPL-3.0-or-later
#include "awg_entropy.h"
#include "capture.h"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <limits>
#include <locale>
#include <set>
#include <sstream>
#include <stdexcept>

namespace {
constexpr size_t MAX_PACKETS = 200000, MAX_FLOWS = 4096;
uint16_t u16(const uint8_t* p, bool le) {
    return le ? uint16_t(p[0] | (unsigned(p[1])<<8)) : uint16_t((unsigned(p[0])<<8)|p[1]);
}
std::string address(const uint8_t* p, bool v6, uint16_t port) {
    std::ostringstream s;
    s.imbue(std::locale::classic());
    if (v6) {
        s << '[' << std::hex;
        for (int i=0;i<8;++i) { if (i) s << ':'; s << u16(p+2*i,false); }
        s << ']' << std::dec;
    } else {
        for (int i=0;i<4;++i) { if (i) s << '.'; s << unsigned(p[i]); }
    }
    s << ':' << port;
    return s.str();
}
struct Reader {
    AwgCapture out;
    std::set<std::string> flows;
    void packet(const uint8_t* p, size_t n, uint32_t link, uint64_t ns, const std::string& scope) {
        ++out.records;
        // skip non-udp, fragments and truncated packets
        // partial ciphertext can't give us reliable entropy
        auto decode = [&]() -> bool {
            size_t off = 0;
            uint16_t proto = 0;
            if (link == 1) {
                if (n<14) return false;
                proto=u16(p+12,false); off=14;
                for (int tags=0; proto==0x8100 || proto==0x88a8 || proto==0x9100; ++tags) {
                    if (tags>=4 || n-off<4) return false;
                    proto=u16(p+off+2,false); off+=4;
                }
            } else if (link==113 || link==276) {
                off=link==113 ? 16 : 20;
                if (n<off) return false;
                proto=u16(p+(link==113 ? 14 : 0),false);
            } else {
                if (link==0 || link==108) off=4;
                if (n<=off) return false;
                proto=(p[off]>>4)==4 ? 0x0800 : (p[off]>>4)==6 ? 0x86dd : 0;
            }
            if (n<=off) return false;
            const uint8_t* ip=p+off;
            size_t left=n-off, udp=0, end=0;
            const uint8_t *src=nullptr, *dst=nullptr;
            bool v6=false;
            if (proto==0x0800) {
                if (left<20 || (ip[0]>>4)!=4) return false;
                udp=size_t(ip[0]&15)*4;
                end=u16(ip+2,false);
                if (udp<20 || end<udp || end>left || ip[9]!=17 || (u16(ip+6,false)&0x3fff)) return false;
                src=ip+12; dst=ip+16;
            } else if (proto==0x86dd) {
                if (left<40 || (ip[0]>>4)!=6) return false;
                v6=true;
                end=40+u16(ip+4,false);
                if (end>left || end==40) return false; // jumbograms unsupported
                src=ip+8; dst=ip+24; udp=40;
                uint8_t next=ip[6];
                for (int count=0; next!=17; ++count) {
                    if (count>=8 || udp>end || end-udp<2) return false;
                    if (next!=0 && next!=43 && next!=60 && next!=51) return false; // includes fragments
                    size_t len=next==51 ? (size_t(ip[udp+1])+2)*4 : (size_t(ip[udp+1])+1)*8;
                    if (len>end-udp) return false;
                    next=ip[udp]; udp+=len;
                }
            } else return false;
            if (udp>end || end-udp<8) return false;
            size_t length=u16(ip+udp+4,false);
            if (length<8 || length!=end-udp) return false;
            auto o=awg_observe(ip+udp+8,length-8);
            o.src=address(src,v6,u16(ip+udp,false));
            o.dst=address(dst,v6,u16(ip+udp+2,false));
            o.time_ns=ns; o.scope=scope;
            auto ends=std::minmax(o.src,o.dst);
            flows.insert(scope+"/"+ends.first+"/"+ends.second);
            if (flows.size()>MAX_FLOWS || out.packets.size()>=MAX_PACKETS)
                throw std::runtime_error("capture exceeds 4096 flows or 200000 UDP packets; split the capture");
            out.packets.push_back(std::move(o));
            return true;
        };
        if (!decode()) ++out.skipped;
    }
};
std::string quote(const std::string& s) {
    std::string out="\"";
    for (unsigned char c:s) {
        if (c=='"' || c=='\\') out+='\\';
        if (c<32) { const char* h="0123456789abcdef"; out+="\\u00"; out+=h[c>>4]; out+=h[c&15]; }
        else out+=char(c);
    }
    return out+'"';
}
}

AwgCapture awg_read_capture(const std::vector<uint8_t>& bytes) {
    Reader r;
    size_t records = 0, skipped = 0;
    try {
        capture_walk(bytes, [&](const uint8_t* p, size_t n, uint32_t link, uint64_t ns, const std::string& scope) {
            r.packet(p, n, link, ns, scope);
        }, records, skipped);
        r.out.ok=true;
    } catch (const std::exception& e) {
        r.out.error=e.what(); r.out.packets.clear();
    }
    // the walker counts container records, the reader the frames it decoded
    r.out.records=records;
    r.out.skipped+=skipped;
    return r.out;
}

AwgCapture awg_read_capture_file(const std::string& path) {
    AwgCapture error;
    std::vector<uint8_t> bytes;
    if (!capture_read_file(path, bytes, error.error)) return error;
    return awg_read_capture(bytes);
}
std::string awg_capture_json(const AwgCapture& c,const std::vector<AwgFlow>& flows) {
    std::ostringstream s;
    s.imbue(std::locale::classic()); s << std::fixed << std::setprecision(4);
    s << "{\"ok\":" << (c.ok ? "true" : "false") << ",\"error\":" << quote(c.error)
      << ",\"mode\":\"awg-entropy\",\"protocol_confirmed\":false,\"records\":" << c.records
      << ",\"skipped_records\":" << c.skipped << ",\"udp_packets\":" << c.packets.size() << ",\"flows\":[";
    for (size_t i=0;i<flows.size();++i) {
        const auto& f=flows[i]; if (i) s << ',';
        s << "{\"a\":" << quote(f.endpoint_a) << ",\"b\":" << quote(f.endpoint_b) << ",\"scope\":" << quote(f.scope)
          << ",\"verdict\":" << quote(f.verdict) << ",\"awg_version\":" << quote(f.version)
          << ",\"packets\":" << f.packets << ",\"a_to_b\":" << f.a_to_b << ",\"b_to_a\":" << f.b_to_a
          << ",\"sampled_packets\":" << f.sampled << ",\"random_like_packets\":" << f.random_packets
          << ",\"mean_byte_entropy\":" << f.mean_byte_entropy << ",\"mean_nibble_entropy\":" << f.mean_nibble_entropy
          << ",\"candidate_bursts\":" << f.candidate_bursts << ",\"competing_protocol\":" << (f.competing_protocol ? "true" : "false")
          << ",\"evidence\":[";
        for (size_t j=0;j<f.evidence.size();++j) { if(j) s << ','; s << quote(f.evidence[j]); }
        s << "]}";
    }
    s << "]}\n";
    return s.str();
}
