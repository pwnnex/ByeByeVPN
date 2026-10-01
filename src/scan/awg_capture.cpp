// SPDX-License-Identifier: GPL-3.0-or-later
#include "awg_entropy.h"
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
constexpr size_t MAX_FILE = 64*1024*1024, MAX_PACKETS = 200000, MAX_FLOWS = 4096;
uint16_t u16(const uint8_t* p, bool le) {
    return le ? uint16_t(p[0] | (unsigned(p[1])<<8)) : uint16_t((unsigned(p[0])<<8)|p[1]);
}
uint32_t u32(const uint8_t* p, bool le) {
    return le ? uint32_t(u16(p,true)) | (uint32_t(u16(p+2,true))<<16)
              : (uint32_t(u16(p,false))<<16) | u16(p+2,false);
}
bool link_supported(uint32_t link) {
    return link==1 || link==101 || link==228 || link==229 || link==113 || link==276 || link==0 || link==108;
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
struct Interface {
    uint32_t link=0, snap=0;
    long double ns_per_tick=1000, offset_seconds=0;
};
void require(bool yes,const char* error) { if (!yes) throw std::runtime_error(error); }
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
    try {
        require(bytes.size()<=MAX_FILE,"capture exceeds 64 MiB; split the capture");
        require(bytes.size()>=4,"truncated capture header");
        const uint8_t* d=bytes.data();
        uint32_t magic=u32(d,true);
        if (magic!=0x0a0d0d0a) {
            bool le=magic==0xa1b2c3d4 || magic==0xa1b23c4d;
            bool nano=magic==0xa1b23c4d || magic==0x4d3cb2a1;
            require(le || magic==0xd4c3b2a1 || magic==0x4d3cb2a1,"not PCAP/PCAPNG");
            require(bytes.size()>=24,"truncated PCAP header");
            require(u16(d+4,le)==2 && u16(d+6,le)==4,"unsupported PCAP version");
            uint32_t snap=u32(d+16,le), link=u32(d+20,le)&0xffff;
            require(link_supported(link),"unsupported PCAP link type");
            size_t pos=24;
            while (pos<bytes.size()) {
                require(bytes.size()-pos>=16,"truncated PCAP record");
                const uint8_t* h=d+pos;
                uint32_t sec=u32(h,le), frac=u32(h+4,le), cap=u32(h+8,le), wire=u32(h+12,le);
                pos+=16;
                require(frac<(nano ? 1000000000U : 1000000U),"invalid PCAP timestamp fraction");
                require(cap<=wire && cap<=snap && cap<=bytes.size()-pos,"invalid/truncated PCAP packet length");
                r.packet(d+pos,cap,link,uint64_t(sec)*1000000000ULL+uint64_t(frac)*(nano ? 1 : 1000),"0:0");
                pos+=cap;
            }
        } else {
            size_t pos=0, section=0;
            bool le=true, have_section=false;
            std::vector<Interface> interfaces;
            while (pos<bytes.size()) {
                require(bytes.size()-pos>=12,"truncated PCAPNG block");
                const uint8_t* h=d+pos;
                bool shb=u32(h,true)==0x0a0d0d0a;
                if (shb) {
                    uint32_t bom=u32(h+8,true);
                    require(bom==0x1a2b3c4d || bom==0x4d3c2b1a,"invalid PCAPNG byte-order magic");
                    le=bom==0x1a2b3c4d;
                }
                uint32_t type=u32(h,le), len=u32(h+4,le);
                require(len>=12 && len%4==0 && len<=bytes.size()-pos,"invalid/truncated PCAPNG block length");
                require(u32(h+len-4,le)==len,"PCAPNG block trailer length mismatch");
                if (shb) {
                    require(len>=28 && u16(h+12,le)==1,"unsupported PCAPNG section");
                    if (have_section) ++section;
                    have_section=true; interfaces.clear();
                } else {
                    require(have_section,"PCAPNG block before section");
                    if (type==1) {
                        require(len>=20 && interfaces.size()<1024,"invalid/too many PCAPNG interfaces");
                        Interface in;
                        in.link=u16(h+8,le); in.snap=u32(h+12,le);
                        size_t opt=16;
                        while (opt<len-4) {
                            require(len-4-opt>=4,"truncated PCAPNG option");
                            uint16_t code=u16(h+opt,le), sz=u16(h+opt+2,le); opt+=4;
                            require(size_t(sz)<=len-4-opt,"invalid PCAPNG option size");
                            if (!code) { require(!sz,"invalid end-of-options"); break; }
                            if (code==9) {
                                require(sz==1,"invalid if_tsresol");
                                unsigned v=h[opt];
                                in.ns_per_tick=1e9L/std::pow(v&128 ? 2.0L : 10.0L,int(v&127));
                            } else if (code==14) {
                                require(sz==8,"invalid if_tsoffset");
                                uint64_t v=le ? uint64_t(u32(h+opt,true)) | (uint64_t(u32(h+opt+4,true))<<32)
                                              : (uint64_t(u32(h+opt,false))<<32) | u32(h+opt+4,false);
                                in.offset_seconds=(v>>63) ? -static_cast<long double>((~v)+1) : static_cast<long double>(v);
                            }
                            size_t padded=(size_t(sz)+3)&~size_t(3);
                            require(padded<=len-4-opt,"truncated PCAPNG option padding"); opt+=padded;
                        }
                        interfaces.push_back(in);
                    } else if (type==6) {
                        require(len>=32,"short PCAPNG enhanced packet");
                        uint32_t idx=u32(h+8,le), cap=u32(h+20,le), wire=u32(h+24,le);
                        require(idx<interfaces.size(),"PCAPNG unknown interface");
                        auto in=interfaces[idx];
                        require(cap<=wire && (!in.snap || cap<=in.snap) && cap<=len-32,"invalid PCAPNG packet length");
                        require(((size_t(cap)+3)&~size_t(3))<=len-32,"invalid PCAPNG packet padding");
                        uint64_t ticks=(uint64_t(u32(h+12,le))<<32)|u32(h+16,le);
                        long double ns=static_cast<long double>(ticks)*in.ns_per_tick+in.offset_seconds*1e9L;
                        require(std::isfinite(ns) && ns>=0 && ns<18446744073709551616.0L,"PCAPNG timestamp out of range");
                        if (link_supported(in.link)) r.packet(h+28,cap,in.link,uint64_t(ns),std::to_string(section)+":"+std::to_string(idx));
                        else { ++r.out.records; ++r.out.skipped; }
                    } else if (type==3 || type==2) { // timestamp-less / obsolete packets
                        ++r.out.records; ++r.out.skipped;
                    }
                }
                pos+=len;
            }
        }
        r.out.ok=true;
    } catch (const std::exception& e) {
        r.out.error=e.what(); r.out.packets.clear();
    }
    return r.out;
}

AwgCapture awg_read_capture_file(const std::string& path) {
    AwgCapture error;
    std::ifstream f(path,std::ios::binary|std::ios::ate);
    if (!f) { error.error="cannot open capture"; return error; }
    auto size=f.tellg();
    if (size<0 || size>std::streamoff(MAX_FILE)) { error.error="capture exceeds 64 MiB or size unavailable"; return error; }
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    f.seekg(0);
    if (!f.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()))) {
        error.error="cannot read complete capture"; return error;
    }
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
