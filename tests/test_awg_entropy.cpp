// SPDX-License-Identifier: GPL-3.0-or-later
#include "doctest.h"
#include "../src/scan/awg_entropy.h"
#include <algorithm>
#include <cmath>
#include <random>

namespace {
using Bytes=std::vector<uint8_t>;
Bytes random_bytes(size_t n) {
    static std::mt19937 rng(20260828);
    Bytes b(n); for (auto& c:b) c=uint8_t(rng()); return b;
}
AwgPacket observation(uint64_t ms, bool reverse, size_t len=256) {
    auto b=random_bytes(len);
    auto p=awg_observe(b.data(),b.size());
    p.time_ns=ms*1000000;
    p.src=reverse ? "203.0.113.1:443" : "192.0.2.1:1234";
    p.dst=reverse ? "192.0.2.1:1234" : "203.0.113.1:443";
    p.scope="0:0";
    return p;
}
std::vector<AwgPacket> sessions(bool variable=true) {
    std::vector<AwgPacket> ps;
    for (uint64_t base : {0,20000}) {
        // awg's i-chain + jc + initiation is one outbound train. lengths
        // vary, including the last packet (3.1 random trailers).
        for (size_t i=0;i<5;++i) ps.push_back(observation(base+i,false,variable ? 220+i*113+base/100 : 256));
        for (uint64_t j=0;j<14;++j) ps.push_back(observation(base+30+j*20,j%2==0,200+size_t(j*23)));
    }
    return ps;
}
void put(Bytes& b,uint32_t v,size_t n,bool le=true) {
    for (size_t i=0;i<n;++i) b.push_back(uint8_t(v>>(8*(le ? i : n-1-i))));
}
Bytes frame(bool ipv6=false) {
    Bytes payload=random_bytes(180), b(14,0);
    b[12]=ipv6 ? 0x86 : 8; b[13]=ipv6 ? 0xdd : 0;
    Bytes ip(ipv6 ? 40 : 20,0);
    ip[0]=ipv6 ? 0x60 : 0x45;
    if (ipv6) { ip[5]=188; ip[6]=17; ip[8]=0x20; ip[9]=1; ip[23]=1; ip[24]=0x20; ip[25]=1; ip[39]=2; }
    else { ip[3]=208; ip[9]=17; ip[12]=192; ip[14]=2; ip[15]=1; ip[16]=203; ip[18]=113; ip[19]=1; }
    b.insert(b.end(),ip.begin(),ip.end());
    put(b,1234,2,false); put(b,443,2,false); put(b,188,2,false); put(b,0,2,false);
    b.insert(b.end(),payload.begin(),payload.end()); return b;
}
Bytes pcap(const Bytes& packet,bool le=true,bool nano=false,uint32_t link=1) {
    Bytes b;
    put(b,nano ? 0xa1b23c4d : 0xa1b2c3d4,4,le);
    put(b,2,2,le); put(b,4,2,le); put(b,0,4,le); put(b,0,4,le);
    put(b,65535,4,le); put(b,link,4,le);
    put(b,1,4,le); put(b,123,4,le); put(b,uint32_t(packet.size()),4,le); put(b,uint32_t(packet.size()),4,le);
    b.insert(b.end(),packet.begin(),packet.end()); return b;
}
void block(Bytes& b,uint32_t type,Bytes body,bool le=true) {
    while (body.size()%4) body.push_back(0);
    put(b,type,4,le); put(b,uint32_t(body.size()+12),4,le);
    b.insert(b.end(),body.begin(),body.end()); put(b,uint32_t(body.size()+12),4,le);
}
Bytes pcapng(const Bytes& packet,bool le=true,uint8_t resolution=9) {
    Bytes b,body;
    put(body,0x1a2b3c4d,4,le); put(body,1,2,le); put(body,0,2,le);
    put(body,0xffffffff,4,le); put(body,0xffffffff,4,le); block(b,0x0a0d0d0a,body,le);
    body.clear(); put(body,1,2,le); put(body,0,2,le); put(body,65535,4,le);
    put(body,9,2,le); put(body,1,2,le); body.push_back(resolution); body.insert(body.end(),3,0);
    put(body,0,4,le); block(b,1,body,le);
    body.clear(); put(body,0,4,le); put(body,0,4,le); put(body,1000000,4,le);
    put(body,uint32_t(packet.size()),4,le); put(body,uint32_t(packet.size()),4,le);
    body.insert(body.end(),packet.begin(),packet.end()); block(b,6,body,le); return b;
}
}

TEST_CASE("AWG entropy is descriptive and guarded for small samples") {
    auto b=random_bytes(1024);
    CHECK(awg_observe(b.data(),b.size()).random_like);
    b.assign(1024,0); CHECK_FALSE(awg_observe(b.data(),b.size()).random_like);
    CHECK(awg_observe(nullptr,0).byte_entropy == 0);
    b=random_bytes(32); CHECK_FALSE(awg_observe(b.data(),b.size()).random_like);
    b.assign(1024,'A'); CHECK(awg_observe(b.data(),b.size()).nibble_entropy < 2);
}
TEST_CASE("AWG compatible trains are heuristic, version remains unknown") {
    auto flows=awg_analyze(sessions());
    REQUIRE(flows.size()==1);
    CHECK(flows[0].candidate_bursts==2);
    CHECK(flows[0].verdict=="AWG_COMPATIBLE_HEURISTIC");
    CHECK(flows[0].version=="unknown");
    auto ps=sessions(); ps.resize(19);
    CHECK(awg_analyze(ps)[0].verdict=="ENCRYPTED_UDP_INCONCLUSIVE");
    CHECK(awg_analyze(sessions(false))[0].candidate_bursts==0);
}
TEST_CASE("Entropy alone and unidirectional junk never identify AWG") {
    std::vector<AwgPacket> ps;
    for (uint64_t i=0;i<80;++i) ps.push_back(observation(i*20,i%2==0));
    CHECK(awg_analyze(ps)[0].verdict=="ENCRYPTED_UDP_INCONCLUSIVE");
    for (auto& p:ps) { p.src="a";p.dst="b"; }
    CHECK(awg_analyze(ps)[0].verdict=="INSUFFICIENT_DATA");
}
TEST_CASE("A lone QUIC-shaped CPS decoy does not suppress, bidirectional framing does") {
    auto ps=sessions();
    ps[0].marker=AwgPacket::Marker::QuicLong;
    CHECK(awg_analyze(ps)[0].verdict=="AWG_COMPATIBLE_HEURISTIC");
    ps[1].marker=AwgPacket::Marker::QuicLong;
    ps[5].marker=AwgPacket::Marker::QuicLong;
    CHECK(awg_analyze(ps)[0].verdict=="OTHER_PROTOCOL_HINT");
}
TEST_CASE("Capture interfaces and UDP conversations are never pooled") {
    auto ps=sessions();
    for(size_t i=19;i<ps.size();++i) ps[i].scope="0:1";
    auto fs=awg_analyze(ps); REQUIRE(fs.size()==2);
    for(const auto& f:fs) CHECK(f.verdict=="ENCRYPTED_UDP_INCONCLUSIVE");
    std::reverse(ps.begin(),ps.end());
    CHECK(awg_analyze(ps)[0].candidate_bursts==1);
}
TEST_CASE("Classic PCAP byte order timestamp units IPv4 and IPv6") {
    for(bool le:{true,false}) for(bool nano:{true,false}) for(bool v6:{true,false}) {
        auto c=awg_read_capture(pcap(frame(v6),le,nano));
        REQUIRE(c.ok); REQUIRE(c.packets.size()==1);
        CHECK(c.packets[0].payload_size==180);
        CHECK(c.packets[0].time_ns==(nano ? 1000000123ULL : 1000123000ULL));
    }
}
TEST_CASE("PCAPNG section endian timestamps and interface separation") {
    for(bool le:{true,false}) {
        auto c=awg_read_capture(pcapng(frame(),le));
        REQUIRE(c.ok); REQUIRE(c.packets.size()==1);
        CHECK(c.packets[0].time_ns==1000000);
    }
    auto b=pcapng(frame(),true);auto other=pcapng(frame(true),false);
    b.insert(b.end(),other.begin(),other.end());
    auto c=awg_read_capture(b); REQUIRE(c.ok); REQUIRE(c.packets.size()==2);
    CHECK(c.packets[0].scope!=c.packets[1].scope);
    c=awg_read_capture(pcapng(frame(),true,0x80|10));
    REQUIRE(c.ok); CHECK(c.packets[0].time_ns==976562500000ULL);
}
TEST_CASE("Fragments and payload truncation cannot create entropy evidence") {
    auto b=frame();b[14+6]=0x20;
    auto c=awg_read_capture(pcap(b));REQUIRE(c.ok);CHECK(c.packets.empty());CHECK(c.skipped==1);
    b=frame();b.pop_back();c=awg_read_capture(pcap(b));REQUIRE(c.ok);CHECK(c.packets.empty());
}
TEST_CASE("Malformed capture bounds fail without returning partial observations") {
    auto b=pcap(frame());b.pop_back();CHECK_FALSE(awg_read_capture(b).ok);
    b=pcapng(frame());b.back()=1;CHECK_FALSE(awg_read_capture(b).ok);
    b=pcapng(frame());b[4]=0;CHECK_FALSE(awg_read_capture(b).ok);
    b=pcap(frame());b[32]=255;b[33]=255;b[34]=255;b[35]=127;
    CHECK_FALSE(awg_read_capture(b).ok);
    CHECK_FALSE(awg_read_capture(Bytes{}).ok);
    CHECK_FALSE(awg_read_capture(pcap(frame(),true,false,999)).ok);
    auto valid=pcap(frame());valid.push_back(0);
    auto c=awg_read_capture(valid);CHECK_FALSE(c.ok);CHECK(c.packets.empty());
}
TEST_CASE("AWG JSON contains evidence and no authentication claim") {
    AwgCapture c;c.ok=true;c.packets=sessions();
    auto json=awg_capture_json(c,awg_analyze(c.packets));
    CHECK(json.find("\"protocol_confirmed\":false")!=std::string::npos);
    CHECK(json.find("AWG_COMPATIBLE_HEURISTIC")!=std::string::npos);
    CHECK(json.find("\"awg_version\":\"unknown\"")!=std::string::npos);
}

TEST_CASE("Competing protocol hints inspect bytes rather than ports") {
    using M=AwgPacket::Marker;
    auto b=random_bytes(148);b[0]=1;b[1]=b[2]=b[3]=0;
    CHECK(awg_observe(b.data(),b.size()).marker==M::WireGuard);
    b.assign(80,0);b[0]=0xc0;b[4]=1;b[5]=8;b[14]=8;
    CHECK(awg_observe(b.data(),b.size()).marker==M::QuicLong);
    b[5]=255;CHECK(awg_observe(b.data(),b.size()).marker!=M::QuicLong);
    b.assign(33,0);b[0]=23;b[1]=0xfe;b[2]=0xfd;b[12]=20;
    CHECK(awg_observe(b.data(),b.size()).marker==M::Dtls);
    b.assign(20,0);b[4]=0x21;b[5]=0x12;b[6]=0xa4;b[7]=0x42;
    CHECK(awg_observe(b.data(),b.size()).marker==M::Stun);
    b.assign(19,0);b[5]=1;b[12]=1;b[13]='a';b[16]=1;b[18]=1;
    CHECK(awg_observe(b.data(),b.size()).marker==M::Dns);
}
TEST_CASE("Ethernet VLAN raw IP SLL SLL2 and loopback captures") {
    auto eth=frame();Bytes raw(eth.begin()+14,eth.end());
    auto vlan=eth;vlan[12]=0x81;vlan[13]=0;vlan.insert(vlan.begin()+14,{0,1,8,0});
    REQUIRE(awg_read_capture(pcap(vlan)).packets.size()==1);
    REQUIRE(awg_read_capture(pcap(raw,true,false,101)).packets.size()==1);
    for(auto link:{113,276,0,108}) {
        Bytes header(link==113 ? 16 : link==276 ? 20 : 4,0);
        if(link==113) header[14]=8;
        if(link==276) header[0]=8;
        if(link==0) header[0]=2;
        if(link==108) header[3]=2;
        header.insert(header.end(),raw.begin(),raw.end());
        REQUIRE(awg_read_capture(pcap(header,true,false,uint32_t(link))).packets.size()==1);
    }
}
TEST_CASE("IPv6 extension headers walked but fragmented IPv6 skipped") {
    auto b=frame(true);
    b[14+6]=0; b[14+5]=196;
    b.insert(b.begin()+54,{17,0,0,0,0,0,0,0});
    auto c=awg_read_capture(pcap(b));REQUIRE(c.ok);REQUIRE(c.packets.size()==1);
    b[14+6]=44;c=awg_read_capture(pcap(b));REQUIRE(c.ok);CHECK(c.packets.empty());
}
TEST_CASE("Capture parser bounded mutation smoke") {
    std::mt19937 rng(7);
    for(int i=0;i<3000;++i) {
        Bytes b=i%2 ? pcapng(frame()) : pcap(frame());
        for(int j=0;j<4;++j) b[rng()%b.size()]=uint8_t(rng());
        if(i%3==0) b.resize(rng()%b.size());
        auto c=awg_read_capture(b);
        if(!c.ok) CHECK(c.packets.empty());
        else for(const auto& p:c.packets) {
            CHECK(std::isfinite(p.byte_entropy));
            CHECK(p.payload_size<=65535);
        }
    }
}
