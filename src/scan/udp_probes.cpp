#include "udp_probes.h"
#include "../common/winhdr.h"

#include <openssl/rand.h>

#include <cstring>
#include <ctime>
#include <vector>

using std::string;
using std::vector;

UdpResult quic_probe(const string& host, int port) {
    // minimal QUIC v1 Initial. server should answer with version-neg or retry.
    unsigned char pkt[] = {
        0xc0,
        0x00,0x00,0x00,0x01,
        0x08,
        0,0,0,0,0,0,0,0,             // DCID (filled below)
        0x00,
        0x00,
        0x44,0x40,
    };
    RAND_bytes(pkt + 6, 8);
    vector<unsigned char> full(1200, 0x00);
    std::memcpy(full.data(), pkt, sizeof(pkt));
    return udp_probe(host, port, full.data(), (int)full.size(), 1500);
}

UdpResult openvpn_probe(const string& host, int port) {
    unsigned char pkt[26];
    pkt[0] = 0x38; // P_CONTROL_HARD_RESET_CLIENT_V2 (7) << 3 | key_id 0
    RAND_bytes(pkt + 1, 8);                       // session id
    pkt[9] = 0x00;                                // packet id array len
    unsigned int pid = htonl(0);
    std::memcpy(pkt + 10, &pid, 4);               // packet id
    // session-creation timestamp. real clients stamp this seconds before
    // emitting the packet — exact arrival-time stamps are a tool fingerprint.
    unsigned char rnd_off = 0;
    RAND_bytes(&rnd_off, 1);
    unsigned int ts = htonl((unsigned int)std::time(nullptr) - (unsigned int)rnd_off);
    std::memcpy(pkt + 14, &ts, 4);
    RAND_bytes(pkt + 18, 8);                      // padding
    return udp_probe(host, port, pkt, sizeof(pkt), 1200);
}

UdpResult wireguard_probe(const string& host, int port) {
    unsigned char pkt[148] = {0};
    pkt[0] = 0x01;   // type: handshake initiation
    RAND_bytes(pkt + 4, 140);
    return udp_probe(host, port, pkt, sizeof(pkt), 1500);
}

UdpResult ike_probe(const string& host, int port) {
    unsigned char pkt[28] = {0};
    RAND_bytes(pkt, 8);   // ICOOKIE
    pkt[16] = 0x21;       // next payload: SA + version hint
    pkt[17] = 0x20;       // IKEv2 v2.0
    pkt[18] = 0x22;       // exchange type: IKE_SA_INIT
    pkt[19] = 0x08;       // flags: Initiator
    pkt[24] = 0; pkt[25] = 0; pkt[26] = 0; pkt[27] = 28;
    return udp_probe(host, port, pkt, sizeof(pkt), 1200);
}

UdpResult dns_probe(const string& host, int port) {
    // standard DNS query, 1 question: example.com A.
    // RFC 5452 requires a real resolver to randomize txn id, so a hardcoded
    // constant would be a tool fingerprint AND protocol-incorrect.
    unsigned char q[] = {
        0,0,        0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
        0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00,
        0x00,0x01, 0x00,0x01
    };
    RAND_bytes(q, 2);
    return udp_probe(host, port, q, sizeof(q), 1200);
}

UdpResult hysteria2_probe(const string& host, int port) {
    // vanilla QUIC v1 Initial with random DCID. caller compares with the
    // QUIC-on-:443 result to distinguish vanilla HTTP/3 vs Hysteria2.
    unsigned char pkt[] = {
        0xc0, 0x00,0x00,0x00,0x01, 0x08,
        0,0,0,0,0,0,0,0,
        0x00, 0x00, 0x44,0x40
    };
    RAND_bytes(pkt + 6, 8);
    vector<unsigned char> full(1200, 0x00);
    std::memcpy(full.data(), pkt, sizeof(pkt));
    return udp_probe(host, port, full.data(), (int)full.size(), 1500);
}

UdpResult tuic_probe(const string& host, int port) {
    // same QUIC shell — interpretation differs in the verdict engine.
    return quic_probe(host, port);
}

UdpResult l2tp_probe(const string& host, int port) {
    // minimal SCCRQ with mandatory AVPs: Message Type, Protocol Version,
    // Framing/Bearer Caps, Host Name, Assigned Tunnel ID.
    unsigned char pkt[] = {
        0xC8,0x02,
        0x00,0x2D,
        0x00,0x00,
        0x00,0x00,
        0x00,0x00,
        0x00,0x00,
        0x80,0x08, 0x00,0x00, 0x00,0x00, 0x00,0x01,
        0x80,0x08, 0x00,0x00, 0x00,0x02, 0x01,0x00,
        0x80,0x0A, 0x00,0x00, 0x00,0x03, 0x00,0x00,0x00,0x03,
        0x80,0x0B, 0x00,0x00, 0x00,0x07, 'l','a','c',
        0x80,0x08, 0x00,0x00, 0x00,0x09, 0,0
    };
    unsigned char tid[2];
    do { RAND_bytes(tid, 2); } while (tid[0] == 0 && tid[1] == 0);
    pkt[sizeof(pkt) - 2] = tid[0];
    pkt[sizeof(pkt) - 1] = tid[1];
    return udp_probe(host, port, pkt, sizeof(pkt), 1500);
}

UdpResult amneziawg_probe(const string& host, int port) {
    // WG init with 8-byte random prefix (Sx=8 default for AmneziaWG).
    unsigned char pkt[148 + 8] = {0};
    RAND_bytes(pkt, 8);
    pkt[8] = 0x01;
    RAND_bytes(pkt + 12, 140);
    return udp_probe(host, port, pkt, sizeof(pkt), 1500);
}
