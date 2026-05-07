// hand-crafted UDP probes for VPN-ish protocols. each builds a minimal
// well-formed handshake packet and uses udp_probe() to fire-and-wait.
//
// payload bytes that would otherwise be a tool fingerprint (timestamps,
// transaction IDs, tunnel IDs, SNI prefixes) are randomized per-probe.
#pragma once

#include "../net/udp.h"
#include <string>

UdpResult quic_probe       (const std::string& host, int port);   // QUIC v1 Initial
UdpResult openvpn_probe    (const std::string& host, int port);   // HARD_RESET_CLIENT_V2
UdpResult wireguard_probe  (const std::string& host, int port);   // 148B handshake init
UdpResult ike_probe        (const std::string& host, int port);   // ISAKMP IKE_SA_INIT
UdpResult dns_probe        (const std::string& host, int port);   // A query for example.com
UdpResult hysteria2_probe  (const std::string& host, int port);   // QUIC w/ obfuscated DCID
UdpResult tuic_probe       (const std::string& host, int port);   // QUIC-shaped (same shell)
UdpResult l2tp_probe       (const std::string& host, int port);   // SCCRQ
UdpResult amneziawg_probe  (const std::string& host, int port);   // WG with Sx=8 junk prefix
