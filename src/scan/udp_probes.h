// SPDX-License-Identifier: GPL-3.0-or-later
// hand-crafted UDP probes for the modern signature-less tunnel set.
//
// v2.6.0 scope cut: this tool now focuses only on the stacks that are
// actually relevant to 2026 RU/DPI bypass and that have no trivial port
// or banner signature: WireGuard, AmneziaWG, Hysteria2. the legacy probes
// (OpenVPN HARD_RESET, IKEv2 ISAKMP, L2TP SCCRQ, plain DNS, vanilla QUIC,
// TUIC) were removed: they target protocols with well-known fixed-port /
// fixed-header signatures that any DPI already catches, so probing for
// them added scan time without adding detection value for this niche.
//
// payload bytes that would otherwise be a tool fingerprint (ephemeral
// keys, junk-prefix contents, QUIC DCID) are randomized per-probe via
// OpenSSL RAND_bytes.
#pragma once

#include "../net/udp.h"
#include <string>

UdpResult wireguard_probe (const std::string& host, int port);   // 148B handshake init
UdpResult amneziawg_probe (const std::string& host, int port);   // WG with Sx=8 junk prefix
UdpResult hysteria2_probe (const std::string& host, int port);   // QUIC v1 Initial, random DCID
