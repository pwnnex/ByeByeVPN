// SPDX-License-Identifier: GPL-3.0-or-later
// udp probe payloads for wireguard, amneziawg and hysteria2
// randomize keys, prefixes and quic ids with RAND_bytes
#pragma once

#include "../net/udp.h"
// the predicates that decide whether a reply is actually the protocol we
// probed for live in udp_validate.h - pure byte logic, unit-tested, and kept
// out of this winsock-bound translation unit.
#include "udp_validate.h"
#include "wg_handshake.h"

#include <string>

UdpResult wireguard_probe (const std::string& host, int port);   // 148B handshake init
UdpResult amneziawg_probe (const std::string& host, int port);   // wg with sx=8 junk prefix
UdpResult hysteria2_probe (const std::string& host, int port);   // real protected quic v1 Initial
UdpResult hysteria2_vn_probe(const std::string& host, int port); // forces version-negotiation

// owner self-check: a full initiation from a configured peer. reply is
// judged here because the handshake state is wiped before returning.
UdpResult wireguard_keyed_probe(const std::string& host, int port, const WgKeys& keys, WgReply& reply);
void      wg_keyed_gap();   // 1.0 to 1.5 s between keyed initiations, always

// classify a quic reply (e.g. from hysteria2_probe / hysteria2_vn_probe).
// returns "" when the reply doesn't look like a quic packet, and a refusal
// line when it fails quic_response_valid().
std::string quic_reply_summary(const UdpResult& u);
