// SPDX-License-Identifier: GPL-3.0-or-later
// udp reply validation - pure byte logic, no winsock, no network.
//
// split out of udp_probes.cpp (which needs the windows socket headers) so the
// predicates that decide "is this reply actually the protocol we probed for"
// compile into the platform-agnostic unit-test build. same arrangement as
// ech.cpp vs ech_query.cpp and sweep_core.cpp vs sweep.cpp.
//
// why this exists: a datagram coming back isn't evidence of a protocol. echo
// services, reflectors and generic middleboxes all answer a udp probe, and the
// verdict engine used to treat any reply as a confirmed WireGuard / amneziawg /
// hysteria2 handshake. these predicates match the reply against the protocol's
// real response layout instead.
//
// none of them authenticates the peer - we hold no key, so a deliberate
// impostor can still forge a well-formed header. they rule out the accidental
// false positives, which is the most a score is entitled to rest on.
#pragma once

#include "../net/udp.h"

// WireGuard answered our messageinitiation with a real messageresponse
// (type 0x02 + 3 reserved zero bytes, 92 bytes total) or a cookie reply
// (type 0x03 + 3 reserved zero bytes, 64 bytes). both layouts are rfc-fixed,
// so a match is strong evidence of a WireGuard-family responder.
bool wg_response_valid(const UdpResult& u);

// amneziawg running default h1-h4 answers with a standard wg messageresponse
// carrying an s2 junk prefix. returns the offset the messageresponse header
// sits at, or -1 if the datagram carries no such header.
//   -1  no messageresponse anywhere -> not an amneziawg reply
//    0  header at offset 0          -> indistinguishable from vanilla WireGuard
//   >0  header behind a junk prefix -> amneziawg-consistent, offset == s2 size
// a custom h1-h4 set rewrites the type byte and will not match; that is a
// false negative we accept rather than guessing.
int awg_response_offset(const UdpResult& u);

// the reply parses as a genuine quic packet (Initial / Retry / Handshake /
// version-negotiation). this confirms a quic endpoint and nothing more:
// http/3 is ordinary web traffic and every quic stack answers an Initial
// identically, so it is never by itself a tunnel signature.
bool quic_response_valid(const UdpResult& u);
