// SPDX-License-Identifier: GPL-3.0-or-later
// synthetic clienthello builders.
//
// build_chromelike_clienthello: the pre-ml-kem chrome extension set with
// GREASE at the spec positions, a GREASE-prefixed x25519 key_share and
// boringssl-style padding. its ja4 is t13d1516h2_8daaf6152771_e5627efa2ab1,
// the foxio example, which chrome sent before x25519mlkem768.
//
// not a current chrome hello: the extension order is fixed (chrome permutes
// it per connection), there is no x25519mlkem768 key share and no
// encrypted_client_hello GREASE. treat it as its own fingerprint, not as
// browser traffic.
//
// build_minimal_clienthello: the small tls 1.3-only hello used by the j3
// invalid-sni probe. one suite, x25519 only, empty key_share list.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

// each returns a complete tls plaintext record (5-byte record header
// followed by the handshake message) ready to write to a connected socket.
std::vector<uint8_t> build_chromelike_clienthello(const std::string& sni);
std::vector<uint8_t> build_minimal_clienthello(const std::string& sni);
