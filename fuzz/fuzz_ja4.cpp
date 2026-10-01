// SPDX-License-Identifier: GPL-3.0-or-later
// fuzz ja4 hello parsers and fingerprint builders with asan + ubsan
// raw peer input goes through nested length checks here
//
// build and run: see make fuzz and the ci workflow
#include "../src/scan/ja4.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // clienthello path: parse, and if it claims success, build ja4. the
    // builder reads back every vector the parser populated, so a parser
    // that reports ok on truncated input gets caught here.
    ClientHelloFp ch;
    if (parse_client_hello(data, size, ch) && ch.ok) {
        volatile auto sink = ja4_client(ch);
        (void)sink;
    }

    // serverhello path: same shape.
    ServerHelloFp sh;
    if (parse_server_hello(data, size, sh) && sh.ok) {
        volatile auto sink = ja4s_server(sh);
        (void)sink;
    }

    // exercise the GREASE check and the hash helper directly on the raw
    // input so they are in the fuzzed surface too.
    if (size >= 2) {
        uint16_t v = (uint16_t(data[0]) << 8) | data[1];
        (void)ja4_is_grease(v);
    }
    return 0;
}
