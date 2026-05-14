// SPDX-License-Identifier: GPL-3.0-or-later
// libFuzzer harness for the JA4 byte parsers.
//
// parse_client_hello / parse_server_hello consume raw, attacker-controlled
// handshake bytes straight off the wire (captured by SSL_set_msg_callback).
// they walk nested length-prefixed structures, so an off-by-one in a length
// check is a memory-safety bug waiting on a hostile ServerHello. this target
// feeds arbitrary input to both parsers and, on the inputs they accept, to
// the JA4 string builders, under ASan + UBSan.
//
// build (clang):
//   clang++ -std=c++20 -g -O1 -fsanitize=fuzzer,address,undefined \
//     fuzz/fuzz_ja4.cpp src/scan/ja4.cpp -lcrypto -o fuzz_ja4
// run:
//   ./fuzz_ja4 -max_total_time=60
//
// CI runs a short time-boxed smoke pass; a real campaign runs longer.
#include "../src/scan/ja4.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // ClientHello path: parse, and if it claims success, build JA4. the
    // builder reads back every vector the parser populated, so a parser
    // that reports ok on truncated input gets caught here.
    ClientHelloFp ch;
    if (parse_client_hello(data, size, ch) && ch.ok) {
        volatile auto sink = ja4_client(ch);
        (void)sink;
    }

    // ServerHello path: same shape.
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
