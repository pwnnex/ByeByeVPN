// SPDX-License-Identifier: GPL-3.0-or-later
// fuzz the capture walker, ip/tcp/udp decoder, tcp reassembly, tls record
// walk, quic initial decode and dns question parser with asan + ubsan.
// a capture file is untrusted input from disk.
//
// build and run: see make fuzz and the ci workflow
#include "../src/scan/pcap_analysis.h"

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::vector<uint8_t> bytes(data, data + size);
    PcapReport r = pcap_analyze(bytes);
    if (r.ok) {
        // the json writer reads every field the analyzer filled
        LeakView v = pcap_leaks(r, "203.0.113.5");
        volatile auto sink = pcap_report_json(r, v);
        (void)sink;
    }
    return 0;
}
