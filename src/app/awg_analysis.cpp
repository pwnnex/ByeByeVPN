// SPDX-License-Identifier: GPL-3.0-or-later
#include "cli.h"
#include "../common/config.h"
#include "../common/console.h"
#include "../scan/awg_entropy.h"
#include <cstdio>

int run_awg_analysis(const std::string& path) {
    auto capture=awg_read_capture_file(path);
    auto flows=capture.ok ? awg_analyze(capture.packets) : std::vector<AwgFlow>{};
    if (g_json) {
        auto json=awg_capture_json(capture,flows);
        std::fputs(json.c_str(),stdout);
    } else {
        printf("\nAmneziaWG traffic analysis (entropy + packet sequence)\n");
        if (!capture.ok) printf("Error: %s\n",capture.error.c_str());
        else {
            printf("Records: %zu; UDP: %zu; skipped: %zu; flows: %zu\n",
                   capture.records,capture.packets.size(),capture.skipped,flows.size());
            printf("Skipped records include non-UDP, fragments, truncated packets and unsupported/timestamp-less records.\n");
            for (const auto& f:flows) {
                printf("\n[%s] %s <-> %s (capture interface %s)\n",f.verdict.c_str(),f.endpoint_a.c_str(),f.endpoint_b.c_str(),f.scope.c_str());
                printf("  packets=%zu (%zu/%zu), sampled=%zu, random-like=%zu, bursts=%zu\n",
                       f.packets,f.a_to_b,f.b_to_a,f.sampled,f.random_packets,f.candidate_bursts);
                printf("  mean byte entropy=%.3f/8; nibble entropy=%.3f/4; AWG version=unknown\n",f.mean_byte_entropy,f.mean_nibble_entropy);
                for (const auto& e:f.evidence) printf("  %s\n",e.c_str());
            }
            if (flows.empty()) printf("No complete UDP observations; result is inconclusive.\n");
            printf("\nHeuristic compatibility only. This does not change the live scan score or TSPU verdict.\n");
        }
    }
    // 0 means analysis completed, not "clean". findings live in the report.
    return capture.ok ? 0 : 64;
}
