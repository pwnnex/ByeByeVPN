// SPDX-License-Identifier: GPL-3.0-or-later
// subnet sweep — networking + threading half (run_sweep). the CIDR math and
// clustering live in sweep_core.cpp (pure, unit-tested).
#include "sweep.h"
#include "../common/platform.h"
#include "../common/console.h"
#include "../net/tcp.h"
#include "../scan/tls.h"
#include "../scan/utls.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using std::string;
using std::vector;

namespace {

// light per-host fingerprint: liveness on :443, then (if open) a JA4S probe
// and a cert probe. no port scan, no J3 — just enough to cluster.
SweepHost light_probe(const string& ip) {
    SweepHost h;
    h.ip = ip;
    auto t0 = std::chrono::steady_clock::now();
    string err;
    SOCKET s = tcp_connect(ip, 443, 700, err);
    if (s == INVALID_SOCKET) return h;        // open443 stays false
    h.open443 = true;
    h.rtt_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - t0).count();
    closesocket(s);

    UtlsProbeResult u = utls_probe_openssl(ip, 443, "");
    if (u.handshake_completed) {
        h.tls_ok = true;
        h.ja4s = u.ja4s;
        if (u.cert_sha256.size() >= 16) h.cert_sha16 = u.cert_sha256.substr(0, 16);
    }
    TlsProbe tp = tls_probe(ip, 443, "");
    if (tp.ok) {
        h.tls_ok = true;
        h.issuer_cn = tp.issuer_cn;
        if (h.cert_sha16.empty() && tp.cert_sha256.size() >= 16)
            h.cert_sha16 = tp.cert_sha256.substr(0, 16);
    }
    return h;
}

} // namespace

int run_sweep(const string& cidr) {
    vector<string> ips;
    string err;
    if (!parse_cidr(cidr, ips, 1024, err)) {
        printf("%ssweep: %s%s\n", col(C::RED), err.c_str(), col(C::RST));
        return 64;
    }

    printf("\n%s[SWEEP]%s %s%s%s  ->  %zu hosts, probing :443\n",
           col(C::BOLD), col(C::RST), col(C::WHT), cidr.c_str(), col(C::RST), ips.size());

    vector<SweepHost> results(ips.size());
    std::atomic<size_t> idx{0};
    std::atomic<int>    done{0};
    int nthreads = (int)std::min<size_t>(64, ips.size());
    if (nthreads < 1) nthreads = 1;

    auto worker = [&]{
        for (;;) {
            size_t i = idx.fetch_add(1);
            if (i >= ips.size()) break;
            results[i] = light_probe(ips[i]);
            int d = ++done;
            if (d % 16 == 0 || (size_t)d == ips.size()) {
                std::fprintf(stderr, "\r  probed %d/%zu   ", d, ips.size());
                std::fflush(stderr);
            }
        }
    };
    vector<std::thread> th;
    for (int i = 0; i < nthreads; ++i) th.emplace_back(worker);
    for (auto& t : th) t.join();
    std::fprintf(stderr, "\r  probed %zu/%zu        \n", ips.size(), ips.size());

    int live = 0, tls = 0;
    for (auto& h : results) { if (h.open443) ++live; if (h.tls_ok) ++tls; }
    printf("  %s%d/%zu hosts have :443 open, %d completed TLS%s\n",
           col(C::DIM), live, ips.size(), tls, col(C::RST));

    auto groups = cluster_hosts(results);
    printf("\n  %sClusters (by TLS fingerprint):%s\n", col(C::BOLD), col(C::RST));
    int shown = 0;
    for (auto& [key, members] : groups) {
        if (key == "down") continue;             // skip the (large) dead set
        const char* c = (members.size() >= 2) ? col(C::CYN) : col(C::DIM);
        printf("  %s[%zu host%s]%s %s\n",
               c, members.size(), members.size() == 1 ? "" : "s", col(C::RST),
               key.c_str());
        // list the member IPs, capped so a /22 doesn't flood the terminal.
        printf("      ");
        size_t cap = 24;
        for (size_t i = 0; i < members.size() && i < cap; ++i)
            printf("%s ", members[i].ip.c_str());
        if (members.size() > cap) printf("... (+%zu more)", members.size() - cap);
        printf("\n");
        ++shown;
    }
    if (shown == 0)
        printf("  %s(no live TLS hosts in range)%s\n", col(C::DIM), col(C::RST));
    else
        printf("\n  %s=> hosts sharing a cluster key run the same TLS terminator; an "
               "identical JA4S + cloned cert across many IPs on one provider is the "
               "multi-host Reality/proxy-farm signature.%s\n",
               col(C::DIM), col(C::RST));
    return 0;
}
