// SPDX-License-Identifier: GPL-3.0-or-later
// subnet sweep: light-probe every host in a cidr and cluster them by tls
// fingerprint. answers osint-shaped questions like "which hosts in this /24
// run the same reality deployment" - identical cloned cert + ja4s land in one
// cluster. the cidr math and the clustering are pure (unit-tested); the
// per-host probe + threading live in sweep.cpp (networking, windows).
#pragma once

#include <string>
#include <vector>

struct SweepHost {
    std::string ip;
    bool        open443  = false;   // tcp :443 accepted a connection
    bool        tls_ok   = false;   // tls handshake completed
    std::string issuer_cn;          // cert issuer cn
    std::string cert_sha16;         // first 16 hex chars of cert sha-256
    std::string ja4s;               // openssl-flavor ja4s
    long long   rtt_ms   = -1;
};

// expand an ipv4 cidr ("1.2.3.0/24") or a bare ip into a host list. a bare ip
// is treated as /32. refuses ranges larger than `max_hosts` (sets err). all
// addresses in range are included (network + broadcast too). returns false on
// a malformed cidr or an oversized range.
bool parse_cidr(const std::string& cidr, std::vector<std::string>& out,
                int max_hosts, std::string& err);

// the cluster key for one host: groups hosts that look like the same stack.
// "down" / "open443-no-tls" for non-tls hosts; otherwise the ja4s ext-hash +
// cert issuer (+ cert sha prefix), so identical deployments collapse together.
std::string sweep_cluster_key(const SweepHost& h);

// group hosts by sweep_cluster_key, returning (key, members) pairs sorted by
// descending member count.
std::vector<std::pair<std::string, std::vector<SweepHost>>>
cluster_hosts(const std::vector<SweepHost>& hosts);

// run a full sweep over `cidr`: enumerate, light-probe each host in parallel,
// cluster, and print. returns 0 on success, 64 on a bad/oversized cidr.
int run_sweep(const std::string& cidr);
