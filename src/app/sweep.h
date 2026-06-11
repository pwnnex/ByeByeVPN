// SPDX-License-Identifier: GPL-3.0-or-later
// subnet sweep: light-probe every host in a CIDR and cluster them by TLS
// fingerprint. answers OSINT-shaped questions like "which hosts in this /24
// run the same Reality deployment" — identical cloned cert + JA4S land in one
// cluster. the CIDR math and the clustering are pure (unit-tested); the
// per-host probe + threading live in sweep.cpp (networking, Windows).
#pragma once

#include <string>
#include <vector>

struct SweepHost {
    std::string ip;
    bool        open443  = false;   // TCP :443 accepted a connection
    bool        tls_ok   = false;   // TLS handshake completed
    std::string issuer_cn;          // cert issuer CN
    std::string cert_sha16;         // first 16 hex chars of cert SHA-256
    std::string ja4s;               // openssl-flavor JA4S
    long long   rtt_ms   = -1;
};

// expand an IPv4 CIDR ("1.2.3.0/24") or a bare IP into a host list. a bare IP
// is treated as /32. refuses ranges larger than `max_hosts` (sets err). all
// addresses in range are included (network + broadcast too). returns false on
// a malformed CIDR or an oversized range.
bool parse_cidr(const std::string& cidr, std::vector<std::string>& out,
                int max_hosts, std::string& err);

// the cluster key for one host: groups hosts that look like the same stack.
// "down" / "open443-no-tls" for non-TLS hosts; otherwise the JA4S ext-hash +
// cert issuer (+ cert SHA prefix), so identical deployments collapse together.
std::string sweep_cluster_key(const SweepHost& h);

// group hosts by sweep_cluster_key, returning (key, members) pairs sorted by
// descending member count.
std::vector<std::pair<std::string, std::vector<SweepHost>>>
cluster_hosts(const std::vector<SweepHost>& hosts);

// run a full sweep over `cidr`: enumerate, light-probe each host in parallel,
// cluster, and print. returns 0 on success, 64 on a bad/oversized CIDR.
int run_sweep(const std::string& cidr);
