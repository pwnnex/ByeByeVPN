// SPDX-License-Identifier: GPL-3.0-or-later
#include "preflight.h"

#include <set>

const char* const PREFLIGHT_DEAD_ADDRESS = "192.0.2.1";

namespace {
std::string join(const std::vector<std::string>& v) {
    std::string s;
    for (const auto& x : v) { if (!s.empty()) s += ", "; s += x; }
    return s;
}
}

PreflightReport preflight_decide(const PreflightFacts& f, bool override_flag) {
    PreflightReport r;
    r.facts = f;
    if (f.target_iface_is_tunnel)
        r.blockers.push_back("traffic to " + f.target_ip + " leaves through tunnel adapter '" + f.target_iface +
                             "'; probes measure the tunnel, not the target");
    if (f.fake_ip_target)
        r.blockers.push_back(f.target_ip + " is a fake-IP or CGNAT address; a local proxy answers for it");
    if (f.local_ack_all)
        r.blockers.push_back(std::string("a TCP connect to ") + PREFLIGHT_DEAD_ADDRESS +
                             " (RFC 5737, routed nowhere) succeeded; a local stack accepts every SYN, open ports are fake");
    if (!f.rewriters.empty())
        r.blockers.push_back("packet rewriting tools running (" + join(f.rewriters) + "); our ClientHello and timing are modified in flight");

    std::set<std::string> ips;
    int answered = 0;
    for (const auto& ip : f.external_ips) if (!ip.empty()) { ips.insert(ip); ++answered; }
    if (!f.expect_ip.empty() && answered >= 2 && (ips.size() != 1 || *ips.begin() != f.expect_ip))
        r.blockers.push_back("external address seen by lookup services (" + join({ips.begin(), ips.end()}) +
                             ") differs from --expect-ip " + f.expect_ip);

    if (!f.tunnels_up.empty() && !f.target_iface_is_tunnel)
        r.warnings.push_back("tunnel adapters up (" + join(f.tunnels_up) + "); the target route is direct, but GeoIP, CT and RTT anchors may leave through the tunnel");
    if (!f.proxy_clients.empty())
        r.warnings.push_back("proxy clients running (" + join(f.proxy_clients) + ")");
    if (!f.system_proxy.empty())
        r.warnings.push_back("system proxy set (" + f.system_proxy + "); third-party lookups go through it, target probes do not");
    if (!f.proxy_env.empty())
        r.warnings.push_back("proxy environment variables set (" + join(f.proxy_env) + "); ignored by the scanner");
    if (ips.size() > 1)
        r.warnings.push_back("lookup services see different external addresses (" + join({ips.begin(), ips.end()}) +
                             "); egress depends on destination");
    if (!f.ack_all_checked)
        r.warnings.push_back("local ack-all check did not run");

    r.blocked = !r.blockers.empty();
    r.overridden = r.blocked && override_flag;
    return r;
}
