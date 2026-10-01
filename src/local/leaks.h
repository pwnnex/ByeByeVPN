// SPDX-License-Identifier: GPL-3.0-or-later
// ipv6 and dns leaks on this machine: does traffic the owner expects in
// the tunnel leave beside it. decisions only; local.cpp gathers the facts.
#pragma once

#include "../common/outcome.h"

#include <string>
#include <vector>

struct LeakAdapter {
    std::string   name;
    unsigned long index = 0, metric = 0;
    bool          tunnel = false, up = false, gateway = false;
    std::vector<std::string> v6;    // unicast addresses
    std::vector<std::string> dns;   // configured resolvers
};

// one look at a public ipv6 address: which local address a connect used
enum class V6Seen { Outside, Tunnel, NoPath, Silent };
struct V6Probe { std::string target; V6Seen seen = V6Seen::Silent; std::string detail; };

// one resolver outside the tunnel, asked a benign name
enum class DnsSeen { Answer, Blocked, Silent };
struct DnsProbe { std::string server, adapter; std::vector<DnsSeen> seen; };

struct LeakCheck {
    Outcome     outcome = Outcome::NotApplicable;
    std::string reason;
};

// a global unicast ipv6 address (not link-local, unique-local, site-local, loopback)
bool v6_global(const std::string& addr);
bool any_tunnel_up(const std::vector<LeakAdapter>& ads);
// adapters with a global ipv6 address beside the tunnel
std::vector<const LeakAdapter*> v6_outside(const std::vector<LeakAdapter>& ads);
// resolvers the system would ask beside the tunnel. smart: windows sends
// each query to every adapter's resolvers unless policy turns it off.
std::vector<std::pair<std::string, const LeakAdapter*>> dns_outside(const std::vector<LeakAdapter>& ads, bool smart);

LeakCheck ipv6_leak(const std::vector<LeakAdapter>& ads, const std::vector<V6Probe>& probes);
LeakCheck dns_leak(const std::vector<LeakAdapter>& ads, bool smart, const std::vector<DnsProbe>& probes);
