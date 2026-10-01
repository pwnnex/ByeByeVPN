// SPDX-License-Identifier: GPL-3.0-or-later
#include "leaks.h"

#include <algorithm>
#include <cctype>

bool v6_global(const std::string& addr) {
    // 2000::/3 is the only global unicast block in use
    unsigned g = 0;
    size_t n = 0;
    for (char c : addr) {
        if (c == ':' || c == '%') break;
        if (!std::isxdigit(static_cast<unsigned char>(c)) || ++n > 4) return false;
        const int d = std::tolower(static_cast<unsigned char>(c));
        g = g * 16 + unsigned(d <= '9' ? d - '0' : d - 'a' + 10);
    }
    return n > 0 && (g & 0xe000) == 0x2000;
}

bool any_tunnel_up(const std::vector<LeakAdapter>& ads) {
    return std::any_of(ads.begin(), ads.end(), [](const LeakAdapter& a) { return a.up && a.tunnel; });
}

std::vector<const LeakAdapter*> v6_outside(const std::vector<LeakAdapter>& ads) {
    std::vector<const LeakAdapter*> out;
    for (const auto& a : ads)
        if (a.up && !a.tunnel && std::any_of(a.v6.begin(), a.v6.end(), v6_global)) out.push_back(&a);
    return out;
}

namespace {

// windows puts fec0:0:0:ffff::1-3 on adapters with no ipv6 resolver
bool placeholder(const std::string& s) {
    return s.size() >= 4 && std::tolower(static_cast<unsigned char>(s[0])) == 'f' &&
           std::tolower(static_cast<unsigned char>(s[1])) == 'e' &&
           std::tolower(static_cast<unsigned char>(s[2])) == 'c';
}

unsigned long tunnel_dns_metric(const std::vector<LeakAdapter>& ads, bool& any) {
    unsigned long best = ~0UL;
    any = false;
    for (const auto& a : ads) {
        if (!a.up || !a.tunnel) continue;
        for (const auto& d : a.dns) {
            if (placeholder(d)) continue;
            any = true;
            best = std::min(best, a.metric);
        }
    }
    return best;
}

} // namespace

std::vector<std::pair<std::string, const LeakAdapter*>> dns_outside(const std::vector<LeakAdapter>& ads, bool smart) {
    std::vector<std::pair<std::string, const LeakAdapter*>> out;
    bool tunnel_dns = false;
    const unsigned long first = tunnel_dns_metric(ads, tunnel_dns);
    for (const auto& a : ads) {
        if (!a.up || a.tunnel) continue;
        // without parallel queries the lowest metric is asked first
        if (tunnel_dns && !smart && a.metric >= first) continue;
        for (const auto& d : a.dns)
            if (!placeholder(d)) out.emplace_back(d, &a);
    }
    return out;
}

LeakCheck ipv6_leak(const std::vector<LeakAdapter>& ads, const std::vector<V6Probe>& probes) {
    LeakCheck c;
    if (!any_tunnel_up(ads)) {
        c.reason = "no tunnel adapter is up; with a proxy-only client every app outside the proxy uses ipv6 directly";
        return c;
    }
    const auto outside = v6_outside(ads);
    if (outside.empty()) {
        c.outcome = Outcome::Negative;
        c.reason = "no global ipv6 address beside the tunnel; nothing can leave over ipv6";
        return c;
    }
    std::vector<Outcome> obs;
    bool tunnel = false;
    for (const auto& p : probes) {
        tunnel = tunnel || p.seen == V6Seen::Tunnel;
        obs.push_back(p.seen == V6Seen::Outside ? Outcome::Positive
                    : p.seen == V6Seen::Silent  ? Outcome::Inconclusive : Outcome::Negative);
    }
    c.outcome = combine_observations(obs);
    if (c.outcome == Outcome::Positive)
        c.reason = "connections to public ipv6 addresses leave through " + outside.front()->name +
                   ", beside the tunnel; a box on that link sees them in full";
    else if (c.outcome == Outcome::Negative)
        c.reason = tunnel ? "ipv6 goes into the tunnel" : "no ipv6 path beside the tunnel (unreachable or blocked)";
    else
        c.reason = probes.empty() ? "global ipv6 beside the tunnel on " + outside.front()->name + "; not tested"
                                  : "no two agreeing answers from public ipv6 addresses";
    return c;
}

LeakCheck dns_leak(const std::vector<LeakAdapter>& ads, bool smart, const std::vector<DnsProbe>& probes) {
    LeakCheck c;
    if (!any_tunnel_up(ads)) {
        c.reason = "no tunnel adapter is up; with a proxy-only client the system resolver always works beside it";
        return c;
    }
    if (dns_outside(ads, smart).empty()) {
        c.outcome = Outcome::Negative;
        bool tunnel_dns = false;
        tunnel_dns_metric(ads, tunnel_dns);
        c.reason = tunnel_dns && !smart ? "the tunnel's resolver is asked first and parallel queries are off"
                                        : "no resolver configured beside the tunnel";
        return c;
    }
    if (probes.empty()) {
        c.outcome = Outcome::Inconclusive;
        c.reason = "resolvers configured beside the tunnel; not asked";
        return c;
    }
    bool all_blocked = true;
    for (const auto& p : probes) {
        const auto answers = std::count(p.seen.begin(), p.seen.end(), DnsSeen::Answer);
        const auto blocked = std::count(p.seen.begin(), p.seen.end(), DnsSeen::Blocked);
        if (answers >= 2) {
            c.outcome = Outcome::Positive;
            c.reason = p.server + " on " + p.adapter + " answers beside the tunnel" +
                       (smart ? "; windows asks every adapter's resolver in parallel" : "") +
                       ", so names go out in the clear";
            return c;
        }
        all_blocked = all_blocked && blocked >= 2;
    }
    c.outcome = all_blocked ? Outcome::Negative : Outcome::Inconclusive;
    c.reason = all_blocked ? "resolvers beside the tunnel are configured but blocked there (a kill switch)"
                           : "no two agreeing answers from the resolvers beside the tunnel";
    return c;
}
