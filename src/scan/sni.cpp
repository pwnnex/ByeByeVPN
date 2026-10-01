// SPDX-License-Identifier: GPL-3.0-or-later
#include "sni.h"
#include "../common/util.h"

SniConsistency sni_consistency(const std::string& ip, int port, const std::string& base_sni) {
    const auto base = tls_probe(ip, port, base_sni);
    if (!base.ok) return analyze_sni(base_sni, base, {});
    static const std::vector<std::string> alt = {
        "www.microsoft.com", "www.apple.com", "www.amazon.com", "www.google.com",
        "www.cloudflare.com", "www.bing.com", "addons.mozilla.org", "www.yandex.ru",
        "www.github.com", "random-domain-that-does-not-exist.invalid"
    };
    std::vector<SniConsistency::Entry> entries;
    for (const auto& name : alt) {
        if (tolower_s(name) == tolower_s(base_sni)) continue;
        if (!entries.empty()) stealth_sleep_ms(200, 1200);
        const auto probe = tls_probe(ip, port, name);
        entries.push_back({name, probe.ok, probe.cert_sha256, probe.cert_subject, probe.err});
    }
    return analyze_sni(base_sni, base, entries);
}
