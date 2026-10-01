// SPDX-License-Identifier: GPL-3.0-or-later
#include "sni.h"
#include "brand.h"
#include "../common/util.h"
#include <set>

SniConsistency analyze_sni(const std::string& base_sni, const TlsProbe& base,
                           const std::vector<SniConsistency::Entry>& entries) {
    SniConsistency c;
    c.base_sni = base_sni;
    c.base_sha = base.cert_sha256;
    c.base_subject = base.cert_subject;
    c.base_san = base.san;
    c.base_ok = base.ok && !base.cert_sha256.empty();
    c.entries = entries;
    c.brand_claimed = cert_claims_brand(base.subject_cn, base.san);
    if (!c.base_ok) { c.err = base.err.empty() ? "base certificate unavailable" : base.err; return c; }
    std::set<std::string> distinct{base.cert_sha256};
    std::set<std::string> names{tolower_s(base_sni)};
    for (const auto& e : entries) {
        if (e.sni.empty() || !names.insert(tolower_s(e.sni)).second) continue;
        if (!e.ok || e.sha.empty()) { ++c.failed; continue; }
        ++c.compared;
        if (e.sha == base.cert_sha256) ++c.same_as_base;
        distinct.insert(e.sha);
    }
    c.distinct_certs = static_cast<int>(distinct.size());
    if (c.compared < 3) return c;
    if (c.same_as_base == c.compared) {
        c.same_cert_always = true;
        c.default_cert_only = true;
        c.pattern = "same-for-successful-probes";
    } else if (c.same_as_base == 0) c.pattern = "different-from-base";
    else c.pattern = "mixed-certificates";
    return c;
}
