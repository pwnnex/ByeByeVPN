// SPDX-License-Identifier: GPL-3.0-or-later
#include "sni.h"
#include "tls.h"
#include "brand.h"
#include "../common/util.h"
#include "../common/winhdr.h"

#include <set>
#include <vector>

using std::string;
using std::vector;

static bool cert_covers_name(const string& sni,
                             const string& subject_oneline,
                             const vector<string>& san) {
    string cn = extract_cn(subject_oneline);
    if (dns_name_match(sni, cn)) return true;
    for (auto& s: san) if (dns_name_match(sni, s)) return true;
    return false;
}

SniConsistency sni_consistency(const string& ip, int port, const string& base_sni) {
    SniConsistency c; c.base_sni = base_sni;
    TlsProbe base = tls_probe(ip, port, base_sni);
    if (!base.ok) return c;
    c.base_sha     = base.cert_sha256;
    c.base_subject = base.cert_subject;
    c.base_san     = base.san;

    // expanded probe list: common Reality dest= targets + unrelated SNIs +
    // a junk SNI to catch "always-accept-any-SNI" plain servers.
    static const vector<string> alt = {
        "www.microsoft.com",
        "www.apple.com",
        "www.amazon.com",
        "www.google.com",
        "www.cloudflare.com",
        "www.bing.com",
        "addons.mozilla.org",
        "www.yandex.ru",
        "www.github.com",
        "random-domain-that-does-not-exist.invalid"
    };
    int same = 0, total = 0;
    std::set<string> distinct;
    if (!base.cert_sha256.empty()) distinct.insert(base.cert_sha256);
    for (auto& s: alt) {
        TlsProbe p = tls_probe(ip, port, s);
        SniConsistency::Entry e;
        e.sni = s;
        e.ok  = p.ok;
        e.sha = p.cert_sha256;
        e.subject = p.cert_subject;
        if (p.ok) {
            ++total;
            if (p.cert_sha256 == base.cert_sha256) ++same;
            if (!p.cert_sha256.empty()) distinct.insert(p.cert_sha256);
        }
        c.entries.push_back(std::move(e));
    }
    c.distinct_certs = (int)distinct.size();

    // Brand claim ALWAYS runs on the base cert. ASN cross-check happens
    // at verdict time where GeoIP data is available.
    c.brand_claimed = cert_claims_brand(base.subject_cn, base.san);

    if (total >= 3 && same == total) {
        c.same_cert_always = true;
        bool cert_covers_base = cert_covers_name(base_sni, base.cert_subject, base.san);
        if (!cert_covers_base) {
            for (auto& s: alt) {
                if (_stricmp(s.c_str(), base_sni.c_str()) == 0) continue;
                if (cert_covers_name(s, base.cert_subject, base.san)) {
                    c.reality_like = true;
                    c.matched_foreign_sni = s;
                    break;
                }
            }
        }
        if (!c.brand_claimed.empty()) {
            c.cert_impersonation = true;
            if (!c.reality_like && !cert_covers_base) {
                c.reality_like = true;
                c.matched_foreign_sni = c.brand_claimed;
            }
        }
        if (!c.reality_like) c.default_cert_only = true;
    } else if (total >= 3 && same == 0 && c.distinct_certs >= 3) {
        // cert varies per SNI. if base cert is for a famous brand on a
        // non-owning ASN, this is Reality in passthrough-dest mode.
        if (!c.brand_claimed.empty()) {
            c.cert_impersonation = true;
            c.reality_like       = true;
            c.matched_foreign_sni = c.brand_claimed;
            c.passthrough_mode   = true;
        }
    } else if (total >= 3 && same > 0 && same < total) {
        // mixed: some SNIs share a cert, others get different ones.
        if (!c.brand_claimed.empty()) {
            c.cert_impersonation = true;
            c.reality_like       = true;
            c.matched_foreign_sni = c.brand_claimed;
            c.passthrough_mode   = true;
        }
    }
    return c;
}