#include "sni_consistency.h"
#include "../network/tls_probe.h"
#include "brand_cert.h"
#include <set>
#include <cstring>
#include "../core/utils.h"

static bool dns_name_match(const std::string& name, const std::string& pat) {
    if (name.empty() || pat.empty()) return false;
    if (pat.size() > 2 && pat[0] == '*' && pat[1] == '.') {
        std::string suffix = pat.substr(1);
        if (name.size() <= suffix.size()) return false;
        size_t off = name.size() - suffix.size();
        return _stricmp(name.c_str() + off, suffix.c_str()) == 0 &&
               name.find('.') == off;
    }
    return _stricmp(name.c_str(), pat.c_str()) == 0;
}

static std::string extract_cn(const std::string& subject_oneline) {
    size_t pos = subject_oneline.find("/CN=");
    if (pos == std::string::npos) return "";
    size_t end = subject_oneline.find('/', pos + 4);
    return subject_oneline.substr(pos + 4,
        end == std::string::npos ? std::string::npos : end - pos - 4);
}

static bool cert_covers_name(const std::string& sni,
                             const std::string& subject_oneline,
                             const std::vector<std::string>& san) {
    std::string cn = extract_cn(subject_oneline);
    if (dns_name_match(sni, cn)) return true;
    for (auto& s: san) if (dns_name_match(sni, s)) return true;
    return false;
}

SniConsistency sni_consistency(const std::string& ip, int port, const std::string& base_sni) {
    SniConsistency c; c.base_sni = base_sni;
    TlsProbe base = tls_probe(ip, port, base_sni);
    if (!base.ok) return c;
    c.base_sha     = base.cert_sha256;
    c.base_subject = base.cert_subject;
    c.base_san     = base.san;
    static const std::vector<std::string> alt = {
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
    std::set<std::string> distinct;
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
        if (!c.brand_claimed.empty()) {
            c.cert_impersonation = true;
            c.reality_like = true;
            c.matched_foreign_sni = c.brand_claimed;
            c.passthrough_mode   = true;
        }
    } else if (total >= 3 && same > 0 && same < total) {
        if (!c.brand_claimed.empty()) {
            c.cert_impersonation = true;
            c.reality_like = true;
            c.matched_foreign_sni = c.brand_claimed;
            c.passthrough_mode   = true;
        }
    }
    return c;
}