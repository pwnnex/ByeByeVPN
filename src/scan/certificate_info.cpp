// SPDX-License-Identifier: GPL-3.0-or-later
#include "tls.h"
#include "../common/util.h"
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace {
std::string name_text(const X509_NAME* name) {
    if (!name) return {};
    char* text = X509_NAME_oneline(name, nullptr, 0);
    std::string out = text ? text : "";
    OPENSSL_free(text);
    return out;
}

std::string attribute(const X509_NAME* name, int nid) {
    if (!name) return {};
    const int index = X509_NAME_get_index_by_NID(name, nid, -1);
    if (index < 0) return {};
    auto* entry = X509_NAME_get_entry(name, index);
    unsigned char* value = nullptr;
    const int length = ASN1_STRING_to_UTF8(&value, X509_NAME_ENTRY_get_data(entry));
    std::string out;
    if (length > 0) out.assign(reinterpret_cast<char*>(value), length);
    OPENSSL_free(value);
    return out;
}

bool seconds_between(const ASN1_TIME* from, const ASN1_TIME* to, int64_t& seconds) {
    if (!from || !to) return false;
    int days = 0, rest = 0;
    if (ASN1_TIME_diff(&days, &rest, from, to) != 1) return false;
    seconds = static_cast<int64_t>(days) * 86400 + rest;
    return true;
}
}

void inspect_certificate(X509* cert, CertificateInfo& r, std::time_t now) {
    r = CertificateInfo{};
    if (!cert) return;
    r.certificate_present = true;
    auto* subject = X509_get_subject_name(cert);
    auto* issuer = X509_get_issuer_name(cert);
    r.cert_subject = name_text(subject);
    r.cert_issuer = name_text(issuer);
    r.subject_cn = attribute(subject, NID_commonName);
    r.issuer_cn = attribute(issuer, NID_commonName);
    r.is_letsencrypt = attribute(issuer, NID_organizationName) == "Let's Encrypt";
    r.self_issued = subject && issuer && X509_NAME_cmp(subject, issuer) == 0;
    // equal names alone do not prove that the leaf signed itself.
    const bool marked = ERR_set_mark() == 1;
    if (r.self_issued) {
        EVP_PKEY* key = X509_get_pubkey(cert);
        if (key) {
            const int verified = X509_verify(cert, key);
            r.self_signature_checked = verified >= 0;
            r.self_signed = verified == 1;
            EVP_PKEY_free(key);
        }
    }
    if (marked) ERR_pop_to_mark(); else ERR_clear_error();

    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned int length = 0;
    if (X509_digest(cert, EVP_sha256(), digest, &length) == 1) r.cert_sha256 = hex_s(digest, length);
    const ASN1_TIME* before = X509_get0_notBefore(cert);
    const ASN1_TIME* after = X509_get0_notAfter(cert);
    ASN1_TIME* reference = ASN1_TIME_set(nullptr, now);
    int64_t age = 0, left = 0, validity = 0;
    r.certificate_times_valid = seconds_between(before, after, validity) && validity >= 0 &&
                                seconds_between(before, reference, age) && seconds_between(reference, after, left);
    ASN1_TIME_free(reference);
    if (r.certificate_times_valid) {
        r.age_days = static_cast<int>(age / 86400);
        r.days_left = static_cast<int>(left / 86400);
        r.total_validity_days = static_cast<int>(validity / 86400);
        r.total_validity_seconds = validity;
        r.certificate_expired = left < 0;
        r.certificate_not_yet_valid = age < 0;
    }
    auto* names = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (names) {
        for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
            const auto* name = sk_GENERAL_NAME_value(names, i);
            if (name->type != GEN_DNS) continue;
            const auto* value = name->d.dNSName;
            const auto* data = ASN1_STRING_get0_data(value);
            const int size = ASN1_STRING_length(value);
            if (size <= 0 || !data) continue;
            std::string dns(reinterpret_cast<const char*>(data), size);
            if (dns.rfind("*.", 0) == 0) r.is_wildcard = true;
            r.san.push_back(std::move(dns));
        }
        GENERAL_NAMES_free(names);
    }
    r.san_count = static_cast<int>(r.san.size());
    if (r.subject_cn.rfind("*.", 0) == 0) r.is_wildcard = true;
}
