// SPDX-License-Identifier: GPL-3.0-or-later
#include "doctest.h"
#include "../src/scan/tls.h"
#include "../src/scan/https_probe.h"
#include "../src/scan/ct.h"
#include "../src/scan/j3.h"
#include "../src/net/http.h"
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <memory>

namespace {
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Cert = std::unique_ptr<X509, decltype(&X509_free)>;
constexpr std::time_t NOW = 1789462800;

Key key() {
    Key k(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1"), EVP_PKEY_free);
    REQUIRE(k);
    return k;
}

Cert certificate(EVP_PKEY* public_key, EVP_PKEY* signer, long start, long end, const char* issuer_org = nullptr) {
    Cert c(X509_new(), X509_free);
    REQUIRE(c);
    REQUIRE(X509_set_version(c.get(), 2) == 1);
    REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(c.get()), 1) == 1);
    REQUIRE(X509_set_pubkey(c.get(), public_key) == 1);
    auto* subject = X509_get_subject_name(c.get());
    REQUIRE(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("probe.example"), -1, -1, 0) == 1);
    REQUIRE(X509_set_issuer_name(c.get(), subject) == 1);
    if (issuer_org)
        REQUIRE(X509_NAME_add_entry_by_txt(X509_get_issuer_name(c.get()), "O", MBSTRING_ASC,
                reinterpret_cast<const unsigned char*>(issuer_org), -1, -1, 0) == 1);
    REQUIRE(ASN1_TIME_set(X509_getm_notBefore(c.get()), NOW + start));
    REQUIRE(ASN1_TIME_set(X509_getm_notAfter(c.get()), NOW + end));
    REQUIRE(X509_sign(c.get(), signer, EVP_sha256()) > 0);
    return c;
}

J3Result reply(const char* name, const char* line, int length) {
    J3Result r;
    r.name = name;
    r.first_line = line;
    r.bytes = length;
    r.responded = true;
    return r;
}
}

TEST_CASE("sub-day certificate expiry and future activation are not rounded away") {
    auto k = key();
    auto expired = certificate(k.get(), k.get(), -86400, -3600);
    CertificateInfo info;
    inspect_certificate(expired.get(), info, NOW);
    CHECK(info.certificate_times_valid);
    CHECK(info.days_left == 0);
    CHECK(info.certificate_expired);
    CHECK_FALSE(info.certificate_not_yet_valid);
    auto future = certificate(k.get(), k.get(), 300, 86400);
    inspect_certificate(future.get(), info, NOW);
    CHECK(info.age_days == 0);
    CHECK(info.certificate_not_yet_valid);
    CHECK_FALSE(info.certificate_expired);
    auto boundary = certificate(k.get(), k.get(), -3600, 0);
    inspect_certificate(boundary.get(), info, NOW);
    CHECK_FALSE(info.certificate_expired);
}

TEST_CASE("short-lived certificates have exact validity metadata") {
    auto k = key();
    auto c = certificate(k.get(), k.get(), -3600, 159 * 3600, "Let's Encrypt");
    CertificateInfo info;
    inspect_certificate(c.get(), info, NOW);
    CHECK(info.total_validity_seconds == 160 * 3600);
    CHECK(info.total_validity_days == 6);
    CHECK(info.certificate_times_valid);
    CHECK(info.is_letsencrypt); // issuer name only; no trust assertion
    CHECK_FALSE(info.self_issued);
    CHECK_FALSE(info.self_signed);
    CHECK(info.cert_sha256.size() == 64);
}

TEST_CASE("equal issuer and subject names do not prove a self-signature") {
    auto leaf = key();
    auto signer = key();
    auto c = certificate(leaf.get(), signer.get(), -3600, 86400);
    CertificateInfo info;
    ERR_clear_error();
    inspect_certificate(c.get(), info, NOW);
    CHECK(info.self_issued);
    CHECK(info.self_signature_checked);
    CHECK_FALSE(info.self_signed);
    CHECK(ERR_peek_error() == 0);
    auto self = certificate(leaf.get(), leaf.get(), -3600, 86400);
    inspect_certificate(self.get(), info, NOW);
    CHECK(info.self_signed);
    inspect_certificate(nullptr, info, NOW);
    CHECK_FALSE(info.certificate_present);
    CHECK_FALSE(info.self_signed);
}

TEST_CASE("invalid certificate dates remain unknown rather than day zero") {
    auto k = key();
    auto reversed = certificate(k.get(), k.get(), 86400, -86400);
    CertificateInfo info;
    inspect_certificate(reversed.get(), info, NOW);
    CHECK_FALSE(info.certificate_times_valid);
    auto c = certificate(k.get(), k.get(), -3600, 86400, "Internal R3 lab");
    REQUIRE(ASN1_STRING_set(X509_getm_notBefore(c.get()), "bad date", 8) == 1);
    inspect_certificate(c.get(), info, NOW);
    CHECK_FALSE(info.certificate_times_valid);
    CHECK_FALSE(info.certificate_expired);
    CHECK_FALSE(info.is_letsencrypt);
}

TEST_CASE("HTTP without Server and interim responses is parsed normally") {
    auto r = parse_https_response("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    CHECK(r.http_valid);
    CHECK(r.headers_complete);
    CHECK(r.server_hdr.empty());
    CHECK_FALSE(r.version_anomaly);
    r = parse_https_response("HTTP/1.1 103 Early Hints\r\nServer: interim\r\n\r\n"
                             "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204\r\n\r\n");
    CHECK(r.http_valid);
    CHECK(r.status_code == 204);
    CHECK(r.server_hdr.empty());
    CHECK(parse_https_response("HTTP/1.0 404 Not Found\n\n").http_valid);
}

TEST_CASE("HTTP parsing separates incomplete headers from invalid responses") {
    for (const char* data : {"", "HTTP/1.1 20", "HTTP/1.1 200 OK\r\nServer: x",
                              "HTTP/1.1 103 Early Hints\r\n\r\n"}) {
        auto r = parse_https_response(data);
        CHECK_FALSE(r.http_valid);
        CHECK_FALSE(r.version_anomaly);
        CHECK_FALSE(r.headers_complete);
    }
    CHECK(parse_https_response("HTTP/2.0 200 OK\r\n\r\n").version_anomaly);
    for (const char* data : {"HTTP/1.1 20x Bad\r\n\r\n", "HTTP/1.1 600 Weird\r\n\r\n",
                              "HTTP/1.1 2000 Wrong\r\n\r\n", "binary junk\r\n\r\n",
                              "HTTP/1.1 200 OK\r\nServer : x\r\n\r\n", "HTTP/1.1 200 O\x7fK\r\n\r\n"})
        CHECK_FALSE(parse_https_response(data).http_valid);
    std::string many;
    for (int i = 0; i < 10; ++i) many += "HTTP/1.1 103 Early Hints\r\n\r\n";
    CHECK_FALSE(parse_https_response(many).http_valid);
    CHECK_FALSE(parse_https_response("HTTP/1.1 200 OK\r\nX-Pad: " + std::string(HTTPS_HEADER_LIMIT, 'a')).http_valid);
}

TEST_CASE("only actual HTTP fields contribute header observations") {
    const auto r = parse_https_response("HTTP/1.1 200 OK\r\nsErVeR: demo\r\nVia: a\r\nVIA: b\r\n"
                                       "Via-Other: false\r\n\r\nX-Forwarded-For: body text\nServer: forged");
    REQUIRE(r.http_valid);
    CHECK(r.server_hdr == "demo");
    CHECK(r.via_hdr == "a, b");
    CHECK(r.xff_hdr.empty());
    CHECK(r.has_proxy_leak);
    const auto body = parse_https_response("HTTP/1.1 200 OK\r\n\r\nVia: body\nServer: body");
    CHECK_FALSE(body.has_proxy_leak);
    CHECK(body.server_hdr.empty());
}

TEST_CASE("crt.sh response errors never become positive or negative evidence") {
    for (const auto& body : std::vector<std::string>{"", "<html>temporary error</html>", "null", "{}", "[] garbage", "[/*bad*/]",
            "[", "[{\"id\":1},", "[{\"id\":0}]", "[{\"id\":1.5}]", "[{\"id\":\"12\"}]", "[{}]", "[1]",
            std::string(512 * 1024 + 1, ' ')}) {
        CAPTURE(body.size());
        auto r = parse_ct_response(body);
        CHECK_FALSE(r.lookup_complete);
        CHECK_FALSE(r.found);
        CHECK_FALSE(r.err.empty());
    }
    auto empty = parse_ct_response(" [ \n ] ");
    CHECK(empty.lookup_complete);
    CHECK_FALSE(empty.found);
    auto found = parse_ct_response("[{\"id\":42},{\"id\":42},{\"id\":43}]");
    CHECK(found.lookup_complete);
    CHECK(found.found);
    CHECK(found.log_entries == 2);
    HttpResp response;
    response.status = 200;
    response.err = "truncated body";
    CHECK_FALSE(response.ok());
    response.err.clear();
    response.status = 302;
    CHECK_FALSE(response.ok());
}

TEST_CASE("J3 compares first lines without asserting identical response bodies") {
    auto a = j3_analyze({reply("HTTP GET /", "HTTP/1.1 400 Bad Request", 80),
                         reply("random", "HTTP/1.1 400 Bad Request", 80)});
    CHECK(a.http_real == 2);
    CHECK(a.canned_identical == 2);
    auto malformed = j3_analyze({reply("random", "HTTP/1.1garbage", 80),
                                reply("random", "HTTP/2.0 200 OK", 80)});
    CHECK(malformed.http_real == 0);
    CHECK(malformed.http_bad_version == 2);
    auto groups = j3_analyze({reply("HTTP GET /", "HTTP/1.1 400 Bad Request", 80),
        reply("random", "HTTP/1.1 400 Bad Request", 80),
        reply("HTTP GET /", "HTTP/1.1 503 Busy", 90), reply("random", "HTTP/1.1 503 Busy", 90),
        reply("SSH", "HTTP/1.1 503 Busy", 90), reply("junk", "HTTP/1.1 503 Busy", 90)});
    CHECK(groups.canned_identical == 4);
    CHECK(groups.canned_line == "HTTP/1.1 503 Busy");
}
