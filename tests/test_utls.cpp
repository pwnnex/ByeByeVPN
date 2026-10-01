// SPDX-License-Identifier: GPL-3.0-or-later
#include "doctest.h"
#include "../src/scan/utls.h"

TEST_CASE("ServerHello is not a completed Chrome TLS handshake") {
    UtlsProbeResult chrome, openssl;
    chrome.server_hello_received = openssl.server_hello_received = true;
    openssl.handshake_completed = true;
    chrome.ja4s = "t130200_1301_abcdef";
    openssl.ja4s = "t130200_1302_abcdef";
    auto d = compare_utls_probes(chrome, openssl);
    CHECK(d.both_responded);
    CHECK_FALSE(d.both_completed);
    CHECK_FALSE(d.ja4s_differs);
    CHECK_FALSE(d.cert_differs);
    CHECK(d.verdict.find("stops at ServerHello") != std::string::npos);
}

TEST_CASE("failed OpenSSL handshake can still have a valid ServerHello") {
    UtlsProbeResult chrome, openssl;
    chrome.server_hello_received = openssl.server_hello_received = true;
    chrome.ja4s = "t130200_1301_abcdef";
    openssl.ja4s = "t120300_c02f_123456";
    auto d = compare_utls_probes(chrome, openssl);
    CHECK(d.ja4s_differs);
    CHECK_FALSE(d.only_chrome_ok);
    CHECK_FALSE(d.only_openssl_ok);
    CHECK_FALSE(d.both_completed);
}

TEST_CASE("incomplete probes cannot prove certificate steering") {
    UtlsProbeResult chrome, openssl;
    chrome.cert_sha256 = "aaa";
    openssl.cert_sha256 = "bbb";
    CHECK_FALSE(compare_utls_probes(chrome, openssl).cert_differs);
    chrome.handshake_completed = openssl.handshake_completed = true;
    CHECK(compare_utls_probes(chrome, openssl).cert_differs);
    openssl.cert_sha256.clear();
    CHECK_FALSE(compare_utls_probes(chrome, openssl).cert_differs);
}

TEST_CASE("one-sided or absent TLS replies do not identify a VPN") {
    for (bool reply : {false, true}) {
        UtlsProbeResult chrome, openssl;
        chrome.server_hello_received = reply;
        auto d = compare_utls_probes(chrome, openssl);
        CHECK(d.only_chrome_ok == reply);
        CHECK_FALSE(d.both_responded);
        CHECK(d.verdict.find("No protocol is identified") != std::string::npos);
        CHECK(d.verdict.find("REALITY") == std::string::npos);
    }
}
