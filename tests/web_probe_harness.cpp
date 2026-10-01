// SPDX-License-Identifier: GPL-3.0-or-later
// loopback driver; certificate files are temporary test credentials.
#include "../src/common/winhdr.h"
#include "../src/common/config.h"
#include "../src/app/json_report.h"
#include "../src/app/verdict.h"
#include "../src/scan/tls.h"
#include "../src/scan/https_probe.h"
#include "../src/scan/ct.h"
#include "../src/net/http.h"
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <string>

int main(int argc, char** argv) {
    if (argc < 3) return 64;
    WSADATA ws{};
    if (WSAStartup(MAKEWORD(2, 2), &ws) != 0) return 1;
    g_no_color = true;
    const std::string mode = argv[1];
    if (mode == "cert" && argc == 5) {
        EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1");
        X509* cert = X509_new();
        if (!key || !cert) return 1;
        const auto now = std::time(nullptr);
        X509_set_version(cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_set_pubkey(cert, key);
        X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
        X509_set_issuer_name(cert, X509_get_subject_name(cert));
        const bool expired = std::string(argv[4]) == "expired";
        ASN1_TIME_set(X509_getm_notBefore(cert), now - (expired ? 7 * 86400 : 3600));
        ASN1_TIME_set(X509_getm_notAfter(cert), now + (expired ? -3600 : 6 * 86400));
        if (X509_sign(cert, key, EVP_sha256()) <= 0) return 1;
        FILE* cert_file = std::fopen(argv[2], "wb");
        FILE* key_file = std::fopen(argv[3], "wb");
        if (!cert_file || !key_file) return 1;
        const int ok = PEM_write_X509(cert_file, cert) && PEM_write_PrivateKey(key_file, key, nullptr, nullptr, 0, nullptr, nullptr);
        std::fclose(cert_file); std::fclose(key_file);
        X509_free(cert); EVP_PKEY_free(key);
        WSACleanup();
        return ok ? 0 : 1;
    }
    const int port = std::atoi(argv[2]);
    if (port < 1 || port > 65535) return 64;
    if (mode == "http") {
        auto h = http_get("http://127.0.0.1:" + std::to_string(port) + "/lookup?q=test&output=json", 500);
        CtCheck ct;
        if (h.ok()) ct = parse_ct_response(h.body);
        std::printf("%d %d %zu %d %d\n", h.ok(), h.status, h.body.size(), ct.lookup_complete, ct.found);
    } else if (mode == "plain" || mode == "connect" || mode == "sstp") {
        const auto f = mode == "plain" ? fp_http_plain("127.0.0.1", port) :
                       mode == "connect" ? fp_http_connect("127.0.0.1", port) : sstp_probe("127.0.0.1", port);
        std::printf("{\"service\":\"%s\",\"connect_accepted\":%d,\"vpn_like\":%d,\"redirect\":%d}\n",
                    f.service.c_str(), f.connect_accepted, f.is_vpn_like, f.tspu_redirect);
    } else {
        FullReport report;
        report.target = "localhost";
        report.completed = true;
        report.fps.emplace_back();
        auto& pf = report.fps.back();
        pf.port = port;
        if (mode == "https") {
            pf.https = https_probe("127.0.0.1", port, "localhost", 500);
            pf.tls = TlsProbe{};
            pf.tls->ok = pf.https->tls_ok;
        } else if (mode == "tls") {
            pf.tls = tls_probe("127.0.0.1", port, "localhost", "http/1.1", 1000);
        } else if (mode == "ws") {
            pf.websocket = ws_probe("127.0.0.1", port, "localhost", 1000);
            pf.tls = TlsProbe{};
            pf.tls->ok = pf.websocket->tls_ok;
        } else if (mode == "grpc") {
            pf.grpc = grpc_probe("127.0.0.1", port, "localhost", 1000);
            pf.tls = TlsProbe{};
            pf.tls->ok = pf.grpc->tls_ok;
        } else if (mode == "empty") {
            report.scan_stats.scanned = report.scan_stats.timeouts = 1000;
        } else return 64;
        evaluate_report(report);
        std::fputs(json_report(report).c_str(), stdout);
    }
    WSACleanup();
    return 0;
}
