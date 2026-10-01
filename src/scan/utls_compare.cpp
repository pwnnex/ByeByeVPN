// SPDX-License-Identifier: GPL-3.0-or-later
#include "utls.h"

#include <utility>

namespace {
// omit the negotiated cipher; each client offers a different list
std::string structure(const std::string& fp) {
    auto first = fp.find('_');
    auto second = first == std::string::npos ? first : fp.find('_', first + 1);
    return second == std::string::npos ? fp : fp.substr(0, first) + fp.substr(second);
}
}

UtlsDualProbe compare_utls_probes(UtlsProbeResult chrome, UtlsProbeResult openssl) {
    UtlsDualProbe d;
    d.chrome = std::move(chrome);
    d.openssl = std::move(openssl);
    d.both_completed = d.chrome.handshake_completed && d.openssl.handshake_completed;
    d.both_responded = d.chrome.server_hello_received && d.openssl.server_hello_received;
    d.only_chrome_ok = d.chrome.server_hello_received && !d.openssl.server_hello_received;
    d.only_openssl_ok = !d.chrome.server_hello_received && d.openssl.server_hello_received;
    if (d.both_completed && !d.chrome.cert_sha256.empty() && !d.openssl.cert_sha256.empty())
        d.cert_differs = d.chrome.cert_sha256 != d.openssl.cert_sha256;
    if (d.both_responded && !d.chrome.ja4s.empty() && !d.openssl.ja4s.empty())
        d.ja4s_differs = structure(d.chrome.ja4s) != structure(d.openssl.ja4s);

    if (d.only_chrome_ok || d.only_openssl_ok)
        d.verdict = "Only one probe received ServerHello. TLS policy, negotiation or transient failure may explain this.";
    else if (d.cert_differs)
        d.verdict = "Completed TLS probes returned different certificates; frontend routing is one possible cause.";
    else if (d.both_responded)
        d.verdict = d.ja4s_differs ? "ServerHello parameters differ between probes; ordinary TLS negotiation can do this." :
                                   "Both probes received the same ServerHello structure.";
    else
        d.verdict = "Neither probe received a usable ServerHello.";
    if (d.chrome.server_hello_received && !d.chrome.handshake_completed)
        d.verdict += " The raw Chrome probe stops at ServerHello.";
    // naming products here read as a hint
    d.verdict += " No protocol is identified by this comparison.";
    return d;
}
