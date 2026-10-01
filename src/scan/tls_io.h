// SPDX-License-Identifier: GPL-3.0-or-later
// socket must be nonblocking; retries share one deadline.
#pragma once
#include "../common/winhdr.h"
#include "tls_ctx.h"
#include <openssl/ssl.h>
#include <chrono>
#include <string>

template<class Operation>
int tls_io(SSL* ssl, SOCKET socket, std::chrono::steady_clock::time_point deadline,
           Operation operation, std::string& error, const char* fallback) {
    for (;;) {
        if (std::chrono::steady_clock::now() >= deadline) { error = "TLS I/O deadline exceeded"; return -1; }
        ssl_clear_errors();
        const int result = operation();
        if (result > 0) return result;
        const int why = SSL_get_error(ssl, result);
        if (why == SSL_ERROR_ZERO_RETURN) return 0;
        if (why != SSL_ERROR_WANT_READ && why != SSL_ERROR_WANT_WRITE) {
            error = ssl_error_string(fallback);
            return -1;
        }
        const auto left = std::chrono::duration_cast<std::chrono::microseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) { error = "TLS I/O deadline exceeded"; return -1; }
        timeval timeout{static_cast<long>(left / 1000000), static_cast<long>(left % 1000000)};
        fd_set ready;
        FD_ZERO(&ready); FD_SET(socket, &ready);
        const int selected = select(0, why == SSL_ERROR_WANT_READ ? &ready : nullptr,
                                    why == SSL_ERROR_WANT_WRITE ? &ready : nullptr, nullptr, &timeout);
        if (selected == 0) { error = "TLS I/O deadline exceeded"; return -1; }
        if (selected < 0) { error = "TLS socket wait failed"; return -1; }
    }
}
