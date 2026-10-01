// SPDX-License-Identifier: GPL-3.0-or-later
#include "tls_ctx.h"

#include <openssl/err.h>

#include <mutex>

void ssl_clear_errors() { ERR_clear_error(); }

std::string ssl_error_string(const char* fallback) {
    unsigned long first = ERR_get_error();
    while (ERR_get_error() != 0) { }        // drain, so the next probe starts clean
    if (first == 0) return fallback ? std::string(fallback) : std::string();
    char buf[256] = {0};
    ERR_error_string_n(first, buf, sizeof(buf));
    return buf[0] ? std::string(buf)
                  : (fallback ? std::string(fallback) : std::string());
}

SSL_CTX* shared_tls_client_ctx() {
    static SSL_CTX* ctx = nullptr;
    static std::once_flag once;
    std::call_once(once, []{
        ctx = SSL_CTX_new(TLS_client_method());
        if (ctx) {
            SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        }
    });
    return ctx;
}