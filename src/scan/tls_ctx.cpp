// SPDX-License-Identifier: GPL-3.0-or-later
#include "tls_ctx.h"

#include <mutex>

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