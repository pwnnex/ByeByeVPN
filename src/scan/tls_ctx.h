// SPDX-License-Identifier: GPL-3.0-or-later
// shared SSL_CTX for all client-side TLS probes (verify=none, min=TLS1.2).
// previously every tls_probe / https_probe / sni_consistency call allocated
// its own ctx + freed it again, which dominates handshake CPU when probing
// 11 SNIs against the same host. one ctx, lazy-init, never freed.
//
// thread-safe: SSL_CTX is reference-counted and safe to share across SSL*
// objects from multiple threads (OpenSSL 1.1+ guarantees this).
#pragma once

#include <openssl/ssl.h>

SSL_CTX* shared_tls_client_ctx();