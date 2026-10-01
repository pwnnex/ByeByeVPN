// SPDX-License-Identifier: GPL-3.0-or-later
// reuse one SSL_CTX for client tls probes (verify=none, min=tls1.2)
// lazy init, shared across threads; each connection gets its own SSL
#pragma once

#include <openssl/ssl.h>

#include <string>

SSL_CTX* shared_tls_client_ctx();

// return the first openssl error and drain the rest
// call ssl_clear_errors() before the operation, or stale errors leak into the next probe
std::string ssl_error_string(const char* fallback);

// drop anything already queued so a later failure reports only its own errors.
void ssl_clear_errors();