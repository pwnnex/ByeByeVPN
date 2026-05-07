// non-blocking TCP connect with timeout, plus thin send/recv wrappers.
// classifies failure modes (refused / timeout / other / dns) so the
// caller can give meaningful diagnostics.
#pragma once

#include "../common/winhdr.h"
#include <string>

// connect to host:port, return socket on success, INVALID_SOCKET on failure.
// err is set to "refused" / "timeout" / "other" / "dns" on failure.
SOCKET tcp_connect(const std::string& host, int port, int timeout_ms, std::string& err);

// recv with SO_RCVTIMEO set to timeout_ms. returns recv()'s value.
int tcp_recv_to(SOCKET s, char* buf, int max, int timeout_ms);

// best-effort send-all. returns total bytes sent or recv()'s error code.
int tcp_send_all(SOCKET s, const void* data, int n);
