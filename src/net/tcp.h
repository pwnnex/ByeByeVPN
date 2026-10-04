// SPDX-License-Identifier: GPL-3.0-or-later
// non-blocking tcp connect with timeout, plus thin send/recv wrappers.
// classifies failure modes (refused / timeout / unreachable / other / dns)
// so the caller can give meaningful diagnostics.
#pragma once

#include "../common/platform.h"
#include "read_end.h"
#include <string>

// connect to host:port, return socket on success, INVALID_SOCKET on failure.
// err is set to "refused" / "timeout" / "unreachable" / "other" / "dns" on
// failure. syn retransmission is off, see tcp.cpp.
SOCKET tcp_connect(const std::string& host, int port, int timeout_ms, std::string& err);

// recv with SO_RCVTIMEO set to timeout_ms. returns recv()'s value.
int tcp_recv_to(SOCKET s, char* buf, int max, int timeout_ms);

// best-effort send-all. returns total bytes sent or recv()'s error code.
int tcp_send_all(SOCKET s, const void* data, int n);

// classify a recv() return value; call right after recv on the same thread.
ReadEnd classify_recv(int rc, int wsa_error);
