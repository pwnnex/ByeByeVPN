// SPDX-License-Identifier: GPL-3.0-or-later
// parallel TCP port scan with banner grab + interactive cancel ('q' to skip).
#pragma once

#include <string>
#include <vector>
#include <cstddef>

struct TcpOpen {
    int         port       = 0;
    long long   connect_ms = -1;
    std::string banner;     // grabbed on connect, if any
    std::string err;        // only set on failure: "timeout"/"refused"/"other"/"dns"
};

struct ScanStats {
    std::size_t scanned  = 0;
    std::size_t timeouts = 0;
    std::size_t refused  = 0;
    std::size_t other    = 0;
    bool        skipped  = false;
};

TcpOpen probe_tcp(const std::string& host, int port, int to_ms);

std::vector<TcpOpen> scan_tcp(const std::string& host,
                              const std::vector<int>& ports,
                              int threads, int to_ms,
                              ScanStats* stats = nullptr);