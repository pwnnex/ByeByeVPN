// SPDX-License-Identifier: GPL-3.0-or-later
#include "tcpfp.h"
#include "../common/platform.h"
#include "../common/util.h"
#include "../net/tcp.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <vector>

using std::string;
using std::vector;

namespace {

double median(vector<double> v) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    size_t n = v.size();
    return (n & 1) ? v[n/2] : 0.5 * (v[n/2 - 1] + v[n/2]);
}

double stddev(const vector<double>& v) {
    if (v.size() < 2) return 0.0;
    double mean = 0.0;
    for (auto x: v) mean += x;
    mean /= v.size();
    double s = 0.0;
    for (auto x: v) s += (x - mean) * (x - mean);
    return std::sqrt(s / v.size());
}

// classify the OS based on collected signals. coarse, no false certainty.
string classify_os(const TcpFp& f) {
    // peer_window heuristics on top of stddev / MSS:
    //   linux 5.x nginx: SndWnd often 64240 (or 64K), MSS 1460
    //   windows server 2022 IIS: SndWnd 65535, MSS 1460
    //   go runtime (xray default): SndWnd 65535 with wscale 10, MSS 1460
    //   bsd / openbsd: SndWnd 65535, different ts behavior
    if (f.peer_window <= 0 || f.peer_mss <= 0) {
        if (f.handshake_stddev_ms > 30.0 && f.handshake_median_ms < 200.0) {
            return "userspace-stack-like (high handshake variance, possible TUN/usermode TCP)";
        }
        return "unknown (insufficient signals)";
    }
    bool tight = f.handshake_stddev_ms < f.handshake_median_ms * 0.10;
    if (f.peer_window >= 64000 && f.peer_window <= 64512 && f.peer_mss == 1460 && tight) {
        return "linux 5.x kernel stack (nginx / openssh / haproxy class)";
    }
    if (f.peer_window == 65535 && f.peer_mss == 1460 && tight) {
        return "windows server / go-runtime stack (cannot disambiguate without raw SYN)";
    }
    if (f.peer_window > 65535) {
        return "wscale-aware modern stack (linux 6.x / freebsd / windows 11)";
    }
    if (f.handshake_stddev_ms > 30.0) {
        return "userspace-stack-like (high handshake variance, possible TUN/usermode TCP)";
    }
    return "generic kernel-stack (no specific stack signature)";
}

// one TCP handshake timed in microseconds, returns ms as double. -1 on fail.
double timed_connect(const string& host, int port, int to_ms) {
    auto t0 = std::chrono::steady_clock::now();
    string err;
    SOCKET s = tcp_connect(host, port, to_ms, err);
    if (s == INVALID_SOCKET) return -1.0;
    auto t1 = std::chrono::steady_clock::now();
    closesocket(s);
    return std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() / 1000.0;
}

// connect, immediately probe SIO_TCP_INFO, return the snapshot.
bool snapshot_tcp_info(const string& host, int port, int to_ms, SocketTcpInfo& out) {
    string err;
    SOCKET s = tcp_connect(host, port, to_ms, err);
    if (s == INVALID_SOCKET) return false;
    bool ok = query_socket_tcp_info(s, out);
    closesocket(s);
    return ok;
}

// closed-port behavior. returns ms-to-RST or -1 on timeout.
int closed_port_probe(const string& host, int port, int to_ms) {
    auto t0 = std::chrono::steady_clock::now();
    string err;
    SOCKET s = tcp_connect(host, port, to_ms, err);
    auto t1 = std::chrono::steady_clock::now();
    if (s != INVALID_SOCKET) { closesocket(s); return -2; /* unexpectedly open */ }
    int dt = (int)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    if (err == "refused")      return dt;          // got RST
    if (err == "timeout")      return -1;          // dropped
    return -1;
}

} // namespace

TcpFp tcp_fingerprint(const string& ip, int open_port, int closed_port_hint) {
    TcpFp f;
    if (open_port <= 0) {
        f.err = "no open port to probe";
        return f;
    }

    // 1) handshake distribution: 6 connects.
    vector<double> samples;
    samples.reserve(6);
    for (int i = 0; i < 6; ++i) {
        double ms = timed_connect(ip, open_port, 2000);
        if (ms > 0) samples.push_back(ms);
    }
    f.samples_taken = (int)samples.size();
    if (samples.size() < 3) {
        f.err = "too few successful handshakes (" + std::to_string(samples.size()) + "/6)";
        return f;
    }
    // drop top outlier
    std::sort(samples.begin(), samples.end());
    if (samples.size() >= 5) samples.pop_back();
    f.handshake_min_ms    = samples.front();
    f.handshake_max_ms    = samples.back();
    f.handshake_median_ms = median(samples);
    f.handshake_stddev_ms = stddev(samples);
    f.bimodal = f.handshake_stddev_ms > 0.5 * f.handshake_median_ms;

    // 2) peer window + MSS via SIO_TCP_INFO
    SocketTcpInfo info{};
    if (snapshot_tcp_info(ip, open_port, 2000, info)) {
        f.tcp_info_ok = true;
        f.peer_window = (int)info.send_window;
        f.peer_mss    = (int)info.mss;
    }

    // 3) closed-port behavior (optional)
    if (closed_port_hint > 0 && closed_port_hint <= 65535) {
        int dt = closed_port_probe(ip, closed_port_hint, 1500);
        if (dt == -1) {
            f.closed_port_behavior = "drop";
            f.closed_port_rtt_ms   = -1;
        } else if (dt == -2) {
            f.closed_port_behavior = "n/a (port unexpectedly open)";
            f.closed_port_rtt_ms   = -1;
        } else {
            f.closed_port_rtt_ms = dt;
            // anchor against handshake_min_ms: a RST within 2x of one-way RTT
            // is "fast" (kernel emits it); slower is firewall in path.
            if (dt <= (int)(f.handshake_min_ms * 2 + 5)) f.closed_port_behavior = "rst-fast";
            else                                          f.closed_port_behavior = "rst-slow";
        }
    } else {
        f.closed_port_behavior = "n/a";
    }

    // 4) ISN delta variance via SIO_TCP_INFO (no SYN-ACK ISN exposed by win stack;
    //    use the local-side SEQ from BytesOut window after handshake as a coarse
    //    proxy. limited but cheap.)
    //    skipped in this minimal impl: would need raw SYN to capture peer ISN.
    f.isn_samples = 0;
    f.isn_delta_stddev = 0.0;

    f.os_guess = classify_os(f);
    f.ok = true;
    return f;
}