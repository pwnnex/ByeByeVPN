// SPDX-License-Identifier: GPL-3.0-or-later
// TCP stack fingerprint without admin / raw socket.
//
// classic p0f reads SYN-ACK options (mss, wscale, sack, ts, options order) to
// classify the OS / TCP stack. that needs raw socket capture which on Windows
// requires Npcap or WinDivert with admin. we don't ship a kernel driver.
//
// instead we extract OS-revealing signals via behavioral probes that work over
// regular winsock SOCK_STREAM:
//
//   1) advertised_recv_window: post-handshake call to WSAIoctl(SIO_TCP_INFO_v0)
//      returns the local socket's view of the connection. on Windows 10+ this
//      includes the peer's last advertised window. window value alone is a
//      coarse OS hint (linux nginx ~64240, win iis ~65535, go runtime ~65535
//      with wscale 7).
//
//   2) handshake_rtt_dist: 6 sequential TCP connect() calls to the same open
//      port, drop top outlier, compute median + stddev. real linux kernel
//      stack has tight distribution (stddev ~RTT*0.05). a userspace TCP stack
//      (gvisor / sing-box tun / xray inbound over a TUN device) shows higher
//      stddev because each connect bounces the user-thread stack.
//
//   3) closed_port_behavior: try connect() to a port that had RST on the full
//      scan + a port that timed out. classify:
//        rst-fast  - server's stack returned RST within RTT (typical linux/win)
//        rst-slow  - RST returned but >2*RTT later (firewall in path)
//        drop      - timed out, no RST. firewall drop policy or full filter.
//      operator-grade firewalls (TSPU ACL) drop instead of RST. residential
//      ISPs RST.
//
//   4) isn_entropy: capture SYN reply ISN via WSAIoctl(SIO_TCP_INFO) over 5
//      successive connects, measure delta variance. linux/win use crypto-grade
//      ISN (high variance). older / embedded stacks have linear ISN counter
//      (low variance). go runtime ISN looks slightly different from linux.
//
// the resulting "stack guess" is a coarse label, never a hard signal on its
// own. it feeds the verdict engine as a soft tell when combined with port
// profile and JA4S.
#pragma once

#include <string>

struct TcpFp {
    bool        ok = false;
    int         samples_taken = 0;       // out of 6 attempts
    double      handshake_median_ms = 0.0;
    double      handshake_min_ms = 0.0;
    double      handshake_max_ms = 0.0;
    double      handshake_stddev_ms = 0.0;
    bool        bimodal = false;         // suggests usermode stack / TUN

    int         peer_window = -1;        // last advertised peer recv window
    int         peer_mss = -1;           // negotiated MSS as observed by win stack
    bool        tcp_info_ok = false;

    std::string closed_port_behavior;    // "rst-fast" / "rst-slow" / "drop" / "n/a"
    int         closed_port_rtt_ms = -1;

    int         isn_samples = 0;
    double      isn_delta_stddev = 0.0;

    std::string os_guess;                // human label, e.g. "linux/nginx-like"
    std::string err;
};

// open_port: a port confirmed open from the prior TCP scan.
// closed_port_hint: a port we expect to be closed (firewall RST or drop).
//   pass -1 to skip the closed-port probe.
TcpFp tcp_fingerprint(const std::string& ip, int open_port, int closed_port_hint = -1);