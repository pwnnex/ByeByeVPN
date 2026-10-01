// SPDX-License-Identifier: GPL-3.0-or-later
// tcp stack fingerprint without admin / raw socket.
//
// classic p0f reads syn-ack options (mss, wscale, sack, ts, options order) to
// classify the os / tcp stack. that needs raw socket capture which on windows
// requires npcap or windivert with admin. we don't ship a kernel driver.
//
// instead we extract os-revealing signals via behavioral probes that work over
// regular winsock SOCK_STREAM:
//
//   1) advertised_recv_window: post-handshake call to WSAIoctl(sio_tcp_info_v0)
//      returns the local socket's view of the connection. on windows 10+ this
//      includes the peer's last advertised window. window value alone is a
//      coarse os hint (linux nginx ~64240, win iis ~65535, go runtime ~65535
//      with wscale 7).
//
//   2) handshake_rtt_dist: 6 sequential tcp connect() calls to the same open
//      port, drop top outlier, compute median + stddev. real linux kernel
//      stack has tight distribution (stddev ~rtt*0.05). a userspace tcp stack
//      (gvisor / sing-box tun / xray inbound over a tun device) shows higher
//      stddev because each connect bounces the user-thread stack.
//
//   3) closed_port_behavior: connect() to a port expected closed.
//        rst-fast  - RST within 2x the fastest handshake
//        rst-slow  - RST later than that
//        no answer - timeout; loss, filtering and ack-all paths all look alike
//
//   4) isn_entropy: not implemented, needs a raw socket.
//
// no os guess is made: on the ground-truth lab it named 0 of 9 windows
// targets correctly. reference output only, never scored.
#pragma once

#include <string>

struct TcpFp {
    bool        ok = false;
    int         samples_taken = 0;       // out of 6 attempts
    double      handshake_median_ms = 0.0;
    double      handshake_min_ms = 0.0;
    double      handshake_max_ms = 0.0;
    double      handshake_stddev_ms = 0.0;
    bool        bimodal = false;         // suggests usermode stack / tun

    int         peer_window = -1;        // last advertised peer recv window
    int         peer_mss = -1;           // negotiated mss as observed by win stack
    bool        tcp_info_ok = false;

    std::string closed_port_behavior;    // "rst-fast" / "rst-slow" / "no answer in 1500 ms" / ...
    int         closed_port_rtt_ms = -1;

    int         isn_samples = 0;
    double      isn_delta_stddev = 0.0;

    std::string os_guess;                // always "not estimated", kept for json
    std::string err;
};

// open_port: a port confirmed open from the prior tcp scan.
// closed_port_hint: a port we expect to be closed (firewall RST or drop).
//   pass -1 to skip the closed-port probe.
TcpFp tcp_fingerprint(const std::string& ip, int open_port, int closed_port_hint = -1);