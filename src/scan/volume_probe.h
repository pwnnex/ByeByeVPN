// SPDX-License-Identifier: GPL-3.0-or-later
// client-side volume check (dpi --volume): download one resource from the
// owner's node and from a control host over TLS, record where bytes stop.
// it measures the path from this client to that host at this moment; the
// result does not carry over to another connection, operator or day.
#pragma once

#include "../common/outcome.h"

#include <string>
#include <vector>

// field reports put the freeze at 16-20 KB (docs/TSPU-MODEL.md F7); a
// resource must serve at least this much for a pass to mean anything
constexpr long long VOLUME_WINDOW = 64 * 1024;
constexpr long long VOLUME_CAP    = 128 * 1024;   // stop reading here
constexpr int       VOLUME_STALL_MS = 8000;       // no byte for this long, connection open

struct VolumeTrace {
    enum class End { Failed, Complete, Cap, Stall, Closed, Reset };
    End         end = End::Failed;
    bool        connected = false;
    bool        tls_ok = false;
    bool        response = false;     // an http status line arrived
    int         status = 0;
    long long   content_length = -1;
    long long   body = 0;             // body bytes received
    long long   wire = 0;             // bytes read from the socket, tls handshake included
    int         first_byte_ms = -1;
    int         last_byte_ms = -1;
    int         total_ms = 0;
    std::string err;
};

const char* volume_end_name(VolumeTrace::End e);

// one transfer: positive = bytes then silence on an open connection
Outcome volume_transfer_outcome(const VolumeTrace& t);

struct VolumeVerdict {
    Outcome     outcome = Outcome::Inconclusive;
    std::string reason;
    long long   stall_wire = -1;      // lowest agreeing stall offset
};

// controls run before and after the targets; both must carry the window
VolumeVerdict volume_verdict(const std::vector<VolumeTrace>& targets,
                             const std::vector<VolumeTrace>& controls);

// split "host[:port][/path]"; false on an empty host or a bad port
bool volume_parse_endpoint(const std::string& spec, std::string& host, int& port, std::string& path);

// network side, volume_probe.cpp
VolumeTrace volume_fetch(const std::string& ip, int port, const std::string& host, const std::string& path);
