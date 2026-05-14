// SPDX-License-Identifier: GPL-3.0-or-later
// machine-readable JSON serializer for a completed FullReport.
//
// emitted on stdout when --json is passed. the human-readable scan output
// is redirected to stderr in that mode (see console.cpp), so a caller can
// do `byebyevpn --json <ip> 1>report.json 2>/dev/null` and get a clean
// JSON document.
//
// the schema is flat and stable: top-level keys are tool / version /
// target / resolved_ip / score / label / stack / tspu{} / signals{} /
// geo[] / open_tcp[] / udp[] / tls_ports[] / tcp_fp{} / amnezia_sweep{}.
// every string value is JSON-escaped. no trailing commas. one object,
// pretty-printed with 2-space indent.
#pragma once

#include "report.h"
#include <string>

std::string json_report(const FullReport& R);
