// SPDX-License-Identifier: GPL-3.0-or-later
// config-advisor: predict a config's TSPU/DPI detectability BEFORE deploy.
//
// it takes an Xray (v2ray-core) or sing-box JSON config and runs the same
// signal logic the live scanner's verdict engine uses — brand-on-non-owning-
// ASN dest, default protocol ports, plaintext transports, missing fallbacks,
// debug leaks — but statically, against the config the operator is about to
// ship. no network, no target. reuses src/scan/brand.cpp for the brand table.
//
// this core is platform-agnostic (no console / no Win32) so it compiles into
// the Linux unit-test build. the colored CLI printer lives in src/app/cli.cpp.
#pragma once

#include "../common/json.h"

#include <string>
#include <vector>

struct AuditFinding {
    enum class Sev { High, Medium, Info };
    Sev         sev = Sev::Info;
    bool        named = false;   // true = a named-protocol signature (A-tier:
                                 // an instant TSPU handshake-block, not a soft
                                 // accumulating anomaly).
    std::string tag;             // short stable id, e.g. "reality-dest-brand"
    std::string where;           // "inbound[0] vless :443" — locates the issue
    std::string title;           // what is wrong
    std::string fix;             // how to harden it
};

struct ConfigAudit {
    bool        ok = false;
    std::string err;
    std::string format = "unknown";   // "xray" / "sing-box" / "unknown"
    int         inbound_count = 0;

    std::vector<AuditFinding> findings;
    int high = 0, medium = 0, info = 0;

    // predicted TSPU verdict, mirroring the live engine's A/B tiering:
    //   any named-protocol finding         -> "IMMEDIATE BLOCK"
    //   >=1 High or >=2 Medium (soft)       -> "BLOCK (accumulative)"
    //   exactly 1 Medium                    -> "THROTTLE / QoS"
    //   otherwise                           -> "PASS / ALLOW"
    std::string tspu_tier = "PASS / ALLOW";
    std::string verdict_line;
    int a_hits = 0;   // named-protocol signature count
    int b_hits = 0;   // soft-anomaly count (High + Medium)
};

// audit an already-parsed config tree.
ConfigAudit audit_config_json(const JsonValue& root);

// audit a WireGuard / AmneziaWG `.conf` (INI) file.
ConfigAudit audit_wireguard_ini(const std::string& text);

// auto-detect the format of `text` (JSON Xray/sing-box vs INI WireGuard/
// AmneziaWG) and audit it. on a parse failure the returned ConfigAudit has
// ok=false and err set.
ConfigAudit audit_config_text(const std::string& text);

// serialize an audit result to a machine-readable JSON object (for --json).
std::string config_audit_to_json(const ConfigAudit& a);
