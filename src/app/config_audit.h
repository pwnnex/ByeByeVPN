// SPDX-License-Identifier: GPL-3.0-or-later
// offline config checks; no socket access or runtime validation
#pragma once

#include "../common/json.h"

#include <string>
#include <vector>

struct AuditFinding {
    enum class Sev { High, Medium, Info };
    Sev         sev = Sev::Info;
    bool        named = false;   // legacy scoring flag, not a network observation
    std::string category = "exposure"; // compatibility findings don't affect dpi scoring
    std::string tag;             // short stable id, e.g. "reality-dest-brand"
    std::string where;           // "inbound[0] vless :443" - locates the issue
    std::string title;           // what is wrong
    std::string fix;             // how to harden it
};

struct ConfigProtocol {
    int inbound = 0;
    std::string protocol;
    std::string transport;
    std::string security;
    std::string encryption;
    std::string flow = "not_applicable";
    int vision_users = 0;
    int plain_users = 0;
    int invalid_flow_users = 0;
};

struct ConfigAudit {
    bool        ok = false;
    std::string err;
    std::string format = "unknown";   // "xray" / "sing-box" / "unknown"
    int         inbound_count = 0;

    std::vector<AuditFinding> findings;
    std::vector<ConfigProtocol> protocols; // xray settings only; no keys or passwords
    int compatibility_errors = 0;
    int high = 0, medium = 0, info = 0;

    // predicted tspu verdict, mirroring the live engine's A/B tiering:
    //   any named-protocol finding         -> "IMMEDIATE BLOCK"
    //   >=1 High or >=2 Medium (soft)       -> "BLOCK (accumulative)"
    //   exactly 1 Medium                    -> "THROTTLE / QoS"
    //   otherwise                           -> "PASS / ALLOW"
    std::string tspu_tier = "UNKNOWN";
    std::string verdict_line;
    int a_hits = 0;   // named-protocol signature count
    int b_hits = 0;   // soft-anomaly count (High + Medium)
};

// audit an already-parsed config tree.
ConfigAudit audit_config_json(const JsonValue& root);

// audit a WireGuard / amneziawg `.conf` (ini) file.
ConfigAudit audit_wireguard_ini(const std::string& text);

// auto-detect the format of `text` (json xray/sing-box vs ini WireGuard/
// amneziawg) and audit it. on a parse failure the returned ConfigAudit has
// ok=false and err set.
ConfigAudit audit_config_text(const std::string& text);

// serialize an audit result to a machine-readable json object (for --json).
std::string config_audit_to_json(const ConfigAudit& a);
