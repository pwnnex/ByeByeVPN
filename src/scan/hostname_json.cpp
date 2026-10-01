// SPDX-License-Identifier: GPL-3.0-or-later
#include "hostname_marks.h"

#include <cstdio>

namespace {
std::string quote(const std::string& text, bool byte_escape = false) {
    std::string out = "\"";
    for (unsigned char c : text) {
        if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
        else if (c < 32 || (byte_escape && c >= 127)) {
            char buf[7];
            std::snprintf(buf, sizeof(buf), "\\u%04x", c);
            out += buf;
        } else out += static_cast<char>(c);
    }
    return out + '"';
}
}

std::string hostname_marks_json(const HostnameAnalysis& analysis) {
    std::string out = "[";
    for (const auto& m : analysis.marks) {
        if (out.size() > 1) out += ',';
        out += "{\"token\":" + quote(m.token) + ",\"label\":" + quote(m.label) +
               ",\"decoded_label\":" + quote(m.decoded_label) + ",\"host\":" + quote(m.host) +
               ",\"in_subdomain\":" + (m.in_subdomain ? "true" : "false") +
               ",\"tier\":" + quote(hostname_tier_name(m.tier)) + ",\"kind\":" + quote(m.kind) +
               ",\"why\":" + quote(m.why) + ",\"sources\":[";
        for (size_t i = 0; i < m.sources.size(); ++i) {
            if (i) out += ',';
            out += quote(m.sources[i]);
        }
        out += "]}";
    }
    return out + ']';
}

std::string hostname_report_json(const std::vector<std::string>& names) {
    std::string out = "{\"mode\":\"hostname-analysis\",\"evidence_source\":\"names\","
                      "\"protocol_confirmed\":false,\"network_checked\":false,\"score_impact\":0,"
                      "\"error\":";
    out += names.empty() ? "\"need at least one hostname\"" : "null";
    out += ",\"results\":[";
    for (size_t i = 0; i < names.size(); ++i) {
        if (i) out += ',';
        const auto parsed = parse_hostname(names[i]);
        const auto a = analyze_hostname(names[i]);
        const bool invalid = parsed.status == HostnameInput::Status::Invalid;
        const char* status = invalid ? "invalid" : parsed.status == HostnameInput::Status::IpLiteral
                           ? "ip_literal" : "hostname";
        out += "{\"input\":" + quote(names[i], invalid) + ",\"status\":" + quote(status) +
               ",\"normalized_host\":" + quote(parsed.canonical) + ",\"error\":" +
               (invalid ? quote(parsed.error) : "null") + ",\"strong\":" + std::to_string(a.strong) +
               ",\"moderate\":" + std::to_string(a.moderate) + ",\"weak\":" + std::to_string(a.weak) +
               ",\"marks\":" + hostname_marks_json(a) + '}';
    }
    return out + "]}\n";
}
