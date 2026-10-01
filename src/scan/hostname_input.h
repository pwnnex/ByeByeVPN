// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

struct HostnameInput {
    enum class Status { Hostname, IpLiteral, Invalid };
    Status status = Status::Invalid;
    std::string canonical;
    std::vector<std::string> labels;
    std::vector<std::string> decoded_labels;
    std::string error;
    bool wildcard = false;
};

// ascii names and punycode only. '_' is allowed for dns service labels.
HostnameInput parse_hostname(const std::string& host);
