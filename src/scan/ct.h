// SPDX-License-Identifier: GPL-3.0-or-later
// crt.sh search results; a missing match is not proof of absence from all logs.
#pragma once

#include <string>

struct CtCheck {
    bool        queried     = false;
    bool        lookup_complete = false;
    bool        found       = false;
    int         log_entries = 0; // legacy field: unique search record ids, not distinct logs
    std::string err;
};

CtCheck ct_check(const std::string& cert_sha256);
CtCheck parse_ct_response(const std::string& body);
