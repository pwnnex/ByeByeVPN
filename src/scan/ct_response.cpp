// SPDX-License-Identifier: GPL-3.0-or-later
#include "ct.h"
#include "../common/json.h"
#include "../common/util.h"
#include <cmath>
#include <set>

CtCheck parse_ct_response(const std::string& body) {
    CtCheck r;
    r.queried = true;
    if (body.size() > 512 * 1024) { r.err = "crt.sh response too large"; return r; }
    const auto text = trim(body);
    // the shared config parser accepts comments; service JSON must not.
    bool quoted = false, escaped = false;
    for (char c : text) {
        if (quoted) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') quoted = false;
        } else if (c == '"') quoted = true;
        else if (c == '/') { r.err = "comments in crt.sh JSON"; return r; }
    }
    bool ok = false;
    const auto root = json_parse(text, &ok);
    if (!ok || !root.is_arr() || text.empty() || text.front() != '[') {
        r.err = "invalid crt.sh JSON array";
        return r;
    }
    std::set<double> ids;
    for (const auto& row : root.arr) {
        const auto& id = row["id"];
        if (!row.is_obj() || !id.is_num() || !std::isfinite(id.num) || id.num < 1 ||
            id.num > 9007199254740991.0 || std::floor(id.num) != id.num) {
            r.err = "invalid crt.sh record";
            return r;
        }
        ids.insert(id.num);
    }
    r.lookup_complete = true;
    r.found = !ids.empty();
    r.log_entries = static_cast<int>(ids.size());
    return r;
}
