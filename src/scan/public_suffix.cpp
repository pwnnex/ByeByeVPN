// SPDX-License-Identifier: GPL-3.0-or-later
#include "public_suffix.h"

#include <algorithm>
#include <iterator>
#include <string_view>

namespace {
constexpr std::string_view rules[] = {
#include "public_suffix_data.inc"
};

bool has_rule(const std::string& name) {
    return std::binary_search(std::begin(rules), std::end(rules), name);
}
}

size_t public_suffix_start(const std::vector<std::string>& labels) {
    if (labels.empty()) return 0;
    size_t start = labels.size() - 1;
    std::string suffix;
    for (size_t i = labels.size(); i-- > 0;) {
        suffix = labels[i] + (suffix.empty() ? "" : "." + suffix);
        if (has_rule("!" + suffix)) return i + 1;
        if (has_rule(suffix)) start = i;
        if (i > 0 && has_rule("*." + suffix)) start = i - 1;
    }
    return start;
}

size_t registrable_domain_start(const std::vector<std::string>& labels) {
    const size_t start = public_suffix_start(labels);
    return start ? start - 1 : 0;
}
