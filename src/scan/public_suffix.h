// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

// index of the public suffix. includes private rules; unknown suffixes use '*'.
size_t public_suffix_start(const std::vector<std::string>& labels);
size_t registrable_domain_start(const std::vector<std::string>& labels);
