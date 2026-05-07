// TSPU helpers: management-subnet recogniser, redirect-page blacklist.
// see DanielLavrushin/tspu-docs ch. 5 / 7 / 10 for the methodology.
#pragma once

#include <string>

// returns true if addr looks like a tspu mgmt-subnet hop.
//   layout: 10.<region>.<site>.Z, with Z in [131..235], [241..245], or 254.
//   used by traceroute analysis.
bool looks_like_tspu_hop(const std::string& addr);

// case-insensitive substring match against a curated list of operator
// warning-page hostnames / IPs. returns the matched marker on hit, or
// nullptr otherwise. used by HTTP probe to detect type-A blocks.
const char* looks_like_tspu_redirect(const std::string& location);
