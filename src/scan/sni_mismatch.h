// SPDX-License-Identifier: GPL-3.0-or-later
// dpi --real: the same sni to the owner's node and to the address the name
// really lives on. a name that passes to its own address and fails to the
// node points at an sni plus ip rule on this path (docs/TSPU-MODEL.md F10).
// it measures this client's path at this moment, not the node.
#pragma once

#include "../common/outcome.h"

#include <string>
#include <vector>

// how one clienthello ended
enum class ChEnd { NoTcp, Reply, Reset, Silent, Other };
const char* ch_end_name(ChEnd e);

// one round: target sni to the node, benign sni to the node, target sni to the real address
struct SniRound {
    ChEnd node_target = ChEnd::Other;
    ChEnd node_benign = ChEnd::Other;
    ChEnd real_target = ChEnd::Other;
};

enum class SniRoundVerdict { Mismatch, NameBlocked, Passes, Unclear };
SniRoundVerdict sni_round_verdict(const SniRound& r);

struct SniMismatchVerdict {
    Outcome     outcome = Outcome::Inconclusive;
    bool        name_blocked = false;   // the name fails to both addresses
    std::string reason;
};
SniMismatchVerdict sni_mismatch_verdict(const std::vector<SniRound>& rounds);
