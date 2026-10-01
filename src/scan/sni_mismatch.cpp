// SPDX-License-Identifier: GPL-3.0-or-later
#include "sni_mismatch.h"

const char* ch_end_name(ChEnd e) {
    switch (e) {
    case ChEnd::NoTcp:  return "no-tcp";
    case ChEnd::Reply:  return "reply";
    case ChEnd::Reset:  return "reset";
    case ChEnd::Silent: return "silent";
    default:            return "no-reply";
    }
}

namespace {
bool failed(ChEnd e) { return e == ChEnd::Reset || e == ChEnd::Silent; }
}

SniRoundVerdict sni_round_verdict(const SniRound& r) {
    if (r.node_target == ChEnd::Reply) return SniRoundVerdict::Passes;
    // without a working node and a reply from the real address nothing is compared
    if (!failed(r.node_target) || r.node_benign != ChEnd::Reply) return SniRoundVerdict::Unclear;
    if (r.real_target == ChEnd::Reply) return SniRoundVerdict::Mismatch;
    if (failed(r.real_target)) return SniRoundVerdict::NameBlocked;
    return SniRoundVerdict::Unclear;
}

SniMismatchVerdict sni_mismatch_verdict(const std::vector<SniRound>& rounds) {
    SniMismatchVerdict v;
    std::vector<Outcome> obs;
    int blocked = 0;
    for (const auto& r : rounds) {
        switch (sni_round_verdict(r)) {
        case SniRoundVerdict::Mismatch:    obs.push_back(Outcome::Positive); break;
        case SniRoundVerdict::Passes:      obs.push_back(Outcome::Negative); break;
        case SniRoundVerdict::NameBlocked: obs.push_back(Outcome::Inconclusive); ++blocked; break;
        default:                           obs.push_back(Outcome::Inconclusive); break;
        }
    }
    v.outcome = combine_observations(obs);
    v.name_blocked = blocked >= 2;
    if (v.outcome == Outcome::Positive)
        v.reason = "the name gets a TLS reply from its own address and fails to the node, with a benign name "
                   "to the node working: a rule on this path ties the name to its address";
    else if (v.outcome == Outcome::Negative)
        v.reason = "the node answers this name on this path";
    else if (v.name_blocked)
        v.reason = "the name fails to both addresses: it is blocked on this path whatever the address, "
                   "so the address pairing is not what stops it";
    else
        v.reason = "rounds disagree or a control failed (the node with a benign name, or the real address); "
                   "nothing is concluded";
    return v;
}
