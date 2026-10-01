// SPDX-License-Identifier: GPL-3.0-or-later
#include "outcome.h"

const char* outcome_name(Outcome o) {
    switch (o) {
    case Outcome::Positive:      return "positive";
    case Outcome::Negative:      return "negative";
    case Outcome::Inconclusive:  return "inconclusive";
    default:                     return "not applicable";
    }
}

Outcome combine_observations(const std::vector<Outcome>& obs) {
    int pos = 0, neg = 0, na = 0;
    for (Outcome o : obs) {
        if (o == Outcome::Positive) ++pos;
        else if (o == Outcome::Negative) ++neg;
        else if (o == Outcome::NotApplicable) ++na;
    }
    if (pos && neg) return Outcome::Inconclusive;
    if (pos >= 2) return Outcome::Positive;
    if (neg >= 2) return Outcome::Negative;
    if (!obs.empty() && na == (int)obs.size()) return Outcome::NotApplicable;
    return Outcome::Inconclusive;
}

bool observations_settled(const std::vector<Outcome>& obs, int max_obs) {
    if ((int)obs.size() >= max_obs) return true;
    int pos = 0, neg = 0;
    for (Outcome o : obs) {
        if (o == Outcome::Positive) ++pos;
        else if (o == Outcome::Negative) ++neg;
    }
    if (pos && neg) return true;
    const int left = max_obs - (int)obs.size();
    // two agree already, or nothing left can reach two
    if (pos >= 2 || neg >= 2) return true;
    return pos + left < 2 && neg + left < 2;
}
