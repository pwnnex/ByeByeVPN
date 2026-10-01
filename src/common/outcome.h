// SPDX-License-Identifier: GPL-3.0-or-later
// three-valued result of one measurement, plus "not applicable".
// inconclusive means the measurement did not happen; it says nothing
// about the target and never turns into negative.
#pragma once

#include <vector>

enum class Outcome {
    Positive,       // target has the property
    Negative,       // target lacks it, and we saw proof
    Inconclusive,   // measurement failed or disagreed
    NotApplicable,  // nothing to measure here
};

const char* outcome_name(Outcome o);

// repeats rule: at least two agreeing conclusive observations and no
// contradiction. a mix of positive and negative is unstable, not a vote.
Outcome combine_observations(const std::vector<Outcome>& obs);

// true once more observations can no longer change the combined result
bool observations_settled(const std::vector<Outcome>& obs, int max_obs = 3);
