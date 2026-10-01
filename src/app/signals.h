// SPDX-License-Identifier: GPL-3.0-or-later
// signal registry. every id that can reach the score has a passport in
// docs/SIGNALS.md; ids without one never reach evaluate_report().
#pragma once

#include "../common/outcome.h"

#include <string>
#include <vector>

struct SignalSpec {
    const char* id;
    const char* claim;      // what a positive says about the target
    char        tier;       // 'A' named signature, 'B' accumulative, 'R' reference only
    int         weight;     // score penalty on positive, 0 for reference
    bool        heuristic;  // author heuristic, not from the classifier model
    const char* group;      // ids measuring one fact; a group scores once
};

const std::vector<SignalSpec>& signal_registry();
const SignalSpec* signal_spec(const std::string& id);

// one measured check against the target
struct CheckResult {
    std::string id;
    int         port = 0;
    Outcome     outcome = Outcome::Inconclusive;
    int         observations = 0;   // how many probes went into it
    std::string observed;           // what was seen, plain facts
    std::string reason;             // why inconclusive or n/a
};

// passport anchor for the printed report
std::string signal_passport(const std::string& id);
