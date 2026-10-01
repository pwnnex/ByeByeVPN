// SPDX-License-Identifier: GPL-3.0-or-later
#include "verdict.h"
#include "../common/console.h"
#include "../common/util.h"
#include <cstdio>

namespace {
// what no active probe from here can see
const char* const BLIND_SPOTS =
    "Reality with a working target, Shadowsocks AEAD and 2022, WireGuard without the "
    "owner's keys (--wg-pubkey, --wg-key), AmneziaWG, Trojan or VLESS behind a real site";
}

void print_verdict(const FullReport& r) {
    section(8, 8, "Findings");
    printf("\n");
    // one glance answer before the details
    const std::string score = std::to_string(r.score) + "/100";
    if (r.unreliable)
        card(C::RED, "UNRELIABLE", "preflight failed, the target was not measured");
    else if (!r.score_available)
        card(C::YEL, "INCONCLUSIVE", "no verdict: " + std::to_string(r.failed_reasons.size()) + " reason(s) listed below");
    else if (r.label == "CLEAN")
        card(C::GRN, "CLEAN " + score, "no named signature answered");
    else
        card(r.label == "NOISY" ? C::YEL : r.label == "SUSPICIOUS" ? C::ORG : C::RED, r.label + " " + score,
             std::to_string(r.scored.size()) + " weighted indicator(s), see below");
    printf("\n");
    if (r.unreliable) {
        printf("  %sUNRELIABLE%s: preflight failed; results describe this machine's path, not the target.\n",
               col(C::RED), col(C::RST));
        for (const auto& b : r.preflight.blockers) printf("    - %s\n", b.c_str());
    } else if (!r.score_available) {
        printf("  %sINCONCLUSIVE%s: the scan did not happen in a way that supports a verdict.\n",
               col(C::YEL), col(C::RST));
        for (const auto& why : r.failed_reasons) printf("    - %s\n", why.c_str());
    } else {
        printf("  Legacy heuristic: %d/100 (%s). Higher means fewer weighted indicators.\n", r.score, r.label.c_str());
        if (r.overridden)
            printf("  %sPreflight failed and was overridden with --i-know-what-i-am-doing.%s\n", col(C::RED), col(C::RST));
    }
    printf("  %s\n", r.stack_name.c_str());

    printf("\n  %sObserved services%s\n", col(C::BOLD), col(C::RST));
    if (r.port_observations.empty()) printf("    no usable service responses\n");
    for (const auto& [port, detail] : r.port_observations)
        printf("    :%-5d  %s\n", port, printable_prefix(detail, 220).c_str());

    printf("\n  %sWeighted indicators%s (each: what was seen, how often, passport)\n", col(C::BOLD), col(C::RST));
    if (r.scored.empty()) printf("    none\n");
    for (const auto& s : r.scored) {
        const SignalSpec* spec = signal_spec(s.id);
        printf("    - [%s tier %c, -%d] :%d %s\n", s.id.c_str(), s.tier, s.weight, s.port, spec ? spec->claim : "");
        printf("      seen: %s; %s\n", s.observed.c_str(), s.heuristic ? "author heuristic" : "from the classifier model");
        printf("      passport: %s\n", signal_passport(s.id).c_str());
    }

    bool any_unmeasured = false;
    for (const auto& c : r.checks) {
        if (c.outcome != Outcome::Inconclusive && c.outcome != Outcome::NotApplicable) continue;
        if (!any_unmeasured) printf("\n  %sCould not measure%s (no effect on the score)\n", col(C::BOLD), col(C::RST));
        any_unmeasured = true;
        printf("    - %s :%d  %s: %s\n", c.id.c_str(), c.port, outcome_name(c.outcome), c.reason.c_str());
    }
    if (r.checks_applicable)
        printf("\n  Coverage: %d of %d applicable signature checks gave a conclusive answer.\n",
               r.checks_conclusive, r.checks_applicable);

    printf("\n  %sNotes and limits%s (reference only)\n", col(C::BOLD), col(C::RST));
    for (const auto& [tag, text] : r.notes)
        printf("    [%s] %s\n", tag.c_str(), printable_prefix(text, 320).c_str());
    printf("\n  Protocol-associated rules: %d; reputation rules: %d.\n", r.tspu_a_hits, r.tspu_b_hits);
    printf("  Legacy TSPU category: %s (unvalidated; actual blocking untested).\n", r.tspu_tier.c_str());
    printf("  Not visible to these probes: %s.\n", BLIND_SPOTS);
    if (r.label == "CLEAN")
        printf("  CLEAN means no named signature answered; it does not mean DPI cannot see this node.\n");
}
