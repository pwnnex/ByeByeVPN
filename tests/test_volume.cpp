// SPDX-License-Identifier: GPL-3.0-or-later
// client-side volume check (dpi --volume) and the sni check's four outcomes.
// cases mirror lab runs VZ, VV, VY, VT, VA, VC, VN in docs/GROUNDTRUTH.md.
#include "doctest.h"
#include "../src/scan/volume_probe.h"
#include "../src/scan/dpi_probe.h"

namespace {

using End = VolumeTrace::End;

VolumeTrace tr(End end, long long body, long long wire, bool response = true) {
    VolumeTrace t;
    t.connected = t.tls_ok = true;
    t.response = response;
    t.status = response ? 200 : 0;
    t.end = end;
    t.body = body;
    t.wire = wire;
    return t;
}

const VolumeTrace FULL = tr(End::Cap, VOLUME_CAP, VOLUME_CAP + 6000);

} // namespace

TEST_CASE("one transfer: a stall counts only after a real answer") {
    CHECK(volume_transfer_outcome(FULL) == Outcome::Negative);
    CHECK(volume_transfer_outcome(tr(End::Complete, 200000, 205000)) == Outcome::Negative);
    CHECK(volume_transfer_outcome(tr(End::Stall, 14000, 18500)) == Outcome::Positive);
    // stall before any http answer: the server may still be working
    CHECK(volume_transfer_outcome(tr(End::Stall, 0, 4200, false)) == Outcome::Inconclusive);
    // a stall past the window is not this rule
    CHECK(volume_transfer_outcome(tr(End::Stall, 90000, 95000)) == Outcome::Negative);
    // a freeze leaves the connection open; fin or rst is something else
    CHECK(volume_transfer_outcome(tr(End::Closed, 14000, 18500)) == Outcome::Inconclusive);
    CHECK(volume_transfer_outcome(tr(End::Reset, 14000, 18500)) == Outcome::Inconclusive);
    CHECK(volume_transfer_outcome(tr(End::Complete, 80, 4000)) == Outcome::NotApplicable);
    VolumeTrace failed;
    CHECK(volume_transfer_outcome(failed) == Outcome::Inconclusive);
}

TEST_CASE("freeze needs two agreeing stalls and a working control on both sides") {
    const auto s1 = tr(End::Stall, 14000, 18432), s2 = tr(End::Stall, 14100, 18600);
    auto v = volume_verdict({s1, s2}, {FULL, FULL});
    CHECK(v.outcome == Outcome::Positive);
    CHECK(v.stall_wire == 18432);
    CHECK(v.reason.find("inside the 16-20 KB band") != std::string::npos);

    // lab VN: no control, no claim
    CHECK(volume_verdict({s1, s2}, {}).outcome == Outcome::Inconclusive);
    // lab VC: control froze too, the link is the problem
    v = volume_verdict({s1, s2}, {FULL, tr(End::Stall, 14000, 18000)});
    CHECK(v.outcome == Outcome::Inconclusive);
    CHECK(v.reason.find("control") != std::string::npos);
    // one stall only
    CHECK(volume_verdict({s1}, {FULL, FULL}).outcome == Outcome::Inconclusive);
    // stall and pass disagree
    CHECK(volume_verdict({s1, FULL, s2}, {FULL, FULL}).outcome == Outcome::Inconclusive);
    // loss stalls anywhere
    v = volume_verdict({s1, tr(End::Stall, 40000, 45000)}, {FULL, FULL});
    CHECK(v.outcome == Outcome::Inconclusive);
    CHECK(v.reason.find("different offsets") != std::string::npos);
    // a band outside 16-20 KB is still reported, with that said
    v = volume_verdict({tr(End::Stall, 30000, 34000), tr(End::Stall, 30500, 34500)}, {FULL, FULL});
    CHECK(v.outcome == Outcome::Positive);
    CHECK(v.reason.find("outside the 16-20 KB band") != std::string::npos);
}

TEST_CASE("pass, small resource and closed connections") {
    // lab VV and VY: the node carries the volume, pauses included
    CHECK(volume_verdict({FULL, FULL}, {FULL, FULL}).outcome == Outcome::Negative);
    // lab VA: an 80-byte page cannot answer the question
    auto v = volume_verdict({tr(End::Complete, 80, 4000)}, {FULL, FULL});
    CHECK(v.outcome == Outcome::NotApplicable);
    CHECK(v.reason.find("--volume") != std::string::npos);
    // lab VT: the server closes after 14 KB
    CHECK(volume_verdict({tr(End::Closed, 14000, 18000), tr(End::Closed, 14000, 18000)}, {FULL, FULL}).outcome ==
          Outcome::Inconclusive);
}

TEST_CASE("control endpoints parse strictly") {
    std::string h, p;
    int port = 0;
    REQUIRE(volume_parse_endpoint("ya.example:8443/static/big.bin", h, port, p));
    CHECK(h == "ya.example"); CHECK(port == 8443); CHECK(p == "/static/big.bin");
    REQUIRE(volume_parse_endpoint("127.0.1.21", h, port, p));
    CHECK(h == "127.0.1.21"); CHECK(port == 443); CHECK(p == "/");
    CHECK_FALSE(volume_parse_endpoint("host:0/x", h, port, p));
    CHECK_FALSE(volume_parse_endpoint("host:99999", h, port, p));
    CHECK_FALSE(volume_parse_endpoint(":443/x", h, port, p));
    CHECK_FALSE(volume_parse_endpoint("host/a b", h, port, p));
    CHECK_FALSE(volume_parse_endpoint("host/a\r\nX: y", h, port, p));
}

TEST_CASE("sni and address: positive only when the real address answers the same name") {
    using E = ChEnd;
    const SniRound mismatch{E::Silent, E::Reply, E::Reply};
    const SniRound reset_mismatch{E::Reset, E::Reply, E::Reply};
    const SniRound passes{E::Reply, E::Reply, E::Reply};
    const SniRound blocked{E::Silent, E::Reply, E::Silent};
    CHECK(sni_round_verdict(mismatch) == SniRoundVerdict::Mismatch);
    CHECK(sni_round_verdict(reset_mismatch) == SniRoundVerdict::Mismatch);
    CHECK(sni_round_verdict(passes) == SniRoundVerdict::Passes);
    CHECK(sni_round_verdict(blocked) == SniRoundVerdict::NameBlocked);
    // lab SD: the node itself is dead, nothing is compared
    CHECK(sni_round_verdict({E::Silent, E::Silent, E::Reply}) == SniRoundVerdict::Unclear);
    // the real address unreachable is not a pass for the node
    CHECK(sni_round_verdict({E::Silent, E::Reply, E::NoTcp}) == SniRoundVerdict::Unclear);
    CHECK(sni_round_verdict({E::NoTcp, E::NoTcp, E::Reply}) == SniRoundVerdict::Unclear);

    auto v = sni_mismatch_verdict({mismatch, reset_mismatch});
    CHECK(v.outcome == Outcome::Positive);
    CHECK_FALSE(v.name_blocked);
    // one round is not enough
    CHECK(sni_mismatch_verdict({mismatch}).outcome == Outcome::Inconclusive);
    CHECK(sni_mismatch_verdict({mismatch, passes, mismatch}).outcome == Outcome::Inconclusive);
    CHECK(sni_mismatch_verdict({passes, passes}).outcome == Outcome::Negative);
    v = sni_mismatch_verdict({blocked, blocked});
    CHECK(v.outcome == Outcome::Inconclusive);
    CHECK(v.name_blocked);
    CHECK(v.reason.find("whatever the address") != std::string::npos);
}

TEST_CASE("sni check maps onto the shared four outcomes") {
    DpiProbe d;
    d.ran = true;
    CHECK(dpi_outcome(d) == Outcome::Inconclusive);
    d.target_progressed = true;
    CHECK(dpi_outcome(d) == Outcome::Negative);
    d.target_progressed = false; d.sni_dropped = true;
    CHECK(dpi_outcome(d) == Outcome::Positive);
    d.sni_dropped = false; d.sni_blocked = true;
    CHECK(dpi_outcome(d) == Outcome::Positive);
    d.tunneled = true;
    CHECK(dpi_outcome(d) == Outcome::NotApplicable);
}
