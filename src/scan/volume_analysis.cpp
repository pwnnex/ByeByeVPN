// SPDX-License-Identifier: GPL-3.0-or-later
// pure part of the volume check; volume_probe.cpp does the sockets
#include "volume_probe.h"

#include <algorithm>
#include <charconv>

const char* volume_end_name(VolumeTrace::End e) {
    switch (e) {
    case VolumeTrace::End::Complete: return "complete";
    case VolumeTrace::End::Cap:      return "read limit reached";
    case VolumeTrace::End::Stall:    return "stalled, connection open";
    case VolumeTrace::End::Closed:   return "closed by peer";
    case VolumeTrace::End::Reset:    return "reset";
    default:                         return "failed";
    }
}

Outcome volume_transfer_outcome(const VolumeTrace& t) {
    if (!t.tls_ok || t.end == VolumeTrace::End::Failed) return Outcome::Inconclusive;
    // past the window the path carried volume, however it ended
    if (t.body >= VOLUME_WINDOW) return Outcome::Negative;
    switch (t.end) {
    case VolumeTrace::End::Complete:
    case VolumeTrace::End::Cap:
        return Outcome::NotApplicable;                 // resource smaller than the window
    case VolumeTrace::End::Stall:
        // bytes of a real answer, then nothing; before any answer the server may be thinking
        return t.response ? Outcome::Positive : Outcome::Inconclusive;
    default:
        return Outcome::Inconclusive;                  // a freeze leaves the connection open
    }
}

namespace {

std::string kb(long long b) { return b < 1024 ? std::to_string(b) + " B" : std::to_string((b + 512) / 1024) + " KB"; }

bool carried(const VolumeTrace& t) { return volume_transfer_outcome(t) == Outcome::Negative; }

} // namespace

VolumeVerdict volume_verdict(const std::vector<VolumeTrace>& targets,
                             const std::vector<VolumeTrace>& controls) {
    VolumeVerdict v;
    if (controls.empty()) {
        v.reason = "no control host given (--control); without a working control the result means nothing";
        return v;
    }
    for (const auto& c : controls)
        if (!carried(c)) {
            v.reason = "the control transfer did not carry " + kb(VOLUME_WINDOW) + " (" +
                       volume_end_name(c.end) + " after " + kb(c.wire) + "); this link cannot support any conclusion";
            return v;
        }
    std::vector<Outcome> obs;
    std::vector<long long> stalls;
    for (const auto& t : targets) {
        obs.push_back(volume_transfer_outcome(t));
        if (obs.back() == Outcome::Positive) stalls.push_back(t.wire);
    }
    for (const auto& t : targets)
        if (volume_transfer_outcome(t) == Outcome::NotApplicable) {
            v.outcome = Outcome::NotApplicable;
            v.reason = "the node served only " + kb(t.body) + " of body; give --volume a path of at least " +
                       kb(VOLUME_WINDOW);
            return v;
        }
    v.outcome = combine_observations(obs);
    if (v.outcome == Outcome::Positive) {
        std::sort(stalls.begin(), stalls.end());
        const long long lo = stalls.front(), hi = stalls.back();
        // random loss stalls anywhere; a volume rule stalls at one offset
        if (hi - lo > std::max<long long>(4096, lo / 4)) {
            v.outcome = Outcome::Inconclusive;
            v.reason = "transfers stalled at different offsets (" + kb(lo) + " and " + kb(hi) +
                       "); loss or server pacing, not one volume rule";
            return v;
        }
        v.stall_wire = lo;
        const bool band = lo >= 12 * 1024 && lo <= 24 * 1024;
        v.reason = "bytes stopped after " + kb(lo) + " on an open connection in " + std::to_string(stalls.size()) +
                   " transfers, while the control carried " + kb(VOLUME_WINDOW) + " or more" +
                   (band ? "; inside the 16-20 KB band field reports describe" : "; outside the 16-20 KB band field reports describe");
        return v;
    }
    if (v.outcome == Outcome::Negative) {
        v.reason = "the node carried " + kb(VOLUME_WINDOW) + " or more in every transfer, like the control";
        return v;
    }
    int p = 0, n = 0, closed = 0;
    for (Outcome o : obs) { p += o == Outcome::Positive; n += o == Outcome::Negative; }
    for (const auto& t : targets) closed += t.end == VolumeTrace::End::Closed || t.end == VolumeTrace::End::Reset;
    v.reason = p && n ? "one transfer stalled and another carried the volume; unstable, not counted"
             : p      ? "one stall only; a second agreeing transfer is required"
             : closed == (int)targets.size() && closed
                      ? "the connection was closed (FIN or RST) after " + kb(targets.front().wire) +
                        "; a freeze leaves it open, so this is a different behaviour, not counted"
                      : "no transfer ended in a way that can be read (failed, or no answer before the stall)";
    return v;
}

bool volume_parse_endpoint(const std::string& spec, std::string& host, int& port, std::string& path) {
    host.clear(); path = "/"; port = 443;
    std::string hp = spec;
    const size_t slash = spec.find('/');
    if (slash != std::string::npos) { hp = spec.substr(0, slash); path = spec.substr(slash); }
    const size_t colon = hp.rfind(':');
    if (colon != std::string::npos && hp.find(':') == colon) {
        int p = 0;
        const std::string ps = hp.substr(colon + 1);
        auto r = std::from_chars(ps.data(), ps.data() + ps.size(), p);
        if (ps.empty() || r.ec != std::errc{} || r.ptr != ps.data() + ps.size() || p < 1 || p > 65535) return false;
        port = p;
        hp.resize(colon);
    }
    // a request line must not be steerable from the command line
    if (path.find_first_of("\r\n \t") != std::string::npos) return false;
    host = hp;
    return !host.empty();
}
