// SPDX-License-Identifier: GPL-3.0-or-later
// batch: scan a list of nodes, one report each. diff: compare two reports
// or two batch directories.
#include <cstdio>
#include "cli.h"
#include "json_report.h"
#include "orchestrator.h"
#include "report_diff.h"
#include "verdict.h"
#include "../common/config.h"
#include "../common/console.h"
#include "../common/json.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr size_t BATCH_MAX = 256;
constexpr std::uintmax_t REPORT_MAX = 16 * 1024 * 1024;

std::string trim(const std::string& s) {
    const size_t a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
    return a == std::string::npos ? std::string() : s.substr(a, b - a + 1);
}

// same file names as --save
std::string safe_name(const std::string& target) {
    std::string out;
    for (char c : target) out += std::string(":/\\*?\"<>|").find(c) != std::string::npos ? '_' : c;
    return out;
}

bool read_text(const fs::path& p, std::string& out, std::string& err) {
    std::error_code ec;
    const auto size = fs::file_size(p, ec);
    if (ec) { err = "cannot read " + p.string(); return false; }
    if (size > REPORT_MAX) { err = p.string() + " is larger than 16 MiB"; return false; }
    std::ifstream f(p, std::ios::binary);
    std::ostringstream s;
    s << f.rdbuf();
    if (!f && !f.eof()) { err = "cannot read " + p.string(); return false; }
    out = s.str();
    return true;
}

const char* class_color(const std::string& cls) {
    return cls == "verdict" ? C::ORG : cls == "surface" ? C::CYN : C::DIM;
}

void print_diff(const std::string& name, const ReportDiff& d) {
    if (!d.ok) {
        printf("  %s%s%s: %s\n", col(C::BOLD), name.c_str(), col(C::RST), d.error.c_str());
        return;
    }
    const std::string who = d.target_a == d.target_b ? d.target_a : d.target_a + " vs " + d.target_b;
    printf("  %s%s%s  %s  %s%s%s\n", col(C::BOLD), name.c_str(), col(C::RST), who.c_str(),
           col(d.items.empty() ? C::GRN : C::YEL),
           d.items.empty() ? "no change" : (std::to_string(d.items.size()) + " changes").c_str(), col(C::RST));
    for (const auto& it : d.items) {
        const char sign = it.from.empty() ? '+' : it.to.empty() ? '-' : '~';
        const std::string val = it.from.empty() ? it.to : it.to.empty() ? it.from : it.from + " -> " + it.to;
        printf("    %s%c %-8s%s %-34s %s\n", col(class_color(it.cls)), sign, it.cls.c_str(), col(C::RST),
               it.what.c_str(), val.c_str());
    }
}

} // namespace

int run_diff(const std::string& a, const std::string& b) {
    std::vector<std::pair<std::string, ReportDiff>> pairs;
    std::error_code ec;
    const bool dirs = fs::is_directory(a, ec) && fs::is_directory(b, ec);
    if (dirs) {
        // one report per node on each side, paired by file name
        std::map<std::string, std::pair<fs::path, fs::path>> by;
        for (const auto* side : {&a, &b})
            for (const auto& e : fs::directory_iterator(*side, ec)) {
                if (!e.is_regular_file() || e.path().extension() != ".json") continue;
                auto& slot = by[e.path().filename().string()];
                (side == &a ? slot.first : slot.second) = e.path();
            }
        for (const auto& kv : by) {
            ReportDiff d;
            std::string ta, tb, err;
            if (kv.second.first.empty() || kv.second.second.empty()) {
                d.ok = true;
                const bool first = !kv.second.first.empty();
                d.items.push_back({"surface", "report", first ? "present" : "", first ? "" : "present"});
                if (read_text(first ? kv.second.first : kv.second.second, ta, err)) {
                    const JsonValue j = json_parse(ta);
                    (first ? d.target_a : d.target_b) = j["target"].as_str();
                }
            } else if (!read_text(kv.second.first, ta, err) || !read_text(kv.second.second, tb, err)) {
                d.error = err;
            } else {
                d = diff_reports(ta, tb);
            }
            pairs.emplace_back(kv.first, d);
        }
        if (pairs.empty()) {
            printf("  diff: no .json reports in %s or %s\n", a.c_str(), b.c_str());
            return 64;
        }
    } else {
        std::string ta, tb, err;
        ReportDiff d;
        if (!read_text(a, ta, err) || !read_text(b, tb, err)) d.error = err;
        else d = diff_reports(ta, tb);
        pairs.emplace_back(fs::path(b).filename().string(), d);
    }
    int rc = 0;
    bool bad = false;
    for (const auto& p : pairs) {
        if (!p.second.ok) bad = true;
        else rc = std::max(rc, diff_exit_code(p.second));
    }
    if (g_json) {
        std::fputs(diff_json(pairs).c_str(), stdout);
    } else {
        section(1, 1, "Diff", a + "  ->  " + b);
        for (const auto& p : pairs) print_diff(p.first, p.second);
        printf("  %sverdict: label, tier, checks, scored signals. surface: address, ports, certificates, ja4s.\n"
               "  context: score, geoip tags, unreliable flag.%s\n", col(C::DIM), col(C::RST));
    }
    return bad ? 64 : rc;
}

int run_batch(const std::string& list) {
    std::string text, err;
    if (!read_text(list, text, err)) { printf("  batch: %s\n", err.c_str()); return 64; }
    std::vector<std::string> targets;
    std::set<std::string> seen;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        const size_t hash = line.find('#');
        const std::string t = trim(hash == std::string::npos ? line : line.substr(0, hash));
        if (t.empty() || !seen.insert(t).second) continue;
        if (t.find_first_of(" \t") != std::string::npos) { printf("  batch: one target per line, got '%s'\n", t.c_str()); return 64; }
        targets.push_back(t);
    }
    if (targets.empty()) { printf("  batch: no targets in %s\n", list.c_str()); return 64; }
    if (targets.size() > BATCH_MAX) { printf("  batch: more than %zu targets\n", BATCH_MAX); return 64; }
    std::error_code ec;
    if (!g_batch_out.empty() && !fs::create_directories(g_batch_out, ec) && ec) {
        printf("  batch: cannot create %s\n", g_batch_out.c_str());
        return 64;
    }

    struct Row { std::string target, label, score, tier, signals, file; int exit = 0; };
    std::vector<Row> rows;
    int rc = 0;
    for (size_t i = 0; i < targets.size(); ++i) {
        section(int(i + 1), int(targets.size()), "Batch", targets[i]);
        const FullReport R = run_full_target(targets[i]);
        Row r;
        r.target = targets[i];
        r.label = R.label.empty() ? "?" : R.label;
        r.score = R.completed && R.score_available ? std::to_string(R.score) : "-";
        r.tier = R.tspu_tier.empty() ? "UNKNOWN" : R.tspu_tier;
        for (const auto& s : R.scored) r.signals += (r.signals.empty() ? "" : ",") + s.id;
        r.exit = report_exit_code(R);
        if (!g_batch_out.empty()) {
            const fs::path p = fs::path(g_batch_out) / (safe_name(targets[i]) + ".json");
            std::ofstream f(p, std::ios::binary);
            f << json_report(R);
            r.file = f ? p.string() : "";
            if (!f) printf("  batch: cannot write %s\n", p.string().c_str());
        }
        rc = std::max(rc, r.exit);
        rows.push_back(r);
    }

    if (g_json) {
        std::string o = "{\n  \"check\": \"batch\",\n  \"targets\": [";
        auto q = [](const std::string& s) { return "\"" + json_escape_string(s) + "\""; };
        for (size_t i = 0; i < rows.size(); ++i)
            o += std::string(i ? "," : "") + "\n    { \"target\": " + q(rows[i].target) + ", \"label\": " +
                 q(rows[i].label) + ", \"score\": " + (rows[i].score == "-" ? "null" : rows[i].score) +
                 ", \"tier\": " + q(rows[i].tier) + ", \"signals\": " + q(rows[i].signals) +
                 ", \"exit\": " + std::to_string(rows[i].exit) + ", \"file\": " + q(rows[i].file) + " }";
        o += "\n  ]\n}\n";
        std::fputs(o.c_str(), stdout);
    }
    printf("\n");
    section(int(targets.size()), int(targets.size()), "Batch summary",
            std::to_string(targets.size()) + (targets.size() == 1 ? " node" : " nodes"));
    for (const auto& r : rows)
        printf("    %-32s %-14s %5s  %-16s %s\n", r.target.c_str(), r.label.c_str(), r.score.c_str(), r.tier.c_str(),
               r.signals.empty() ? "-" : r.signals.c_str());
    if (!g_batch_out.empty())
        printf("  %sreports in %s; compare two runs with: byebyevpn diff <old dir> <new dir>%s\n", col(C::DIM),
               g_batch_out.c_str(), col(C::RST));
    return rc;
}
