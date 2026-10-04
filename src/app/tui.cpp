// SPDX-License-Identifier: GPL-3.0-or-later
#include "tui.h"
#include "cli.h"
#include "orchestrator.h"
#include "preflight.h"
#include "verdict.h"
#include "../common/terminal.h"
#include "../common/config.h"
#include "../common/util.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using std::string;
using std::vector;

namespace {

// panel output bypasses the --save tee on purpose
void out(const string& s) {
    std::fwrite(s.data(), 1, s.size(), stdout);
    std::fflush(stdout);
}

string sgr(const char* code) { return g_no_color ? string() : string("\x1b[") + code + "m"; }
const char* const RESET = "\x1b[0m";

// box drawing, utf-8
const char* const TL = "\xE2\x95\xAD";
const char* const TR = "\xE2\x95\xAE";
const char* const BL = "\xE2\x95\xB0";
const char* const BR = "\xE2\x95\xAF";
const char* const HZ = "\xE2\x94\x80";
const char* const VT = "\xE2\x94\x82";
const char* const DOT = "\xE2\x97\x8F";
const char* const ARROW = "\xE2\x96\xB8";
const char* const UPDN = "\xE2\x86\x91\xE2\x86\x93";
const char* const LTRT = "\xE2\x86\x90\xE2\x86\x92";

string rep(const char* s, int n) { string r; for (int i = 0; i < n; ++i) r += s; return r; }

using Size = TerminalSize;
using K = TerminalKeyCode;
using Key = TerminalKey;

Size term_size() { return terminal_size(); }
Key read_key() { return terminal_read_key(); }
string utf8(wchar_t character) { return terminal_utf8(character); }

vector<string> split_ws(const string& s) {
    vector<string> v;
    string cur;
    for (char c : s) {
        if (c == ' ' || c == '\t') { if (!cur.empty()) v.push_back(cur); cur.clear(); }
        else cur += c;
    }
    if (!cur.empty()) v.push_back(cur);
    return v;
}

// a framed box of exactly w x h columns and rows
vector<string> box(const string& title, const vector<string>& body, int w, int h, bool focus) {
    vector<string> rows;
    if (w < 4 || h < 2) return rows;
    const string bc = focus ? sgr("36") : sgr("2");
    string t = title.empty() ? string() : " " + title + " ";
    int tw = (int)tui_visible_width(t);
    if (tw > w - 4) { t = tui_fit(t, w - 4); tw = w - 4; }
    rows.push_back(bc + TL + HZ + RESET + sgr("1") + t + RESET + bc + rep(HZ, w - 3 - tw) + TR + RESET);
    for (int i = 0; i < h - 2; ++i) {
        const string line = i < (int)body.size() ? body[i] : string();
        rows.push_back(bc + VT + RESET + " " + tui_fit(line, w - 3) + RESET + bc + VT + RESET);
    }
    rows.push_back(bc + BL + rep(HZ, w - 2) + BR + RESET);
    return rows;
}

enum class Act {
    Scan, Fast, Dpi, Ports, Udp, Tls, J3, Grpc, Geoip, Ech, Snitch, Trace,
    Names, Audit, Awg, Machine, Local, Settings, Last, Help, Quit
};

struct Item {
    const char* section;
    const char* title;
    Act act;
    const char* desc;
    const char* sends;
};

const Item ITEMS[] = {
    {"SCAN", "Full scan", Act::Scan,
     "Preflight, TCP ports, path check, UDP, TLS, junk probes, verdict. The main self-check for one of your nodes. "
     "The verdict only moves on named signatures that answered twice.",
     "Preflight, then every probe of the pipeline to the target. Port range from Settings."},
    {"SCAN", "Quick scan (205 ports)", Act::Fast,
     "The same pipeline on the curated 205-port list instead of all 65535. Minutes instead of tens of minutes.",
     "Same as full scan, fewer TCP connects."},
    {"SCAN", "DPI path test (SNI)", Act::Dpi,
     "Does YOUR provider reset or silently drop a TLS ClientHello with this SNI? Compares against a benign SNI to the same address.",
     "Preflight, then 2 or 3 ClientHellos to host:port."},
    {"PROBES", "TCP ports", Act::Ports, "Connect-scan only. Closed ports answer in about a millisecond, not after the Windows two-second retry.",
     "Preflight, one connect per port."},
    {"PROBES", "UDP probes", Act::Udp,
     "WireGuard, AmneziaWG and QUIC Initials. Real WireGuard stays silent without its key, so silence proves nothing.",
     "Preflight, 3 handshake-shaped datagrams, 7 QUIC Initials."},
    {"PROBES", "TLS + SNI", Act::Tls, "Handshake, certificate and whether the certificate changes with the SNI.",
     "Preflight, 11 TLS handshakes."},
    {"PROBES", "Junk probes (J3)", Act::J3,
     "Eight malformed first flights on one port. Shows reply, close, reset or held open per probe. Reference only.",
     "Preflight, 8 connections."},
    {"PROBES", "HTTP/2 + gRPC", Act::Grpc, "HTTP/2 preface and a gRPC-shaped request over TLS.",
     "Preflight, 1 TLS connection."},
    {"LOOKUPS", "GeoIP", Act::Geoip,
     "Five lookup services: country, ASN and their VPN or proxy tags. Tags are reference only and never scored.",
     "5 HTTPS requests to the lookup services, nothing to the target."},
    {"LOOKUPS", "ECH / HTTPS record", Act::Ech,
     "DNS HTTPS record over DoH. A failed lookup is reported as unknown, not as absent.",
     "1 or 2 DoH requests (Google, then Cloudflare)."},
    {"LOOKUPS", "RTT check (snitch)", Act::Snitch,
     "RTT to the target against Cloudflare, Google and Yandex anchors. Observations only; causes are never guessed.",
     "Preflight, 6 connects to the target, anchor connects, 1 GeoIP lookup."},
    {"LOOKUPS", "Traceroute", Act::Trace, "ICMP hop list with the Windows ping payload.", "Preflight, ICMP echoes with rising TTL."},
    {"OFFLINE", "Hostname markers", Act::Names,
     "Does the NAME give you away? Protocol, panel and provider naming conventions. No packets.", "Nothing."},
    {"OFFLINE", "Config audit", Act::Audit,
     "Reads an Xray, sing-box or WireGuard config and lists detectability issues before you deploy.", "Nothing."},
    {"OFFLINE", "AWG capture analysis", Act::Awg,
     "Entropy and packet-train analysis of a PCAP of a real connection. A compatibility hint, not proof.", "Nothing."},
    {"THIS MACHINE", "Machine check", Act::Machine,
     "Is this machine fit to measure? Tunnel on the route, local ack-all stack, packet rewriters, proxies, external address.",
     "1 SYN to 192.0.2.1 (only on the default route), 3 external-address lookups unless GeoIP is off."},
    {"THIS MACHINE", "Adapters, routes, leaks", Act::Local,
     "Adapters, default routes, full or split tunnel, VPN processes, config folders, IPv6 and DNS leaving beside the tunnel.",
     "Nothing without a tunnel. With one: two TCP connects to public IPv6 resolvers (only with global IPv6 beside it) "
     "and two example.com queries to each resolver beside it."},
    {"PANEL", "Settings", Act::Settings, "Port range, timeouts, stealth, lookups, saving reports, preflight override.", "Nothing."},
    {"PANEL", "Last full scan", Act::Last, "The verdict block of the most recent full or quick scan in this session.", "Nothing."},
    {"PANEL", "Help (all flags)", Act::Help, "The --help text.", "Nothing."},
    {"PANEL", "Quit", Act::Quit, "Leave the panel.", "Nothing."},
};
constexpr int N_ITEMS = (int)(sizeof(ITEMS) / sizeof(ITEMS[0]));

struct State {
    int sel = 0;
    bool save = false;
    vector<string> history;
    LocalHealth health;
    string flash;   // one-line message after an action
};

string port_mode_name() {
    switch (g_port_mode) {
    case PortMode::FULL: return "all 65535";
    case PortMode::FAST: return "205 curated";
    case PortMode::RANGE: return std::to_string(g_range_lo) + "-" + std::to_string(g_range_hi);
    default: return std::to_string(g_port_list.size()) + " listed";
    }
}

// flow short chips into lines no wider than w
vector<string> pack(const vector<string>& chips, size_t w) {
    vector<string> lines;
    string line;
    for (const auto& c : chips) {
        const size_t need = tui_visible_width(line) + (line.empty() ? 0 : 3) + tui_visible_width(c);
        if (!line.empty() && need > w) { lines.push_back(line); line.clear(); }
        line += (line.empty() ? "" : "   ") + c;
    }
    if (!line.empty()) lines.push_back(line);
    return lines;
}

string join(const vector<string>& v) {
    string s;
    for (const auto& x : v) s += (s.empty() ? "" : ", ") + x;
    return s;
}

string on_off(bool b) { return b ? sgr("32") + "on" + RESET : sgr("2") + "off" + RESET; }

string label_color(const string& label) {
    if (label == "CLEAN") return sgr("1;32");
    if (label == "NOISY" || label == "INCONCLUSIVE") return sgr("1;33");
    if (label == "UNRELIABLE") return sgr("1;97;41");
    return sgr("1;31");
}

vector<string> report_card(const FullReport& r, size_t width) {
    vector<string> v;
    v.push_back("target  " + r.target + (r.dns.primary_ip.empty() || r.dns.primary_ip == r.target ? "" : "  (" + r.dns.primary_ip + ")"));
    string head = label_color(r.label) + " " + r.label + " " + RESET;
    if (r.score_available) head += "  " + std::to_string(r.score) + "/100   tier " + r.tspu_tier;
    v.push_back(head);
    if (r.checks_applicable)
        v.push_back("coverage " + std::to_string(r.checks_conclusive) + "/" + std::to_string(r.checks_applicable) + " signature checks conclusive");
    if (r.scored.empty()) v.push_back("signals  none answered");
    for (const auto& s : r.scored)
        v.push_back(sgr("31") + "signal  " + RESET + s.id + " :" + std::to_string(s.port) + "  -" + std::to_string(s.weight) + "  " + s.observed);
    const auto& why = r.unreliable ? r.preflight.blockers : r.failed_reasons;
    for (size_t i = 0; i < why.size() && i < 3; ++i)
        for (const auto& l : tui_wrap("why     " + why[i], width)) v.push_back(sgr("33") + l + RESET);
    if (r.overridden) v.push_back(sgr("31") + "preflight overridden" + RESET);
    return v;
}

string render(const State& st, int cols, int lines) {
    const int W = std::max(60, cols), H = std::max(20, lines);
    vector<string> rows;

    rows.push_back(sgr("1;97;45") + tui_fit(string("  ") + DOT + " byebyevpn " + SCANNER_VERSION +
                   "   your node through a DPI box's eyes", W) + RESET);

    // status bar: what this machine would do to a measurement
    const auto& h = st.health;
    string status = " machine  ";
    if (h.public_via_tunnel)
        status += sgr("31") + DOT + " via tunnel " + h.public_iface + RESET;
    else
        status += sgr("32") + DOT + " direct via " + (h.public_iface.empty() ? string("unknown") : h.public_iface) + RESET;
    if (!h.rewriters.empty()) status += "   " + sgr("31") + DOT + " packet rewriter" + RESET;
    if (!h.proxy_clients.empty())
        status += "   " + sgr("33") + DOT + " " + std::to_string(h.proxy_clients.size()) + " proxy client(s)" + RESET;
    if (!h.system_proxy.empty()) status += "   " + sgr("33") + DOT + " system proxy" + RESET;
    if (!h.public_via_tunnel && h.rewriters.empty()) status += "   " + sgr("2") + "public targets pass preflight" + RESET;
    else status += "   " + sgr("31") + "public targets stop at preflight" + RESET;
    rows.push_back(tui_fit(status, W));

    const int body_h = H - 4;
    const int LW = std::min(34, W / 3 + 4);
    const int RW = W - LW;

    // left: sections and items, scrolled to keep the selection visible
    vector<string> menu;
    int sel_line = 0;
    const char* last_section = "";
    for (int i = 0; i < N_ITEMS; ++i) {
        if (string(ITEMS[i].section) != last_section) {
            if (i) menu.push_back("");
            menu.push_back(sgr("2") + ITEMS[i].section + RESET);
            last_section = ITEMS[i].section;
        }
        if (i == st.sel) {
            sel_line = (int)menu.size();
            const string hl = g_no_color ? "\x1b[7m" : "\x1b[30;46m";
            menu.push_back(hl + tui_fit(string(ARROW) + " " + ITEMS[i].title, LW - 4) + RESET);
        } else {
            menu.push_back("  " + string(ITEMS[i].title));
        }
    }
    const int inner = body_h - 2;
    int off = 0;
    if ((int)menu.size() > inner) off = std::clamp(sel_line - inner / 2, 0, (int)menu.size() - inner);
    vector<string> visible(menu.begin() + off, menu.end());
    auto left = box("menu", visible, LW, body_h, true);

    // right: what the selection does, then settings and the last verdict
    const Item& it = ITEMS[st.sel];
    const size_t tw = (size_t)std::max(10, RW - 4);
    vector<string> info;
    info.push_back(sgr("1") + it.title + RESET);
    // result of the last action, where the eye lands
    if (!st.flash.empty()) info.push_back(sgr("36") + string(ARROW) + " " + st.flash + RESET);
    for (const auto& l : tui_wrap(it.desc, tw)) info.push_back(l);
    info.push_back("");
    for (const auto& l : tui_wrap(string("sends: ") + it.sends, tw)) info.push_back(sgr("2") + l + RESET);
    info.push_back("");
    info.push_back(sgr("1") + "settings" + RESET + sgr("2") + "  (S to change)" + RESET);
    for (const auto& l : pack({"ports " + port_mode_name(), "timeout " + std::to_string(g_tcp_to) + " ms",
                               "threads " + std::to_string(g_threads), "stealth " + on_off(g_stealth),
                               "passive " + on_off(g_passive), "geoip " + on_off(!g_no_geoip), "ct " + on_off(!g_no_ct),
                               "save " + on_off(st.save)}, tw))
        info.push_back(l);
    if (g_override_preflight) info.push_back(sgr("31") + "preflight override is ON: verdicts are marked overridden" + RESET);
    // the verdict matters more than the machine details
    if (const FullReport* r = last_full_report()) {
        info.push_back("");
        info.push_back(sgr("1") + "last full scan" + RESET);
        for (const auto& l : report_card(*r, tw)) info.push_back(l);
    }
    // what the status bar summarizes
    if (!h.tunnels_up.empty() || !h.proxy_clients.empty() || !h.rewriters.empty() || !h.system_proxy.empty()) {
        info.push_back("");
        info.push_back(sgr("1") + "this machine" + RESET);
        if (!h.tunnels_up.empty())
            for (const auto& l : tui_wrap("tunnels up: " + join(h.tunnels_up), tw)) info.push_back(l);
        if (!h.rewriters.empty())
            for (const auto& l : tui_wrap("rewriters: " + join(h.rewriters), tw)) info.push_back(sgr("31") + l + RESET);
        if (!h.proxy_clients.empty())
            for (const auto& l : tui_wrap("proxy clients: " + join(h.proxy_clients), tw)) info.push_back(l);
        if (!h.system_proxy.empty())
            for (const auto& l : tui_wrap("system proxy: " + h.system_proxy, tw)) info.push_back(l);
        if (h.public_via_tunnel)
            for (const auto& l : tui_wrap("Scans of public addresses stop before the first probe. Turn the tunnel off, "
                                          "or use Settings > override to scan through it.", tw))
                info.push_back(sgr("33") + l + RESET);
    }
    auto right = box(it.section, info, RW, body_h, false);

    for (int i = 0; i < body_h; ++i) rows.push_back(left[i] + right[i]);
    const string keys = W >= 100
        ? string(" ") + UPDN + " move   " + LTRT + " section   Enter run   S settings   L last scan   R refresh status   Q quit"
        : string(" ") + UPDN + " move  " + LTRT + " section  Enter run  S set  L last  R refresh  Q quit";
    rows.push_back(sgr("2") + tui_fit(keys, W) + RESET);

    string frame = "\x1b[H";
    for (size_t i = 0; i < rows.size(); ++i) {
        frame += rows[i];
        if (i + 1 < rows.size()) frame += "\r\n";
    }
    // a line shorter than the window leaves stale cells
    frame += "\x1b[J";
    return frame;
}

void draw(const State& st) {
    const Size sz = term_size();
    out(render(st, sz.w, sz.h));
}

// centred single-line input; up/down walk the history
bool prompt(const string& title, const string& label, string& value, const vector<string>* history) {
    int hist = -1;
    for (;;) {
        const Size sz = term_size();
        const int w = std::min(72, std::max(40, sz.w - 8));
        vector<string> body = {label, "", sgr("1") + "> " + value + RESET + sgr("5") + "_" + RESET, "",
                               sgr("2") + "Enter ok   Esc cancel" + (history && !history->empty() ? string("   ") + UPDN + " history" : "") + RESET};
        auto b = box(title, body, w, (int)body.size() + 2, true);
        const int top = std::max(0, (sz.h - (int)b.size()) / 2);
        const int left = std::max(0, (sz.w - w) / 2);
        string frame = "\x1b[2J";
        for (size_t i = 0; i < b.size(); ++i)
            frame += "\x1b[" + std::to_string(top + 1 + (int)i) + ";" + std::to_string(left + 1) + "H" + b[i];
        out(frame);
        Key k = read_key();
        if (k.k == K::Enter) return true;
        if (k.k == K::Esc) return false;
        if (k.k == K::Back && !value.empty()) {
            // drop one utf-8 code point
            size_t n = value.size() - 1;
            while (n > 0 && ((unsigned char)value[n] & 0xC0) == 0x80) --n;
            value.erase(n);
        } else if (history && !history->empty() && (k.k == K::Up || k.k == K::Down)) {
            const int n = (int)history->size();
            hist = k.k == K::Up ? std::min(hist + 1, n - 1) : std::max(hist - 1, -1);
            value = hist < 0 ? string() : (*history)[n - 1 - hist];
        } else if (k.k == K::Char && k.ch >= 0x20 && value.size() < 400) {
            value += utf8(k.ch);
        }
    }
}

void remember(State& st, const string& t) {
    st.history.erase(std::remove(st.history.begin(), st.history.end(), t), st.history.end());
    st.history.push_back(t);
    if (st.history.size() > 12) st.history.erase(st.history.begin());
}

void wait_key(const string& msg) {
    out("\r\n" + sgr("2") + msg + RESET);
    read_key();
}

// leave the panel, run, come back
int run_outside(State& st, const string& heading, const vector<string>& args) {
    terminal_hide_ui();
    out("\x1b[2J\x1b[H");
    out(sgr("1;97;45") + "  " + heading + "  " + RESET + "\r\n");
    if (st.save) { g_save_requested = true; g_save_path.clear(); save_begin(args); }
    const int rc = run_command(args);
    if (st.save) { save_end(); g_save_requested = false; }
    return rc;
}

void print_card_below(const FullReport& r) {
    const Size sz = term_size();
    const int w = std::min(90, std::max(50, sz.w - 2));
    auto b = box("result", report_card(r, (size_t)w - 4), w, (int)report_card(r, (size_t)w - 4).size() + 2, true);
    string s = "\r\n";
    for (const auto& l : b) s += l + "\r\n";
    out(s);
}

// every command has its own exit table, see --help
string exit_meaning(Act a, int rc) {
    const string n = std::to_string(rc) + " ";
    if (rc == 5) return n + "preflight failed, nothing sent";
    if (rc == 64) return n + "usage or input error";
    switch (a) {
    case Act::Scan: case Act::Fast:
        switch (rc) {
        case 0: return n + "CLEAN";   case 1: return n + "NOISY";
        case 2: return n + "SUSPICIOUS"; case 3: return n + "OBVIOUSLY-VPN";
        case 4: return n + "INCONCLUSIVE"; default: return n;
        }
    case Act::Dpi:
        return n + (rc == 0 ? "TLS reply, no SNI filtering seen" : rc == 2 ? "SNI-specific reset or drop" :
                    rc == 4 ? "inconclusive" : "");
    case Act::Ech:
        return n + (rc == 0 ? "HTTPS record found" : rc == 1 ? "no HTTPS record" : rc == 4 ? "lookup failed, unknown" : "");
    case Act::Names:
        return n + (rc == 3 ? "strong naming hint" : rc == 2 ? "moderate naming hint" : rc == 0 ? "weak or none" : "");
    case Act::Audit:
        return n + (rc == 65 ? "compatibility errors" : "legacy exposure tier");
    default:
        return n + (rc == 0 ? "done" : "");
    }
}

void settings_screen(State& st) {
    int sel = 0;
    static const int TIMEOUTS[] = {300, 500, 800, 1200, 2000};
    static const int THREADS[] = {50, 100, 250, 500, 1000};
    auto cycle = [](const int* v, int n, int cur, int dir) {
        int i = 0;
        while (i < n && v[i] != cur) ++i;
        i = i >= n ? 0 : (i + dir + n) % n;
        return v[i];
    };
    for (;;) {
        vector<std::pair<string, string>> rows = {
            {"port range", port_mode_name()},
            {"tcp timeout", std::to_string(g_tcp_to) + " ms"},
            {"threads", std::to_string(g_threads)},
            {"stealth (jitter, no lookups)", on_off(g_stealth)},
            {"passive (skip loud probes)", on_off(g_passive)},
            {"GeoIP and address lookups", on_off(!g_no_geoip)},
            {"CT log lookup", on_off(!g_no_ct)},
            {"junk probes per port", g_j3_subset ? std::to_string(g_j3_subset) : string("all 8")},
            {"save each run to <target>.md", on_off(st.save)},
            {"override failed preflight", g_override_preflight ? sgr("1;31") + "ON" + RESET : on_off(false)},
            {"back", ""},
        };
        const Size sz = term_size();
        const int w = std::min(70, std::max(46, sz.w - 8));
        vector<string> body;
        for (size_t i = 0; i < rows.size(); ++i) {
            string line = tui_fit(rows[i].first, (size_t)w - 22) + rows[i].second;
            if ((int)i == sel) line = (g_no_color ? string("\x1b[7m") : string("\x1b[30;46m")) + tui_fit(string(ARROW) + " " + line, (size_t)w - 4) + RESET;
            else line = "  " + line;
            body.push_back(line);
        }
        body.push_back("");
        body.push_back(sgr("2") + string(LTRT) + " or Enter change   Esc back" + RESET);
        if (g_override_preflight)
            body.push_back(sgr("31") + "override: scans run through a tunnel or ack-all path" + RESET);
        auto b = box("settings", body, w, (int)body.size() + 2, true);
        const int top = std::max(0, (sz.h - (int)b.size()) / 2), left = std::max(0, (sz.w - w) / 2);
        string frame = "\x1b[2J";
        for (size_t i = 0; i < b.size(); ++i)
            frame += "\x1b[" + std::to_string(top + 1 + (int)i) + ";" + std::to_string(left + 1) + "H" + b[i];
        out(frame);

        Key k = read_key();
        const int n = (int)rows.size();
        if (k.k == K::Esc || (k.k == K::Char && (k.ch == 'q' || k.ch == 'Q'))) return;
        if (k.k == K::Up) { sel = (sel + n - 1) % n; continue; }
        if (k.k == K::Down || k.k == K::Tab) { sel = (sel + 1) % n; continue; }
        if (k.k != K::Enter && k.k != K::Left && k.k != K::Right) continue;
        const int dir = k.k == K::Left ? -1 : 1;
        switch (sel) {
        case 0: {
            if (g_port_mode == PortMode::FULL) g_port_mode = PortMode::FAST;
            else if (g_port_mode == PortMode::FAST) {
                string list;
                if (prompt("port list", "comma separated ports, e.g. 22,80,443,8443", list, nullptr) && !list.empty()) {
                    g_port_list.clear();
                    for (const auto& p : split(list, ',')) { int v = std::atoi(p.c_str()); if (v > 0 && v < 65536) g_port_list.push_back(v); }
                    g_port_mode = g_port_list.empty() ? PortMode::FULL : PortMode::LIST;
                } else g_port_mode = PortMode::FULL;
            } else g_port_mode = PortMode::FULL;
            break;
        }
        case 1: g_tcp_to = cycle(TIMEOUTS, 5, g_tcp_to, dir); break;
        case 2: g_threads = cycle(THREADS, 5, g_threads, dir); break;
        case 3:
            g_stealth = !g_stealth;
            if (g_stealth) { g_no_geoip = g_no_ct = g_udp_jitter = true; }
            break;
        case 4: g_passive = !g_passive; break;
        case 5: g_no_geoip = !g_no_geoip; break;
        case 6: g_no_ct = !g_no_ct; break;
        case 7: g_j3_subset = g_j3_subset == 0 ? 4 : g_j3_subset == 4 ? 2 : 0; break;
        case 8: st.save = !st.save; break;
        case 9: g_override_preflight = !g_override_preflight; break;
        default: return;
        }
    }
}

bool ask_target(State& st, const string& title, string& t) {
    t.clear();
    if (!prompt(title, "IP address or host name of YOUR node", t, &st.history)) return false;
    t = trim(t);
    if (t.empty()) return false;
    remember(st, t);
    return true;
}

bool ask_port(const string& title, int def, string& port) {
    port = std::to_string(def);
    if (!prompt(title, "port", port, nullptr)) return false;
    port = trim(port);
    if (port.empty()) port = std::to_string(def);
    return std::atoi(port.c_str()) > 0;
}

// true when the panel should close
bool act(State& st) {
    const Item& it = ITEMS[st.sel];
    string t, p;
    vector<string> args;
    string heading = it.title;
    switch (it.act) {
    case Act::Quit: return true;
    case Act::Settings: settings_screen(st); return false;
    case Act::Scan:
    case Act::Fast:
        if (!ask_target(st, it.title, t)) return false;
        args = {"scan", t};
        heading += ": " + t;
        break;
    case Act::Dpi:
        if (!ask_target(st, it.title, t) || !ask_port(it.title, 443, p)) return false;
        args = {"dpi", t, p};
        heading += ": " + t + ":" + p;
        break;
    case Act::Ports: case Act::Udp: case Act::Trace:
        if (!ask_target(st, it.title, t)) return false;
        args = {it.act == Act::Ports ? "ports" : it.act == Act::Udp ? "udp" : "trace", t};
        heading += ": " + t;
        break;
    case Act::Tls: case Act::J3: case Act::Grpc: case Act::Snitch:
        if (!ask_target(st, it.title, t) || !ask_port(it.title, 443, p)) return false;
        args = {it.act == Act::Tls ? "tls" : it.act == Act::J3 ? "j3" : it.act == Act::Grpc ? "grpc" : "snitch", t, p};
        heading += ": " + t + ":" + p;
        break;
    case Act::Geoip:
        if (!prompt(it.title, "IP address (empty: your own)", t, &st.history)) return false;
        args = {"geoip"};
        if (!trim(t).empty()) args.push_back(trim(t));
        break;
    case Act::Ech:
        if (!prompt(it.title, "domain name", t, nullptr) || trim(t).empty()) return false;
        args = {"ech", trim(t)};
        break;
    case Act::Names: {
        if (!prompt(it.title, "one or more host names, space separated", t, nullptr)) return false;
        auto names = split_ws(t);
        if (names.empty()) return false;
        args = {"names"};
        args.insert(args.end(), names.begin(), names.end());
        break;
    }
    case Act::Audit: case Act::Awg:
        if (!prompt(it.title, it.act == Act::Audit ? "path to the config file" : "path to a .pcap or .pcapng", t, nullptr) || trim(t).empty())
            return false;
        args = {it.act == Act::Audit ? "audit-config" : "awg-entropy", trim(t)};
        break;
    case Act::Local: args = {"local"}; break;
    case Act::Help: {
        terminal_hide_ui();
        out("\x1b[2J\x1b[H");
        help();
        wait_key("any key: back to the panel");
        terminal_show_ui();
        return false;
    }
    case Act::Last: {
        const FullReport* r = last_full_report();
        if (!r) { st.flash = "no full scan in this session yet"; return false; }
        terminal_hide_ui();
        out("\x1b[2J\x1b[H");
        print_verdict(*r);
        print_card_below(*r);
        wait_key("any key: back to the panel");
        terminal_show_ui();
        return false;
    }
    case Act::Machine: {
        terminal_hide_ui();
        out("\x1b[2J\x1b[H");
        out(sgr("1;97;45") + "  Machine check  " + RESET + "\r\n");
        // a public address stands in for "any remote node"
        PreflightReport pf = preflight_decide(preflight_gather("1.1.1.1", !g_no_geoip, g_expect_ip), g_override_preflight);
        print_preflight(pf);
        st.health = local_health();
        st.flash = pf.blocked ? "machine check: scans of public targets will stop at preflight" : "machine check: fit to measure";
        wait_key("any key: back to the panel");
        terminal_show_ui();
        return false;
    }
    }

    const PortMode saved_mode = g_port_mode;
    if (it.act == Act::Fast) g_port_mode = PortMode::FAST;
    const int rc = run_outside(st, heading, args);
    g_port_mode = saved_mode;
    if (it.act == Act::Scan || it.act == Act::Fast)
        if (const FullReport* r = last_full_report()) print_card_below(*r);
    out("\r\n" + sgr("2") + "exit code " + exit_meaning(it.act, rc) + RESET);
    st.flash = heading + ": exit " + exit_meaning(it.act, rc);
    wait_key("   any key: back to the panel");
    terminal_show_ui();
    return false;
}

} // namespace

std::string tui_preview(int w, int h, int sel) {
    State st;
    st.health = local_health();
    st.sel = std::clamp(sel, 0, N_ITEMS - 1);
    return render(st, w, h);
}

bool tui_available() {
    return terminal_available();
}

void tui_run() {
    State st;
    st.health = local_health();
    TerminalSession terminal;
    for (;;) {
        draw(st);
        Key k = read_key();
        const bool quit_key = k.k == K::Esc || (k.k == K::Char && (k.ch == 'q' || k.ch == 'Q'));
        if (quit_key) break;
        if (k.k == K::Up) st.sel = (st.sel + N_ITEMS - 1) % N_ITEMS;
        else if (k.k == K::Down || k.k == K::Tab) st.sel = (st.sel + 1) % N_ITEMS;
        else if (k.k == K::Home || k.k == K::PgUp) st.sel = 0;
        else if (k.k == K::End || k.k == K::PgDn) st.sel = N_ITEMS - 1;
        else if (k.k == K::Left || k.k == K::Right) {
            // first item of the neighbouring section, wrapping
            vector<int> starts;
            for (int i = 0; i < N_ITEMS; ++i)
                if (i == 0 || string(ITEMS[i].section) != ITEMS[i - 1].section) starts.push_back(i);
            int cur = 0;
            for (int s = 0; s < (int)starts.size(); ++s) if (starts[s] <= st.sel) cur = s;
            const int n = (int)starts.size();
            st.sel = starts[(cur + (k.k == K::Right ? 1 : n - 1)) % n];
        }
        else if (k.k == K::Char && (k.ch == 's' || k.ch == 'S')) settings_screen(st);
        else if (k.k == K::Char && (k.ch == 'l' || k.ch == 'L')) {
            for (int i = 0; i < N_ITEMS; ++i) if (ITEMS[i].act == Act::Last) st.sel = i;
            if (act(st)) break;
        }
        else if (k.k == K::Char && (k.ch == 'r' || k.ch == 'R')) { st.health = local_health(); st.flash = "status refreshed"; }
        else if (k.k == K::Enter) { if (act(st)) break; }
    }
}
