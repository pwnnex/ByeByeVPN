// SPDX-License-Identifier: GPL-3.0-or-later
#include "hostname_marks.h"
#include "../common/util.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <set>

using std::string;
using std::vector;

namespace {

enum class Match {
    // split on '-' and '_'; allow numeric suffixes after a known token.
    Word,
    // distinctive names also match in combined labels like v2rayshare.
    Anywhere,
};

struct TokenDef {
    const char* token;
    Match mode;
    HostnameMark::Tier tier;
    const char* why;
};

// tiers describe the name's specificity, not measured detection accuracy.
const TokenDef TOKENS[] = {
    // distinctive protocol and software names
    {"vless",       Match::Anywhere, HostnameMark::Tier::Strong,   "names the VLESS protocol outright"},
    {"vmess",       Match::Anywhere, HostnameMark::Tier::Strong,   "names the VMess protocol outright"},
    {"v2ray",       Match::Anywhere, HostnameMark::Tier::Strong,   "names the v2ray/V2Fly core outright"},
    {"shadowsocks", Match::Anywhere, HostnameMark::Tier::Strong,   "names the Shadowsocks protocol outright"},
    {"wireguard",   Match::Anywhere, HostnameMark::Tier::Strong,   "names the WireGuard protocol outright"},
    {"openvpn",     Match::Anywhere, HostnameMark::Tier::Strong,   "names the OpenVPN protocol outright"},
    {"amneziawg",   Match::Anywhere, HostnameMark::Tier::Strong,   "names AmneziaWG outright"},
    {"marzban",     Match::Anywhere, HostnameMark::Tier::Strong,   "names the Marzban panel outright"},
    {"marzneshin",  Match::Anywhere, HostnameMark::Tier::Strong,   "names the Marzneshin panel outright"},
    {"hiddify",     Match::Anywhere, HostnameMark::Tier::Strong,   "names the Hiddify panel outright"},
    {"remnawave",   Match::Anywhere, HostnameMark::Tier::Strong,   "names the Remnawave panel outright"},
    {"selfsteal",   Match::Anywhere, HostnameMark::Tier::Strong,   "the literal SELF_STEAL_DOMAIN string from the RU Reality installers"},
    {"ovpn",        Match::Word,     HostnameMark::Tier::Strong,   "the standard OpenVPN abbreviation"},

    // suggestive names with unrelated uses
    {"vpn",         Match::Word,     HostnameMark::Tier::Moderate, "also the standard label for corporate IPsec/SSL-VPN concentrators"},
    {"wg",          Match::Word,     HostnameMark::Tier::Moderate, "WireGuard shorthand; the Mullvad/IVPN fleet convention"},
    {"xray",        Match::Word,     HostnameMark::Tier::Moderate, "names the Xray core; also an ordinary English word"},
    {"xtls",        Match::Word,     HostnameMark::Tier::Moderate, "names the XTLS transport"},
    {"reality",     Match::Word,     HostnameMark::Tier::Moderate, "names the Reality transport; RU installers prompt with reality.example.com"},
    {"amnezia",     Match::Word,     HostnameMark::Tier::Moderate, "names the Amnezia project"},
    {"awg",         Match::Word,     HostnameMark::Tier::Moderate, "AmneziaWG shorthand"},
    {"socks",       Match::Word,     HostnameMark::Tier::Moderate, "names the SOCKS proxy protocol"},
    {"socks5",      Match::Word,     HostnameMark::Tier::Moderate, "names the SOCKS5 proxy protocol"},
    {"subscription",Match::Word,     HostnameMark::Tier::Moderate, "the panel subscription endpoint convention"},
    {"substore",    Match::Word,     HostnameMark::Tier::Moderate, "names a self-hosted Sub-Store instance"},
    {"sublink",     Match::Word,     HostnameMark::Tier::Moderate, "subscription-link host convention"},
    {"subconverter",Match::Word,     HostnameMark::Tier::Moderate, "names a subscription-format converter"},
    {"panel",       Match::Word,     HostnameMark::Tier::Moderate, "the admin-UI label prescribed by 3x-ui/Marzban/Remnawave docs - but also cPanel/Plesk/Pterodactyl"},
    {"sub",         Match::Word,     HostnameMark::Tier::Moderate, "the subscription-host convention - but also the laziest subdomain in any tutorial"},
    {"node",        Match::Word,     HostnameMark::Tier::Moderate, "the Marzban/Remnawave traffic-carrying server label; also ordinary cluster naming"},
    {"xui",         Match::Word,     HostnameMark::Tier::Moderate, "names the x-ui / 3x-ui panel"},
    {"3xui",        Match::Word,     HostnameMark::Tier::Moderate, "names the 3x-ui panel"},
    {"sui",         Match::Word,     HostnameMark::Tier::Moderate, "names the s-ui panel"},
    {"clash",       Match::Word,     HostnameMark::Tier::Moderate, "names the Clash client family"},
    {"mihomo",      Match::Word,     HostnameMark::Tier::Moderate, "names the Mihomo (Clash.Meta) core"},
    {"singbox",     Match::Word,     HostnameMark::Tier::Moderate, "names the sing-box core"},
    {"relays",      Match::Word,     HostnameMark::Tier::Moderate, "the Mullvad relay-zone convention"},

    // broad associations
    {"proxy",       Match::Word,     HostnameMark::Tier::Weak,     "names the function, but used for every kind of proxy"},
    {"trojan",      Match::Word,     HostnameMark::Tier::Weak,     "names the Trojan protocol; also an everyday English word"},
    {"hysteria",    Match::Word,     HostnameMark::Tier::Weak,     "names the Hysteria protocol; also an everyday English word"},
    {"hysteria2",   Match::Word,     HostnameMark::Tier::Weak,     "names the Hysteria2 protocol"},
    {"hy2",         Match::Word,     HostnameMark::Tier::Weak,     "Hysteria2 shorthand"},
    {"tuic",        Match::Word,     HostnameMark::Tier::Weak,     "names the TUIC protocol; a handful of unrelated orgs use it too"},
    {"ssr",         Match::Word,     HostnameMark::Tier::Weak,     "ShadowsocksR shorthand"},
    {"shadowtls",   Match::Word,     HostnameMark::Tier::Weak,     "names the ShadowTLS transport"},
    {"naiveproxy",  Match::Word,     HostnameMark::Tier::Weak,     "names NaiveProxy"},
    {"snell",       Match::Word,     HostnameMark::Tier::Weak,     "names the Snell protocol"},
    {"juicity",     Match::Word,     HostnameMark::Tier::Weak,     "names the Juicity protocol"},
    {"anytls",      Match::Word,     HostnameMark::Tier::Weak,     "names the AnyTLS protocol"},
    {"mtproto",     Match::Word,     HostnameMark::Tier::Weak,     "names the Telegram MTProto proxy"},
    {"mtproxy",     Match::Word,     HostnameMark::Tier::Weak,     "names the Telegram MTProto proxy"},
    {"obfs4",       Match::Word,     HostnameMark::Tier::Weak,     "names the Tor obfs4 pluggable transport"},
    {"snowflake",   Match::Word,     HostnameMark::Tier::Weak,     "names the Tor Snowflake transport; also an ordinary word"},
    {"psiphon",     Match::Word,     HostnameMark::Tier::Weak,     "names Psiphon"},
    {"ocserv",      Match::Word,     HostnameMark::Tier::Weak,     "names the OpenConnect server"},
    {"openconnect", Match::Word,     HostnameMark::Tier::Weak,     "names OpenConnect"},
    {"anyconnect",  Match::Word,     HostnameMark::Tier::Weak,     "names Cisco AnyConnect - enterprise remote access, not circumvention"},
    {"softether",   Match::Word,     HostnameMark::Tier::Weak,     "names SoftEther VPN"},
    {"pritunl",     Match::Word,     HostnameMark::Tier::Weak,     "names the Pritunl VPN server"},
    {"sstp",        Match::Word,     HostnameMark::Tier::Weak,     "names Microsoft SSTP"},
    {"l2tp",        Match::Word,     HostnameMark::Tier::Weak,     "names L2TP"},
    {"pptp",        Match::Word,     HostnameMark::Tier::Weak,     "names PPTP"},
    {"ikev2",       Match::Word,     HostnameMark::Tier::Weak,     "names IKEv2"},
    {"ipsec",       Match::Word,     HostnameMark::Tier::Weak,     "names IPsec - overwhelmingly enterprise, not circumvention"},
    {"tailscale",   Match::Word,     HostnameMark::Tier::Weak,     "names Tailscale - mesh VPN, ordinary corporate and homelab use"},
    {"headscale",   Match::Word,     HostnameMark::Tier::Weak,     "names Headscale"},
    {"zerotier",    Match::Word,     HostnameMark::Tier::Weak,     "names ZeroTier"},
    {"netbird",     Match::Word,     HostnameMark::Tier::Weak,     "names NetBird"},
    {"wstunnel",    Match::Word,     HostnameMark::Tier::Weak,     "names wstunnel"},
    {"sspanel",     Match::Word,     HostnameMark::Tier::Weak,     "names SSPanel-Uim"},
    {"v2board",     Match::Word,     HostnameMark::Tier::Weak,     "names the V2Board panel"},
    {"xboard",      Match::Word,     HostnameMark::Tier::Weak,     "names the Xboard panel"},
    {"pasarguard",  Match::Word,     HostnameMark::Tier::Weak,     "names the PasarGuard panel"},
    {"xrayr",       Match::Word,     HostnameMark::Tier::Weak,     "names the XrayR backend"},
    {"wgdashboard", Match::Word,     HostnameMark::Tier::Weak,     "names WGDashboard"},
    {"nekobox",     Match::Word,     HostnameMark::Tier::Weak,     "names the NekoBox client"},
    {"nekoray",     Match::Word,     HostnameMark::Tier::Weak,     "names the NekoRay client"},
    {"tor",         Match::Word,     HostnameMark::Tier::Weak,     "names Tor; composes with exit/node marks"},
    {"exit",        Match::Word,     HostnameMark::Tier::Weak,     "how tor-exit / exit-node are actually spelled once hyphens are split"},
    {"tunnel",      Match::Word,     HostnameMark::Tier::Weak,     "names the technique; Cloudflare Tunnel and ngrok made it mainstream"},
    {"subs",        Match::Word,     HostnameMark::Tier::Weak,     "subscription-host variant"},
    {"subscribe",   Match::Word,     HostnameMark::Tier::Weak,     "subscription-host variant; also ordinary newsletter vocabulary"},
    {"config",      Match::Word,     HostnameMark::Tier::Weak,     "config-distribution host practice; also Spring Cloud Config"},
    {"pool",        Match::Word,     HostnameMark::Tier::Weak,     "proxypool / sspool naming; also ordinary connection pools"},
    {"airport",     Match::Word,     HostnameMark::Tier::Weak,     "the CN community word for a subscription seller"},
    {"jichang",     Match::Word,     HostnameMark::Tier::Weak,     "jichang - the CN word for a subscription seller"},
    {"free",        Match::Word,     HostnameMark::Tier::Weak,     "free-node sharing sites; also an everyday word"},
    {"впн",         Match::Word,     HostnameMark::Tier::Moderate, "Russian spelling of VPN"},
    {"подписка",    Match::Word,     HostnameMark::Tier::Weak,     "Russian word for subscription; also ordinary commerce"},
};
constexpr size_t TOKENS_N = sizeof(TOKENS) / sizeof(TOKENS[0]);

bool numbered_token(const string& word, const string& token) {
    return word.size() > token.size() && word.compare(0, token.size(), token) == 0 &&
           std::all_of(word.begin() + token.size(), word.end(), [](char c) { return c >= '0' && c <= '9'; });
}

// split a label into hyphen/underscore separated words. "vless-de1" -> {vless, de1}
vector<string> label_words(const string& label) {
    vector<string> out;
    string cur;
    for (char c : label) {
        if (c == '-' || c == '_') { if (!cur.empty()) out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

bool in_zone(const string& name, const string& zone) {
    return name == zone || (name.size() > zone.size() &&
           name.compare(name.size() - zone.size(), zone.size(), zone) == 0 &&
           name[name.size() - zone.size() - 1] == '.');
}

// these are naming conventions, not a live server inventory. see docs/HOSTNAME_ANALYSIS.md.
void append_provider_marks(const HostnameInput& input, HostnameAnalysis& a) {
    struct Provider { const char* zone; const char* name; };
    static const Provider providers[] = {
        {"mullvad.net", "Mullvad"}, {"ivpn.net", "IVPN"},
        {"nordvpn.com", "NordVPN"}, {"cloudflareclient.com", "Cloudflare WARP"},
    };
    auto add = [&](const char* token, const char* kind, HostnameMark::Tier tier, const string& why) {
        HostnameMark m;
        m.token = token;
        m.host = input.canonical;
        m.label = input.labels.front();
        m.decoded_label = input.decoded_labels.front();
        m.in_subdomain = registrable_domain_start(input.labels) > 0;
        m.kind = kind;
        m.tier = tier;
        m.why = why;
        m.sources = {"target"};
        a.marks.push_back(std::move(m));
    };
    for (const auto& p : providers) {
        if (!in_zone(input.canonical, p.zone)) continue;
        add(p.name, "provider_domain", HostnameMark::Tier::Weak,
            "name under a documented provider domain; website/API names do not establish a VPN endpoint");
        if (input.wildcard) continue;
        const auto& l = input.labels;
        bool node = false;
        if (string(p.zone) == "mullvad.net" && l.size() == 4 && l[1] == "relays") {
            const auto words = label_words(l[0]);
            node = (words.size() == 4 || words.size() == 5) && words[0].size() == 2 &&
                   words[1].size() == 3 && words[2] == "wg" &&
                   (words.size() == 4 || words[3] == "socks5") &&
                   std::all_of(words.back().begin(), words.back().end(), [](char c) { return c >= '0' && c <= '9'; });
        } else if (string(p.zone) == "ivpn.net") {
            node = l.size() == 4 && l[1] == "wg" && l[0].size() >= 2;
        } else if (string(p.zone) == "nordvpn.com" && l.size() == 3) {
            node = l[0].size() >= 3 && l[0][0] >= 'a' && l[0][0] <= 'z' &&
                   l[0][1] >= 'a' && l[0][1] <= 'z' && numbered_token(l[0], l[0].substr(0, 2));
        }
        if (node) add(p.name, "provider_node", HostnameMark::Tier::Moderate,
                      "matches a provider's documented node naming pattern; DNS and service availability are unverified");
    }
    if (in_zone(input.canonical, "workers.dev"))
        add("Cloudflare Workers", "hosting_domain", HostnameMark::Tier::Weak,
            "shared application hosting; this suffix is not VPN evidence");
}

} // namespace

const char* hostname_tier_name(HostnameMark::Tier t) {
    switch (t) {
        case HostnameMark::Tier::Strong:   return "strong";
        case HostnameMark::Tier::Moderate: return "moderate";
        default:                           return "weak";
    }
}

vector<string> hostname_labels(const string& host) {
    return parse_hostname(host).labels;
}

HostnameAnalysis analyze_hostname(const string& host) {
    HostnameAnalysis a;
    const auto input = parse_hostname(host);
    const auto& labels = input.labels;
    if (labels.empty()) return a;

    size_t sub_end = registrable_domain_start(labels);

    // public suffix labels belong to a registry or shared host, not the user.
    for (size_t i = 0; i < public_suffix_start(labels); ++i) {
        const string& label = input.decoded_labels[i];
        const bool in_sub = (i < sub_end);
        // one mark per token per label, even if the token appears twice.
        std::set<string> hit;

        auto add_mark = [&](const TokenDef& def) {
            if (!hit.insert(def.token).second) return;
            HostnameMark m;
            m.token = def.token;
            m.label = labels[i];
            m.decoded_label = label;
            m.host = input.canonical;
            m.in_subdomain = in_sub;
            m.tier = def.tier;
            m.why  = def.why;
            m.sources = {"target"};
            a.marks.push_back(std::move(m));
        };

        // coined names are label-level: they may sit anywhere inside it.
        for (size_t t = 0; t < TOKENS_N; ++t)
            if (TOKENS[t].mode == Match::Anywhere &&
                label.find(TOKENS[t].token) != string::npos)
                add_mark(TOKENS[t]);

        // exact matches win; socks5 must not also count as socks.
        for (const string& w : label_words(label)) {
            bool exact = false;
            for (size_t t = 0; t < TOKENS_N; ++t) {
                if (TOKENS[t].mode != Match::Word) continue;
                if (w == TOKENS[t].token) { add_mark(TOKENS[t]); exact = true; }
            }
            if (exact) continue;

            const TokenDef* best = nullptr;
            for (const auto& def : TOKENS)
                if (def.mode == Match::Word && numbered_token(w, def.token) &&
                    (!best || string(def.token).size() > string(best->token).size())) best = &def;
            if (best) add_mark(*best);
        }
    }

    append_provider_marks(input, a);
    for (const auto& m : a.marks) {
        switch (m.tier) {
            case HostnameMark::Tier::Strong:   ++a.strong;   break;
            case HostnameMark::Tier::Moderate: ++a.moderate; break;
            default:                           ++a.weak;     break;
        }
    }
    return a;
}

HostnameAnalysis analyze_host_names(const vector<ObservedHostname>& names) {
    std::map<string, vector<string>> sources;
    vector<string> ordered;
    for (const auto& observation : names) {
        const auto input = parse_hostname(observation.name);
        if (input.status != HostnameInput::Status::Hostname) continue;
        auto [it, inserted] = sources.try_emplace(input.canonical);
        if (inserted) ordered.push_back(input.canonical);
        auto& list = it->second;
        if (std::find(list.begin(), list.end(), observation.source) == list.end()) list.push_back(observation.source);
    }
    HostnameAnalysis all;
    for (const auto& n : ordered) {
        HostnameAnalysis one = analyze_hostname(n);
        for (auto& m : one.marks) {
            m.sources = sources.at(n);
            all.marks.push_back(std::move(m));
        }
    }
    for (const auto& m : all.marks) {
        switch (m.tier) {
            case HostnameMark::Tier::Strong:   ++all.strong;   break;
            case HostnameMark::Tier::Moderate: ++all.moderate; break;
            default:                           ++all.weak;     break;
        }
    }
    return all;
}

HostnameAnalysis analyze_host_names(const string& scanned_host,
                                    const string& subject_cn,
                                    const vector<string>& san) {
    vector<ObservedHostname> names = {{scanned_host, "target"}, {subject_cn, "cert_cn"}};
    for (const auto& s : san) names.push_back({s, "cert_san"});
    return analyze_host_names(names);
}
