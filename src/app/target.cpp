// SPDX-License-Identifier: GPL-3.0-or-later
#include "target.h"
#include "../common/console.h"

#include <string>

using std::string;

void print_banner_scan(const string& t) {
    printf("%s%s== Target: %s ==%s\n", col(C::BOLD), col(C::WHT), t.c_str(), col(C::RST));
}

void print_geo(const GeoInfo& g) {
    if (!g.err.empty()) {
        printf("  %s%-12s%s %serr: %s%s\n",
               col(C::CYN), g.source.c_str(), col(C::RST),
               col(C::RED), g.err.c_str(), col(C::RST));
        return;
    }
    printf("  %s%-12s%s IP %s%-15s%s  %s%s%s  (%s) AS %s %s\n",
           col(C::CYN), g.source.c_str(), col(C::RST),
           col(C::WHT), g.ip.c_str(), col(C::RST),
           col(C::BOLD), g.country_code.empty() ? g.country.c_str() : g.country_code.c_str(), col(C::RST),
           g.city.c_str(), g.asn.c_str(), g.asn_org.c_str());
    string flags;
    auto add = [&](bool v, const char* n, const char* c){
        if (v) {
            if (!flags.empty()) flags += " ";
            flags += col(c); flags += n; flags += col(C::RST);
        }
    };
    add(g.is_hosting, "HOSTING", C::YEL);
    add(g.is_vpn,     "VPN",     C::RED);
    add(g.is_proxy,   "PROXY",   C::RED);
    add(g.is_tor,     "TOR",     C::RED);
    add(g.is_abuser,  "ABUSER",  C::RED);
    if (!flags.empty()) printf("               flags: %s\n", flags.c_str());
}