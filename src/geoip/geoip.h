// SPDX-License-Identifier: GPL-3.0-or-later
// GeoIP aggregation across 5 HTTPS-only providers.
//
// v2.6.0 scope cut: the four HTTP-only providers (api.2ip.me,
// ip-api.com, ip-api.com/ru, api.sypexgeo.net) were removed. a plaintext
// HTTP GeoIP query exposes the target IP being looked up to every
// on-path observer between the scanner host and the provider, which on a
// censored network is exactly the leak this tool is meant to help avoid.
// the five remaining providers all speak HTTPS, so the lookup payload
// stays encrypted in transit.
#pragma once

#include <string>

struct GeoInfo {
    std::string ip, country, country_code, city, asn, asn_org;
    bool is_hosting = false;
    bool is_vpn     = false;
    bool is_proxy   = false;
    bool is_tor     = false;
    bool is_abuser  = false;
    std::string source;
    std::string err;
};

// all five providers are HTTPS-only.
GeoInfo geo_ipapi_is(const std::string& ip);
GeoInfo geo_iplocate(const std::string& ip);
GeoInfo geo_freeipapi(const std::string& ip);
GeoInfo geo_ipwho_is(const std::string& ip);
GeoInfo geo_ipinfo_io(const std::string& ip);
