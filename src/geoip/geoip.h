// SPDX-License-Identifier: GPL-3.0-or-later
// geoip aggregation across five https providers
// queries reveal the target ip to those providers
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

// all five providers are https-only.
GeoInfo geo_ipapi_is(const std::string& ip);
GeoInfo geo_iplocate(const std::string& ip);
GeoInfo geo_freeipapi(const std::string& ip);
GeoInfo geo_ipwho_is(const std::string& ip);
GeoInfo geo_ipinfo_io(const std::string& ip);
