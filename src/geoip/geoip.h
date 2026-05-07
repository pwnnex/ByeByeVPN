// GeoIP aggregation across 9 providers (3 EU / 3 RU / 3 global).
// disagreement between providers is itself diagnostic — RU providers see
// Russian hosting ASNs differently from EU/US.
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

// EU
GeoInfo geo_ipapi_is(const std::string& ip);
GeoInfo geo_iplocate(const std::string& ip);
GeoInfo geo_freeipapi(const std::string& ip);

// RU
GeoInfo geo_2ip_ru(const std::string& ip);
GeoInfo geo_ipapi_ru(const std::string& ip);
GeoInfo geo_sypex(const std::string& ip);

// global
GeoInfo geo_ip_api_com(const std::string& ip);
GeoInfo geo_ipwho_is(const std::string& ip);
GeoInfo geo_ipinfo_io(const std::string& ip);
