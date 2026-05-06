#ifndef ANALYSIS_GEOIP_H
#define ANALYSIS_GEOIP_H

#include <string>

struct GeoInfo {
    std::string ip, country, country_code, city, asn, asn_org;
    bool is_hosting = false, is_vpn = false, is_proxy = false, is_tor = false, is_abuser = false;
    std::string source;
    std::string err;
};

GeoInfo geo_ipapi_is(const std::string& ip);
GeoInfo geo_iplocate(const std::string& ip);
GeoInfo geo_ip_api_com(const std::string& ip);
GeoInfo geo_ipwho_is(const std::string& ip);
GeoInfo geo_ipinfo_io(const std::string& ip);
GeoInfo geo_freeipapi(const std::string& ip);
GeoInfo geo_2ip_ru(const std::string& ip);
GeoInfo geo_ipapi_ru(const std::string& ip);
GeoInfo geo_sypex(const std::string& ip);

#endif // ANALYSIS_GEOIP_H