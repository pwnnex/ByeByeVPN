#include "geoip.h"
#include "../net/http.h"
#include "../common/util.h"

using std::string;

GeoInfo geo_ipapi_is(const string& ip) {
    GeoInfo g; g.source = "ipapi.is";
    string url = "https://api.ipapi.is/";
    if (!ip.empty()) url += "?q=" + ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ip");
    g.country      = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "country_code");
    g.city         = json_get_str(r.body, "city");
    string asn_block;
    size_t ap = r.body.find("\"asn\"");
    if (ap != string::npos) {
        size_t ob = r.body.find('{', ap);
        size_t ce = ob == string::npos ? string::npos : r.body.find('}', ob);
        if (ob != string::npos && ce != string::npos)
            asn_block = r.body.substr(ob, ce - ob + 1);
    }
    g.asn     = json_get_str(asn_block, "asn");
    g.asn_org = json_get_str(asn_block, "org");
    if (g.asn.empty()) g.asn = json_get_str(r.body, "asn");
    auto t = [&](const char* k){ return json_get_str(r.body, k) == "true"; };
    g.is_hosting = t("is_datacenter") || t("is_hosting");
    g.is_vpn     = t("is_vpn");
    g.is_proxy   = t("is_proxy");
    g.is_tor     = t("is_tor");
    g.is_abuser  = t("is_abuser");
    return g;
}

GeoInfo geo_iplocate(const string& ip) {
    GeoInfo g; g.source = "iplocate.io";
    string url = "https://iplocate.io/api/lookup/";
    if (!ip.empty()) url += ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ip");
    g.country      = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "country_code");
    g.city         = json_get_str(r.body, "city");
    string asn_block;
    size_t ap = r.body.find("\"asn\"");
    if (ap != string::npos) {
        size_t ob = r.body.find('{', ap);
        size_t ce = ob == string::npos ? string::npos : r.body.find('}', ob);
        if (ob != string::npos && ce != string::npos
            && ob < (r.body.find(',', ap) == string::npos ? ce + 1 : r.body.find(',', ap)))
            asn_block = r.body.substr(ob, ce - ob + 1);
    }
    if (!asn_block.empty()) {
        g.asn     = json_get_str(asn_block, "asn");
        g.asn_org = json_get_str(asn_block, "name");
        if (g.asn_org.empty()) g.asn_org = json_get_str(asn_block, "org");
    } else {
        g.asn     = json_get_str(r.body, "asn");
        g.asn_org = json_get_str(r.body, "org");
    }
    g.is_hosting = json_get_str(r.body, "is_hosting") == "true";
    g.is_vpn     = json_get_str(r.body, "is_vpn") == "true"
                || json_get_str(r.body, "is_anonymous") == "true";
    g.is_proxy   = json_get_str(r.body, "is_proxy") == "true";
    g.is_tor     = json_get_str(r.body, "is_tor") == "true";
    return g;
}

GeoInfo geo_ip_api_com(const string& ip) {
    GeoInfo g; g.source = "ip-api.com";
    string url = "http://ip-api.com/json/";
    if (!ip.empty()) url += ip;
    url += "?fields=status,country,countryCode,city,isp,org,as,asname,hosting,proxy,mobile,query";
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "query");
    g.country      = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "countryCode");
    g.city         = json_get_str(r.body, "city");
    g.asn          = json_get_str(r.body, "as");
    g.asn_org      = json_get_str(r.body, "isp");
    if (g.asn_org.empty()) g.asn_org = json_get_str(r.body, "org");
    g.is_hosting   = json_get_str(r.body, "hosting") == "true";
    g.is_proxy     = json_get_str(r.body, "proxy")   == "true";
    return g;
}

GeoInfo geo_ipwho_is(const string& ip) {
    GeoInfo g; g.source = "ipwho.is";
    string url = "https://ipwho.is/";
    if (!ip.empty()) url += ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ip");
    g.country      = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "country_code");
    g.city         = json_get_str(r.body, "city");
    size_t cp = r.body.find("\"connection\"");
    if (cp != string::npos) {
        size_t ob = r.body.find('{', cp);
        size_t ce = ob == string::npos ? string::npos : r.body.find('}', ob);
        if (ob != string::npos && ce != string::npos) {
            string sb = r.body.substr(ob, ce - ob + 1);
            g.asn     = json_get_str(sb, "asn");
            g.asn_org = json_get_str(sb, "isp");
            if (g.asn_org.empty()) g.asn_org = json_get_str(sb, "org");
        }
    }
    return g;
}

GeoInfo geo_ipinfo_io(const string& ip) {
    GeoInfo g; g.source = "ipinfo.io";
    string url = "https://ipinfo.io/";
    if (!ip.empty()) url += ip;
    url += "/json";
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ip");
    g.country_code = json_get_str(r.body, "country");
    g.city         = json_get_str(r.body, "city");
    string orgraw  = json_get_str(r.body, "org");
    if (!orgraw.empty()) {
        if (orgraw.rfind("AS", 0) == 0) {
            size_t sp = orgraw.find(' ');
            if (sp != string::npos) {
                g.asn     = orgraw.substr(0, sp);
                g.asn_org = orgraw.substr(sp + 1);
            } else g.asn = orgraw;
        } else g.asn_org = orgraw;
    }
    return g;
}

GeoInfo geo_freeipapi(const string& ip) {
    GeoInfo g; g.source = "freeipapi.com";
    string url = "https://freeipapi.com/api/json/";
    if (!ip.empty()) url += ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ipAddress");
    g.country      = json_get_str(r.body, "countryName");
    g.country_code = json_get_str(r.body, "countryCode");
    g.city         = json_get_str(r.body, "cityName");
    return g;
}

GeoInfo geo_2ip_ru(const string& ip) {
    GeoInfo g; g.source = "2ip.me (RU)";
    string url = "http://api.2ip.me/geo.json?ip=" + ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ip");
    if (g.ip.empty()) g.ip = ip;
    g.country      = json_get_str(r.body, "country");
    if (g.country.empty()) g.country = json_get_str(r.body, "country_rus");
    if (g.country.empty()) g.country = json_get_str(r.body, "countryName");
    g.country_code = json_get_str(r.body, "country_code");
    if (g.country_code.empty()) g.country_code = json_get_str(r.body, "countryCode");
    g.city         = json_get_str(r.body, "city");
    if (g.city.empty()) g.city = json_get_str(r.body, "city_rus");
    if (g.city.empty()) g.city = json_get_str(r.body, "cityName");
    string org     = json_get_str(r.body, "org");
    if (!org.empty()) g.asn_org = org;
    return g;
}

GeoInfo geo_ipapi_ru(const string& ip) {
    GeoInfo g; g.source = "ip-api.com/ru (RU)";
    string url = "http://ip-api.com/json/";
    if (!ip.empty()) url += ip;
    url += "?lang=ru&fields=status,country,countryCode,city,isp,org,as,asname,hosting,proxy,mobile,query";
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "query");
    g.country      = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "countryCode");
    g.city         = json_get_str(r.body, "city");
    g.asn          = json_get_str(r.body, "as");
    g.asn_org      = json_get_str(r.body, "isp");
    if (g.asn_org.empty()) g.asn_org = json_get_str(r.body, "org");
    g.is_hosting   = json_get_str(r.body, "hosting") == "true";
    g.is_proxy     = json_get_str(r.body, "proxy")   == "true";
    return g;
}

GeoInfo geo_sypex(const string& ip) {
    GeoInfo g; g.source = "sypexgeo.net (RU)";
    string url = "http://api.sypexgeo.net/json/" + ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = ip;
    // nested JSON: country.name_en / city.name_en / region.name_en
    g.country_code = json_get_str(r.body, "iso");
    {
        size_t cp = r.body.find("\"country\"");
        if (cp != string::npos) {
            size_t ob = r.body.find('{', cp);
            size_t ce = ob == string::npos ? string::npos : r.body.find('}', ob);
            if (ob != string::npos && ce != string::npos) {
                string sb = r.body.substr(ob, ce - ob + 1);
                g.country = json_get_str(sb, "name_en");
                if (g.country.empty()) g.country = json_get_str(sb, "name_ru");
                if (g.country_code.empty()) g.country_code = json_get_str(sb, "iso");
            }
        }
    }
    {
        size_t cp = r.body.find("\"city\"");
        if (cp != string::npos) {
            size_t ob = r.body.find('{', cp);
            size_t ce = ob == string::npos ? string::npos : r.body.find('}', ob);
            if (ob != string::npos && ce != string::npos) {
                string sb = r.body.substr(ob, ce - ob + 1);
                g.city = json_get_str(sb, "name_en");
                if (g.city.empty()) g.city = json_get_str(sb, "name_ru");
            }
        }
    }
    return g;
}
