// SPDX-License-Identifier: GPL-3.0-or-later
#include "brand.h"
#include "../common/util.h"

#include <cctype>

using std::string;
using std::vector;

namespace {

struct BrandMarker {
    const char* brand;
    const char* asn_markers;  // comma-separated ASN-org substrings
};

const BrandMarker BRAND_TABLE[] = {
    // global tech giants
    {"amazon.com",     "amazon,aws,a100 row,amazon technologies"},
    {"aws.amazon.com", "amazon,aws"},
    {"microsoft.com",  "microsoft,msn,msft,akamai,edgecast"},
    {"apple.com",      "apple,akamai"},
    {"icloud.com",     "apple"},
    {"google.com",     "google,gts,gcp,youtube"},
    {"googleusercontent.com", "google,gcp"},
    {"googleapis.com", "google,gcp"},
    {"youtube.com",    "google,youtube"},
    {"cloudflare.com", "cloudflare,cloudflare inc"},
    {"github.com",     "github,microsoft,fastly"},
    {"gitlab.com",     "gitlab,cloudflare"},
    {"bitbucket.org",  "atlassian,amazon"},
    {"yahoo.com",      "yahoo,oath,verizon"},
    {"netflix.com",    "netflix,akamai"},
    {"cdn.jsdelivr.net","fastly,cloudflare"},
    {"bing.com",       "microsoft"},
    {"gstatic.com",    "google"},
    {"wikipedia.org",  "wikimedia"},
    {"wikimedia.org",  "wikimedia"},
    {"linkedin.com",   "linkedin,microsoft"},
    {"office.com",     "microsoft"},
    {"office365.com",  "microsoft"},
    {"outlook.com",    "microsoft"},
    {"live.com",       "microsoft"},
    {"azure.com",      "microsoft"},
    {"onedrive.com",   "microsoft"},
    // social networks / messengers
    {"facebook.com",   "facebook,meta"},
    {"instagram.com",  "facebook,meta"},
    {"whatsapp.com",   "facebook,meta"},
    {"whatsapp.net",   "facebook,meta"},
    {"messenger.com",  "facebook,meta"},
    {"threads.net",    "facebook,meta"},
    {"twitter.com",    "twitter,x corp,x holdings"},
    {"x.com",          "twitter,x corp,x holdings"},
    {"tiktok.com",     "tiktok,bytedance,akamai"},
    {"telegram.org",   "telegram,telegram messenger"},
    {"t.me",           "telegram,telegram messenger"},
    {"telegram.me",    "telegram,telegram messenger"},
    {"discord.com",    "discord,cloudflare,google"},
    {"discordapp.com", "discord,cloudflare,google"},
    {"slack.com",      "slack,amazon,aws"},
    {"zoom.us",        "zoom"},
    {"signal.org",     "signal,amazon,aws"},
    // RU-priority (state DPI context)
    {"yandex.ru",      "yandex"},
    {"yandex.net",     "yandex"},
    {"yandex.com",     "yandex"},
    {"ya.ru",          "yandex"},
    {"mail.ru",        "mail.ru,vk,v kontakte"},
    {"vk.com",         "vk,v kontakte,mail.ru"},
    {"vk.ru",          "vk,v kontakte,mail.ru"},
    {"vkontakte.ru",   "vk,v kontakte,mail.ru"},
    {"ok.ru",          "vk,v kontakte,mail.ru"},
    {"avito.ru",       "avito,kiev internet"},
    {"ozon.ru",        "ozon"},
    {"wildberries.ru", "wildberries"},
    {"kinopoisk.ru",   "yandex"},
    {"rutube.ru",      "rutube,rbc,gpmd"},
    {"dzen.ru",        "yandex,vk"},
    {"habr.com",       "habr,habrahabr"},
    {"rambler.ru",     "rambler,rambler internet"},
    // Russian banks / state
    {"sberbank.ru",    "sberbank,sber"},
    {"sber.ru",        "sberbank,sber"},
    {"sberbank.com",   "sberbank,sber"},
    {"tinkoff.ru",     "tinkoff,t-bank,tcs"},
    {"tbank.ru",       "tinkoff,t-bank,tcs"},
    {"vtb.ru",         "vtb,vtb bank"},
    {"alfabank.ru",    "alfabank,alfa bank"},
    {"gazprombank.ru", "gazprombank,gazprom"},
    {"rosbank.ru",     "rosbank,societe"},
    {"gosuslugi.ru",   "rostelecom,rt,rt-labs"},
    {"mos.ru",         "dit,moscow,mgts"},
    {"rt.ru",          "rostelecom,rt"},
    {"nalog.gov.ru",   "rostelecom,rt"},
    // Russian telecom
    {"mts.ru",         "mts"},
    {"megafon.ru",     "megafon"},
    {"beeline.ru",     "beeline,vimpelcom,pjsc vimpelcom"},
    {"rostelecom.ru",  "rostelecom,rt"},
    {"tele2.ru",       "tele2,rostelecom"},
    // finance / commerce (global)
    {"stripe.com",     "stripe,amazon,aws"},
    {"paypal.com",     "paypal,akamai"},
    {"shopify.com",    "shopify,fastly,cloudflare"},
    {"adobe.com",      "adobe"},
    {"salesforce.com", "salesforce"},
    {"dropbox.com",    "dropbox,amazon,aws"},
    // streaming / media
    {"spotify.com",    "spotify,amazon,aws"},
    {"twitch.tv",      "twitch,amazon,aws"},
    {"vimeo.com",      "vimeo,akamai,amazon"},
    {"reddit.com",     "reddit,fastly"},
    // gaming
    {"steampowered.com","valve,akamai"},
    {"steamcommunity.com","valve,akamai"},
    {"playstation.com","sony,akamai"},
    {"xbox.com",       "microsoft"},
    {"nintendo.com",   "nintendo,amazon,aws,akamai"},
    {"epicgames.com",  "epic games,cloudflare,amazon"},
    {"battle.net",     "blizzard,akamai"},
};

constexpr size_t BRAND_TABLE_N = sizeof(BRAND_TABLE) / sizeof(BRAND_TABLE[0]);

const char* match_brand(const string& name) {
    if (name.empty()) return nullptr;
    string ln = name;
    for (auto& c: ln) c = (char)std::tolower((unsigned char)c);
    if (ln.size() > 2 && ln[0] == '*' && ln[1] == '.') ln = ln.substr(2);
    for (size_t i = 0; i < BRAND_TABLE_N; ++i) {
        string b = BRAND_TABLE[i].brand;
        if (ln == b) return BRAND_TABLE[i].brand;
        if (ln.size() > b.size() + 1 &&
            ln.compare(ln.size() - b.size(), b.size(), b) == 0 &&
            ln[ln.size() - b.size() - 1] == '.') return BRAND_TABLE[i].brand;
    }
    return nullptr;
}

} // namespace

string cert_claims_brand(const string& subject_cn, const vector<string>& san) {
    const char* hit = match_brand(subject_cn);
    if (hit) return hit;
    for (auto& s: san) { hit = match_brand(s); if (hit) return hit; }
    return {};
}

bool asn_owns_brand(const string& brand_domain, const vector<string>& asn_orgs) {
    if (brand_domain.empty() || asn_orgs.empty()) return false;
    const char* markers = nullptr;
    for (size_t i = 0; i < BRAND_TABLE_N; ++i) {
        if (brand_domain == BRAND_TABLE[i].brand) {
            markers = BRAND_TABLE[i].asn_markers; break;
        }
    }
    if (!markers) return false;
    string ms = markers;
    for (auto& c: ms) c = (char)std::tolower((unsigned char)c);
    vector<string> parts = split(ms, ',');
    for (auto& org: asn_orgs) {
        string lo = org;
        for (auto& c: lo) c = (char)std::tolower((unsigned char)c);
        for (auto& m: parts) {
            string mm = trim(m);
            if (!mm.empty() && lo.find(mm) != string::npos) return true;
        }
    }
    return false;
}

string server_header_brand(const string& server_hdr) {
    if (server_hdr.empty()) return {};
    string s = server_hdr;
    for (auto& c: s) c = (char)std::tolower((unsigned char)c);
    if (s.find("cloudfront") != string::npos) return "amazon.com";
    if (s.find("amazons3")   != string::npos) return "amazon.com";
    if (s.find("awselb")     != string::npos) return "amazon.com";
    if (s.find("aws elb")    != string::npos) return "amazon.com";
    if (s == "gws" || s.find("gws/") != string::npos) return "google.com";
    if (s.find("gfe/")       != string::npos) return "google.com";
    if (s.find("gse/")       != string::npos) return "google.com";
    if (s.find("esf")        != string::npos) return "google.com";
    if (s == "cloudflare" || s.find("cloudflare-nginx") != string::npos) return "cloudflare.com";
    if (s.find("microsoft-iis")    != string::npos) return "microsoft.com";
    if (s.find("microsoft-httpapi")!= string::npos) return "microsoft.com";
    if (s.find("yandex")     != string::npos) return "yandex.ru";
    if (s.find("applehttpserver") != string::npos) return "apple.com";
    return {};
}