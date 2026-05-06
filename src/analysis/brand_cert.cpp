#include "brand_cert.h"
#include "../core/utils.h"

struct BrandMarker {
    const char* brand;
    const char* asn_markers;
};
static const BrandMarker BRAND_TABLE[] = {
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
    {"mts.ru",         "mts"},
    {"megafon.ru",     "megafon"},
    {"beeline.ru",     "beeline,vimpelcom,pjsc vimpelcom"},
    {"rostelecom.ru",  "rostelecom,rt"},
    {"tele2.ru",       "tele2,rostelecom"},
    {"stripe.com",     "stripe,amazon,aws"},
    {"paypal.com",     "paypal,akamai"},
    {"shopify.com",    "shopify,fastly,cloudflare"},
    {"adobe.com",      "adobe"},
    {"salesforce.com", "salesforce"},
    {"dropbox.com",    "dropbox,amazon,aws"},
    {"spotify.com",    "spotify,amazon,aws"},
    {"twitch.tv",      "twitch,amazon,aws"},
    {"vimeo.com",      "vimeo,akamai,amazon"},
    {"reddit.com",     "reddit,fastly"},
    {"steampowered.com","valve,akamai"},
    {"steamcommunity.com","valve,akamai"},
    {"playstation.com","sony,akamai"},
    {"xbox.com",       "microsoft"},
    {"nintendo.com",   "nintendo,amazon,aws,akamai"},
    {"epicgames.com",  "epic games,cloudflare,amazon"},
    {"battle.net",     "blizzard,akamai"},
};
static const size_t BRAND_TABLE_N = sizeof(BRAND_TABLE)/sizeof(BRAND_TABLE[0]);

std::string cert_claims_brand(const std::string& subject_cn, const std::vector<std::string>& san) {
    auto is_brand = [](const std::string& name)->const char*{
        if (name.empty()) return nullptr;
        std::string ln = name;
        for (auto& c: ln) c = (char)std::tolower((unsigned char)c);
        if (ln.size() > 2 && ln[0]=='*' && ln[1]=='.') ln = ln.substr(2);
        for (size_t i=0;i<BRAND_TABLE_N;++i) {
            std::string b = BRAND_TABLE[i].brand;
            if (ln == b) return BRAND_TABLE[i].brand;
            if (ln.size() > b.size() + 1 &&
                ln.compare(ln.size()-b.size(), b.size(), b) == 0 &&
                ln[ln.size()-b.size()-1] == '.') return BRAND_TABLE[i].brand;
        }
        return nullptr;
    };
    const char* hit = is_brand(subject_cn);
    if (hit) return hit;
    for (auto& s: san) { hit = is_brand(s); if (hit) return hit; }
    return {};
}

bool asn_owns_brand(const std::string& brand_domain, const std::vector<std::string>& asn_orgs) {
    if (brand_domain.empty() || asn_orgs.empty()) return false;
    const char* markers = nullptr;
    for (size_t i=0;i<BRAND_TABLE_N;++i) {
        if (brand_domain == BRAND_TABLE[i].brand) {
            markers = BRAND_TABLE[i].asn_markers; break;
        }
    }
    if (!markers) return false;
    std::string ms = markers;
    for (auto& c: ms) c = (char)std::tolower((unsigned char)c);
    std::vector<std::string> parts = split(ms, ',');
    for (auto& org: asn_orgs) {
        std::string lo = org;
        for (auto& c: lo) c = (char)std::tolower((unsigned char)c);
        for (auto& m: parts) {
            std::string mm = trim(m);
            if (!mm.empty() && lo.find(mm) != std::string::npos) return true;
        }
    }
    return false;
}

std::string server_header_brand(const std::string& server_hdr) {
    if (server_hdr.empty()) return {};
    std::string s = server_hdr;
    for (auto& c: s) c = (char)std::tolower((unsigned char)c);
    if (s.find("cloudfront") != std::string::npos) return "amazon.com";
    if (s.find("amazons3")   != std::string::npos) return "amazon.com";
    if (s.find("awselb")     != std::string::npos) return "amazon.com";
    if (s.find("aws elb")    != std::string::npos) return "amazon.com";
    if (s == "gws" || s.find("gws/") != std::string::npos) return "google.com";
    if (s.find("gfe/")       != std::string::npos) return "google.com";
    if (s.find("gse/")       != std::string::npos) return "google.com";
    if (s.find("esf")        != std::string::npos) return "google.com";
    if (s == "cloudflare" || s.find("cloudflare-nginx") != std::string::npos) return "cloudflare.com";
    if (s.find("microsoft-iis")    != std::string::npos) return "microsoft.com";
    if (s.find("microsoft-httpapi")!= std::string::npos) return "microsoft.com";
    if (s.find("yandex")     != std::string::npos) return "yandex.ru";
    if (s.find("applehttpserver") != std::string::npos) return "apple.com";
    return {};
}