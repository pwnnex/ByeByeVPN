#include "snitch.h"
#include "../network/tcp_scanner.h"
#include <chrono>
#include <cmath>
#include <algorithm>
#include <future>

static double percentile(std::vector<double> v, double pct) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    size_t n = v.size();
    double idx = pct * (n - 1);
    size_t lo = (size_t)std::floor(idx);
    size_t hi = (size_t)std::ceil(idx);
    if (lo == hi) return v[lo];
    double frac = idx - lo;
    return v[lo] * (1 - frac) + v[hi] * frac;
}

static double tcp_rtt_sample_ms(const std::string& host, int port, int to_ms) {
    auto t0 = std::chrono::steady_clock::now();
    std::string err;
    SOCKET s = tcp_connect(host, port, to_ms, err);
    if (s == INVALID_SOCKET) return -1.0;
    auto t1 = std::chrono::steady_clock::now();
    closesocket(s);
    double us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    return us / 1000.0;
}

static void measure_rtt_series(const std::string& host, int port, int to_ms, int samples, std::vector<double>& out) {
    out.reserve(samples);
    for (int i = 0; i < samples; ++i) {
        double ms = tcp_rtt_sample_ms(host, port, to_ms);
        if (ms > 0) out.push_back(ms);
    }
}

static double country_min_rtt_ms(const std::string& cc) {
    static const struct { const char* cc; double min_ms; double max_ms; } TBL[] = {
        {"RU",     4,    40},
        {"BY",    10,    40},
        {"UA",    10,    50},
        {"KZ",    20,    80},
        {"LT",    15,    45},
        {"LV",    15,    45},
        {"EE",    15,    45},
        {"FI",    10,    45},
        {"SE",    20,    55},
        {"NO",    25,    60},
        {"DE",    25,    60},
        {"NL",    30,    65},
        {"FR",    30,    70},
        {"GB",    35,    75},
        {"IT",    35,    80},
        {"ES",    45,    90},
        {"PL",    25,    60},
        {"CZ",    25,    60},
        {"AT",    30,    65},
        {"CH",    30,    70},
        {"BE",    30,    65},
        {"HU",    30,    65},
        {"RO",    30,    70},
        {"BG",    30,    70},
        {"TR",    45,   100},
        {"IL",    60,   120},
        {"IR",    70,   150},
        {"AE",    80,   150},
        {"SA",    80,   160},
        {"IN",   110,   220},
        {"CN",   130,   290},
        {"HK",   140,   280},
        {"JP",   150,   300},
        {"KR",   150,   300},
        {"SG",   160,   320},
        {"TH",   160,   320},
        {"ID",   180,   350},
        {"AU",   230,   420},
        {"NZ",   260,   460},
        {"US",   100,   200},
        {"CA",   100,   200},
        {"MX",   130,   260},
        {"BR",   180,   340},
        {"AR",   210,   380},
        {"ZA",   160,   320},
        {"EG",   60,    130},
    };
    if (cc.empty()) return 0.0;
    std::string u = cc;
    for (auto& c: u) c = (char)std::toupper((unsigned char)c);
    for (auto& e: TBL) if (u == e.cc) return e.min_ms;
    return 0.0;
}

static double country_max_rtt_ms(const std::string& cc) {
    static const struct { const char* cc; double max_ms; } TBL[] = {
        {"RU",40},{"BY",40},{"UA",50},{"KZ",80},{"LT",45},{"LV",45},{"EE",45},
        {"FI",45},{"SE",55},{"NO",60},{"DE",60},{"NL",65},{"FR",70},{"GB",75},
        {"IT",80},{"ES",90},{"PL",60},{"CZ",60},{"AT",65},{"CH",70},{"BE",65},
        {"HU",65},{"RO",70},{"BG",70},{"TR",100},{"IL",120},{"IR",150},{"AE",150},
        {"SA",160},{"IN",220},{"CN",290},{"HK",280},{"JP",300},{"KR",300},{"SG",320},
        {"TH",320},{"ID",350},{"AU",420},{"NZ",460},{"US",200},{"CA",200},{"MX",260},
        {"BR",340},{"AR",380},{"ZA",320},{"EG",130},
    };
    if (cc.empty()) return 0.0;
    std::string u = cc;
    for (auto& c: u) c = (char)std::toupper((unsigned char)c);
    for (auto& e: TBL) if (u == e.cc) return e.max_ms;
    return 0.0;
}

SnitchResult snitch_check(const std::string& target_ip, int target_port, const std::string& country_code) {
    SnitchResult r; r.country_code = country_code;
    const int samples = 6;

    auto anchor_job = [&](std::string ip, int port) {
        std::vector<double> xs; measure_rtt_series(ip, port, 1500, 4, xs);
        std::sort(xs.begin(), xs.end());
        if (xs.size() >= 4) xs.pop_back();
        return xs.empty() ? -1.0 : percentile(xs, 0.5);
    };
    auto f_cf   = std::async(std::launch::async, anchor_job, "1.1.1.1",      443);
    auto f_goog = std::async(std::launch::async, anchor_job, "8.8.8.8",      443);
    auto f_yan  = std::async(std::launch::async, anchor_job, "77.88.8.8",    443);

    std::vector<double> samples_v;
    measure_rtt_series(target_ip, target_port, 2000, samples, samples_v);
    r.samples = (int)samples_v.size();
    if (r.samples < 3) {
        r.ok = false;
        r.summary = "insufficient samples (<3 successful TCP handshakes)";
        r.cf_median_ms     = f_cf.get();
        r.google_median_ms = f_goog.get();
        r.yandex_median_ms = f_yan.get();
        return r;
    }
    std::sort(samples_v.begin(), samples_v.end());
    if ((int)samples_v.size() >= 5) samples_v.pop_back();
    double sum = 0.0;
    r.min_ms = samples_v.front();
    r.max_ms = samples_v.back();
    for (auto v: samples_v) sum += v;
    double mean = sum / static_cast<double>(samples_v.size());
    double var  = 0;
    for (auto v: samples_v) var += (v - mean) * (v - mean);
    var /= static_cast<double>(samples_v.size());
    r.stddev_ms = std::sqrt(var);
    r.median_ms = percentile(samples_v, 0.5);

    r.cf_median_ms     = f_cf.get();
    r.google_median_ms = f_goog.get();
    r.yandex_median_ms = f_yan.get();

    double emin = country_min_rtt_ms(country_code);
    double emax = country_max_rtt_ms(country_code);
    r.expected_min_ms = emin;
    if (emin > 0) {
        if (r.median_ms < emin * 0.5) r.too_low  = true;
        if (r.median_ms > emax * 3.0) r.too_high = true;
    }
    if (r.stddev_ms > 40.0) r.high_jitter = true;

    double closest = std::min({
        r.cf_median_ms > 0 ? r.cf_median_ms : 9e9,
        r.google_median_ms > 0 ? r.google_median_ms : 9e9,
        r.yandex_median_ms > 0 ? r.yandex_median_ms : 9e9
    });
    if (closest > 0 && closest < 9e9 && r.median_ms > 0) {
        double ratio = r.median_ms / closest;
        if (emax > 0 && emax < 80.0 && ratio > 4.0) r.anchor_ratio_off = true;
        if (emin > 0 && emin > 60.0 && r.median_ms < closest * 0.8) r.anchor_ratio_off = true;
    }
    r.ok = true;
    {
        char buf[256];
        if (r.too_low)
            snprintf(buf, sizeof(buf),
                     "median %.1fms but %s geo implies >=%.0fms — impossibly low (GeoIP lies OR anycast proxy)",
                     r.median_ms, country_code.c_str(), emin);
        else if (r.too_high)
            snprintf(buf, sizeof(buf),
                     "median %.1fms is >3x the normal %.0fms band for %s — extra hops in path (tunnel / long middlebox chain)",
                     r.median_ms, emax, country_code.c_str());
        else if (r.high_jitter)
            snprintf(buf, sizeof(buf),
                     "stddev %.1fms over %d samples — high jitter typical of tunnel queue/encryption overhead",
                     r.stddev_ms, r.samples);
        else if (r.anchor_ratio_off)
            snprintf(buf, sizeof(buf),
                     "target RTT doesn't match closest anchor ratio — location doesn't add up");
        else
            snprintf(buf, sizeof(buf),
                     "RTT %.1fms (min %.1f, stddev %.1f) — consistent with %s geolocation",
                     r.median_ms, r.min_ms, r.stddev_ms, country_code.c_str());
        r.summary = buf;
    }
    return r;
}