#ifndef ANALYSIS_SNITCH_H
#define ANALYSIS_SNITCH_H

#include <string>
#include <vector>

struct SnitchResult {
    bool    ok = false;
    int     samples = 0;
    double  median_ms = 0.0;
    double  min_ms    = 0.0;
    double  max_ms    = 0.0;
    double  stddev_ms = 0.0;
    double  cf_median_ms      = -1.0;
    double  google_median_ms  = -1.0;
    double  yandex_median_ms  = -1.0;
    std::string  country_code;
    double  expected_min_ms = 0.0;
    bool    too_low        = false;
    bool    too_high       = false;
    bool    high_jitter    = false;
    bool    anchor_ratio_off = false;
    std::string  summary;
};

SnitchResult snitch_check(const std::string& target_ip, int target_port, const std::string& country_code);

#endif // ANALYSIS_SNITCH_H