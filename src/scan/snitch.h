// SNITCH-style latency / GeoIP consistency check (methodika §10.1).
// 6 TCP samples to target + 3 parallel anchor batches (CF/Google/Yandex).
// classifies "RTT impossibly low for claimed country" / "extra hops" /
// "high jitter" patterns.
#pragma once

#include <string>

struct SnitchResult {
    bool   ok       = false;
    int    samples  = 0;
    double median_ms = 0.0;
    double min_ms    = 0.0;
    double max_ms    = 0.0;
    double stddev_ms = 0.0;
    // anchor RTTs (vantage-point baselines)
    double cf_median_ms     = -1.0;  // 1.1.1.1
    double google_median_ms = -1.0;  // 8.8.8.8
    double yandex_median_ms = -1.0;  // 77.88.8.8

    std::string country_code;
    double      expected_min_ms   = 0.0;
    bool        too_low           = false;
    bool        too_high          = false;
    bool        high_jitter       = false;
    bool        anchor_ratio_off  = false;
    std::string summary;
};

SnitchResult snitch_check(const std::string& target_ip,
                          int target_port,
                          const std::string& country_code);
