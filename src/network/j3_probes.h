#ifndef NETWORK_J3_PROBES_H
#define NETWORK_J3_PROBES_H

#include <string>
#include <vector>
#include <cstdint>

struct J3Result {
    std::string name;
    bool   responded = false;
    int    bytes = 0;
    std::string first_line;
    std::string hex_head;
    int64_t ms = 0;
};

struct J3Analysis {
    int  silent = 0;
    int  resp   = 0;
    int  http_real = 0;
    int  http_bad_version = 0;
    int  raw_non_http = 0;
    int  canned_identical = 0;
    std::string canned_line;
    int  canned_bytes = 0;
};

std::vector<J3Result> j3_probes(const std::string& host, int port);
J3Analysis j3_analyze(const std::vector<J3Result>& probes);

#endif // NETWORK_J3_PROBES_H