#ifndef ANALYSIS_CT_CHECK_H
#define ANALYSIS_CT_CHECK_H

#include <string>

struct CtCheck {
    bool   queried     = false;
    bool   found       = false;
    int    log_entries = 0;
    std::string err;
};

CtCheck ct_check(const std::string& cert_sha256);

#endif // ANALYSIS_CT_CHECK_H