#ifndef ANALYSIS_TSPU_H
#define ANALYSIS_TSPU_H

#include <string>

bool looks_like_tspu_hop(const std::string& addr);
const char* looks_like_tspu_redirect(const std::string& location);

#endif // ANALYSIS_TSPU_H