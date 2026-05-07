// crt.sh Certificate Transparency lookup. real public CAs MUST submit
// every issued cert to a CT log (RFC 9162). a SHA256 returning [] means
// the cert was never logged = private CA / internal / cloned / LE-staging.
#pragma once

#include <string>

struct CtCheck {
    bool        queried     = false;
    bool        found       = false;
    int         log_entries = 0;
    std::string err;
};

CtCheck ct_check(const std::string& cert_sha256);
