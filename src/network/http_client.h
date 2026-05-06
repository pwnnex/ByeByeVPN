#ifndef NETWORK_HTTP_CLIENT_H
#define NETWORK_HTTP_CLIENT_H

#include <string>

struct HttpResp {
    int status = 0;
    std::string body;
    std::string err;
    long long ms = 0;
    bool ok() const { return status >= 200 && status < 400; }
};

HttpResp http_get(const std::string& url, int timeout_ms = 7000);

#endif // NETWORK_HTTP_CLIENT_H