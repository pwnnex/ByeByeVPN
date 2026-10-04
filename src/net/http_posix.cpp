// SPDX-License-Identifier: GPL-3.0-or-later
#include "http.h"

#include <curl/curl.h>

#include <chrono>
#include <mutex>
#include <string>

using std::string;

HttpResp http_get(const string& url, int timeout_ms, const string& accept) {
    HttpResp response;
    const auto started = std::chrono::steady_clock::now();
    static std::once_flag curl_initialized;
    std::call_once(curl_initialized, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });

    CURL* curl = curl_easy_init();
    if (!curl) { response.err = "curl init"; return response; }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_ms));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(timeout_ms));
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
        +[](char* data, size_t size, size_t count, void* opaque) -> size_t {
            auto* body = static_cast<string*>(opaque);
            const size_t bytes = size * count;
            if (body->size() + bytes > 512 * 1024) return 0;
            body->append(data, bytes);
            return bytes;
        });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);

    curl_slist* headers = nullptr;
    if (!accept.empty()) {
        headers = curl_slist_append(headers, ("Accept: " + accept).c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }
    const CURLcode code = curl_easy_perform(curl);
    if (code == CURLE_OK) {
        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        response.status = static_cast<int>(status);
    } else if (code == CURLE_WRITE_ERROR && response.body.size() >= 512 * 1024) {
        response.err = "HTTP body exceeds 512 KiB";
    } else {
        response.err = curl_easy_strerror(code);
    }
    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    response.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();
    return response;
}
