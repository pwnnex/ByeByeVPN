// SPDX-License-Identifier: GPL-3.0-or-later
#include "http.h"
#include "../common/platform.h"
#include "../common/util.h"

#include <chrono>
#include <mutex>
#include <vector>

#ifndef _WIN32
#include <curl/curl.h>
#endif

using std::string;
using std::vector;

HttpResp http_get(const string& url, int timeout_ms, const string& accept) {
    HttpResp r;
    auto t0 = std::chrono::steady_clock::now();
#ifdef _WIN32
    URL_COMPONENTS u{}; u.dwStructSize = sizeof(u);
    wchar_t host[256] = {0}, path[1024] = {0};
    u.lpszHostName = host; u.dwHostNameLength = 255;
    u.lpszUrlPath = path;  u.dwUrlPathLength  = 1023;
    std::wstring wurl = s2ws(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &u)) { r.err = "bad url"; return r; }

    // bare GET, no UA. JSON endpoints don't need anything else.
    HINTERNET hS = WinHttpOpen(L"", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) { r.err = "open"; return r; }
    WinHttpSetTimeouts(hS, timeout_ms, timeout_ms, timeout_ms, timeout_ms);
    // force empty UA, winhttp sneaks a default one in otherwise
    WinHttpSetOption(hS, WINHTTP_OPTION_USER_AGENT, (LPVOID)L"", 0);
    DWORD decomp = WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
    WinHttpSetOption(hS, WINHTTP_OPTION_DECOMPRESSION, &decomp, sizeof(decomp));

    HINTERNET hC = WinHttpConnect(hS, host, u.nPort, 0);
    if (!hC) { r.err = "connect"; WinHttpCloseHandle(hS); return r; }
    DWORD flags = (u.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hR = WinHttpOpenRequest(hC, L"GET", path, nullptr,
                                      WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hR) { r.err = "req"; WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return r; }
    // optional Accept header (content-negotiating endpoints only; empty for the
    // bare-GET callers). -1L length tells WinHTTP to measure the string itself.
    LPCWSTR hdr_ptr = WINHTTP_NO_ADDITIONAL_HEADERS;
    DWORD   hdr_len = 0;
    std::wstring hdrs;
    if (!accept.empty()) {
        hdrs = s2ws("Accept: " + accept + "\r\n");
        hdr_ptr = hdrs.c_str();
        hdr_len = (DWORD)-1L;
    }
    if (!WinHttpSendRequest(hR, hdr_ptr, hdr_len,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hR, nullptr)) {
        r.err = "io " + std::to_string(GetLastError());
        WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
        return r;
    }
    DWORD st = 0, sz = sizeof(st);
    WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        nullptr, &st, &sz, nullptr);
    r.status = (int)st;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hR, &avail) || avail == 0) break;
        vector<char> buf(avail);
        DWORD got = 0;
        if (!WinHttpReadData(hR, buf.data(), avail, &got) || got == 0) break;
        r.body.append(buf.data(), got);
        if (r.body.size() > 512 * 1024) break;
    }
    WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
#else
    static std::once_flag curl_initialized;
    std::call_once(curl_initialized, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
    CURL* curl = curl_easy_init();
    if (!curl) { r.err = "curl init"; return r; }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_ms));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(timeout_ms));
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "");
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
        +[](char* data, size_t size, size_t count, void* opaque) -> size_t {
            auto* body = static_cast<string*>(opaque);
            size_t bytes = size * count;
            if (body->size() + bytes > 512 * 1024) return 0;
            body->append(data, bytes);
            return bytes;
        });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &r.body);
    curl_slist* headers = nullptr;
    if (!accept.empty()) {
        headers = curl_slist_append(headers, ("Accept: " + accept).c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }
    CURLcode code = curl_easy_perform(curl);
    if (code == CURLE_OK) {
        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        r.status = static_cast<int>(status);
    } else {
        r.err = curl_easy_strerror(code);
    }
    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
#endif
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    return r;
}