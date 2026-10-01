// SPDX-License-Identifier: GPL-3.0-or-later
#include "http.h"
#include "../common/winhdr.h"
#include "../common/util.h"

#include <chrono>
#include <algorithm>
#include <cstdint>
#include <limits>
#include <vector>

using std::string;
using std::vector;

HttpResp http_get(const string& url, int timeout_ms, const string& accept) {
    HttpResp r;
    auto t0 = std::chrono::steady_clock::now();
    URL_COMPONENTS u{}; u.dwStructSize = sizeof(u);
    wchar_t host[256] = {0}, path[1024] = {0};
    u.lpszHostName = host; u.dwHostNameLength = 255;
    u.lpszUrlPath = path;  u.dwUrlPathLength  = 1023;
    std::wstring wurl = s2ws(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &u)) { r.err = "bad url"; return r; }

    // bare get, no ua. json endpoints don't need anything else.
    HINTERNET hS = WinHttpOpen(L"", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) { r.err = "open"; return r; }
    WinHttpSetTimeouts(hS, timeout_ms, timeout_ms, timeout_ms, timeout_ms);
    // force empty ua, winhttp sneaks a default one in otherwise
    WinHttpSetOption(hS, WINHTTP_OPTION_USER_AGENT, (LPVOID)L"", 0);
    // no WINHTTP_OPTION_DECOMPRESSION: it adds accept-encoding

    HINTERNET hC = WinHttpConnect(hS, host, u.nPort, 0);
    if (!hC) { r.err = "connect"; WinHttpCloseHandle(hS); return r; }
    DWORD flags = (u.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hR = WinHttpOpenRequest(hC, L"GET", path, nullptr,
                                      WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hR) { r.err = "req"; WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return r; }
    // optional accept header (content-negotiating endpoints only; empty for the
    // bare-get callers). -1L length tells winhttp to measure the string itself.
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
    uint64_t expected_length = 0;
    bool check_length = false;
    wchar_t length_text[64]{};
    DWORD length_size = sizeof(length_text);
    const bool has_length = WinHttpQueryHeaders(hR, WINHTTP_QUERY_CONTENT_LENGTH,
                            nullptr, length_text, &length_size, nullptr) != 0;
    const DWORD length_error = has_length ? ERROR_SUCCESS : GetLastError();
    if (!has_length && length_error != ERROR_WINHTTP_HEADER_NOT_FOUND)
        r.err = "cannot read HTTP Content-Length";
    if (has_length) {
        check_length = true;
        if (length_text[0] == 0) r.err = "empty HTTP Content-Length";
        for (wchar_t c : std::wstring(length_text)) {
            if (c < L'0' || c > L'9' ||
                expected_length > (std::numeric_limits<uint64_t>::max() - (c - L'0')) / 10) {
                r.err = "invalid HTTP Content-Length";
                break;
            }
            expected_length = expected_length * 10 + (c - L'0');
        }
    }
    // we never ask for gzip, an encoded body is unusable
    wchar_t encoding[32]{};
    DWORD encoding_size = sizeof(encoding);
    if (WinHttpQueryHeaders(hR, WINHTTP_QUERY_CONTENT_ENCODING, nullptr,
                            encoding, &encoding_size, nullptr)) {
        if (_wcsicmp(encoding, L"identity") != 0 && r.err.empty())
            r.err = "unrequested HTTP Content-Encoding";
    } else if (GetLastError() != ERROR_WINHTTP_HEADER_NOT_FOUND && r.err.empty()) {
        r.err = "unrequested HTTP Content-Encoding";
    }
    // a fixed buffer bounds allocation; read failures must not look like success.
    constexpr size_t limit = 512 * 1024;
    char buffer[8192];
    while (r.err.empty()) {
        DWORD got = 0;
        const DWORD want = static_cast<DWORD>(std::min(sizeof(buffer), limit + 1 - r.body.size()));
        if (!WinHttpReadData(hR, buffer, want, &got)) {
            r.err = "read " + std::to_string(GetLastError());
            break;
        }
        if (got == 0) break;
        r.body.append(buffer, got);
        if (r.body.size() > limit) {
            r.body.resize(limit);
            r.err = "HTTP body exceeds 512 KiB";
            break;
        }
    }
    if (r.err.empty() && check_length && r.body.size() != expected_length)
        r.err = "HTTP body length differs from Content-Length";
    WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    return r;
}
