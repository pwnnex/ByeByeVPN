#include "http.h"
#include "../common/winhdr.h"
#include "../common/util.h"

#include <chrono>
#include <vector>

using std::string;
using std::vector;

HttpResp http_get(const string& url, int timeout_ms) {
    HttpResp r;
    auto t0 = std::chrono::steady_clock::now();
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
    if (!WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
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
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    return r;
}
