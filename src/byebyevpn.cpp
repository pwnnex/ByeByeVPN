// ByeByeVPN — full VPN / proxy / Reality detectability analyzer
// ----------------------------------------------------------------------------
// Targets an arbitrary IP or hostname and performs:
//
//   1) DNS resolution + parallel GeoIP aggregation (7 providers, RU + EU).
//   2) TCP port scan — full (1..65535), fast (205 curated ports), ranged or
//      explicit list. Banner grab + service hints on every open port.
//   3) UDP probes: OpenVPN HARD_RESET, WireGuard handshake init, IKEv2 on
//      500/4500, QUIC on 443, Tailscale on 41641, DNS.
//   4) Service fingerprint on every open port:
//        SSH banner, HTTP probe, TLS handshake + SNI-steering test + ALPN,
//        SOCKS5 greet, HTTP CONNECT proxy test, Shadowsocks/Trojan probe,
//        Reality discriminator (cert must cover a foreign SNI), VLESS/XHTTP
//        fallback check.
//   5) J3 / TSPU / GFW-style active-probing suite (8 probes per TLS port).
//   6) TLS fingerprint: version, cipher, ALPN, group, cert subject / issuer /
//      SHA-256 / SAN list.
//   7) Timing analysis: RTT jitter, duplicate-RTT middlebox detection.
//   8) Verdict engine: strict protocol-level stack identification + per-port
//      role classification + technical recommendations.
//
//   Extra: `byebyevpn local` — local-host posture (adapters, routes, split-
//   tunnel detection, running VPN/proxy processes, installed config dirs).
//
// No raw sockets. No admin privileges required.
// Platform: Windows x64, OpenSSL 3.x. Builds as a single static .exe.
//
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <windows.h>
#include <tlhelp32.h>
#include <winhttp.h>
#include <conio.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <future>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using std::string;
using std::vector;
using std::optional;
using std::set;

// ============================================================================
// console
// ============================================================================
static bool g_no_color = false;
static bool g_verbose  = false;
static int  g_threads  = 500;
static int  g_tcp_to   = 800;
static int  g_udp_to   = 900;
// Stealth / privacy opt-outs (all default off = full scanner behaviour).
// Documented in SECURITY.md §Known open threats — these toggle the
// inherent behavioural-fingerprint surfaces that can't be closed at the
// per-byte layer.
static bool g_stealth    = false;  // master toggle: implies no-geoip + no-ct + udp-jitter
static bool g_no_geoip   = false;  // skip all 9 3rd-party GeoIP services
static bool g_no_ct      = false;  // skip crt.sh Certificate Transparency lookups
static bool g_udp_jitter = false;  // add 50-300ms random delay between UDP probes

// v2.5.7 - save scan output to a file (#7).
// --save           writes <target>.md in the current directory
// --save <path>    writes the explicit path (still wrapped as markdown)
// Implementation: every printf/puts call is teed to stdout (with ANSI colors)
// AND to g_save_fp (with ANSI escapes stripped). The file is wrapped in a
// markdown code block so it renders cleanly in any md viewer.
static bool   g_save_requested = false;
static FILE*  g_save_fp        = nullptr;
static string g_save_path;

// port-scan mode
enum class PortMode { FULL, FAST, RANGE, LIST };
static PortMode    g_port_mode = PortMode::FULL;
static int         g_range_lo  = 1;
static int         g_range_hi  = 65535;
static std::vector<int> g_port_list;

namespace C {
    static const char* RST  = "\x1b[0m";
    static const char* BOLD = "\x1b[1m";
    static const char* DIM  = "\x1b[2m";
    static const char* RED  = "\x1b[31m";
    static const char* GRN  = "\x1b[32m";
    static const char* YEL  = "\x1b[33m";
    static const char* BLU  = "\x1b[34m";
    static const char* MAG  = "\x1b[35m";
    static const char* CYN  = "\x1b[36m";
    static const char* WHT  = "\x1b[97m";
}
static const char* col(const char* c) { return g_no_color ? "" : c; }

// ----------------------------------------------------------------------------
// Tee-output infrastructure (v2.5.7, --save flag, issue #7).
// ----------------------------------------------------------------------------
// Strip ANSI CSI / SGR sequences (ESC '[' ... letter) when writing to the
// save file, so the .md is plain text without escape codes. We never emit
// any other escape class (no OSC, no ESC ] etc.), so this is sufficient.
static void save_write_stripped(const char* s, size_t n) {
    if (!g_save_fp || !s || !n) return;
    for (size_t i = 0; i < n; ) {
        if (s[i] == '\x1b' && i + 1 < n && s[i+1] == '[') {
            i += 2;
            while (i < n && !(s[i] >= '@' && s[i] <= '~')) ++i;
            if (i < n) ++i; // consume terminator letter
        } else {
            fputc((unsigned char)s[i], g_save_fp);
            ++i;
        }
    }
}

// tee_printf: prints to stdout (ANSI preserved) AND to g_save_fp (ANSI stripped).
static int tee_printf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vprintf(fmt, ap);
    va_end(ap);
    if (g_save_fp && fmt) {
        char small[2048];
        va_list ap2; va_start(ap2, fmt);
        int needed = vsnprintf(small, sizeof(small), fmt, ap2);
        va_end(ap2);
        if (needed > 0 && needed < (int)sizeof(small)) {
            save_write_stripped(small, (size_t)needed);
        } else if (needed >= (int)sizeof(small)) {
            std::vector<char> big((size_t)needed + 1);
            va_list ap3; va_start(ap3, fmt);
            vsnprintf(big.data(), big.size(), fmt, ap3);
            va_end(ap3);
            save_write_stripped(big.data(), (size_t)needed);
        }
    }
    return n;
}

// tee_puts: same idea for puts (puts always appends a newline).
// NOTE: must use fputs/fputc, not puts(), because the macro below would
// otherwise turn the recursive call back into tee_puts -> infinite loop.
static int tee_puts(const char* s) {
    if (!s) return 0;
    fputs(s, stdout);
    fputc('\n', stdout);
    if (g_save_fp) {
        save_write_stripped(s, strlen(s));
        fputc('\n', g_save_fp);
    }
    return 0;
}

#define printf tee_printf
#define puts   tee_puts

static void enable_vt() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleOutputCP(CP_UTF8);
}

static void banner() {
    printf("%s%s", col(C::BOLD), col(C::MAG));
    puts(" ____             ____           __     ______  _   _ ");
    puts("| __ ) _   _  ___| __ ) _   _  __\\ \\   / /  _ \\| \\ | |");
    puts("|  _ \\| | | |/ _ \\  _ \\| | | |/ _ \\ \\ / /| |_) |  \\| |");
    puts("| |_) | |_| |  __/ |_) | |_| |  __/\\ V / |  __/| |\\  |");
    puts("|____/ \\__, |\\___|____/ \\__, |\\___| \\_/  |_|   |_| \\_|");
    puts("       |___/            |___/                          ");
    printf("%s", col(C::RST));
    printf("%s  Full TSPU/DPI/VPN detectability scanner  v2.5.7%s\n\n",
           col(C::DIM), col(C::RST));
}

// ============================================================================
// util
// ============================================================================
static string tolower_s(string s) {
    for (auto& c: s) c = (char)tolower((unsigned char)c);
    return s;
}
static bool contains(const string& h, const string& n) { return h.find(n) != string::npos; }
static bool starts_with(const string& s, const string& p) {
    return s.size() >= p.size() && std::memcmp(s.data(), p.data(), p.size()) == 0;
}
static string trim(const string& s) {
    size_t a=0,b=s.size();
    while(a<b && isspace((unsigned char)s[a])) ++a;
    while(b>a && isspace((unsigned char)s[b-1])) --b;
    return s.substr(a,b-a);
}
static vector<string> split(const string& s, char sep) {
    vector<string> r; string cur;
    for (char c: s) {
        if (c == sep) { r.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    r.push_back(cur);
    return r;
}
static string hex_s(const unsigned char* d, size_t n, bool spaces = false) {
    static const char* hex = "0123456789abcdef";
    string s; s.reserve(n*(spaces?3:2));
    for (size_t i=0;i<n;++i) {
        s += hex[(d[i]>>4)&0xF]; s += hex[d[i]&0xF];
        if (spaces && i+1<n) s += ' ';
    }
    return s;
}
static string ws2s(const wchar_t* w) {
    if (!w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    string s((size_t)n - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}
static std::wstring s2ws(const string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring w((size_t)n - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

// JSON scan (plain)
static string json_get_str(const string& body, const string& key) {
    string pat = "\"" + key + "\"";
    size_t p = 0;
    while ((p = body.find(pat, p)) != string::npos) {
        size_t q = p + pat.size();
        while (q < body.size() && (body[q]==' '||body[q]==':'||body[q]=='\t')) ++q;
        if (q >= body.size()) return {};
        if (body[q] == '"') {
            size_t e = q + 1;
            string v;
            while (e < body.size() && body[e] != '"') {
                if (body[e] == '\\' && e+1 < body.size()) { v += body[e+1]; e += 2; }
                else { v += body[e]; ++e; }
            }
            return v;
        } else {
            size_t e = q;
            while (e < body.size() && body[e]!=',' && body[e]!='}' && body[e]!='\n') ++e;
            return trim(body.substr(q, e-q));
        }
    }
    return {};
}

// ============================================================================
// TSPU-specific helpers (see DanielLavrushin/tspu-docs for the methodology)
// ============================================================================

// tspu management subnets use 10.<region>.<site>.Z layout:
//   .131-.140 balancers, .141-.150 bmc, .151-.190 filters,
//   .191-.230 ipmi, .231-.235 spfs, .241-.245 spxd, .254 kontinent gw.
// if a private hop seen in traceroute falls in these ranges - likely tspu.
static bool looks_like_tspu_hop(const string& addr) {
    if (addr.size() < 8 || addr.size() > 15) return false;
    if (addr.compare(0, 3, "10.") != 0) return false;
    unsigned a = 0, b = 0, c = 0;
    if (sscanf(addr.c_str(), "10.%u.%u.%u", &a, &b, &c) != 3) return false;
    if (a > 255 || b > 255 || c > 255) return false;
    // last-octet ranges from tspu-docs ch. 10
    if (c >= 131 && c <= 235) return true;
    if (c >= 241 && c <= 245) return true;
    if (c == 254) return true;
    return false;
}

// known tspu-operator block/warning redirect destinations (http 302 Location).
// source: public observations + tspu-docs ch. 5.1.5
// all entries hardcoded, never modified at runtime.
static const char* TSPU_REDIRECT_MARKERS[] = {
    "rkn.gov.ru",
    "warning.rt.ru",
    "nt.rtk.ru",
    "blocked.rt.ru",
    "blocked.ruvds.com",
    "blocked.tattelecom.ru",
    "blocked.yota.ru",
    "zapret.gov.ru",
    "eais.rkn.gov.ru",
    "185.76.180.75",      // rostelecom warning page
    "185.76.180.76",
    "185.76.180.77",
    nullptr
};

// compare a Location: value (up to 512 chars) against the blacklist.
// case-insensitive substring match. caller must ensure location is bounded.
static const char* looks_like_tspu_redirect(const string& location) {
    if (location.empty() || location.size() > 512) return nullptr;
    string ll = location;
    for (auto& ch: ll) ch = (char)std::tolower((unsigned char)ch);
    for (const char** p = TSPU_REDIRECT_MARKERS; *p; ++p) {
        if (ll.find(*p) != string::npos) return *p;
    }
    return nullptr;
}

// ============================================================================
// DNS resolve (returns all IPs)
// ============================================================================
struct Resolved {
    string host;
    string primary_ip;
    vector<string> ips;
    string family; // v4 / v6 / mixed
    string err;
    long long ms = 0;
};

static string sa_ip(const sockaddr* sa) {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (sa->sa_family == AF_INET) {
        auto* s4 = (sockaddr_in*)sa;
        InetNtopA(AF_INET, &s4->sin_addr, buf, sizeof(buf));
    } else {
        auto* s6 = (sockaddr_in6*)sa;
        InetNtopA(AF_INET6, &s6->sin6_addr, buf, sizeof(buf));
    }
    return buf;
}

static Resolved resolve_host(const string& host) {
    Resolved r; r.host = host;
    auto t0 = std::chrono::steady_clock::now();
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    addrinfo* ai = nullptr;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &ai);
    if (rc != 0) { r.err = gai_strerrorA(rc); return r; }
    // v2.4 — split resolution by family and ALWAYS prefer IPv4 as primary.
    //
    // Rationale: a hostname like my.vpn.server can have both AAAA and A
    // records. Depending on DNS ordering and the host's OS happy-eyeballs
    // policy, getaddrinfo often returns the AAAA record FIRST. If we then
    // use that as primary_ip, every subsequent TCP/UDP probe goes over
    // v6 — and on a v4-only ISP connection (common in Russia/CIS) v6
    // connects silently timeout, producing an entirely empty open-port
    // set. Users saw "works with IP, breaks with hostname" — that's
    // exactly the symptom of silent v6 failure.
    //
    // Fix: put every v4 address first, then v6 as a fallback. The
    // primary_ip picked is always the first v4 if any exist. This
    // matches what a real DPI probe would see (it connects over v4
    // because that's the canonical DPI-observable path on Russian ISPs).
    vector<string> v4_ips, v6_ips;
    for (auto* p = ai; p; p = p->ai_next) {
        string ip = sa_ip(p->ai_addr);
        if (p->ai_family == AF_INET) {
            if (std::find(v4_ips.begin(), v4_ips.end(), ip) == v4_ips.end())
                v4_ips.push_back(ip);
        } else if (p->ai_family == AF_INET6) {
            if (std::find(v6_ips.begin(), v6_ips.end(), ip) == v6_ips.end())
                v6_ips.push_back(ip);
        }
    }
    freeaddrinfo(ai);
    for (auto& s: v4_ips) r.ips.push_back(s);
    for (auto& s: v6_ips) r.ips.push_back(s);
    if (!r.ips.empty()) r.primary_ip = r.ips.front();
    bool has4 = !v4_ips.empty(), has6 = !v6_ips.empty();
    r.family = (has4 && has6) ? "mixed(v4-preferred)"
             : has4 ? "v4"
             : has6 ? "v6" : "";
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    return r;
}

// ============================================================================
// TCP connect (non-blocking with timeout)
// ============================================================================
static SOCKET tcp_connect(const string& host, int port, int timeout_ms, string& err) {
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    addrinfo* ai = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &ai) != 0) {
        err = "dns"; return INVALID_SOCKET;
    }
    // v2.4 — iterate v4 addresses first, then v6. Avoids the common
    // "happy eyeballs" trap where getaddrinfo returns AAAA first and
    // an unreachable v6 burns the whole timeout on every port probe.
    vector<addrinfo*> ordered;
    for (auto* p = ai; p; p = p->ai_next) if (p->ai_family == AF_INET)  ordered.push_back(p);
    for (auto* p = ai; p; p = p->ai_next) if (p->ai_family == AF_INET6) ordered.push_back(p);
    SOCKET s = INVALID_SOCKET;
    // remember the most informative failure across all ai iterations.
    // priority: refused > timeout > other.
    bool saw_timeout = false, saw_refused = false, saw_other = false;
    for (auto* p: ordered) {
        s = socket(p->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) { saw_other = true; continue; }
        u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
        int rc = connect(s, p->ai_addr, (int)p->ai_addrlen);
        if (rc == 0) { u_long bl=0; ioctlsocket(s,FIONBIO,&bl); break; }
        if (WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set wr, ex; FD_ZERO(&wr); FD_SET(s, &wr); FD_ZERO(&ex); FD_SET(s, &ex);
            timeval tv{}; tv.tv_sec = timeout_ms/1000; tv.tv_usec = (timeout_ms%1000)*1000;
            int sr = select(0, nullptr, &wr, &ex, &tv);
            if (sr > 0 && FD_ISSET(s, &wr)) {
                int se = 0; int sl = sizeof(se);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&se, &sl);
                if (se == 0) { u_long bl=0; ioctlsocket(s,FIONBIO,&bl); break; }
                if (se == WSAECONNREFUSED) saw_refused = true;
                else saw_other = true;
            } else if (sr == 0) {
                saw_timeout = true;  // select ran out with no event
            } else {
                saw_other = true;
            }
        } else {
            int le = WSAGetLastError();
            if (le == WSAECONNREFUSED) saw_refused = true;
            else saw_other = true;
        }
        closesocket(s); s = INVALID_SOCKET;
    }
    freeaddrinfo(ai);
    if (s == INVALID_SOCKET) {
        if (saw_refused)      err = "refused";
        else if (saw_timeout) err = "timeout";
        else                  err = "other";
    }
    return s;
}

// recv with timeout (blocking socket, set SO_RCVTIMEO)
static int tcp_recv_to(SOCKET s, char* buf, int max, int timeout_ms) {
    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof(to));
    return recv(s, buf, max, 0);
}
static int tcp_send_all(SOCKET s, const void* data, int n) {
    const char* p = (const char*)data; int left = n;
    while (left > 0) {
        int rc = send(s, p, left, 0);
        if (rc <= 0) return rc;
        p += rc; left -= rc;
    }
    return n;
}

// ============================================================================
// UDP probe
// ============================================================================
struct UdpResult {
    bool    responded = false;
    int     bytes = 0;
    string  reply_hex;       // first 32 bytes hex
    long long ms = 0;
    string  err;
};

static UdpResult udp_probe(const string& host, int port,
                           const unsigned char* payload, int plen,
                           int timeout_ms) {
    UdpResult r;
    // v2.5.2 — optional jitter. Without jitter every scan emits all 12 VPN-ish
    // UDP probes within ~2 seconds, and that "one source IP hits 12 canonical
    // VPN ports in a 2-second window" burst is itself a scanner signature
    // independent of any per-byte marker. A 50-300ms random delay between
    // probes spreads the burst across ~3-4 seconds and smears the timing
    // envelope. Not a complete fix (a determined IDS still spots the unusual
    // port set), but it removes the trivial "exactly N probes in T ms" rule.
    if (g_udp_jitter) {
        unsigned char jb = 0;
        RAND_bytes(&jb, 1);
        Sleep(50 + (jb % 251));   // 50-300 ms
    }
    auto t0 = std::chrono::steady_clock::now();
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM;
    addrinfo* ai = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &ai) != 0) {
        r.err = "dns"; return r;
    }
    // v2.4 — prefer v4 over v6 for UDP too (same DNS-ordering issue as TCP)
    addrinfo* chosen = nullptr;
    for (auto* p = ai; p; p = p->ai_next) if (p->ai_family == AF_INET)  { chosen = p; break; }
    if (!chosen)
        for (auto* p = ai; p; p = p->ai_next) if (p->ai_family == AF_INET6) { chosen = p; break; }
    if (!chosen) { freeaddrinfo(ai); r.err = "dns"; return r; }
    SOCKET s = socket(chosen->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { freeaddrinfo(ai); r.err = "socket"; return r; }
    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof(to));
    int rc = sendto(s, (const char*)payload, plen, 0, chosen->ai_addr, (int)chosen->ai_addrlen);
    freeaddrinfo(ai);
    if (rc <= 0) { closesocket(s); r.err = "send"; return r; }
    char buf[2048];
    int got = recv(s, buf, sizeof(buf), 0);
    closesocket(s);
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    int werr = WSAGetLastError();
    if (got > 0) {
        r.responded = true; r.bytes = got;
        r.reply_hex = hex_s((unsigned char*)buf, std::min(32, got), true);
    } else if (werr == WSAETIMEDOUT || werr == 0) {
        r.err = "no-reply / filtered";
    } else if (werr == WSAECONNRESET) {
        r.err = "ICMP port-unreachable (port closed)";
    } else {
        r.err = "wsa " + std::to_string(werr);
    }
    return r;
}

// ============================================================================
// WinHTTP client (for GeoIP etc)
// ============================================================================
struct HttpResp {
    int status = 0;
    string body;
    string err;
    long long ms = 0;
    bool ok() const { return status >= 200 && status < 400; }
};

static HttpResp http_get(const string& url, int timeout_ms = 7000) {
    HttpResp r;
    auto t0 = std::chrono::steady_clock::now();
    URL_COMPONENTS u{}; u.dwStructSize = sizeof(u);
    wchar_t host[256]={0}, path[1024]={0};
    u.lpszHostName = host; u.dwHostNameLength = 255;
    u.lpszUrlPath = path; u.dwUrlPathLength = 1023;
    std::wstring wurl = s2ws(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &u)) { r.err = "bad url"; return r; }

    // no ua. bare GET, json endpoints don't need more. #5
    HINTERNET hS = WinHttpOpen(L"", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) { r.err = "open"; return r; }
    WinHttpSetTimeouts(hS, timeout_ms, timeout_ms, timeout_ms, timeout_ms);
    // force empty ua, winhttp sneaks a default one in otherwise
    WinHttpSetOption(hS, WINHTTP_OPTION_USER_AGENT, (LPVOID)L"", 0);
    // decode gzip if server sends it anyway
    DWORD decomp = WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
    WinHttpSetOption(hS, WINHTTP_OPTION_DECOMPRESSION, &decomp, sizeof(decomp));
    HINTERNET hC = WinHttpConnect(hS, host, u.nPort, 0);
    if (!hC) { r.err = "connect"; WinHttpCloseHandle(hS); return r; }
    DWORD flags = (u.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hR = WinHttpOpenRequest(hC, L"GET", path, nullptr,
                                      WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hR) { r.err = "req"; WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return r; }
    // no extra hdrs, winhttp writes Host on its own
    if (!WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
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
        if (r.body.size() > 512*1024) break;
    }
    WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    return r;
}

// ============================================================================
// GeoIP
// ============================================================================
struct GeoInfo {
    string ip, country, country_code, city, asn, asn_org;
    bool is_hosting = false, is_vpn = false, is_proxy = false, is_tor = false, is_abuser = false;
    string source;
    string err;
};

static GeoInfo geo_ipapi_is(const string& ip) {
    GeoInfo g; g.source = "ipapi.is";
    string url = "https://api.ipapi.is/";
    if (!ip.empty()) url += "?q=" + ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ip");
    g.country      = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "country_code");
    g.city         = json_get_str(r.body, "city");
    string asn_block;
    size_t ap = r.body.find("\"asn\"");
    if (ap != string::npos) {
        size_t ob = r.body.find('{', ap);
        size_t ce = ob == string::npos ? string::npos : r.body.find('}', ob);
        if (ob != string::npos && ce != string::npos)
            asn_block = r.body.substr(ob, ce-ob+1);
    }
    g.asn     = json_get_str(asn_block, "asn");
    g.asn_org = json_get_str(asn_block, "org");
    if (g.asn.empty()) g.asn = json_get_str(r.body, "asn");
    auto t = [&](const char* k){ return json_get_str(r.body, k) == "true"; };
    g.is_hosting = t("is_datacenter") || t("is_hosting");
    g.is_vpn     = t("is_vpn");
    g.is_proxy   = t("is_proxy");
    g.is_tor     = t("is_tor");
    g.is_abuser  = t("is_abuser");
    return g;
}

static GeoInfo geo_iplocate(const string& ip) {
    GeoInfo g; g.source = "iplocate.io";
    string url = "https://iplocate.io/api/lookup/";
    if (!ip.empty()) url += ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ip");
    g.country      = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "country_code");
    g.city         = json_get_str(r.body, "city");
    string asn_block;
    size_t ap = r.body.find("\"asn\"");
    if (ap != string::npos) {
        size_t ob = r.body.find('{', ap);
        size_t ce = ob == string::npos ? string::npos : r.body.find('}', ob);
        if (ob != string::npos && ce != string::npos
            && ob < (r.body.find(',', ap) == string::npos ? ce+1 : r.body.find(',', ap)))
            asn_block = r.body.substr(ob, ce-ob+1);
    }
    if (!asn_block.empty()) {
        g.asn     = json_get_str(asn_block, "asn");
        g.asn_org = json_get_str(asn_block, "name");
        if (g.asn_org.empty()) g.asn_org = json_get_str(asn_block, "org");
    } else {
        g.asn     = json_get_str(r.body, "asn");
        g.asn_org = json_get_str(r.body, "org");
    }
    g.is_hosting = json_get_str(r.body, "is_hosting") == "true";
    g.is_vpn     = json_get_str(r.body, "is_vpn") == "true"
                 || json_get_str(r.body, "is_anonymous") == "true";
    g.is_proxy   = json_get_str(r.body, "is_proxy") == "true";
    g.is_tor     = json_get_str(r.body, "is_tor") == "true";
    return g;
}

// ip-api.com  —  EU/global, free, no key (HTTP only on free tier)
static GeoInfo geo_ip_api_com(const string& ip) {
    GeoInfo g; g.source = "ip-api.com";
    string url = "http://ip-api.com/json/";
    if (!ip.empty()) url += ip;
    url += "?fields=status,country,countryCode,city,isp,org,as,asname,hosting,proxy,mobile,query";
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "query");
    g.country      = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "countryCode");
    g.city         = json_get_str(r.body, "city");
    g.asn          = json_get_str(r.body, "as");
    g.asn_org      = json_get_str(r.body, "isp");
    if (g.asn_org.empty()) g.asn_org = json_get_str(r.body, "org");
    g.is_hosting   = json_get_str(r.body, "hosting") == "true";
    g.is_proxy     = json_get_str(r.body, "proxy")   == "true";
    return g;
}

// ipwho.is  —  global, free, HTTPS, no key
static GeoInfo geo_ipwho_is(const string& ip) {
    GeoInfo g; g.source = "ipwho.is";
    string url = "https://ipwho.is/";
    if (!ip.empty()) url += ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ip");
    g.country      = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "country_code");
    g.city         = json_get_str(r.body, "city");
    // connection.asn / connection.isp / connection.org
    size_t cp = r.body.find("\"connection\"");
    if (cp != string::npos) {
        size_t ob = r.body.find('{', cp);
        size_t ce = ob == string::npos ? string::npos : r.body.find('}', ob);
        if (ob != string::npos && ce != string::npos) {
            string sb = r.body.substr(ob, ce-ob+1);
            g.asn     = json_get_str(sb, "asn");
            g.asn_org = json_get_str(sb, "isp");
            if (g.asn_org.empty()) g.asn_org = json_get_str(sb, "org");
        }
    }
    return g;
}

// ipinfo.io  —  global, no-token tier returns country/city/org
static GeoInfo geo_ipinfo_io(const string& ip) {
    GeoInfo g; g.source = "ipinfo.io";
    string url = "https://ipinfo.io/";
    if (!ip.empty()) url += ip;
    url += "/json";
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ip");
    g.country_code = json_get_str(r.body, "country");  // ipinfo returns 2-letter only
    g.city         = json_get_str(r.body, "city");
    string orgraw  = json_get_str(r.body, "org");      // e.g. "AS13335 Cloudflare"
    if (!orgraw.empty()) {
        if (orgraw.rfind("AS",0)==0) {
            size_t sp = orgraw.find(' ');
            if (sp != string::npos) {
                g.asn     = orgraw.substr(0, sp);
                g.asn_org = orgraw.substr(sp+1);
            } else g.asn = orgraw;
        } else g.asn_org = orgraw;
    }
    return g;
}

// freeipapi.com  —  EU-based, generous free tier, HTTPS
static GeoInfo geo_freeipapi(const string& ip) {
    GeoInfo g; g.source = "freeipapi.com";
    string url = "https://freeipapi.com/api/json/";
    if (!ip.empty()) url += ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ipAddress");
    g.country      = json_get_str(r.body, "countryName");
    g.country_code = json_get_str(r.body, "countryCode");
    g.city         = json_get_str(r.body, "cityName");
    return g;
}

// ----------------------------------------------------------------------------
// 3 RU-facing providers — important because RU-origin GeoIP sees Russian
// hosting differently from EU/US providers (VEESP, Hostkey, Ruvds etc.)
// ----------------------------------------------------------------------------

// 2ip.io had anti-bot, using api.2ip.me instead. #5
static GeoInfo geo_2ip_ru(const string& ip) {
    GeoInfo g; g.source = "2ip.me (RU)";
    string url = "http://api.2ip.me/geo.json?ip=" + ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ip");
    if (g.ip.empty()) g.ip = ip;
    g.country      = json_get_str(r.body, "country");
    if (g.country.empty()) g.country = json_get_str(r.body, "country_rus");
    if (g.country.empty()) g.country = json_get_str(r.body, "countryName");
    g.country_code = json_get_str(r.body, "country_code");
    if (g.country_code.empty()) g.country_code = json_get_str(r.body, "countryCode");
    g.city         = json_get_str(r.body, "city");
    if (g.city.empty()) g.city = json_get_str(r.body, "city_rus");
    if (g.city.empty()) g.city = json_get_str(r.body, "cityName");
    string org     = json_get_str(r.body, "org");
    if (!org.empty()) g.asn_org = org;
    return g;
}

// ip-api.com/ru  —  same backend as ip-api.com but the /ru/ path returns
// Russian-localised location strings AND carries a different endpoint-
// -tier for RU-routed clients.  We call it with a distinct source label
// so it counts as an independent RU-side opinion (they rate-limit per
// source IP per endpoint).
static GeoInfo geo_ipapi_ru(const string& ip) {
    GeoInfo g; g.source = "ip-api.com/ru (RU)";
    string url = "http://ip-api.com/json/";
    if (!ip.empty()) url += ip;
    url += "?lang=ru&fields=status,country,countryCode,city,isp,org,as,asname,hosting,proxy,mobile,query";
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "query");
    g.country      = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "countryCode");
    g.city         = json_get_str(r.body, "city");
    g.asn          = json_get_str(r.body, "as");
    g.asn_org      = json_get_str(r.body, "isp");
    if (g.asn_org.empty()) g.asn_org = json_get_str(r.body, "org");
    g.is_hosting   = json_get_str(r.body, "hosting") == "true";
    g.is_proxy     = json_get_str(r.body, "proxy")   == "true";
    return g;
}

// SypexGeo — Russian GeoIP project, public API, no key needed for city-level
// lookups.  Endpoint returns JSON with country/city/lat/lon.
static GeoInfo geo_sypex(const string& ip) {
    GeoInfo g; g.source = "sypexgeo.net (RU)";
    string url = "http://api.sypexgeo.net/json/" + ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = ip;
    // Their JSON is nested: country.name_en, city.name_en, region.name_en
    g.country_code = json_get_str(r.body, "iso");
    // try nested
    {
        size_t cp = r.body.find("\"country\"");
        if (cp != string::npos) {
            size_t ob = r.body.find('{', cp);
            size_t ce = ob == string::npos ? string::npos : r.body.find('}', ob);
            if (ob != string::npos && ce != string::npos) {
                string sb = r.body.substr(ob, ce - ob + 1);
                g.country = json_get_str(sb, "name_en");
                if (g.country.empty()) g.country = json_get_str(sb, "name_ru");
                if (g.country_code.empty()) g.country_code = json_get_str(sb, "iso");
            }
        }
    }
    {
        size_t cp = r.body.find("\"city\"");
        if (cp != string::npos) {
            size_t ob = r.body.find('{', cp);
            size_t ce = ob == string::npos ? string::npos : r.body.find('}', ob);
            if (ob != string::npos && ce != string::npos) {
                string sb = r.body.substr(ob, ce - ob + 1);
                g.city = json_get_str(sb, "name_en");
                if (g.city.empty()) g.city = json_get_str(sb, "name_ru");
            }
        }
    }
    return g;
}

// ============================================================================
// Port lists
// ============================================================================
// Curated "fast" port list (205 ports): VPN/proxy/TLS/admin/tor/xray defaults.
// Used when --fast is passed. Default mode is FULL (1-65535).
static const vector<int> TCP_FAST_PORTS = {
    // ssh/mail/web/dns
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 179, 389, 443,
    445, 465, 514, 515, 548, 587, 631, 636, 873, 990, 993, 995,
    // proxy / socks
    1080, 1081, 1082, 1090, 1180, 1443, 1701, 1723,
    3128, 3129, 3130, 3389, 3690, 4433, 4443, 4444, 4500,
    // tls/https alt
    5000, 5001, 5060, 5061, 5222, 5223, 5228, 5269, 5280, 5432, 5500,
    5555, 5900, 5938, 6000, 6379, 6443, 6667, 6697, 6881,
    // modern alt-tls/HTTP/admin
    7000, 7001, 7070, 7443, 7547, 7777, 7999,
    8000, 8008, 8009, 8010, 8018, 8020, 8030, 8040, 8060, 8080, 8081, 8082,
    8083, 8088, 8090, 8091, 8096, 8100, 8118, 8123, 8181, 8188, 8200, 8222,
    8333, 8383, 8388, 8389, 8443, 8444, 8445, 8480, 8500, 8800, 8843, 8880,
    8888, 8889, 8899, 8989,
    // xray/v2ray/reality defaults
    9000, 9001, 9002, 9007, 9050, 9051, 9090, 9091, 9100, 9200, 9300, 9418,
    9443, 9999,
    // 10k range
    10000, 10001, 10050, 10080, 10443, 10800, 10808, 10809, 10810, 10811,
    11211, 11443, 12000, 13000, 13306, 13579, 14443, 14444, 14567,
    15000, 16000, 16999, 17000, 17777, 18080, 18443, 19132, 19999,
    20000, 20443, 21443, 22222, 22443, 23443, 24443, 25443,
    27015, 27017, 28017, 30000, 30003, 31337, 32400,
    33389, 35000, 36000, 36363, 37000, 38000, 39000, 40000,
    41641, 41642, 42000, 43210, 44443, 45000, 46443, 48000,
    49152, 50000, 50051, 50443, 51443, 51820, 51821, 52323, 53333,
    54321, 55443, 55554, 56789, 57621, 58080, 59999, 60000, 61613, 62078, 65000
};
// Build port list per selected PortMode.
static vector<int> build_tcp_ports() {
    vector<int> p;
    switch (g_port_mode) {
        case PortMode::FAST:
            p = TCP_FAST_PORTS; break;
        case PortMode::RANGE: {
            int lo = std::max(1,  g_range_lo);
            int hi = std::min(65535, g_range_hi);
            p.reserve(hi-lo+1);
            for (int i=lo; i<=hi; ++i) p.push_back(i);
        } break;
        case PortMode::LIST:
            p = g_port_list; break;
        case PortMode::FULL:
        default:
            p.reserve(65535);
            for (int i=1; i<=65535; ++i) p.push_back(i);
            break;
    }
    return p;
}

static const vector<int> UDP_SCAN_PORTS = {
    53, 67, 69, 80, 123, 137, 138, 161, 443, 500, 514, 520, 554, 623,
    1194, 1434, 1645, 1701, 1812, 1813, 1900, 2049, 2152, 2302, 2427,
    3702, 4433, 4500, 4789, 5060, 5353, 5683, 6881, 10000, 27015, 41641,
    51820
};

// ============================================================================
// Port fingerprints (reference)
// ============================================================================
struct PortHint { int port; const char* svc; const char* proto; };
static const vector<PortHint> PORT_HINTS = {
    {22,"SSH","tcp"},{53,"DNS","tcp/udp"},{80,"HTTP","tcp"},{88,"Kerberos","tcp"},
    {443,"HTTPS / XTLS / Reality","tcp"},{465,"SMTPS","tcp"},{587,"SMTP+TLS","tcp"},
    {853,"DoT","tcp"},{990,"FTPS","tcp"},{993,"IMAPS","tcp"},{995,"POP3S","tcp"},
    {1080,"SOCKS5","tcp"},{1194,"OpenVPN","tcp/udp"},{1701,"L2TP","udp"},
    {1723,"PPTP","tcp"},{3128,"Squid HTTP proxy","tcp"},{3389,"RDP","tcp"},
    {4433,"XTLS/Reality/Trojan","tcp"},{4443,"XTLS/Reality","tcp"},
    {4500,"IKEv2 NAT-T","udp"},{5060,"SIP","tcp/udp"},{5555,"ADB / alt-admin","tcp"},
    {8080,"HTTP proxy","tcp"},{8118,"Privoxy","tcp"},{8123,"Polipo","tcp"},
    {8388,"Shadowsocks","tcp/udp"},{8443,"HTTPS alt / Reality","tcp"},
    {8888,"HTTP alt","tcp"},{9050,"Tor SOCKS","tcp"},{9051,"Tor control","tcp"},
    {10808,"v2ray/xray SOCKS","tcp"},{10809,"v2ray/xray HTTP","tcp"},
    {10810,"v2ray/xray alt","tcp"},
    {51820,"WireGuard","udp"},{41641,"Tailscale","udp"},
    {500,"IKE ISAKMP","udp"},{1194,"OpenVPN","udp"},
};

static const char* port_hint(int p) {
    for (auto& h: PORT_HINTS) if (h.port == p) return h.svc;
    if (p == 6443 || p == 8443 || p == 4443) return "HTTPS alt / possible VPN over TLS";
    if (p >= 10800 && p <= 10820) return "v2ray/xray local-like range";
    return "";
}

// ============================================================================
// TCP port scan (parallel)
// ============================================================================
struct TcpOpen {
    int port;
    long long connect_ms;
    string banner; // grabbed on connect, if any
    string err;    // only set on failure: "timeout" / "refused" / "other" / "dns"
};

static TcpOpen probe_tcp(const string& host, int port, int to_ms) {
    TcpOpen o; o.port = port; o.connect_ms = -1;
    auto t0 = std::chrono::steady_clock::now();
    string err; SOCKET s = tcp_connect(host, port, to_ms, err);
    if (s == INVALID_SOCKET) { o.err = err; return o; }
    o.connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now() - t0).count();
    // passive banner grab (some servers talk first: SSH/FTP/SMTP)
    char buf[512]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 600);
    if (n > 0) {
        buf[n]=0;
        o.banner.assign(buf, n);
        // strip trailing control
        while (!o.banner.empty() && (o.banner.back()=='\r'||o.banner.back()=='\n'||o.banner.back()==0))
            o.banner.pop_back();
    }
    closesocket(s);
    return o;
}

struct ScanStats {
    size_t scanned  = 0;  // ports actually probed (may be < total if skipped)
    size_t timeouts = 0;
    size_t refused  = 0;
    size_t other    = 0;
    bool   skipped  = false;
};

static vector<TcpOpen> scan_tcp(const string& host, const vector<int>& ports,
                                int threads, int to_ms, ScanStats* stats = nullptr) {
    vector<TcpOpen> open;
    std::mutex mx;
    std::atomic<size_t> idx{0};
    std::atomic<int>    done{0};
    std::atomic<size_t> tmo{0}, refused{0}, other{0};
    std::atomic<bool>   abort_scan{false};

    // drain any pending keys from prior prompts so Enter doesn't skip
    while (_kbhit()) _getch();
    fprintf(stderr, "  (press 'q' to skip this phase)\n");

    std::thread kb([&]{
        while (!abort_scan.load()) {
            if (_kbhit()) {
                int c = _getch();
                if (c == 'q' || c == 'Q' || c == 27) {
                    abort_scan = true;
                    break;
                }
            }
            Sleep(50);
        }
    });

    auto worker = [&]{
        while (true) {
            if (abort_scan.load()) break;
            size_t i = idx.fetch_add(1);
            if (i >= ports.size()) break;
            TcpOpen o = probe_tcp(host, ports[i], to_ms);
            int d = ++done;
            size_t cur = 0;
            if (o.connect_ms < 0) {
                // classify why it closed
                if (o.err == "timeout")      ++tmo;
                else if (o.err == "refused") ++refused;
                else                         ++other;
            }
            {
                std::lock_guard<std::mutex> lk(mx);
                if (o.connect_ms >= 0) open.push_back(std::move(o));
                cur = open.size();
            }
            if (d % 20 == 0 || (size_t)d == ports.size()) {
                fprintf(stderr, "\r  scanning %d/%zu  open=%zu  ", d, ports.size(), cur);
                fflush(stderr);
            }
        }
    };
    threads = std::max(1, std::min(threads, (int)ports.size()));
    vector<std::thread> th;
    for (int i=0;i<threads;++i) th.emplace_back(worker);
    for (auto& t: th) t.join();

    abort_scan = true;  // signal kb-thread to exit
    kb.join();

    size_t scanned = std::min(idx.load(), ports.size());
    bool was_skipped = (scanned < ports.size());
    if (was_skipped) {
        fprintf(stderr, "\r  scan SKIPPED at %zu/%zu (open=%zu)        \n",
                scanned, ports.size(), open.size());
    } else {
        fprintf(stderr, "\r  scan done (%zu/%zu, open=%zu)        \n",
                ports.size(), ports.size(), open.size());
    }
    std::sort(open.begin(), open.end(), [](auto&a,auto&b){return a.port<b.port;});
    if (stats) {
        stats->scanned  = scanned;
        stats->timeouts = tmo.load();
        stats->refused  = refused.load();
        stats->other    = other.load();
        stats->skipped  = was_skipped;
    }
    return open;
}

// ============================================================================
// Service fingerprints
// ============================================================================
struct FpResult {
    string service;
    string details;      // short info line
    string raw_hex;      // for debugging (optional)
    bool   is_vpn_like = false;
    bool   silent      = false; // didn't respond to probes
    bool   tspu_redirect = false; // http 302 Location: matches tspu warning page
    string redirect_target;       // the Location: value if tspu_redirect
    string redirect_marker;       // which blacklist entry matched
};

static string printable_prefix(const string& s, size_t lim = 80) {
    string out;
    for (size_t i=0;i<s.size() && out.size()<lim;++i) {
        char c = s[i];
        if (c>=32 && c<127) out += c;
        else if (c=='\r') out += "\\r";
        else if (c=='\n') out += "\\n";
        else out += '.';
    }
    return out;
}

// HTTP probe (plain)
static FpResult fp_http_plain(const string& host, int port) {
    FpResult f; f.service = "HTTP?";
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    string req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    tcp_send_all(s, req.data(), (int)req.size());
    char buf[2048]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 1500);
    closesocket(s);
    if (n <= 0) { f.silent = true; return f; }
    buf[n]=0; string resp(buf, n);
    string first = resp.substr(0, resp.find('\n'));
    string server;
    size_t sv = tolower_s(resp).find("server:");
    if (sv != string::npos) {
        size_t e = resp.find('\r', sv);
        if (e == string::npos) e = resp.find('\n', sv);
        server = trim(resp.substr(sv+7, e-(sv+7)));
    }
    f.service = "HTTP";
    f.details = trim(first);
    if (!server.empty()) f.details += "  | Server: " + server;
    // parse Location: header for tspu-redirect detection
    {
        string loresp = tolower_s(resp);
        size_t lp = loresp.find("\nlocation:");
        if (lp != string::npos) {
            size_t vs = lp + 10;
            size_t ve = resp.find('\r', vs);
            if (ve == string::npos) ve = resp.find('\n', vs);
            if (ve != string::npos && ve > vs && ve - vs < 512) {
                string location = trim(resp.substr(vs, ve - vs));
                const char* marker = looks_like_tspu_redirect(location);
                if (marker) {
                    f.tspu_redirect   = true;
                    f.redirect_target = location;
                    f.redirect_marker = marker;
                    f.details += string("  [!tspu-redirect to ") + marker + "]";
                }
            }
        }
    }
    // heuristics: does server leak nginx/caddy/trojan/xray fallback?
    string rl = tolower_s(server);
    if (contains(rl, "caddy"))     f.details += "  %[caddy-fronted - common Xray/Reality fallback]";
    else if (contains(rl, "nginx")) f.details += "  %[nginx - fallback host?]";
    else if (contains(rl, "cloudflare")) f.details += "  %[cloudflare]";
    return f;
}

// SSH banner
static FpResult fp_ssh(const string& banner_hint, const string& host, int port) {
    FpResult f; f.service = "SSH?";
    string b = banner_hint;
    if (b.empty() || b.substr(0,4) != "SSH-") {
        // re-grab
        string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
        if (s != INVALID_SOCKET) {
            char buf[256]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 1500);
            closesocket(s);
            if (n > 0) { buf[n]=0; b.assign(buf,n); }
        }
    }
    if (b.substr(0,4) == "SSH-") {
        f.service = "SSH";
        // strip CR/LF
        while (!b.empty() && (b.back()=='\r'||b.back()=='\n')) b.pop_back();
        f.details = b;
    } else {
        f.details = "no SSH banner (but port open)";
    }
    return f;
}

// SOCKS5 probe: send greeting, expect 0x05 reply
static FpResult fp_socks5(const string& host, int port) {
    FpResult f; f.service = "SOCKS?";
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    unsigned char greet[] = {0x05, 0x02, 0x00, 0x02}; // ver, nmethods=2, NO-AUTH + USER/PASS
    tcp_send_all(s, greet, sizeof(greet));
    unsigned char reply[8]; int n = tcp_recv_to(s, (char*)reply, sizeof(reply), 1200);
    closesocket(s);
    if (n <= 0) { f.silent = true; return f; }
    if (reply[0] == 0x05 && n >= 2) {
        f.service = "SOCKS5";
        f.details = "methods=0x" + hex_s(reply+1, 1);
        if (reply[1] == 0x00) f.details += " (no-auth)";
        else if (reply[1] == 0x02) f.details += " (user/pass)";
        else if (reply[1] == 0xFF) f.details += " (no acceptable)";
        f.is_vpn_like = true;
    } else if (reply[0] == 0x05) {
        // 1-byte reply, don't touch reply[1]
        f.service = "SOCKS5"; f.details = "short greeting"; f.is_vpn_like = true;
    } else if (reply[0] == 0x04) {
        f.service = "SOCKS4"; f.is_vpn_like = true;
    } else {
        f.details = "reply=" + hex_s(reply, std::min(4,n));
    }
    return f;
}

// HTTP CONNECT proxy probe
static FpResult fp_http_connect(const string& host, int port) {
    FpResult f; f.service = "HTTP-PROXY?";
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    string req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    tcp_send_all(s, req.data(), (int)req.size());
    char buf[512]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 1500);
    closesocket(s);
    if (n <= 0) { f.silent = true; return f; }
    buf[n]=0;
    string line(buf, buf + std::min(n, 120));
    if (starts_with(line, "HTTP/")) {
        f.service = "HTTP-PROXY";
        f.details = trim(line.substr(0, line.find('\n')));
        f.is_vpn_like = true;
    } else {
        f.details = printable_prefix(line);
    }
    return f;
}

// Shadowsocks probe: open + send random 32 bytes, expect server to just close (AEAD rejects invalid)
// a common heuristic: connect, send garbage, measure how fast RST comes vs timeout
static FpResult fp_shadowsocks(const string& host, int port) {
    FpResult f; f.service = "SS?";
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    // 64 truly-random bytes via OpenSSL CSPRNG — not rand()/time()-seeded
    // LCG, which would leak "was generated by the tool at ~time T" structure.
    unsigned char rnd[64];
    RAND_bytes(rnd, 64);
    tcp_send_all(s, rnd, 64);
    char buf[256]; int n = tcp_recv_to(s, buf, sizeof(buf), 800);
    closesocket(s);
    if (n <= 0) {
        f.service = "silent-on-junk";
        f.details = "accepts random bytes but never replies (ambiguous: Shadowsocks AEAD, Trojan, Reality hidden-mode, or any firewalled service)";
        // do NOT set is_vpn_like: this pattern is not specific to VPN stacks
    } else {
        f.details = "responded "+std::to_string(n)+"B: "+printable_prefix(string(buf,n));
    }
    return f;
}

// ============================================================================
// TLS module (OpenSSL) — includes JA3-like fingerprint
// ============================================================================
struct TlsProbe {
    bool   ok = false;
    string err;
    string version;
    string cipher;
    string alpn;
    string group;
    string cert_subject;
    string cert_issuer;
    string cert_sha256;
    vector<string> san;
    int64_t handshake_ms = 0;
    // v2.2 — richer cert intel for red-flag accumulation
    string  subject_cn;      // CN only (for short display)
    string  issuer_cn;       // issuer CN only
    int     age_days = 0;    // today - notBefore  (negative if not yet valid)
    int     days_left = 0;   // notAfter - today   (negative if expired)
    int     total_validity_days = 0;
    bool    self_signed = false;
    bool    is_letsencrypt = false;  // LE / ZeroSSL / Buypass — free-CA family
    bool    is_wildcard = false;     // any *.foo in SAN or CN
    int     san_count = 0;
};

static int asn1_time_diff_days_now(const ASN1_TIME* t, bool from_t_to_now) {
    if (!t) return 0;
    int day = 0, sec = 0;
    if (from_t_to_now) ASN1_TIME_diff(&day, &sec, t, nullptr);
    else               ASN1_TIME_diff(&day, &sec, nullptr, t);
    return day;
}

static string extract_cn_from_subject(const string& subj) {
    size_t p = subj.find("CN=");
    if (p == string::npos) return {};
    p += 3;
    size_t e = subj.find_first_of("/,", p);
    return subj.substr(p, e == string::npos ? string::npos : e - p);
}

static string x509_name_one(X509_NAME* n) {
    char b[512]={0};
    X509_NAME_oneline(n, b, sizeof(b));
    return b;
}

static TlsProbe tls_probe(const string& ip, int port, const string& sni,
                          const string& alpn = "h2,http/1.1",
                          int to_ms = 5000) {
    TlsProbe r;
    auto t0 = std::chrono::steady_clock::now();
    string err; SOCKET s = tcp_connect(ip, port, to_ms, err);
    if (s == INVALID_SOCKET) { r.err = err; return r; }
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)s);
    if (!sni.empty()) SSL_set_tlsext_host_name(ssl, sni.c_str());
    // ALPN
    vector<unsigned char> wire;
    for (auto& p: split(alpn, ',')) {
        string v = trim(p); if (v.empty()) continue;
        wire.push_back((unsigned char)v.size());
        for (char c: v) wire.push_back((unsigned char)c);
    }
    if (!wire.empty()) SSL_set_alpn_protos(ssl, wire.data(), (unsigned)wire.size());
    if (SSL_connect(ssl) != 1) {
        unsigned long e = ERR_get_error();
        char b[256]; ERR_error_string_n(e, b, sizeof(b));
        r.err = b[0] ? string(b) : string("tls handshake failed");
        SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
        return r;
    }
    r.ok = true;
    r.version = SSL_get_version(ssl);
    r.cipher  = SSL_get_cipher_name(ssl);
    const unsigned char* ap=nullptr; unsigned apl=0;
    SSL_get0_alpn_selected(ssl, &ap, &apl);
    if (apl) r.alpn.assign((const char*)ap, apl);
    int nid = SSL_get_negotiated_group(ssl);
    const char* gn = OBJ_nid2sn(nid);
    if (gn) r.group = gn;
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        r.cert_subject = x509_name_one(X509_get_subject_name(cert));
        r.cert_issuer  = x509_name_one(X509_get_issuer_name(cert));
        r.subject_cn   = extract_cn_from_subject(r.cert_subject);
        r.issuer_cn    = extract_cn_from_subject(r.cert_issuer);
        r.self_signed  = !r.cert_subject.empty() && r.cert_subject == r.cert_issuer;
        // free-CA family commonly used by disposable proxy hosts
        {
            const string& iss = r.cert_issuer;
            r.is_letsencrypt =
                iss.find("Let's Encrypt") != string::npos ||
                iss.find("R3") != string::npos || iss.find("R10") != string::npos ||
                iss.find("R11") != string::npos || iss.find("E5") != string::npos ||
                iss.find("E6") != string::npos ||
                iss.find("ZeroSSL") != string::npos ||
                iss.find("Buypass") != string::npos ||
                iss.find("Google Trust Services") != string::npos;
        }
        unsigned char dgst[32]; unsigned dl = 0;
        X509_digest(cert, EVP_sha256(), dgst, &dl);
        r.cert_sha256 = hex_s(dgst, dl);
        // cert validity
        const ASN1_TIME* nb = X509_get0_notBefore(cert);
        const ASN1_TIME* na = X509_get0_notAfter(cert);
        r.age_days  = asn1_time_diff_days_now(nb, true);    // nb -> now
        r.days_left = asn1_time_diff_days_now(na, false);   // now -> na
        if (nb && na) {
            int d=0, s=0; ASN1_TIME_diff(&d, &s, nb, na); r.total_validity_days = d;
        }
        GENERAL_NAMES* gens = (GENERAL_NAMES*)X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
        if (gens) {
            int nn = sk_GENERAL_NAME_num(gens);
            for (int i=0;i<nn;++i) {
                GENERAL_NAME* g = sk_GENERAL_NAME_value(gens, i);
                if (g->type == GEN_DNS) {
                    unsigned char* us = nullptr;
                    int ul = ASN1_STRING_to_UTF8(&us, g->d.dNSName);
                    if (ul > 0) {
                        string name((char*)us, ul);
                        if (name.size() > 2 && name[0]=='*' && name[1]=='.') r.is_wildcard = true;
                        r.san.push_back(std::move(name));
                    }
                    OPENSSL_free(us);
                }
            }
            GENERAL_NAMES_free(gens);
        }
        r.san_count = (int)r.san.size();
        if (!r.is_wildcard && !r.subject_cn.empty() && r.subject_cn.size() > 2 &&
            r.subject_cn[0] == '*' && r.subject_cn[1] == '.') r.is_wildcard = true;
        X509_free(cert);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
    r.handshake_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0).count();
    return r;
}

// ============================================================================
// Brand-cert impersonation detection  (v2.3)
//
// Classical Xray/VLESS+Reality "static dest" setup: the operator sets
// `dest=www.amazon.com:443` in Reality config, so when ANY SNI-less TLS
// client connects, the Reality listener proxies the handshake to the real
// amazon.com and forwards amazon's cert back to us. Result: a random VPS
// in US on AS56971 CGI GLOBAL LIMITED returns CN=www.amazon.com. That's
// NOT "plain server" — that's impersonation, which is also the exact
// Reality-static profile TSPU/GFW fingerprint.
//
// We detect this by cross-referencing:
//   (a) cert CN / SAN list against a curated list of famous brand domains
//   (b) ASN-org strings against a list of markers that would legitimately
//       own those brands
//
// If a brand cert is served but the ASN clearly doesn't belong to that
// brand, it's impersonation.
// ============================================================================
struct BrandMarker {
    const char* brand;        // the domain the cert claims
    const char* asn_markers;  // comma-separated ASN-org substrings that
                              // legitimately run this brand's endpoints
};
static const BrandMarker BRAND_TABLE[] = {
    // Global tech giants
    {"amazon.com",     "amazon,aws,a100 row,amazon technologies"},
    {"aws.amazon.com", "amazon,aws"},
    {"microsoft.com",  "microsoft,msn,msft,akamai,edgecast"},
    {"apple.com",      "apple,akamai"},
    {"icloud.com",     "apple"},
    {"google.com",     "google,gts,gcp,youtube"},
    {"googleusercontent.com", "google,gcp"},
    {"googleapis.com", "google,gcp"},
    {"youtube.com",    "google,youtube"},
    {"cloudflare.com", "cloudflare,cloudflare inc"},
    {"github.com",     "github,microsoft,fastly"},
    {"gitlab.com",     "gitlab,cloudflare"},
    {"bitbucket.org",  "atlassian,amazon"},
    {"yahoo.com",      "yahoo,oath,verizon"},
    {"netflix.com",    "netflix,akamai"},
    {"cdn.jsdelivr.net","fastly,cloudflare"},
    {"bing.com",       "microsoft"},
    {"gstatic.com",    "google"},
    {"wikipedia.org",  "wikimedia"},
    {"wikimedia.org",  "wikimedia"},
    {"linkedin.com",   "linkedin,microsoft"},
    {"office.com",     "microsoft"},
    {"office365.com",  "microsoft"},
    {"outlook.com",    "microsoft"},
    {"live.com",       "microsoft"},
    {"azure.com",      "microsoft"},
    {"onedrive.com",   "microsoft"},
    // Social networks / messengers
    {"facebook.com",   "facebook,meta"},
    {"instagram.com",  "facebook,meta"},
    {"whatsapp.com",   "facebook,meta"},
    {"whatsapp.net",   "facebook,meta"},
    {"messenger.com",  "facebook,meta"},
    {"threads.net",    "facebook,meta"},
    {"twitter.com",    "twitter,x corp,x holdings"},
    {"x.com",          "twitter,x corp,x holdings"},
    {"tiktok.com",     "tiktok,bytedance,akamai"},
    {"telegram.org",   "telegram,telegram messenger"},
    {"t.me",           "telegram,telegram messenger"},
    {"telegram.me",    "telegram,telegram messenger"},
    {"discord.com",    "discord,cloudflare,google"},
    {"discordapp.com", "discord,cloudflare,google"},
    {"slack.com",      "slack,amazon,aws"},
    {"zoom.us",        "zoom"},
    {"signal.org",     "signal,amazon,aws"},
    // Russian tech / RU-priority (state DPI context)
    {"yandex.ru",      "yandex"},
    {"yandex.net",     "yandex"},
    {"yandex.com",     "yandex"},
    {"ya.ru",          "yandex"},
    {"mail.ru",        "mail.ru,vk,v kontakte"},
    {"vk.com",         "vk,v kontakte,mail.ru"},
    {"vk.ru",          "vk,v kontakte,mail.ru"},
    {"vkontakte.ru",   "vk,v kontakte,mail.ru"},
    {"ok.ru",          "vk,v kontakte,mail.ru"},
    {"avito.ru",       "avito,kiev internet"},
    {"ozon.ru",        "ozon"},
    {"wildberries.ru", "wildberries"},
    {"kinopoisk.ru",   "yandex"},
    {"rutube.ru",      "rutube,rbc,gpmd"},
    {"dzen.ru",        "yandex,vk"},
    {"habr.com",       "habr,habrahabr"},
    {"rambler.ru",     "rambler,rambler internet"},
    // Russian banks / state
    {"sberbank.ru",    "sberbank,sber"},
    {"sber.ru",        "sberbank,sber"},
    {"sberbank.com",   "sberbank,sber"},
    {"tinkoff.ru",     "tinkoff,t-bank,tcs"},
    {"tbank.ru",       "tinkoff,t-bank,tcs"},
    {"vtb.ru",         "vtb,vtb bank"},
    {"alfabank.ru",    "alfabank,alfa bank"},
    {"gazprombank.ru", "gazprombank,gazprom"},
    {"rosbank.ru",     "rosbank,societe"},
    {"gosuslugi.ru",   "rostelecom,rt,rt-labs"},
    {"mos.ru",         "dit,moscow,mgts"},
    {"rt.ru",          "rostelecom,rt"},
    {"nalog.gov.ru",   "rostelecom,rt"},
    // Russian telecom
    {"mts.ru",         "mts"},
    {"megafon.ru",     "megafon"},
    {"beeline.ru",     "beeline,vimpelcom,pjsc vimpelcom"},
    {"rostelecom.ru",  "rostelecom,rt"},
    {"tele2.ru",       "tele2,rostelecom"},
    // Finance / commerce (global)
    {"stripe.com",     "stripe,amazon,aws"},
    {"paypal.com",     "paypal,akamai"},
    {"shopify.com",    "shopify,fastly,cloudflare"},
    {"adobe.com",      "adobe"},
    {"salesforce.com", "salesforce"},
    {"dropbox.com",    "dropbox,amazon,aws"},
    // Streaming / media
    {"spotify.com",    "spotify,amazon,aws"},
    {"twitch.tv",      "twitch,amazon,aws"},
    {"vimeo.com",      "vimeo,akamai,amazon"},
    {"reddit.com",     "reddit,fastly"},
    // Gaming
    {"steampowered.com","valve,akamai"},
    {"steamcommunity.com","valve,akamai"},
    {"playstation.com","sony,akamai"},
    {"xbox.com",       "microsoft"},
    {"nintendo.com",   "nintendo,amazon,aws,akamai"},
    {"epicgames.com",  "epic games,cloudflare,amazon"},
    {"battle.net",     "blizzard,akamai"},
};
static const size_t BRAND_TABLE_N = sizeof(BRAND_TABLE)/sizeof(BRAND_TABLE[0]);

// Returns empty if no brand match, else the brand domain the cert vouches for.
// Checks subject CN + all SAN entries.
static string cert_claims_brand(const string& subject_cn,
                                const vector<string>& san) {
    auto is_brand = [](const string& name)->const char*{
        if (name.empty()) return nullptr;
        string ln = name;
        for (auto& c: ln) c = (char)std::tolower((unsigned char)c);
        // strip leading "*." from wildcard names
        if (ln.size() > 2 && ln[0]=='*' && ln[1]=='.') ln = ln.substr(2);
        for (size_t i=0;i<BRAND_TABLE_N;++i) {
            string b = BRAND_TABLE[i].brand;
            if (ln == b) return BRAND_TABLE[i].brand;
            if (ln.size() > b.size() + 1 &&
                ln.compare(ln.size()-b.size(), b.size(), b) == 0 &&
                ln[ln.size()-b.size()-1] == '.') return BRAND_TABLE[i].brand;
        }
        return nullptr;
    };
    const char* hit = is_brand(subject_cn);
    if (hit) return hit;
    for (auto& s: san) { hit = is_brand(s); if (hit) return hit; }
    return {};
}

// Given a brand and the scanned host's GeoIP ASN-org list, return true iff
// the ASN legitimately owns the brand.
static bool asn_owns_brand(const string& brand_domain,
                           const vector<string>& asn_orgs) {
    if (brand_domain.empty() || asn_orgs.empty()) return false;
    const char* markers = nullptr;
    for (size_t i=0;i<BRAND_TABLE_N;++i) {
        if (brand_domain == BRAND_TABLE[i].brand) {
            markers = BRAND_TABLE[i].asn_markers; break;
        }
    }
    if (!markers) return false;
    string ms = markers;
    for (auto& c: ms) c = (char)std::tolower((unsigned char)c);
    vector<string> parts = split(ms, ',');
    for (auto& org: asn_orgs) {
        string lo = org;
        for (auto& c: lo) c = (char)std::tolower((unsigned char)c);
        for (auto& m: parts) {
            string mm = trim(m);
            if (!mm.empty() && lo.find(mm) != string::npos) return true;
        }
    }
    return false;
}

// Given an HTTP `Server:` header value, return the brand domain from
// BRAND_TABLE that the banner unambiguously belongs to. Only triggers on
// banners a real web server can never produce by accident — e.g.
// "CloudFront" or "AmazonS3" (never set by nginx/Apache/Caddy), "gws"
// (Google's proprietary frontend, only served by Google), etc. Empty
// return = no brand mapping.
static string server_header_brand(const string& server_hdr) {
    if (server_hdr.empty()) return {};
    string s = server_hdr;
    for (auto& c: s) c = (char)std::tolower((unsigned char)c);
    // Amazon / AWS
    if (s.find("cloudfront") != string::npos) return "amazon.com";
    if (s.find("amazons3")   != string::npos) return "amazon.com";
    if (s.find("awselb")     != string::npos) return "amazon.com";
    if (s.find("aws elb")    != string::npos) return "amazon.com";
    // Google
    if (s == "gws" || s.find("gws/") != string::npos) return "google.com";
    if (s.find("gfe/")       != string::npos) return "google.com";
    if (s.find("gse/")       != string::npos) return "google.com";
    if (s.find("esf")        != string::npos) return "google.com";
    // Cloudflare
    if (s == "cloudflare" || s.find("cloudflare-nginx") != string::npos) return "cloudflare.com";
    // Microsoft IIS / Azure
    if (s.find("microsoft-iis")    != string::npos) return "microsoft.com";
    if (s.find("microsoft-httpapi")!= string::npos) return "microsoft.com";
    // Yandex
    if (s.find("yandex")     != string::npos) return "yandex.ru";
    // Apple
    if (s.find("applehttpserver") != string::npos) return "apple.com";
    // Fastly / Akamai are CDNs without brand-table entries — skip.
    return {};
}

// ============================================================================
// Active HTTP/1.1 probe inside an established TLS session  (v2.3)
//
// After the TLS handshake succeeds we try to actually speak HTTP on it.
// A real web server (nginx/Apache/Caddy/CDN) will emit a proper HTTP/1.1
// response line with a valid version (1.0/1.1/2), a legitimate status
// code, and typically a Server: header. A stream-layer proxy (Xray/
// Trojan/SS-AEAD) either closes the stream, returns garbage, or emits
// a canned fallback like "HTTP/0.0 307 Temporary Redirect" (a classic
// Xray `fallback+redirect` signature).
// ============================================================================
struct HttpsProbe {
    bool   tls_ok   = false;
    bool   responded = false;
    int    bytes    = 0;
    string first_line;     // trimmed response line
    string server_hdr;     // Server: value
    string http_version;   // "HTTP/1.1", "HTTP/0.0" (anomaly), ...
    int    status_code = 0;
    bool   version_anomaly = false;  // HTTP/x.y with x!=1,2 or malformed
    bool   no_server_hdr   = false;  // responded but no Server: header
    // v2.4 — proxy-chain leak headers (methodika §10.2)
    //   These headers are injected by intermediate proxies / reverse proxies.
    //   A real origin should only set them if it IS a CDN / reverse-proxy;
    //   their presence on a presumed-direct host betrays a middle proxy.
    string via_hdr;            // Via: (RFC 9110 §7.6.3)
    string forwarded_hdr;      // Forwarded: (RFC 7239)
    string xff_hdr;            // X-Forwarded-For:
    string xreal_ip_hdr;       // X-Real-IP:
    string x_forwarded_proto;  // X-Forwarded-Proto:
    string x_forwarded_host;   // X-Forwarded-Host:
    string cf_ray_hdr;         // CF-Ray: (Cloudflare)
    string cf_cache_status;    // CF-Cache-Status:
    string x_amz_cf_id;        // CloudFront ID
    string x_amz_cf_pop;       // CloudFront POP
    string x_azure_ref;        // Azure Front Door
    string x_azure_clientip;   // Azure AFD client IP leak
    string x_cache;            // Varnish / Fastly
    string x_served_by;        // Fastly
    string alt_svc;            // Alt-Svc: (QUIC endpoint advertisement)
    bool   has_proxy_leak = false;     // Via / Forwarded / XFF / X-Real-IP
    bool   has_cdn_hdr = false;        // CF-Ray, X-Amz-Cf-Id, X-Azure-Ref
    string err;
};

static HttpsProbe https_probe(const string& ip, int port, const string& host_hdr,
                              int to_ms = 5000) {
    HttpsProbe r;
    string err;
    SOCKET s = tcp_connect(ip, port, to_ms, err);
    if (s == INVALID_SOCKET) { r.err = err; return r; }
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)s);
    if (!host_hdr.empty()) SSL_set_tlsext_host_name(ssl, host_hdr.c_str());
    // advertise http/1.1 only so any proper server picks it
    static const unsigned char alpn_h11[] = {8,'h','t','t','p','/','1','.','1'};
    SSL_set_alpn_protos(ssl, alpn_h11, sizeof(alpn_h11));
    if (SSL_connect(ssl) != 1) {
        r.err = "tls handshake failed";
        SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
        return r;
    }
    r.tls_ok = true;
    // bare req, see what the origin answers
    string req = "GET / HTTP/1.1\r\nHost: " + (host_hdr.empty()?string("example.com"):host_hdr) + "\r\n"
                 "Accept: */*\r\n"
                 "Connection: close\r\n\r\n";
    SSL_write(ssl, req.data(), (int)req.size());
    // Collect up to ~4KB of response
    string body;
    char buf[1024];
    for (int i=0; i<6; ++i) {
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) break;
        body.append(buf, n);
        if (body.size() >= 4096) break;
    }
    SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
    r.bytes = (int)body.size();
    if (body.empty()) return r;
    r.responded = true;
    size_t nl = body.find('\n');
    r.first_line = trim(body.substr(0, nl == string::npos ? body.size() : nl));
    // parse "HTTP/x.y CODE REASON"
    if (starts_with(r.first_line, "HTTP/")) {
        size_t sp = r.first_line.find(' ');
        r.http_version = r.first_line.substr(0, sp == string::npos ? r.first_line.size() : sp);
        // x.y check
        if (r.http_version.size() >= 8) {
            char x = r.http_version[5], y = r.http_version[7];
            if (!(x=='1' || x=='2') || !(y=='0' || y=='1')) r.version_anomaly = true;
            // HTTP/2.1, HTTP/3.x text, HTTP/0.0 etc. are all anomalies
            if (x=='0') r.version_anomaly = true;
        } else r.version_anomaly = true;
        if (sp != string::npos) {
            size_t sp2 = r.first_line.find(' ', sp+1);
            if (sp2 != string::npos) {
                string code = r.first_line.substr(sp+1, sp2 - sp - 1);
                r.status_code = atoi(code.c_str());
            }
        }
    } else {
        // not HTTP at all — responded with raw bytes
        r.version_anomaly = true;
    }
    // Server: header
    size_t sh = body.find("\nServer:");
    if (sh == string::npos) sh = body.find("\nserver:");
    if (sh != string::npos) {
        size_t se = body.find('\n', sh + 1);
        string sv = body.substr(sh + 8, (se == string::npos ? body.size() : se) - (sh + 8));
        r.server_hdr = trim(sv);
    } else {
        r.no_server_hdr = (r.status_code > 0);  // HTTP-ish but no Server:
    }
    // v2.4 — parse proxy-chain / CDN headers (methodika §10.2)
    //   These reveal whether the host is behind (or IS) a reverse-proxy /
    //   CDN / middlebox. Case-insensitive header lookup. Classic "proxy
    //   leak" triad is Via / Forwarded / X-Forwarded-For — if any of those
    //   are set AND the ASN is not a known CDN, a middle proxy is in path.
    auto get_hdr = [&](const char* key) -> string {
        string lk = string("\n") + key;
        string lkl = lk;
        for (auto& c: lkl) c = (char)std::tolower((unsigned char)c);
        string bl = body;
        string bll = body;
        for (auto& c: bll) c = (char)std::tolower((unsigned char)c);
        size_t p = bll.find(lkl);
        if (p == string::npos) return {};
        size_t eol = body.find('\n', p + 1);
        size_t colon = body.find(':', p + 1);
        if (colon == string::npos || (eol != string::npos && colon > eol)) return {};
        string val = body.substr(colon + 1, (eol == string::npos ? body.size() : eol) - (colon + 1));
        return trim(val);
    };
    r.via_hdr           = get_hdr("Via");
    r.forwarded_hdr     = get_hdr("Forwarded");
    r.xff_hdr           = get_hdr("X-Forwarded-For");
    r.xreal_ip_hdr      = get_hdr("X-Real-IP");
    r.x_forwarded_proto = get_hdr("X-Forwarded-Proto");
    r.x_forwarded_host  = get_hdr("X-Forwarded-Host");
    r.cf_ray_hdr        = get_hdr("CF-Ray");
    r.cf_cache_status   = get_hdr("CF-Cache-Status");
    r.x_amz_cf_id       = get_hdr("X-Amz-Cf-Id");
    r.x_amz_cf_pop      = get_hdr("X-Amz-Cf-Pop");
    r.x_azure_ref       = get_hdr("X-Azure-Ref");
    r.x_azure_clientip  = get_hdr("X-Azure-ClientIP");
    r.x_cache           = get_hdr("X-Cache");
    r.x_served_by       = get_hdr("X-Served-By");
    r.alt_svc           = get_hdr("Alt-Svc");
    // Proxy-leak classification:
    //   has_proxy_leak = RFC-standard proxy trail present (methodika §10.2)
    //   has_cdn_hdr    = a known-CDN signature is set (these are not a leak
    //                    by themselves, they're the CDN doing its job — but
    //                    on a non-CDN ASN they flag "traffic goes through
    //                    a hidden CDN = possible middlebox / Reality
    //                    passthrough via CDN")
    r.has_proxy_leak = !r.via_hdr.empty() ||
                       !r.forwarded_hdr.empty() ||
                       !r.xff_hdr.empty() ||
                       !r.xreal_ip_hdr.empty();
    r.has_cdn_hdr    = !r.cf_ray_hdr.empty() ||
                       !r.x_amz_cf_id.empty() ||
                       !r.x_azure_ref.empty() ||
                       !r.x_served_by.empty();
    return r;
}

// ============================================================================
// SNI consistency test — probe with foreign SNIs, compare cert fingerprints.
//
// Reality discriminator (vs. plain TLS-with-one-cert false-positive):
//   * "same cert returned for every SNI" ALONE is NOT Reality — a plain
//     nginx with a single default cert exhibits the same behavior.
//   * Real Reality proxies the TLS handshake to dest= (typically a major
//     third-party site like www.microsoft.com), so the returned cert is
//     valid for THAT third-party domain, not for the operator's own name.
//   * So: declare reality_like ONLY when (same cert always) AND (the
//     returned cert is valid for at least one of our probed foreign SNIs).
// ============================================================================
struct SniConsistency {
    string base_sni;
    string base_sha;
    string base_subject;
    vector<string> base_san;
    struct Entry { string sni; bool ok; string sha; string subject; };
    vector<Entry> entries;
    bool same_cert_always = false;
    bool reality_like = false;
    bool default_cert_only = false; // plain server with a single default cert
    string matched_foreign_sni;     // which probed SNI the cert actually serves
    // v2.3 — brand impersonation detection
    string brand_claimed;            // brand domain the cert vouches for
    bool   cert_impersonation = false; // brand cert served AND base_sni is not
                                       // a brand-owned name AND we'll check ASN
                                       // ownership at verdict time
    bool   passthrough_mode = false;   // Reality with real passthrough to `dest=`:
                                       // base (SNI-less) cert is for a famous
                                       // brand, yet per-SNI probes see different
                                       // certs — because the TLS stream is
                                       // transparently tunnelled to the real
                                       // brand, which then does its own SNI
                                       // routing. Classic stealth-optimised
                                       // Reality config.
    int    distinct_certs = 0;         // number of distinct cert SHAs observed
};

// Case-insensitive DNS-name match with wildcard support ("*.example.com").
static bool dns_name_match(const string& name, const string& pat) {
    if (name.empty() || pat.empty()) return false;
    if (pat.size() > 2 && pat[0] == '*' && pat[1] == '.') {
        string suffix = pat.substr(1); // ".example.com"
        if (name.size() <= suffix.size()) return false;
        size_t off = name.size() - suffix.size();
        return _stricmp(name.c_str() + off, suffix.c_str()) == 0 &&
               name.find('.') == off; // exactly one label in place of "*"
    }
    return _stricmp(name.c_str(), pat.c_str()) == 0;
}

static string extract_cn(const string& subject_oneline) {
    // Format: /C=US/O=Microsoft Corporation/CN=www.microsoft.com
    size_t pos = subject_oneline.find("/CN=");
    if (pos == string::npos) return "";
    size_t end = subject_oneline.find('/', pos + 4);
    return subject_oneline.substr(pos + 4,
        end == string::npos ? string::npos : end - pos - 4);
}

static bool cert_covers_name(const string& sni,
                             const string& subject_oneline,
                             const vector<string>& san) {
    string cn = extract_cn(subject_oneline);
    if (dns_name_match(sni, cn)) return true;
    for (auto& s: san) if (dns_name_match(sni, s)) return true;
    return false;
}

static SniConsistency sni_consistency(const string& ip, int port, const string& base_sni) {
    SniConsistency c; c.base_sni = base_sni;
    TlsProbe base = tls_probe(ip, port, base_sni);
    if (!base.ok) return c;
    c.base_sha     = base.cert_sha256;
    c.base_subject = base.cert_subject;
    c.base_san     = base.san;
    // v2.3 — expanded probe list: common "dest=" targets for Xray/VLESS+Reality
    // setups (amazon/apple/microsoft/google etc.) + unrelated SNIs + a junk SNI.
    // This catches both "cert steering to dest" (Reality) and "cert statically
    // impersonates a famous brand" (Reality-static).
    static const vector<string> alt = {
        "www.microsoft.com",        // classic default dest
        "www.apple.com",             // common dest
        "www.amazon.com",            // common dest
        "www.google.com",            // common dest
        "www.cloudflare.com",        // common dest
        "www.bing.com",              // common dest
        "addons.mozilla.org",        // non-brand foreign SNI
        "www.yandex.ru",             // RU-side foreign SNI
        "www.github.com",            // common dest
        "random-domain-that-does-not-exist.invalid"  // junk — catches
                                                      // "always-accept-any-SNI"
                                                      // plain servers
    };
    int same = 0, total = 0;
    set<string> distinct;
    if (!base.cert_sha256.empty()) distinct.insert(base.cert_sha256);
    for (auto& s: alt) {
        TlsProbe p = tls_probe(ip, port, s);
        SniConsistency::Entry e;
        e.sni = s;
        e.ok  = p.ok;
        e.sha = p.cert_sha256;
        e.subject = p.cert_subject;
        if (p.ok) {
            ++total;
            if (p.cert_sha256 == base.cert_sha256) ++same;
            if (!p.cert_sha256.empty()) distinct.insert(p.cert_sha256);
        }
        c.entries.push_back(std::move(e));
    }
    c.distinct_certs = (int)distinct.size();

    // Brand-claim ALWAYS runs on the base cert. A famous-brand CN on the
    // origin's default SNI response is by itself the Reality-static
    // signature, regardless of how per-SNI variation looks — the ASN
    // cross-check at verdict time decides whether it's impersonation or
    // a legitimate brand endpoint.
    c.brand_claimed = cert_claims_brand(base.subject_cn, base.san);

    if (total >= 3 && same == total) {
        c.same_cert_always = true;
        // Reality discriminator — covers 3 cases:
        //   (A) Classical Reality: cert doesn't cover base_sni but covers
        //       one of the probed foreign SNIs (steering to dest=).
        //   (B) Reality-static / "pinned-brand" Reality: cert covers a
        //       famous brand domain (from BRAND_TABLE) even though we
        //       never sent that SNI as base. This is the Xray "fixed
        //       dest" profile where the cert from dest= is shown to
        //       every handshake.
        //   (C) Plain server with one default cert: cert covers nothing
        //       we asked about — neither base nor any foreign SNI.
        bool cert_covers_base = cert_covers_name(base_sni, base.cert_subject, base.san);
        if (!cert_covers_base) {
            for (auto& s: alt) {
                if (_stricmp(s.c_str(), base_sni.c_str()) == 0) continue;
                if (cert_covers_name(s, base.cert_subject, base.san)) {
                    c.reality_like = true;
                    c.matched_foreign_sni = s;
                    break;
                }
            }
        }
        if (!c.brand_claimed.empty()) {
            // cert_impersonation flag is lit here, ASN cross-check
            // happens at verdict time where we have GeoIP data.
            c.cert_impersonation = true;
            // If we didn't catch Reality via foreign-SNI match but the
            // cert is for a brand, escalate to reality_like so the
            // verdict engine treats it as Reality.
            if (!c.reality_like && !cert_covers_base) {
                c.reality_like = true;
                c.matched_foreign_sni = c.brand_claimed;
            }
        }
        if (!c.reality_like) c.default_cert_only = true;
    } else if (total >= 3 && same == 0 && c.distinct_certs >= 3) {
        // Cert varies per SNI. If the base (SNI-less) cert is for a
        // famous brand on a non-owning ASN, this is Reality in full
        // passthrough-dest mode — the TLS stream is transparently
        // tunnelled to the real brand, and the real brand does its own
        // SNI-based vhost routing, which is why we see different certs
        // for different SNIs. The giveaway is that the BASE probe (no
        // SNI / host's own name) still returns a cert for a brand the
        // IP's ASN doesn't own.
        if (!c.brand_claimed.empty()) {
            c.cert_impersonation = true;
            c.reality_like = true;
            c.matched_foreign_sni = c.brand_claimed;
            c.passthrough_mode   = true;
        }
        // Otherwise it's real multi-tenant TLS — no hard signal.
    } else if (total >= 3 && same > 0 && same < total) {
        // Mixed: some SNIs share a cert, others get different ones.
        // Could be a dual-stack (Reality + real vhost) host, or Reality
        // with partial passthrough. Still a brand-on-non-owner-ASN is
        // the key signal.
        if (!c.brand_claimed.empty()) {
            c.cert_impersonation = true;
            // Mark as Reality-like: mixed cert behaviour with a brand
            // cert on base is nearly always Reality (a real vhost with
            // a brand cert would pass the "same_cert_always" test).
            c.reality_like = true;
            c.matched_foreign_sni = c.brand_claimed;
            c.passthrough_mode   = true;
        }
    }
    return c;
}

// ============================================================================
// J3 / TSPU / GFW-style active probing
// ============================================================================
struct J3Result {
    string name;
    bool   responded = false;
    int    bytes = 0;
    string first_line;
    string hex_head;
    int64_t ms = 0;
};

static J3Result j3_send(const string& host, int port, const string& name,
                        const void* data, int dlen, bool close_after_send=false) {
    J3Result r; r.name = name;
    auto t0 = std::chrono::steady_clock::now();
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) return r;
    if (dlen > 0) tcp_send_all(s, data, dlen);
    if (close_after_send) { closesocket(s); return r; }
    char buf[1024]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 1200);
    closesocket(s);
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    if (n > 0) {
        r.responded = true; r.bytes = n;
        string raw(buf, n);
        size_t nl = raw.find('\n');
        r.first_line = trim(raw.substr(0, nl == string::npos ? raw.size() : nl));
        r.hex_head = hex_s((unsigned char*)buf, std::min(16, n), true);
    }
    return r;
}

static vector<J3Result> j3_probes(const string& host, int port) {
    vector<J3Result> out;
    // 1) Empty payload — just close after connect
    {
        string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
        J3Result r; r.name = "empty/close";
        if (s != INVALID_SOCKET) {
            char buf[128]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 800);
            if (n > 0) { r.responded = true; r.bytes = n; r.first_line = printable_prefix(string(buf,n)); r.hex_head = hex_s((unsigned char*)buf, std::min(16,n), true); }
            closesocket(s);
        }
        out.push_back(r);
    }
    // 2) HTTP GET /  — use the REAL host as the Host: header so a real
    //    web server (nginx/Apache/Caddy/CDN) can route properly and emit
    //    a legitimate 200/301/404. Xray/Trojan fallbacks can't route, so
    //    they emit the same canned reply as to junk probes.
    {
        string req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: curl/8.4.0\r\nAccept: */*\r\n\r\n";
        out.push_back(j3_send(host, port, "HTTP GET /", req.data(), (int)req.size()));
    }
    // 3) CONNECT proxy-style
    {
        string req = "CONNECT 1.2.3.4:443 HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n";
        out.push_back(j3_send(host, port, "HTTP CONNECT", req.data(), (int)req.size()));
    }
    // 4) SSH banner (server-in-client-role)
    // Use a realistic OpenSSH banner so the probe can't be identified as a
    // tool-specific scanner; DPI classifies it as a normal SSH handshake
    // attempt, which is what we want to measure.
    {
        string req = "SSH-2.0-OpenSSH_8.9p1\r\n";
        out.push_back(j3_send(host, port, "SSH banner", req.data(), (int)req.size()));
    }
    // 5) 512 random bytes — RAND_bytes(), not rand()/LCG, to avoid a
    // deterministic pattern detectable across runs of the same binary.
    {
        unsigned char buf[512]; RAND_bytes(buf, 512);
        out.push_back(j3_send(host, port, "random 512B", buf, 512));
    }
    // 6) TLS ClientHello minimal (TLS1.0 wrapping, random SNI)
    {
        // handcrafted minimal TLS 1.0 ClientHello with a 3-char-prefix
        // randomized SNI under .invalid TLD (RFC 6761 guarantees .invalid
        // resolves to NXDOMAIN on any real client, so the TLD choice is
        // safe; the 3-char prefix is randomized per-probe so the SNI is
        // not a constant signature). Full ClientHello shape (single
        // cipher, extension set) is still OpenSSL-style rather than
        // uTLS-Chrome — see SECURITY.md "known open threats" for the
        // full-JA3-mimicry roadmap item.
        unsigned char hello[] = {
            0x16,0x03,0x01,0x00,0x70,     // TLS record: handshake, 0x70 len
            0x01,0x00,0x00,0x6c,          // handshake: client_hello, len 0x6c
            0x03,0x03,                    // TLS 1.2
            // 32 bytes ClientRandom (filled by RAND_bytes below)
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0x00,                         // session id len
            0x00,0x02,                    // cipher suites len
            0x13,0x02,                    // TLS_AES_256_GCM_SHA384
            0x01,0x00,                    // compression: null
            // extensions
            0x00,0x41,
            0x00,0x00,0x00,0x10, 0x00,0x0e, 0x00,0x00,0x0b, 0,0,0,'.','i','n','v','a','l','i','d',
            0x00,0x10,0x00,0x0b, 0x00,0x09, 0x08,'h','t','t','p','/','1','.','1',
            0x00,0x0b,0x00,0x02, 0x01,0x00,
            0x00,0x0a,0x00,0x04, 0x00,0x02,0x00,0x1d,
            0x00,0x0d,0x00,0x0a, 0x00,0x08, 0x04,0x01, 0x05,0x01, 0x08,0x07, 0x08,0x08,
            0x00,0x2b,0x00,0x03, 0x02,0x03,0x04,
            0x00,0x33,0x00,0x02, 0x00,0x00
        };
        // ClientRandom starts right after the TLS 1.2 version bytes (offset 11)
        RAND_bytes(hello + 11, 32);
        // Randomize the 3-char prefix of the SNI value. The SNI extension
        // payload lives at offset 9 from the start of the SNI extension.
        // Locate it by the two null server-name-list-length bytes that
        // precede the actual name length + name bytes.
        // In the hello[] above, the name bytes are the 3 zero slots
        // immediately before '.','i','n','v','a','l','i','d'. Patch them.
        for (size_t i = 11 + 32; i + 11 <= sizeof(hello); ++i) {
            // Find the ".invalid" literal; the 3 bytes before it are the
            // ones we randomize.
            if (hello[i]   == '.' && hello[i+1] == 'i' && hello[i+2] == 'n' &&
                hello[i+3] == 'v' && hello[i+4] == 'a' && hello[i+5] == 'l' &&
                hello[i+6] == 'i' && hello[i+7] == 'd' && i >= 3) {
                unsigned char r[3]; RAND_bytes(r, 3);
                hello[i-3] = 'a' + (r[0] % 26);
                hello[i-2] = 'a' + (r[1] % 26);
                hello[i-1] = 'a' + (r[2] % 26);
                break;
            }
        }
        out.push_back(j3_send(host, port, "TLS CH invalid-SNI", hello, (int)sizeof(hello)));
    }
    // 7) HTTP/1.0 proxy request with absolute URL
    {
        string req = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        out.push_back(j3_send(host, port, "HTTP abs-URI (proxy-style)", req.data(), (int)req.size()));
    }
    // 8) trash first byte 0xFF x 128 then TLS
    {
        unsigned char garb[128]; memset(garb, 0xFF, sizeof(garb));
        out.push_back(j3_send(host, port, "0xFF x128", garb, sizeof(garb)));
    }
    return out;
}

// ============================================================================
// J3 response analysis  (v2.3)
//
// TSPU/GFW care about what the endpoint DOES with malformed input, not
// just whether it replies. We bucket replies as:
//   * real HTTP 4xx/5xx (normal web server behaviour)
//   * canned-fallback (same bytes / same first-line for different probes,
//     classic Xray `fallback+redirect` signature)
//   * non-HTTP reply (raw framed bytes — stream-layer proxy talking
//     protocol-of-its-own)
//   * invalid HTTP version in the reply line (e.g. "HTTP/0.0 307")
//   * pure silence (also normal for a strict TLS endpoint, kept here as
//     data rather than a verdict)
// ============================================================================
struct J3Analysis {
    int  silent = 0;
    int  resp   = 0;
    int  http_real = 0;        // replies start with HTTP/1.x or HTTP/2 and
                               // carry a sane status code
    int  http_bad_version = 0; // replies start with HTTP/ but with a
                               // nonsense version (HTTP/0.0, HTTP/3.X text,
                               // truncated "HTTP/"...)
    int  raw_non_http = 0;     // responded, not HTTP-shaped (stream proxy
                               // framing)
    int  canned_identical = 0; // number of probes sharing first_line+bytes
                               // with at least one OTHER probe
    string canned_line;        // the canned first line that repeated
    int  canned_bytes = 0;
};

static bool looks_like_http_line(const string& first_line, bool* bad_version_out = nullptr) {
    if (first_line.size() < 9) return false;
    if (first_line.compare(0, 5, "HTTP/") != 0) return false;
    // version is 3 chars after "HTTP/", e.g. "1.1"
    char x = first_line[5];
    char dot = first_line.size() > 6 ? first_line[6] : 0;
    char y = first_line.size() > 7 ? first_line[7] : 0;
    if (dot != '.') return false;
    // x must be 1 or 2; y must be 0 or 1 (for HTTP/1.0/1.1/2.0)
    bool good_version = ((x=='1' && (y=='0' || y=='1')) || (x=='2' && y=='0'));
    if (!good_version && bad_version_out) *bad_version_out = true;
    return true;
}

static J3Analysis j3_analyze(const vector<J3Result>& probes) {
    J3Analysis a;
    // Count canned pairs: same first_line AND same byte count -> canned
    // response regardless of what we sent.
    //
    // v2.3 refinement: a real web server returns the same HTTP 400 body
    // to every MALFORMED probe — that's normal nginx behaviour, not a
    // canned fallback. The Xray/Trojan tell is when a VALID HTTP probe
    // (our "HTTP GET /" and/or "HTTP abs-URI (proxy-style)") also gets
    // the same canned reply. We therefore only raise `canned_identical`
    // when at least one valid-HTTP probe shares the reply.
    struct KeyEntry { string line; int bytes; const char* name; };
    vector<KeyEntry> keys;
    for (auto& p: probes) {
        if (p.responded) {
            ++a.resp;
            keys.push_back({p.first_line, p.bytes, p.name.c_str()});
            bool bad_v = false;
            bool is_http = looks_like_http_line(p.first_line, &bad_v);
            if (is_http && !bad_v) ++a.http_real;
            else if (is_http && bad_v) ++a.http_bad_version;
            else                       ++a.raw_non_http;
        } else {
            ++a.silent;
        }
    }
    // A probe name is "valid-HTTP" if it sent a well-formed HTTP request
    // that a real web server would distinguish from junk.
    auto is_valid_http_probe = [](const char* n) {
        if (!n) return false;
        return strstr(n, "HTTP GET /") != nullptr ||
               strstr(n, "HTTP abs-URI") != nullptr;
    };
    // Find canned clusters: line+bytes appearing >=2 times AND including
    // at least one valid-HTTP probe (otherwise it's just uniform 400 on
    // malformed junk, which is the correct nginx behaviour).
    for (size_t i=0; i<keys.size(); ++i) {
        int count = 0;
        bool has_valid_http = false;
        for (size_t j=0; j<keys.size(); ++j) {
            if (keys[i].line == keys[j].line && keys[i].bytes == keys[j].bytes) {
                ++count;
                if (is_valid_http_probe(keys[j].name)) has_valid_http = true;
            }
        }
        if (count >= 2 && keys[i].line.size() > 3 && has_valid_http) {
            a.canned_identical = count;
            a.canned_line      = keys[i].line;
            a.canned_bytes     = keys[i].bytes;
            break;
        }
    }
    return a;
}

// ============================================================================
// QUIC (HTTP/3) initial probe on UDP/443
// ============================================================================
static UdpResult quic_probe(const string& host, int port) {
    // Minimal QUIC v1 Initial with CRYPTO frame (bogus but valid length) → should trigger Version Negotiation or retry.
    // DCID is filled with RAND_bytes() per-probe so it looks like a real QUIC client connection ID.
    unsigned char pkt[] = {
        0xc0,                        // long header, type Initial
        0x00,0x00,0x00,0x01,         // QUIC version 1
        0x08,                        // DCID len
        0,0,0,0,0,0,0,0,             // DCID (filled by RAND_bytes below)
        0x00,                        // SCID len
        0x00,                        // Token len
        0x44,0x40,                   // Length varint (1088)
        // payload (not real encryption — server should ignore / NEG)
    };
    RAND_bytes(pkt + 6, 8);          // random 8-byte DCID
    vector<unsigned char> full(1200, 0x00);
    memcpy(full.data(), pkt, sizeof(pkt));
    return udp_probe(host, port, full.data(), (int)full.size(), 1500);
}

// ============================================================================
// OpenVPN UDP probe: HARD_RESET_CLIENT_V2
// ============================================================================
static UdpResult openvpn_probe(const string& host, int port) {
    unsigned char pkt[26];
    pkt[0] = 0x38; // P_CONTROL_HARD_RESET_CLIENT_V2 (7) << 3 | key_id 0 = 0x38
    RAND_bytes(pkt+1, 8);     // session id
    pkt[9] = 0x00;            // packet id array len
    unsigned int pid = htonl(0);
    memcpy(pkt+10, &pid, 4);  // packet id
    // Session-creation timestamp. A real OpenVPN client stamps this
    // several seconds/minutes before actually emitting the packet, so
    // a timestamp that exactly matches the arrival time is a tool
    // fingerprint. We subtract a small random offset (0..300s) to
    // match the distribution of real clients.
    unsigned char rnd_off = 0;
    RAND_bytes(&rnd_off, 1);
    unsigned int ts = htonl((unsigned int)time(nullptr) - (unsigned int)rnd_off);
    memcpy(pkt+14, &ts, 4);   // timestamp
    RAND_bytes(pkt+18, 8);    // some padding
    return udp_probe(host, port, pkt, sizeof(pkt), 1200);
}

// ============================================================================
// WireGuard UDP probe: MessageInitiation (148B)
// ============================================================================
static UdpResult wireguard_probe(const string& host, int port) {
    unsigned char pkt[148] = {0};
    pkt[0] = 0x01;   // type: handshake initiation
    RAND_bytes(pkt+4, 140); // rest: sender idx + ephemeral + encrypted static + encrypted timestamp + mac1/mac2
    return udp_probe(host, port, pkt, sizeof(pkt), 1500);
}

// ============================================================================
// IKE ISAKMP probe (UDP/500): 28-byte header, nothing meaningful
// ============================================================================
static UdpResult ike_probe(const string& host, int port) {
    unsigned char pkt[28] = {0};
    RAND_bytes(pkt, 8);       // ICOOKIE
    // RCOOKIE all-zero (initiator)
    pkt[16] = 0x21;           // next payload: SA (1) + version hint
    pkt[17] = 0x20;           // IKEv2 version 2.0
    pkt[18] = 0x22;           // exchange type: IKE_SA_INIT (34)
    pkt[19] = 0x08;           // flags: Initiator
    // message id = 0
    // length = 28
    pkt[24] = 0; pkt[25] = 0; pkt[26] = 0; pkt[27] = 28;
    return udp_probe(host, port, pkt, sizeof(pkt), 1200);
}

// ============================================================================
// DNS UDP/53 probe — A query for example.com
// ============================================================================
static UdpResult dns_probe(const string& host, int port) {
    // Standard DNS query, 1 question: example.com A.
    // Transaction ID is randomized per-probe via RAND_bytes() — RFC 5452
    // requires a real resolver to randomize txn ID for cache-poisoning
    // resistance, so a hardcoded constant (e.g. 0xBEEF) is both a tool
    // fingerprint AND protocol-incorrect.
    unsigned char q[] = {
        0,0,        0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
        0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00,
        0x00,0x01, 0x00,0x01
    };
    RAND_bytes(q, 2);   // random txn ID
    return udp_probe(host, port, q, sizeof(q), 1200);
}

// ============================================================================
// Local analysis (this machine): adapters, routes, VPN processes, configs
// ============================================================================
struct LocalAdapter {
    string  friendly;       // "Ethernet 3"
    string  description;    // "WireGuard Tunnel"
    string  mac;
    vector<string> ipv4;
    vector<string> ipv6;
    vector<string> gateways;
    unsigned long mtu = 0;
    unsigned long if_index = 0;
    bool    is_vpn = false; // TAP/TUN/WG/WARP/etc
    bool    is_up  = false;
};

struct LocalRoute {
    string prefix;          // "0.0.0.0/0"
    string nexthop;         // "192.168.1.1"
    unsigned long if_index = 0;
    unsigned long metric   = 0;
    string via_adapter;     // filled later
    bool   via_vpn = false;
};

struct LocalProcess {
    unsigned long pid = 0;
    string name;
    string exe_path;
    string category;        // "xray", "wireguard", "warp", ...
};

static bool icontains(const string& hay, const char* needle) {
    string a = hay, b = needle;
    std::transform(a.begin(), a.end(), a.begin(), ::tolower);
    std::transform(b.begin(), b.end(), b.begin(), ::tolower);
    return a.find(b) != string::npos;
}

static string mac_to_str(const unsigned char* mac, int len) {
    char buf[64]; buf[0]=0;
    for (int i=0;i<len;++i)
        sprintf(buf+strlen(buf), "%02X%s", mac[i], i<len-1?":":"");
    return buf;
}

static string sockaddr_to_str(SOCKADDR* sa) {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (sa->sa_family == AF_INET) {
        sockaddr_in* s = (sockaddr_in*)sa;
        inet_ntop(AF_INET, &s->sin_addr, buf, sizeof(buf));
    } else if (sa->sa_family == AF_INET6) {
        sockaddr_in6* s = (sockaddr_in6*)sa;
        inet_ntop(AF_INET6, &s->sin6_addr, buf, sizeof(buf));
    }
    return buf;
}

// Keywords that identify VPN-like adapters by description/name.
static bool adapter_is_vpn(const string& desc, const string& name) {
    static const char* kw[] = {
        "TAP-Windows", "TAP-ProtonVPN", "WireGuard", "WireGuard Tunnel",
        "Wintun", "TUN", "Tun ", "OpenVPN", "Mullvad", "NordLynx", "ProtonVPN",
        "Cloudflare WARP", "Hiddify", "Amnezia", "singbox", "sing-box",
        "v2ray", "xray", "AmneziaWG", "ExpressVPN", "Private Internet",
        "PIA", "Surfshark", "TorGuard"
    };
    for (auto k: kw) if (icontains(desc, k) || icontains(name, k)) return true;
    return false;
}

static vector<LocalAdapter> list_local_adapters() {
    vector<LocalAdapter> out;
    ULONG sz = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                         nullptr, nullptr, &sz);
    if (!sz) return out;
    vector<unsigned char> buf(sz);
    auto* aa = (IP_ADAPTER_ADDRESSES*)buf.data();
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                             nullptr, aa, &sz) != NO_ERROR) return out;
    for (auto* p = aa; p; p = p->Next) {
        LocalAdapter A;
        char fn[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, p->FriendlyName, -1, fn, sizeof(fn), nullptr, nullptr);
        A.friendly = fn;
        char dc[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, p->Description, -1, dc, sizeof(dc), nullptr, nullptr);
        A.description = dc;
        if (p->PhysicalAddressLength)
            A.mac = mac_to_str(p->PhysicalAddress, p->PhysicalAddressLength);
        A.mtu = p->Mtu;
        A.if_index = p->IfIndex;
        A.is_up = (p->OperStatus == IfOperStatusUp);
        for (auto* u = p->FirstUnicastAddress; u; u = u->Next) {
            string s = sockaddr_to_str(u->Address.lpSockaddr);
            if (s.empty()) continue;
            if (u->Address.lpSockaddr->sa_family == AF_INET)  A.ipv4.push_back(s);
            else                                              A.ipv6.push_back(s);
        }
        for (auto* g = p->FirstGatewayAddress; g; g = g->Next) {
            string s = sockaddr_to_str(g->Address.lpSockaddr);
            if (!s.empty()) A.gateways.push_back(s);
        }
        A.is_vpn = adapter_is_vpn(A.description, A.friendly);
        out.push_back(std::move(A));
    }
    return out;
}

static vector<LocalRoute> list_local_routes() {
    vector<LocalRoute> out;
    MIB_IPFORWARD_TABLE2* tbl = nullptr;
    if (GetIpForwardTable2(AF_UNSPEC, &tbl) != NO_ERROR || !tbl) return out;
    for (ULONG i=0; i<tbl->NumEntries; ++i) {
        auto& r = tbl->Table[i];
        LocalRoute R;
        char dst[INET6_ADDRSTRLEN]={0}, nh[INET6_ADDRSTRLEN]={0};
        if (r.DestinationPrefix.Prefix.si_family == AF_INET) {
            inet_ntop(AF_INET, &r.DestinationPrefix.Prefix.Ipv4.sin_addr, dst, sizeof(dst));
            inet_ntop(AF_INET, &r.NextHop.Ipv4.sin_addr,                    nh,  sizeof(nh));
        } else if (r.DestinationPrefix.Prefix.si_family == AF_INET6) {
            inet_ntop(AF_INET6, &r.DestinationPrefix.Prefix.Ipv6.sin6_addr, dst, sizeof(dst));
            inet_ntop(AF_INET6, &r.NextHop.Ipv6.sin6_addr,                   nh,  sizeof(nh));
        } else continue;
        R.prefix   = string(dst) + "/" + std::to_string(r.DestinationPrefix.PrefixLength);
        R.nexthop  = nh;
        R.if_index = r.InterfaceIndex;
        R.metric   = r.Metric;
        out.push_back(R);
    }
    FreeMibTable(tbl);
    return out;
}

struct KnownProc { const char* exe; const char* category; };
static const vector<KnownProc> VPN_PROCESSES = {
    {"xray.exe",          "Xray-core"},
    {"v2ray.exe",         "V2Ray"},
    {"sing-box.exe",      "sing-box"},
    {"singbox.exe",       "sing-box"},
    {"v2rayN.exe",        "v2rayN (GUI → Xray)"},
    {"v2rayNG.exe",       "v2rayNG"},
    {"nekoray.exe",       "NekoRay (GUI → sing-box/Xray)"},
    {"nekobox.exe",       "NekoBox"},
    {"Hiddify.exe",       "Hiddify"},
    {"HiddifyCli.exe",    "Hiddify CLI"},
    {"HiddifyTray.exe",   "Hiddify tray"},
    {"wg.exe",            "WireGuard CLI"},
    {"WireGuard.exe",     "WireGuard (Windows client)"},
    {"wireguard.exe",     "WireGuard"},
    {"tunnel.exe",        "WireGuard tunnel service"},
    {"tun2socks.exe",     "tun2socks"},
    {"openvpn.exe",       "OpenVPN"},
    {"openvpn-gui.exe",   "OpenVPN GUI"},
    {"warp-svc.exe",      "Cloudflare WARP service"},
    {"Cloudflare WARP.exe","Cloudflare WARP"},
    {"ProtonVPN.exe",     "ProtonVPN"},
    {"NordVPN.exe",       "NordVPN"},
    {"ExpressVPN.exe",    "ExpressVPN"},
    {"Mullvad VPN.exe",   "Mullvad"},
    {"Shadowsocks.exe",   "Shadowsocks"},
    {"ShadowsocksR.exe",  "ShadowsocksR"},
    {"clash.exe",         "Clash"},
    {"clash-verge.exe",   "Clash Verge"},
    {"ClashForWindows.exe","Clash for Windows"},
    {"AmneziaVPN.exe",    "AmneziaVPN"},
    {"amneziawg.exe",     "AmneziaWG"},
    {"cisco-vpn.exe",     "Cisco AnyConnect"},
    {"vpncli.exe",        "Cisco AnyConnect CLI"},
};

static vector<LocalProcess> list_vpn_processes() {
    vector<LocalProcess> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            char name[260] = {0};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, sizeof(name), nullptr, nullptr);
            for (auto& kp: VPN_PROCESSES) {
                if (_stricmp(name, kp.exe) == 0) {
                    LocalProcess LP;
                    LP.pid = pe.th32ProcessID;
                    LP.name = name;
                    LP.category = kp.category;
                    // try to resolve exe path
                    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                    if (h) {
                        wchar_t path[MAX_PATH] = {0};
                        DWORD sz = MAX_PATH;
                        if (QueryFullProcessImageNameW(h, 0, path, &sz)) {
                            char p[MAX_PATH] = {0};
                            WideCharToMultiByte(CP_UTF8, 0, path, -1, p, sizeof(p), nullptr, nullptr);
                            LP.exe_path = p;
                        }
                        CloseHandle(h);
                    }
                    out.push_back(std::move(LP));
                    break;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

struct KnownConfig { const char* envvar; const char* subpath; const char* tool; };
static const vector<KnownConfig> KNOWN_CONFIGS = {
    {"APPDATA",      "\\Xray",                            "Xray-core configs"},
    {"APPDATA",      "\\v2rayN",                          "v2rayN configs"},
    {"APPDATA",      "\\v2ray",                           "V2Ray configs"},
    {"APPDATA",      "\\sing-box",                        "sing-box configs"},
    {"APPDATA",      "\\NekoRay",                         "NekoRay configs"},
    {"APPDATA",      "\\nekobox",                         "NekoBox configs"},
    {"APPDATA",      "\\Hiddify",                         "Hiddify configs"},
    {"APPDATA",      "\\Hiddify Next",                    "Hiddify Next"},
    {"APPDATA",      "\\clash",                           "Clash configs"},
    {"APPDATA",      "\\clash-verge",                     "Clash Verge configs"},
    {"LOCALAPPDATA", "\\WireGuard",                       "WireGuard configs"},
    {"LOCALAPPDATA", "\\Programs\\Amnezia",               "AmneziaVPN client"},
    {"LOCALAPPDATA", "\\Programs\\Hiddify",               "Hiddify install"},
    {"PROGRAMFILES", "\\OpenVPN",                         "OpenVPN install"},
    {"PROGRAMFILES", "\\Cloudflare\\Cloudflare WARP",     "Cloudflare WARP"},
    {"PROGRAMFILES", "\\WireGuard",                       "WireGuard (system)"},
    {"PROGRAMFILES", "\\Mullvad VPN",                     "Mullvad"},
    {"PROGRAMFILES", "\\NordVPN",                         "NordVPN"},
    {"PROGRAMFILES", "\\Proton\\VPN",                     "ProtonVPN"},
};

struct ConfigHit { string tool; string path; };

static vector<ConfigHit> find_known_configs() {
    vector<ConfigHit> out;
    for (auto& k: KNOWN_CONFIGS) {
        char ev[512] = {0}; size_t sz = sizeof(ev);
        if (getenv_s(&sz, ev, sizeof(ev), k.envvar) != 0 || !sz) continue;
        string full = string(ev) + k.subpath;
        DWORD attr = GetFileAttributesA(full.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES)
            out.push_back({k.tool, full});
    }
    return out;
}

static void run_local_analysis() {
    printf("\n%s[LOCAL ANALYSIS] This machine — adapters, routes, VPN software%s\n\n",
           col(C::BOLD), col(C::RST));

    // 1. Adapters
    auto adapters = list_local_adapters();
    printf("%s[1/4] Network adapters%s\n", col(C::BOLD), col(C::RST));
    int vpn_up = 0, phys_up = 0;
    for (auto& A: adapters) {
        if (!A.is_up) continue;
        if (A.is_vpn) ++vpn_up; else if (!A.ipv4.empty()) ++phys_up;
        const char* tag = A.is_vpn ? "[VPN]" : "     ";
        const char* clr = A.is_vpn ? C::YEL : C::DIM;
        printf("  %s%s%s  %s%s%s  ifidx=%lu  mtu=%lu\n",
               col(clr), tag, col(C::RST),
               col(C::BOLD), A.friendly.c_str(), col(C::RST),
               A.if_index, A.mtu);
        printf("         desc: %s\n", A.description.c_str());
        if (!A.mac.empty()) printf("         mac:  %s\n", A.mac.c_str());
        for (auto& ip: A.ipv4) printf("         ipv4: %s\n", ip.c_str());
        for (auto& ip: A.ipv6) printf("         ipv6: %s\n", ip.c_str());
        for (auto& g:  A.gateways) printf("         gw:   %s\n", g.c_str());
    }
    if (vpn_up == 0) printf("  %sno active VPN adapters%s\n", col(C::DIM), col(C::RST));

    // 2. Routes — resolve which interface each route belongs to
    auto routes = list_local_routes();
    std::map<unsigned long, LocalAdapter*> by_idx;
    for (auto& A: adapters) by_idx[A.if_index] = &A;
    for (auto& R: routes) {
        auto it = by_idx.find(R.if_index);
        if (it != by_idx.end()) { R.via_adapter = it->second->friendly; R.via_vpn = it->second->is_vpn; }
    }

    // Find default routes
    printf("\n%s[2/4] Default routes%s\n", col(C::BOLD), col(C::RST));
    vector<LocalRoute*> defaults_v4, defaults_v6;
    for (auto& R: routes) {
        if (R.prefix == "0.0.0.0/0") defaults_v4.push_back(&R);
        if (R.prefix == "::/0")       defaults_v6.push_back(&R);
    }
    std::sort(defaults_v4.begin(), defaults_v4.end(),
              [](auto* a, auto* b){return a->metric < b->metric;});
    for (auto* R: defaults_v4) {
        const char* c = R->via_vpn ? C::YEL : C::CYN;
        printf("  %s0.0.0.0/0%s → %s  via %s%s%s%s  metric=%lu\n",
               col(c), col(C::RST), R->nexthop.c_str(),
               col(C::BOLD),
               R->via_adapter.empty()?"?":R->via_adapter.c_str(),
               R->via_vpn?" [VPN]":"",
               col(C::RST), R->metric);
    }
    if (defaults_v4.empty()) printf("  %sno IPv4 default route%s\n", col(C::RED), col(C::RST));

    // Split-tunnel heuristic
    printf("\n%s[3/4] Tunneling mode%s\n", col(C::BOLD), col(C::RST));
    bool has_vpn_if   = vpn_up > 0;
    bool default_via_vpn = !defaults_v4.empty() && defaults_v4.front()->via_vpn;
    bool has_vpn_specific_route = false;
    for (auto& R: routes) {
        if (R.via_vpn && R.prefix != "0.0.0.0/0" && R.prefix != "::/0"
            && R.prefix.find("/32") == string::npos && R.prefix.find("/128") == string::npos)
            has_vpn_specific_route = true;
    }
    if (!has_vpn_if) {
        printf("  %s⚠ No VPN adapter active — you're on raw ISP connection%s\n",
               col(C::YEL), col(C::RST));
    } else if (default_via_vpn && !has_vpn_specific_route) {
        printf("  %s✓ FULL-TUNNEL%s — all traffic routed through VPN adapter \"%s\"\n",
               col(C::GRN), col(C::RST), defaults_v4.front()->via_adapter.c_str());
    } else if (default_via_vpn && has_vpn_specific_route) {
        printf("  %s↯ FULL-TUNNEL + extra VPN-specific routes%s (likely VPN provider pushed split rules)\n",
               col(C::GRN), col(C::RST));
    } else if (!default_via_vpn && has_vpn_specific_route) {
        printf("  %s✂ SPLIT-TUNNEL%s — default route goes via ISP, but selected subnets go through VPN:\n",
               col(C::MAG), col(C::RST));
        int shown = 0;
        for (auto& R: routes) {
            if (R.via_vpn && R.prefix != "0.0.0.0/0" && R.prefix.find("/32") == string::npos) {
                printf("         %s  →  %s%s%s\n",
                       R.prefix.c_str(), col(C::BOLD), R.via_adapter.c_str(), col(C::RST));
                if (++shown >= 8) { printf("         ... (more omitted)\n"); break; }
            }
        }
    } else {
        printf("  %s? Mixed state%s — VPN adapter up, but default route NOT via VPN\n",
               col(C::YEL), col(C::RST));
    }

    // 3. VPN processes
    printf("\n%s[4/4] VPN software detected (running processes + installed configs)%s\n",
           col(C::BOLD), col(C::RST));
    auto procs = list_vpn_processes();
    if (procs.empty()) printf("  %sno known VPN/proxy processes running%s\n", col(C::DIM), col(C::RST));
    else {
        for (auto& p: procs) {
            printf("  %s● %s%s  pid=%lu  (%s)\n",
                   col(C::GRN), p.name.c_str(), col(C::RST),
                   p.pid, p.category.c_str());
            if (!p.exe_path.empty()) printf("     path: %s\n", p.exe_path.c_str());
        }
    }

    auto cfgs = find_known_configs();
    if (!cfgs.empty()) {
        printf("\n  %sInstalled tools / config dirs:%s\n", col(C::BOLD), col(C::RST));
        for (auto& c: cfgs)
            printf("    %s%-32s%s  %s\n", col(C::CYN), c.tool.c_str(), col(C::RST), c.path.c_str());
    }

    // Summary
    printf("\n%sSummary:%s\n", col(C::BOLD), col(C::RST));
    if (has_vpn_if && default_via_vpn)
        printf("  %s→ You are currently tunneled through VPN.%s\n", col(C::GRN), col(C::RST));
    else if (has_vpn_if && !default_via_vpn && has_vpn_specific_route)
        printf("  %s→ Partial tunnel (split-tunneling active).%s\n", col(C::MAG), col(C::RST));
    else if (has_vpn_if)
        printf("  %s→ VPN adapter exists but traffic NOT through it (disconnected or misrouted).%s\n",
               col(C::YEL), col(C::RST));
    else
        printf("  %s→ No VPN active. Traffic goes directly via your ISP.%s\n",
               col(C::YEL), col(C::RST));
    if (!procs.empty()) {
        set<string> cats;
        for (auto& p: procs) cats.insert(p.category);
        printf("     Software stack running: ");
        int n=0; for (auto& c: cats) printf("%s%s", n++?", ":"", c.c_str()); printf("\n");
    }
}

// ============================================================================
// v2.4 — SNITCH-style latency/geo consistency (methodika §10.1)
// ----------------------------------------------------------------------------
// Methodika §10.1 names SNITCH (Server-side Non-intrusive Identification of
// Tunnelled Characteristics) as the canonical "latency vs GeoIP" VPN detector.
// Concept: measure RTT from observer to target, compare against the lower
// bound implied by the target's claimed geolocation. If RTT << physical
// minimum → GeoIP lies (target isn't where it claims). If RTT >> expected
// → extra hops in path (tunnel). High jitter → tunnel queuing.
//
// We do a simplified single-observer version: 6 TCP handshakes to the
// target + parallel anchor measurements to 3 landmarks (1.1.1.1, 8.8.8.8,
// 77.88.8.8). The ratio target_RTT / anchor_RTT is stable across observer
// locations, so we can infer relative geography even without knowing where
// the user runs the tool from.
//
// Fiber light-speed: ~200,000 km/s. Moscow→Frankfurt ≈ 2000km → ~10ms
// one-way → ~20ms RTT minimum. Moscow→Los Angeles ≈ 10,000km → ~100ms.
// ============================================================================
struct SnitchResult {
    bool    ok = false;
    int     samples = 0;
    double  median_ms = 0.0;
    double  min_ms    = 0.0;
    double  max_ms    = 0.0;
    double  stddev_ms = 0.0;
    // anchor RTTs (our vantage-point baselines)
    double  cf_median_ms      = -1.0;  // 1.1.1.1
    double  google_median_ms  = -1.0;  // 8.8.8.8
    double  yandex_median_ms  = -1.0;  // 77.88.8.8
    // anomaly analysis (filled by snitch_classify)
    string  country_code;
    double  expected_min_ms = 0.0;    // physical minimum RTT for geo
    bool    too_low        = false;   // median < 50% of expected_min (impossible)
    bool    too_high       = false;   // median > 3x expected max → extra hops
    bool    high_jitter    = false;   // stddev > 40ms → tunnel queue
    bool    anchor_ratio_off = false; // target_RTT / closest_anchor way off
    string  summary;                  // short one-line verdict
};

static double percentile(vector<double> v, double pct) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    size_t n = v.size();
    double idx = pct * (n - 1);
    size_t lo = (size_t)std::floor(idx);
    size_t hi = (size_t)std::ceil(idx);
    if (lo == hi) return v[lo];
    double frac = idx - lo;
    return v[lo] * (1 - frac) + v[hi] * frac;
}

// Single TCP-connect RTT measurement (milliseconds as double).
// Returns -1 on failure.
static double tcp_rtt_sample_ms(const string& host, int port, int to_ms) {
    auto t0 = std::chrono::steady_clock::now();
    string err;
    SOCKET s = tcp_connect(host, port, to_ms, err);
    if (s == INVALID_SOCKET) return -1.0;
    auto t1 = std::chrono::steady_clock::now();
    closesocket(s);
    double us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    return us / 1000.0;
}

// 6 samples; drop outlier (max); compute median / min / stddev / max.
static void measure_rtt_series(const string& host, int port,
                               int to_ms, int samples,
                               vector<double>& out) {
    out.reserve(samples);
    for (int i = 0; i < samples; ++i) {
        double ms = tcp_rtt_sample_ms(host, port, to_ms);
        if (ms > 0) out.push_back(ms);
    }
}

// Classify: physical RTT minimum for a country code, given the observer
// is somewhere on the planet but likely in RU/EU (our target user base).
// Two-letter ISO 3166-1 alpha-2.
static double country_min_rtt_ms(const string& cc) {
    static const struct { const char* cc; double min_ms; double max_ms; } TBL[] = {
        // CC     min   max      Rationale (from a RU/EU observer vantage)
        {"RU",     4,    40},    // in-country + RU CDN
        {"BY",    10,    40},    // Minsk – neighbour
        {"UA",    10,    50},    // Kiev – neighbour
        {"KZ",    20,    80},    // Almaty
        {"LT",    15,    45},    // Baltics
        {"LV",    15,    45},
        {"EE",    15,    45},
        {"FI",    10,    45},
        {"SE",    20,    55},
        {"NO",    25,    60},
        {"DE",    25,    60},    // Frankfurt is THE EU hub
        {"NL",    30,    65},    // Amsterdam
        {"FR",    30,    70},
        {"GB",    35,    75},
        {"IT",    35,    80},
        {"ES",    45,    90},
        {"PL",    25,    60},
        {"CZ",    25,    60},
        {"AT",    30,    65},
        {"CH",    30,    70},
        {"BE",    30,    65},
        {"HU",    30,    65},
        {"RO",    30,    70},
        {"BG",    30,    70},
        {"TR",    45,   100},
        {"IL",    60,   120},
        {"IR",    70,   150},
        {"AE",    80,   150},
        {"SA",    80,   160},
        {"IN",   110,   220},
        {"CN",   130,   290},
        {"HK",   140,   280},
        {"JP",   150,   300},
        {"KR",   150,   300},
        {"SG",   160,   320},
        {"TH",   160,   320},
        {"ID",   180,   350},
        {"AU",   230,   420},
        {"NZ",   260,   460},
        {"US",   100,   200},    // East coast avg
        {"CA",   100,   200},
        {"MX",   130,   260},
        {"BR",   180,   340},
        {"AR",   210,   380},
        {"ZA",   160,   320},
        {"EG",   60,    130},
    };
    if (cc.empty()) return 0.0;
    string u = cc;
    for (auto& c: u) c = (char)std::toupper((unsigned char)c);
    for (auto& e: TBL) if (u == e.cc) return e.min_ms;
    return 0.0; // unknown
}

static double country_max_rtt_ms(const string& cc) {
    static const struct { const char* cc; double max_ms; } TBL[] = {
        {"RU",40},{"BY",40},{"UA",50},{"KZ",80},{"LT",45},{"LV",45},{"EE",45},
        {"FI",45},{"SE",55},{"NO",60},{"DE",60},{"NL",65},{"FR",70},{"GB",75},
        {"IT",80},{"ES",90},{"PL",60},{"CZ",60},{"AT",65},{"CH",70},{"BE",65},
        {"HU",65},{"RO",70},{"BG",70},{"TR",100},{"IL",120},{"IR",150},{"AE",150},
        {"SA",160},{"IN",220},{"CN",290},{"HK",280},{"JP",300},{"KR",300},{"SG",320},
        {"TH",320},{"ID",350},{"AU",420},{"NZ",460},{"US",200},{"CA",200},{"MX",260},
        {"BR",340},{"AR",380},{"ZA",320},{"EG",130},
    };
    if (cc.empty()) return 0.0;
    string u = cc;
    for (auto& c: u) c = (char)std::toupper((unsigned char)c);
    for (auto& e: TBL) if (u == e.cc) return e.max_ms;
    return 0.0;
}

// Run SNITCH test: 6 target samples + 3 parallel anchor-sample batches.
static SnitchResult snitch_check(const string& target_ip,
                                 int target_port,
                                 const string& country_code) {
    SnitchResult r; r.country_code = country_code;
    const int samples = 6;

    // Anchors in parallel — each does 4 samples
    auto anchor_job = [&](string ip, int port) {
        vector<double> xs; measure_rtt_series(ip, port, 1500, 4, xs);
        std::sort(xs.begin(), xs.end());
        // Trim top outlier
        if (xs.size() >= 4) xs.pop_back();
        return xs.empty() ? -1.0 : percentile(xs, 0.5);
    };
    auto f_cf   = std::async(std::launch::async, anchor_job, "1.1.1.1",      443);
    auto f_goog = std::async(std::launch::async, anchor_job, "8.8.8.8",      443);
    auto f_yan  = std::async(std::launch::async, anchor_job, "77.88.8.8",    443);

    // Target in the current thread
    vector<double> samples_v;
    measure_rtt_series(target_ip, target_port, 2000, samples, samples_v);
    r.samples = (int)samples_v.size();
    if (r.samples < 3) {
        r.ok = false;
        r.summary = "insufficient samples (<3 successful TCP handshakes)";
        r.cf_median_ms     = f_cf.get();
        r.google_median_ms = f_goog.get();
        r.yandex_median_ms = f_yan.get();
        return r;
    }
    // Drop 1 top outlier to smooth occasional OS scheduling blips.
    std::sort(samples_v.begin(), samples_v.end());
    if ((int)samples_v.size() >= 5) samples_v.pop_back();
    double sum = 0.0;
    r.min_ms = samples_v.front();
    r.max_ms = samples_v.back();
    for (auto v: samples_v) sum += v;
    double mean = sum / samples_v.size();
    double var  = 0;
    for (auto v: samples_v) var += (v - mean) * (v - mean);
    var /= samples_v.size();
    r.stddev_ms = std::sqrt(var);
    r.median_ms = percentile(samples_v, 0.5);

    r.cf_median_ms     = f_cf.get();
    r.google_median_ms = f_goog.get();
    r.yandex_median_ms = f_yan.get();

    // Classify
    double emin = country_min_rtt_ms(country_code);
    double emax = country_max_rtt_ms(country_code);
    r.expected_min_ms = emin;
    if (emin > 0) {
        if (r.median_ms < emin * 0.5) r.too_low  = true;
        if (r.median_ms > emax * 3.0) r.too_high = true;
    }
    if (r.stddev_ms > 40.0) r.high_jitter = true;

    // Anchor-ratio check: the closest anchor RTT tells us how far the
    // observer is from major internet backbones. target_RTT / closest_anchor
    // should be small (1-3x) for same-continent targets, larger (3-6x) for
    // cross-continent. Wildly off = proxy.
    double closest = std::min({
        r.cf_median_ms > 0 ? r.cf_median_ms : 9e9,
        r.google_median_ms > 0 ? r.google_median_ms : 9e9,
        r.yandex_median_ms > 0 ? r.yandex_median_ms : 9e9
    });
    if (closest > 0 && closest < 9e9 && r.median_ms > 0) {
        double ratio = r.median_ms / closest;
        // If the target is supposedly in a far country but RTT is similar
        // to our anchors — it's proxied. Or: target's country is near us
        // (low emax) but RTT is far higher than anchors — extra hops.
        if (emax > 0 && emax < 80.0 && ratio > 4.0) r.anchor_ratio_off = true;
        // Same-continent target but RTT < 80% of anchor = anycast proxy
        // serving this IP near the observer (e.g. Cloudflare fronting).
        if (emin > 0 && emin > 60.0 && r.median_ms < closest * 0.8) r.anchor_ratio_off = true;
    }
    r.ok = true;
    // Short summary
    {
        char buf[256];
        if (r.too_low)
            snprintf(buf, sizeof(buf),
                     "median %.1fms but %s geo implies >=%.0fms — impossibly low (GeoIP lies OR anycast proxy)",
                     r.median_ms, country_code.c_str(), emin);
        else if (r.too_high)
            snprintf(buf, sizeof(buf),
                     "median %.1fms is >3x the normal %.0fms band for %s — extra hops in path (tunnel / long middlebox chain)",
                     r.median_ms, emax, country_code.c_str());
        else if (r.high_jitter)
            snprintf(buf, sizeof(buf),
                     "stddev %.1fms over %d samples — high jitter typical of tunnel queue/encryption overhead",
                     r.stddev_ms, r.samples);
        else if (r.anchor_ratio_off)
            snprintf(buf, sizeof(buf),
                     "target RTT doesn't match closest anchor ratio — location doesn't add up");
        else
            snprintf(buf, sizeof(buf),
                     "RTT %.1fms (min %.1f, stddev %.1f) — consistent with %s geolocation",
                     r.median_ms, r.min_ms, r.stddev_ms, country_code.c_str());
        r.summary = buf;
    }
    return r;
}

// ============================================================================
// v2.4 — Certificate Transparency check (crt.sh)
// ----------------------------------------------------------------------------
// Legit public CAs are required to submit issued certs to CT logs. Any cert
// you'd see on a real public website will have CT entries. A cert that does
// NOT appear in CT logs is:
//   * Self-signed (private CA, never submitted)
//   * Internal test-CA issuance
//   * Very recently issued (<1h, log propagation delay)
//   * LE staging (intentionally not logged)
//   * Cloned / re-forged from a real cert (so the SHA-256 changed) —
//     classic Xray dest= behavior when someone hand-copies a cert chain.
//
// We query crt.sh?q=<sha256>&output=json. If JSON array is non-empty, the
// cert IS in the CT log. If empty → we flag CT-absence as a signal.
// This is a soft check: the cert may be fresh, so we only escalate when
// combined with other red flags (fresh + no-CT + hosting ASN = Reality).
// ============================================================================
struct CtCheck {
    bool   queried     = false;
    bool   found       = false;
    int    log_entries = 0;
    string err;
};

static CtCheck ct_check(const string& cert_sha256) {
    CtCheck r;
    if (cert_sha256.size() < 32) { r.err = "no sha256"; return r; }
    r.queried = true;
    // crt.sh accepts "?q=<sha256>" — lower-case hex without colons.
    // JSON output: [] if empty, else [{"id":...},{"id":...},...]
    string url = "https://crt.sh/?q=" + cert_sha256 + "&output=json";
    auto h = http_get(url, 5000);
    if (!h.ok()) { r.err = "http " + std::to_string(h.status); return r; }
    // crt.sh returns `[]` if nothing found, else a JSON array of cert
    // entries. Count by matching "id" keys as a lower bound.
    if (h.body.size() >= 2) {
        string b = trim(h.body);
        if (b.size() >= 2 && b[0] == '[' && b[1] == ']') {
            r.found = false;
            r.log_entries = 0;
        } else {
            r.found = true;
            int cnt = 0;
            size_t p = 0;
            while ((p = h.body.find("\"id\"", p)) != string::npos) {
                ++cnt; ++p; if (cnt > 50) break;
            }
            r.log_entries = cnt;
        }
    }
    return r;
}

// ============================================================================
// v2.4 — Traceroute (hop count) via IcmpSendEcho2, no admin required.
// ----------------------------------------------------------------------------
// Extra hops between observer and target versus the expected path length
// are a classical VPN / overlay-tunnel indicator. A residential-to-DC path
// is typically 7-12 hops. If our trace to the target returns 16+ hops to
// a supposedly-European DC, or if the final hop's latency jumps strangely
// ("200ms until hop 10, then 260ms to target"), something is in the way.
//
// This is subtle — TSPU doesn't directly run traceroutes, but it does
// correlate RTT jumps across anycast measurement points, which is close
// enough. We flag only suspicious profiles (hop count > 20, or ≥2 hop
// RTT steps > 80ms each).
// ============================================================================
struct TraceHop {
    int   ttl = 0;
    string addr;       // IPv4 string
    int   rtt_ms = 0;  // -1 on no-reply
};
struct TraceResult {
    bool  ok = false;
    int   hop_count = 0;          // number of replies (incl. target)
    bool  reached_target = false; // last hop == target
    int   max_rtt_jump_ms = 0;    // biggest RTT delta between consecutive hops
    int   long_hops = 0;          // hops with RTT > 150ms
    int   tspu_hops  = 0;         // private hops matching tspu mgmt-subnet layout
    vector<TraceHop> hops;
};

static TraceResult trace_hops(const string& target_ip, int max_hops = 18) {
    TraceResult r;
    // Resolve once — only IPv4 (ICMP4).
    struct in_addr dst{}; dst.s_addr = 0;
    struct addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* ai = nullptr;
    if (getaddrinfo(target_ip.c_str(), nullptr, &hints, &ai) != 0 || !ai) return r;
    for (auto* p = ai; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            dst = ((sockaddr_in*)p->ai_addr)->sin_addr;
            break;
        }
    }
    freeaddrinfo(ai);
    if (dst.s_addr == 0) return r;

    HANDLE h = IcmpCreateFile();
    if (h == INVALID_HANDLE_VALUE) return r;

    // Standard Windows ping payload (32 bytes, identical to what ping.exe sends)
    // — no tool-specific string, identical to what any Windows user would emit.
    const char payload[] = "abcdefghijklmnopqrstuvwabcdefghi";
    const DWORD rcvsz = sizeof(ICMP_ECHO_REPLY) + sizeof(payload) + 8 + 128;
    vector<unsigned char> rcv(rcvsz);

    int prev_rtt = 0;
    for (int ttl = 1; ttl <= max_hops; ++ttl) {
        IP_OPTION_INFORMATION opt{};
        opt.Ttl = (unsigned char)ttl;
        opt.Tos = 0;
        opt.Flags = 0;
        opt.OptionsSize = 0;
        opt.OptionsData = nullptr;
        DWORD n = IcmpSendEcho2(h, nullptr, nullptr, nullptr, dst.s_addr,
                                (LPVOID)payload, sizeof(payload),
                                &opt, rcv.data(), (DWORD)rcv.size(), 1500);
        TraceHop hop; hop.ttl = ttl;
        if (n > 0) {
            auto* rep = (ICMP_ECHO_REPLY*)rcv.data();
            struct in_addr a{}; a.s_addr = rep->Address;
            char buf[INET_ADDRSTRLEN] = {0};
            InetNtopA(AF_INET, &a, buf, sizeof(buf));
            hop.addr = buf;
            hop.rtt_ms = (int)rep->RoundTripTime;
            if (prev_rtt > 0) {
                int delta = hop.rtt_ms - prev_rtt;
                if (delta > r.max_rtt_jump_ms) r.max_rtt_jump_ms = delta;
            }
            if (hop.rtt_ms > 150) ++r.long_hops;
            prev_rtt = hop.rtt_ms;
            r.hops.push_back(hop);
            // Reached target?
            if (rep->Status == IP_SUCCESS && rep->Address == dst.s_addr) {
                r.reached_target = true;
                break;
            }
        } else {
            hop.rtt_ms = -1;
            r.hops.push_back(hop);
        }
    }
    IcmpCloseHandle(h);
    r.hop_count = 0;
    for (auto& hop: r.hops) if (hop.rtt_ms >= 0) ++r.hop_count;
    // count hops matching tspu mgmt-subnet layout
    for (auto& hop: r.hops) {
        if (hop.rtt_ms >= 0 && looks_like_tspu_hop(hop.addr)) ++r.tspu_hops;
    }
    r.ok = (r.hop_count > 0);
    return r;
}

// ============================================================================
// v2.4 — Additional 2026 VPN protocol probes
//   Hysteria2, TUIC v5, L2TP, AmneziaWG, SSTP.
// ----------------------------------------------------------------------------
// These are the modern obfuscated tunnels that v2.3 didn't probe.  Each
// has a distinct on-the-wire signature TSPU actively checks for.
// ============================================================================

// Hysteria 2 uses QUIC-Initial packets with a custom "salamander" obfuscator.
// A vanilla QUIC initial sent to a Hysteria2 server may get either silence
// (rejected as unknown session) or an encrypted/obfuscated reply.
// Returns generic UdpResult — caller interprets in context of QUIC probe
// already done. Real detection: UDP :443 responds AND dedicated Hysteria2
// ports :36712, :50000 also have servers.
static UdpResult hysteria2_probe(const string& host, int port) {
    // Hysteria2 handshake is a QUIC Initial with obfuscated salt. Send a
    // well-formed QUIC v1 Initial with custom DCID — if the server is
    // Hysteria2, it'll drop (obfuscated DCID doesn't match salt) and we
    // get no reply. If it's vanilla QUIC (HTTP/3) we get version-neg.
    // The *difference* between hysteria and vanilla on :36712 is the
    // diagnostic. We just send the vanilla payload here and caller
    // compares with QUIC-on-:443 to distinguish.
    unsigned char pkt[] = {
        0xc0, 0x00,0x00,0x00,0x01, 0x08,
        0,0,0,0,0,0,0,0,             // DCID (filled by RAND_bytes below)
        0x00, 0x00, 0x44,0x40
    };
    RAND_bytes(pkt + 6, 8);          // random 8-byte DCID
    vector<unsigned char> full(1200, 0x00);
    memcpy(full.data(), pkt, sizeof(pkt));
    return udp_probe(host, port, full.data(), (int)full.size(), 1500);
}

// TUIC v5 uses QUIC as transport; auth is token-based. Without the token
// we can't complete handshake, but we can verify a TUIC listener exists:
// vanilla QUIC Initial elicits QUIC version-neg from standard HTTP/3, but
// TUIC servers typically reply with an encrypted packet (they accept any
// QUIC-compliant Initial as a transport handshake start).
// Port map: TUIC defaults to :443, but common alt ports are :8443, :11223.
static UdpResult tuic_probe(const string& host, int port) {
    // Same underlying QUIC probe — difference is in interpretation,
    // which the verdict engine handles.
    return quic_probe(host, port);
}

// L2TP control connection starts with SCCRQ (Start-Control-Connection-Req):
// the L2TP control message header: 0xC8 0x02 ... + TLV AVPs.
// A real L2TP server replies with SCCRP.
static UdpResult l2tp_probe(const string& host, int port) {
    // Minimal SCCRQ with mandatory AVPs: Message Type, Protocol Version,
    // Framing/Bearer Caps, Host Name, Assigned Tunnel ID.
    // Host Name AVP contains a generic 3-char value — a real L2TP server
    // doesn't use this for routing, it's just a required field.
    // Tunnel ID is randomized per-probe: a constant "1" is a tool
    // fingerprint, real clients allocate tunnel IDs pseudo-randomly.
    unsigned char pkt[] = {
        0xC8,0x02,       // flags (T/L/S/O/P/Ver=2)
        0x00,0x2D,       // length = 45
        0x00,0x00,       // tunnel id = 0
        0x00,0x00,       // session id = 0
        0x00,0x00,       // Ns
        0x00,0x00,       // Nr
        // AVP 1: Message Type = SCCRQ (1)
        0x80,0x08, 0x00,0x00, 0x00,0x00, 0x00,0x01,
        // AVP 2: Protocol Version = 1.0
        0x80,0x08, 0x00,0x00, 0x00,0x02, 0x01,0x00,
        // AVP 3: Framing Capabilities (Sync+Async)
        0x80,0x0A, 0x00,0x00, 0x00,0x03, 0x00,0x00,0x00,0x03,
        // AVP 4: Host Name = "lac" (generic L2TP Access Concentrator)
        0x80,0x0B, 0x00,0x00, 0x00,0x07, 'l','a','c',
        // AVP 5: Assigned Tunnel ID = random (filled below)
        0x80,0x08, 0x00,0x00, 0x00,0x09, 0,0
    };
    // Randomize assigned tunnel id (last 2 bytes of last AVP).
    // Keep it in [1, 0xFFFF] to stay a valid tunnel id.
    unsigned char tid[2];
    do { RAND_bytes(tid, 2); } while (tid[0] == 0 && tid[1] == 0);
    pkt[sizeof(pkt)-2] = tid[0];
    pkt[sizeof(pkt)-1] = tid[1];
    return udp_probe(host, port, pkt, sizeof(pkt), 1500);
}

// AmneziaWG is WG with 4 obfuscation parameters (Jc/Jmin/Jmax/Sx):
// initial junk packets, trailing junk, and random header offsets.
// A vanilla WG handshake sent to AmneziaWG is usually DROPPED because
// the magic header (0x01 type byte) is offset by Sx (commonly 5-15).
// Conversely, if we send a WG init and get no reply on 51820 — it's
// EITHER vanilla-WG-not-here OR AmneziaWG active (header mismatch).
// We distinguish by trying (a) normal WG init on 51820 and (b) a WG
// init with 8 zero-byte prefix (Sx=8 default) — if (b) gets a reply
// but (a) doesn't, it's AmneziaWG.
static UdpResult amneziawg_probe(const string& host, int port) {
    // WG init with 8-byte random prefix (Sx=8)
    unsigned char pkt[148 + 8] = {0};
    RAND_bytes(pkt, 8);              // junk prefix
    pkt[8] = 0x01;                   // WG handshake initiation
    RAND_bytes(pkt + 12, 140);       // rest of WG init
    return udp_probe(host, port, pkt, sizeof(pkt), 1500);
}

// SSTP (Microsoft Secure Socket Tunneling Protocol) runs over HTTPS on
// TCP/443. The handshake is an HTTP/1.1 request with the magic URI
// /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ and SSTP_DUPLEX_POST method.
// A real SSTP server replies with HTTP/1.1 200 OK and Content-Length: 18446744073709551615.
static FpResult sstp_probe(const string& host, int port) {
    FpResult f; f.service = "SSTP?";
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    // Wrap in TLS first
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)s);
    SSL_set_tlsext_host_name(ssl, host.c_str());
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
        f.details = "TLS handshake failed (not HTTPS)"; f.silent = true; return f;
    }
    string req =
        "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "Content-Length: 18446744073709551615\r\n"
        "SSTPCORRELATIONID: {00000000-0000-0000-0000-000000000000}\r\n"
        "\r\n";
    SSL_write(ssl, req.data(), (int)req.size());
    char buf[1024];
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
    if (n <= 0) { f.details = "TLS ok but SSTP request got no reply"; return f; }
    buf[n] = 0;
    string body(buf, n);
    if (body.find("HTTP/1.1 200") != string::npos &&
        body.find("18446744073709551615") != string::npos) {
        f.service = "SSTP";
        f.details = "Microsoft SSTP VPN endpoint (Content-Length: 2^64-1 match)";
        f.is_vpn_like = true;
    } else if (body.find("SSTP") != string::npos) {
        f.service = "SSTP";
        f.details = "SSTP-aware server: " + printable_prefix(body.substr(0, body.find('\n')), 80);
        f.is_vpn_like = true;
    } else {
        // HTTPS responded to a bogus method — that's normal for nginx (400)
        // or IIS (501). Not SSTP.
        size_t nl = body.find('\n');
        f.details = "not SSTP: " + printable_prefix(body.substr(0, nl), 80);
    }
    return f;
}

// ============================================================================
// v2.4 — JA3-variance probe (detect Reality uTLS enforcement)
// ----------------------------------------------------------------------------
// Reality in "xtls-rprx-vision" mode verifies the client JA3 fingerprint
// matches uTLS-Chrome. A plain OpenSSL ClientHello has a very distinctive
// JA3 (cipher list order, extensions, curve prefs) that differs from
// Chrome's. If Reality is uTLS-enforcing, a Chrome-JA3 handshake will
// complete AND the OpenSSL-JA3 handshake will also complete (Reality
// fallbacks catch it). But the BEHAVIOR post-handshake differs: Chrome-JA3
// gets the Reality-tunnelled dest, OpenSSL-JA3 gets the fallback page.
//
// We can't easily send a byte-accurate uTLS-Chrome ClientHello from OpenSSL
// (our CH IS the OpenSSL fingerprint by construction), so this probe is
// limited to:
//   (a) Measure what WE send
//   (b) Cross-check what different OpenSSL cipher-list settings yield
//   (c) Detect post-handshake cert variance based on SNI steering
// The J3 module already covers most of this. For now this function just
// logs our own JA3 fingerprint so the verdict can note: "we sent JA3=X,
// Chrome-real sends Y — if endpoint is Reality uTLS-enforcing, they'd
// diverge".
// ============================================================================
struct Ja3Info {
    string version;    // TLS version we sent
    string ciphers;    // cipher list (hex, no seps)
    string extensions; // extension list
    string groups;     // supported_groups
    string ec_formats; // EC point formats
    string ja3_hash;   // MD5 of comma-joined fields (classic JA3)
};

// We can't compute our actual sent JA3 without a raw packet capture, but
// we can note the standard OpenSSL default JA3 which is well-known:
//   771,4865-4866-4867-49195-49199-...,0-23-65281-...,29-23-30-25,0-1-2
// Real 2026 OpenSSL default JA3 hash: a fixed value that Reality
// servers can fingerprint and reject. This struct documents what we sent
// so the verdict can include the advisory "endpoint accepted OpenSSL
// default JA3 — if it were uTLS-enforcing Reality, it would have rejected
// us at the handshake".
static Ja3Info our_openssl_ja3_signature() {
    Ja3Info j;
    // These strings document OpenSSL 3.x default TLS1.3 CH — stable
    // enough to mention in the verdict.
    j.version    = "771";  // TLS 1.2 record version (TLS 1.3 still carries this)
    j.ciphers    = "4865,4866,4867,49195,49199,49196,49200,52393,52392,49171,49172,156,157,47,53";
    j.extensions = "0,11,10,35,22,23,13,43,45,51";
    j.groups     = "29,23,30,25,24";
    j.ec_formats = "0";
    // Well-known OpenSSL 3.x default JA3 hash (approximate; exact varies by build):
    j.ja3_hash   = "0cce74b0d9b7f8528fb2181588d23793";
    return j;
}

// ============================================================================
// Verdict engine
// ============================================================================
struct Advice {
    string  kind;    // "risk" or "good" or "note"
    string  text;
};

struct FullReport {
    string target;
    Resolved dns;
    vector<GeoInfo> geos;
    vector<TcpOpen> open_tcp;
    vector<std::pair<int,UdpResult>> udp_probes;
    // fingerprints
    struct PortFp {
        int port;
        FpResult fp;
        optional<TlsProbe>        tls;
        optional<SniConsistency>  sni;
        vector<J3Result>          j3;
        optional<J3Analysis>      j3a;   // v2.3 — J3 response analysis
        optional<HttpsProbe>      https; // v2.3 — active HTTP-over-TLS probe
        optional<CtCheck>         ct;    // v2.4 — crt.sh lookup result
    };
    vector<PortFp> fps;
    UdpResult quic;
    // v2.4 — new phases
    optional<SnitchResult>             snitch;
    optional<TraceResult>              trace;
    vector<std::pair<int,UdpResult>>   udp_extra;   // Hysteria2/TUIC/L2TP/AmneziaWG
    optional<FpResult>                 sstp;        // SSTP on :443 (TLS-wrapped)
    // v2.5.5 — scan-phase stats + blackhole detector
    ScanStats scan_stats;
    bool      bgp_blackhole_likely = false;
    // verdict
    int    score = 0;
    string label;
    vector<Advice> advices;
    vector<string> guess_stack;  // "Xray/Reality", "OpenVPN", ...
};

// ============================================================================
// Target pretty print
// ============================================================================
static void print_banner_scan(const string& t) {
    printf("%s%s== Target: %s ==%s\n", col(C::BOLD), col(C::WHT), t.c_str(), col(C::RST));
}

static void print_geo(const GeoInfo& g) {
    if (!g.err.empty()) {
        printf("  %s%-12s%s %serr: %s%s\n",
               col(C::CYN), g.source.c_str(), col(C::RST),
               col(C::RED), g.err.c_str(), col(C::RST));
        return;
    }
    printf("  %s%-12s%s IP %s%-15s%s  %s%s%s  (%s) AS %s %s\n",
           col(C::CYN), g.source.c_str(), col(C::RST),
           col(C::WHT), g.ip.c_str(), col(C::RST),
           col(C::BOLD), g.country_code.empty() ? g.country.c_str() : g.country_code.c_str(), col(C::RST),
           g.city.c_str(), g.asn.c_str(), g.asn_org.c_str());
    string flags;
    auto add = [&](bool v, const char* n, const char* c){
        if (v) { if(!flags.empty()) flags += " "; flags += col(c); flags += n; flags += col(C::RST); }
    };
    add(g.is_hosting, "HOSTING", C::YEL);
    add(g.is_vpn,     "VPN",     C::RED);
    add(g.is_proxy,   "PROXY",   C::RED);
    add(g.is_tor,     "TOR",     C::RED);
    add(g.is_abuser,  "ABUSER",  C::RED);
    if (!flags.empty()) printf("               flags: %s\n", flags.c_str());
}

// ============================================================================
// Orchestrator
// ============================================================================
static FullReport run_full_target(const string& target) {
    FullReport R; R.target = target;

    // 1) resolve
    printf("\n%s[1/8] DNS resolve%s\n", col(C::BOLD), col(C::RST));
    R.dns = resolve_host(target);
    if (!R.dns.err.empty()) {
        printf("  %sERR%s: %s\n", col(C::RED), col(C::RST), R.dns.err.c_str());
        return R;
    }
    printf("  %s%s%s  ->  ", col(C::WHT), target.c_str(), col(C::RST));
    for (auto& ip: R.dns.ips) printf("%s ", ip.c_str());
    printf(" [%s, %lldms]\n", R.dns.family.c_str(), R.dns.ms);
    // v2.4 — explicitly show which IP is used for ALL subsequent probes.
    // If target != primary_ip, user knows we resolved the hostname to an
    // IPv4 address and the whole scan is running against that IP.
    if (R.dns.primary_ip != target) {
        printf("  %susing primary IP%s %s%s%s  for all probes%s\n",
               col(C::DIM), col(C::RST),
               col(C::BOLD), R.dns.primary_ip.c_str(), col(C::RST),
               col(C::RST));
    }

    // 2) GeoIP — 3 EU + 3 RU + 3 global providers, all in parallel.
    //    Diversity matters: EU and RU providers often disagree on hosting/
    //    VPN flags and the disagreement itself is diagnostic.
    //    --stealth / --no-geoip skips this phase entirely: every 3rd-party
    //    lookup leaks the target IP to the service. If you're scanning
    //    your own VPS and don't want those log lines to exist, skip it.
    if (g_no_geoip) {
        printf("\n%s[2/8] GeoIP%s  SKIPPED (--no-geoip / --stealth)\n",
               col(C::BOLD), col(C::RST));
    } else {
    printf("\n%s[2/8] GeoIP%s  (9 providers in parallel: 3 EU / 3 RU / 3 global)\n",
           col(C::BOLD), col(C::RST));
    auto fg_eu1 = std::async(std::launch::async, geo_ipapi_is,   R.dns.primary_ip); // EU (Latvia)
    auto fg_eu2 = std::async(std::launch::async, geo_iplocate,   R.dns.primary_ip); // EU (NL)
    auto fg_eu3 = std::async(std::launch::async, geo_freeipapi,  R.dns.primary_ip); // EU
    auto fg_ru1 = std::async(std::launch::async, geo_2ip_ru,     R.dns.primary_ip); // RU
    auto fg_ru2 = std::async(std::launch::async, geo_ipapi_ru,   R.dns.primary_ip); // RU (ip-api.com/ru)
    auto fg_ru3 = std::async(std::launch::async, geo_sypex,      R.dns.primary_ip); // RU (sypexgeo)
    auto fg_gl1 = std::async(std::launch::async, geo_ip_api_com, R.dns.primary_ip); // global
    auto fg_gl2 = std::async(std::launch::async, geo_ipwho_is,   R.dns.primary_ip); // global
    auto fg_gl3 = std::async(std::launch::async, geo_ipinfo_io,  R.dns.primary_ip); // global
    R.geos.push_back(fg_eu1.get()); R.geos.push_back(fg_eu2.get()); R.geos.push_back(fg_eu3.get());
    R.geos.push_back(fg_ru1.get()); R.geos.push_back(fg_ru2.get()); R.geos.push_back(fg_ru3.get());
    R.geos.push_back(fg_gl1.get()); R.geos.push_back(fg_gl2.get()); R.geos.push_back(fg_gl3.get());
    for (auto& g: R.geos) print_geo(g);
    }

    // 3) TCP scan
    auto _ports = build_tcp_ports();
    const char* _mode_name =
        g_port_mode==PortMode::FULL  ? "FULL 1-65535" :
        g_port_mode==PortMode::FAST  ? "FAST (205 curated)" :
        g_port_mode==PortMode::RANGE ? "RANGE" : "LIST";
    printf("\n%s[3/8] TCP port scan%s  mode=%s%s%s  (%zu ports, %d threads, %dms timeout)\n",
           col(C::BOLD), col(C::RST),
           col(C::CYN), _mode_name, col(C::RST),
           _ports.size(), g_threads, g_tcp_to);
    R.open_tcp = scan_tcp(R.dns.primary_ip, _ports, g_threads, g_tcp_to, &R.scan_stats);
    // bgp-blackhole heuristic: tspu type B filters drop packets at L3 via
    // bgp-pushed ip-lists. visible as "all ports timeout, zero RST". a normal
    // firewalled host either sends RST on closed ports or at least some RST'ed
    // ports. need >=1000 ports scanned to avoid false-positive on short ranges.
    // ref: tspu-docs ch. 7.3.2
    if (!R.scan_stats.skipped && R.scan_stats.scanned >= 1000 && R.open_tcp.empty()) {
        size_t tmo = R.scan_stats.timeouts;
        size_t rst = R.scan_stats.refused;
        if (rst == 0 && tmo >= R.scan_stats.scanned * 99 / 100) {
            R.bgp_blackhole_likely = true;
        }
    }
    // bogus-open detection: WARP/CGNAT/proxy often ACK every port with same latency
    bool warp_like = false;
    if (R.open_tcp.size() > 60) {
        // sample variance of connect_ms
        long long mn = LLONG_MAX, mx = 0;
        for (auto& o: R.open_tcp) { mn = std::min(mn, o.connect_ms); mx = std::max(mx, o.connect_ms); }
        if (mx - mn < 80) warp_like = true;
    }
    if (warp_like) {
        printf("  %s!! %zu ports reported open with near-identical RTT — looks like Cloudflare WARP / a local proxy / CGNAT middlebox that accept-hooks every TCP SYN. Disable WARP/proxy and re-run; otherwise results are fake%s\n",
               col(C::RED), R.open_tcp.size(), col(C::RST));
    }
    if (R.open_tcp.empty()) {
        printf("  %sno open TCP ports found%s\n", col(C::YEL), col(C::RST));
        if (R.bgp_blackhole_likely) {
            printf("  %s!! %zu/%zu ports TIMEOUT with 0 RST - looks like L3 blackhole "
                   "(tspu type B / BGP-pushed IP-list, not a regular dead host)%s\n",
                   col(C::RED), R.scan_stats.timeouts, R.scan_stats.scanned, col(C::RST));
        } else if (R.scan_stats.scanned >= 100) {
            printf("  %s  (breakdown: %zu timeout, %zu refused, %zu other)%s\n",
                   col(C::DIM), R.scan_stats.timeouts, R.scan_stats.refused,
                   R.scan_stats.other, col(C::RST));
        }
    } else {
        for (auto& o: R.open_tcp) {
            const char* hint = port_hint(o.port);
            printf("  %s:%-5d%s  %3lldms  %s%s%s",
                   col(C::GRN), o.port, col(C::RST),
                   o.connect_ms,
                   col(C::DIM), hint[0]?hint:"-", col(C::RST));
            if (!o.banner.empty()) {
                printf("  %sbanner:%s %s",
                       col(C::CYN), col(C::RST),
                       printable_prefix(o.banner, 60).c_str());
            }
            printf("\n");
        }
    }

    // 4) UDP probes
    printf("\n%s[4/8] UDP probes%s\n", col(C::BOLD), col(C::RST));
    auto udp_show = [&](int port, const char* name, UdpResult u){
        const char* c = u.responded ? col(C::GRN) : col(C::DIM);
        printf("  %sUDP:%-5d%s  %-18s  ",
               c, port, col(C::RST), name);
        if (u.responded) printf("%sRESP %dB%s  %s", col(C::GRN), u.bytes, col(C::RST), u.reply_hex.c_str());
        else             printf("%sno answer (%s)%s", col(C::DIM), u.err.empty()?"closed/filtered":u.err.c_str(), col(C::RST));
        printf("\n");
        R.udp_probes.push_back({port, u});
    };
    udp_show(53,    "DNS query",         dns_probe(R.dns.primary_ip, 53));
    udp_show(500,   "IKEv2 SA_INIT",     ike_probe(R.dns.primary_ip, 500));
    udp_show(4500,  "IKEv2 NAT-T",       ike_probe(R.dns.primary_ip, 4500));
    udp_show(1194,  "OpenVPN HARD_RESET",openvpn_probe(R.dns.primary_ip, 1194));
    udp_show(443,   "QUIC v1 Initial",   quic_probe(R.dns.primary_ip, 443));
    R.quic = R.udp_probes.back().second;
    udp_show(51820, "WireGuard handshake", wireguard_probe(R.dns.primary_ip, 51820));
    udp_show(41641, "Tailscale handshake", wireguard_probe(R.dns.primary_ip, 41641));
    // v2.4 — 2026 extra-probes: Hysteria2, TUIC, L2TP, AmneziaWG. These get
    // recorded separately so the verdict engine can tell them apart from
    // the classic VPN probes.
    auto udp_extra = [&](int port, const char* name, UdpResult u){
        const char* c = u.responded ? col(C::GRN) : col(C::DIM);
        printf("  %sUDP:%-5d%s  %-18s  ",
               c, port, col(C::RST), name);
        if (u.responded) printf("%sRESP %dB%s  %s", col(C::GRN), u.bytes, col(C::RST), u.reply_hex.c_str());
        else             printf("%sno answer (%s)%s", col(C::DIM), u.err.empty()?"closed/filtered":u.err.c_str(), col(C::RST));
        printf("\n");
        R.udp_extra.push_back({port, u});
    };
    udp_extra(1701,  "L2TP SCCRQ",         l2tp_probe(R.dns.primary_ip, 1701));
    udp_extra(36712, "Hysteria2 QUIC",     hysteria2_probe(R.dns.primary_ip, 36712));
    udp_extra(8443,  "TUIC v5",            tuic_probe(R.dns.primary_ip, 8443));
    udp_extra(55555, "AmneziaWG Sx=8",     amneziawg_probe(R.dns.primary_ip, 55555));
    udp_extra(51820, "AmneziaWG Sx=8",     amneziawg_probe(R.dns.primary_ip, 51820));

    // 5) Fingerprint per open TCP port
    printf("\n%s[5/8] Service fingerprints per open port%s\n", col(C::BOLD), col(C::RST));
    auto is_tls_port = [](int p){
        return p==443||p==4433||p==4443||p==8443||p==8080||p==8843||p==8444
             ||p==9443||p==10443||p==14443||p==20443||p==21443||p==22443||p==50443||p==51443||p==55443
             ||p==2083||p==2087||p==2096||p==6443||p==7443||p==853;
    };
    for (auto& o: R.open_tcp) {
        FullReport::PortFp pf; pf.port = o.port;
        bool printed = false;
        auto line = [&](const FpResult& f){
            printed = true;
            printf("  %s:%-5d%s  %s%-16s%s  %s",
                   col(C::CYN), o.port, col(C::RST),
                   col(C::BOLD), f.service.c_str(), col(C::RST),
                   f.details.c_str());
            if (f.is_vpn_like) printf("  %s[vpn-like]%s", col(C::YEL), col(C::RST));
            printf("\n");
            pf.fp = f;
        };
        // SSH banner (22/2222/22222)
        if (starts_with(o.banner, "SSH-") || o.port==22 || o.port==2222 || o.port==22222) {
            line(fp_ssh(o.banner, R.dns.primary_ip, o.port));
        }
        // TLS ports
        if (is_tls_port(o.port)) {
            TlsProbe tp = tls_probe(R.dns.primary_ip, o.port, R.dns.host);
            if (tp.ok) {
                FpResult f; f.service = "TLS";
                char agebuf[96] = {0};
                snprintf(agebuf, sizeof(agebuf), "age=%dd left=%dd",
                         tp.age_days, tp.days_left);
                f.details = tp.version + " / " + tp.cipher + " / ALPN=" +
                            (tp.alpn.empty()?"-":tp.alpn) + " / " + tp.group +
                            " / " + std::to_string(tp.handshake_ms) + "ms" +
                            "\n                       cert CN=" +
                            (tp.subject_cn.empty() ? "(none)" : tp.subject_cn) +
                            "  issuer=" + (tp.issuer_cn.empty() ? "(none)" : tp.issuer_cn) +
                            "  " + agebuf +
                            "  SAN=" + std::to_string(tp.san_count) +
                            (tp.is_wildcard  ? " wildcard" : "") +
                            (tp.self_signed  ? " self-signed" : "") +
                            (tp.is_letsencrypt ? " [free-CA]" : "");
                line(f);
                pf.tls = tp;
                // SNI consistency
                SniConsistency sc = sni_consistency(R.dns.primary_ip, o.port, R.dns.host);
                pf.sni = sc;
                if (sc.reality_like && sc.passthrough_mode) {
                    printf("        %sSNI behaviour: cert varies per SNI BUT base cert is for brand '%s' — Reality with real passthrough to dest= (stealth-optimised)%s\n",
                           col(C::RED), sc.matched_foreign_sni.c_str(), col(C::RST));
                } else if (sc.reality_like) {
                    printf("        %sSNI steering: same cert returned for ALL foreign SNIs, and cert is valid for '%s' -> Reality/XTLS pattern%s\n",
                           col(C::GRN), sc.matched_foreign_sni.c_str(), col(C::RST));
                } else if (sc.default_cert_only) {
                    printf("        %sSNI behaviour: single default cert returned regardless of SNI (plain server, not Reality)%s\n",
                           col(C::CYN), col(C::RST));
                } else if (sc.same_cert_always) {
                    printf("        %sSNI behaviour: identical cert across SNIs, but cert does not cover any foreign SNI (inconclusive)%s\n",
                           col(C::YEL), col(C::RST));
                } else {
                    printf("        %sSNI behaviour: cert varies per SNI (normal multi-tenant TLS, not Reality)%s\n",
                           col(C::YEL), col(C::RST));
                }
                if (!sc.base_sha.empty()) {
                    printf("        cert-sha256: %s%.16s...%s  issuer: %s\n",
                           col(C::DIM), sc.base_sha.c_str(), col(C::RST),
                           printable_prefix(tp.cert_issuer, 60).c_str());
                    // v2.4 — crt.sh CT lookup. A real public cert is
                    // ALWAYS in CT logs (RFC 9162, enforced by Chrome/
                    // Firefox). Absence = cert never went through a public
                    // CA = private issuance / clone / LE-staging.
                    // v2.5.2 — --no-ct / --stealth skips this lookup: each
                    // query sends the target cert SHA256 to crt.sh, which
                    // then logs "source IP X asked about cert Y at T".
                    if (g_no_ct) {
                        printf("        %sCT-log (crt.sh): SKIPPED (--no-ct / --stealth)%s\n",
                               col(C::DIM), col(C::RST));
                    } else {
                    CtCheck ct = ct_check(sc.base_sha);
                    pf.ct = ct;
                    if (ct.queried && !ct.err.empty()) {
                        printf("        %sCT-log (crt.sh): query failed — %s%s\n",
                               col(C::DIM), ct.err.c_str(), col(C::RST));
                    } else if (ct.queried && ct.found) {
                        printf("        %sCT-log (crt.sh): cert IS in public CT logs (%d entries) — normal legit cert%s\n",
                               col(C::GRN), ct.log_entries, col(C::RST));
                    } else if (ct.queried && !ct.found) {
                        printf("        %sCT-log (crt.sh): cert NOT found in public CT logs — self-signed / private-CA / LE-staging / forged cert%s\n",
                               col(C::RED), col(C::RST));
                    }
                    }  // end else for g_no_ct
                }
                // v2.3 — active HTTP-over-TLS probe: what does the origin
                // actually emit as an HTTP reply? Real nginx → 'HTTP/1.1 200
                // ...\r\nServer: nginx'. Xray fallback → 'HTTP/0.0 307 ...'
                // or empty. Trojan → TLS handshake ok but HTTP returns
                // nothing or the dest='s real page (detectable).
                HttpsProbe hp = https_probe(R.dns.primary_ip, o.port, R.dns.host);
                pf.https = hp;
                if (hp.tls_ok) {
                    if (hp.responded) {
                        printf("        %sHTTP-over-TLS:%s %s%s%s",
                               col(C::DIM), col(C::RST),
                               hp.version_anomaly ? col(C::RED) :
                                 (hp.status_code>=200 && hp.status_code<600 ? col(C::GRN) : col(C::YEL)),
                               printable_prefix(hp.first_line, 70).c_str(),
                               col(C::RST));
                        if (!hp.server_hdr.empty())
                            printf("   Server: %s%s%s",
                                   col(C::CYN),
                                   printable_prefix(hp.server_hdr, 40).c_str(),
                                   col(C::RST));
                        else if (hp.status_code > 0)
                            printf("   %s(no Server header)%s",
                                   col(C::YEL), col(C::RST));
                        if (hp.version_anomaly)
                            printf("   %s[!version anomaly]%s",
                                   col(C::RED), col(C::RST));
                        printf("\n");
                    } else {
                        printf("        %sHTTP-over-TLS: no reply (TLS ok, origin silent on HTTP request) — stream-layer proxy signature%s\n",
                               col(C::RED), col(C::RST));
                    }
                    // v2.4 — proxy-chain leak headers (methodika §10.2)
                    //   Via / Forwarded / X-Forwarded-For betray a
                    //   middle proxy. CF-Ray / X-Amz-Cf-Id / X-Azure-Ref
                    //   are legit CDN markers (flagged separately).
                    if (hp.has_proxy_leak) {
                        printf("        %s[proxy-leak]%s",
                               col(C::YEL), col(C::RST));
                        if (!hp.via_hdr.empty())
                            printf(" Via='%s'", printable_prefix(hp.via_hdr, 36).c_str());
                        if (!hp.forwarded_hdr.empty())
                            printf(" Forwarded='%s'", printable_prefix(hp.forwarded_hdr, 36).c_str());
                        if (!hp.xff_hdr.empty())
                            printf(" XFF='%s'", printable_prefix(hp.xff_hdr, 36).c_str());
                        if (!hp.xreal_ip_hdr.empty())
                            printf(" X-Real-IP='%s'", printable_prefix(hp.xreal_ip_hdr, 24).c_str());
                        printf("\n");
                    }
                    if (hp.has_cdn_hdr) {
                        string cdn;
                        if (!hp.cf_ray_hdr.empty())       cdn = "Cloudflare (CF-Ray=" + printable_prefix(hp.cf_ray_hdr, 22) + ")";
                        else if (!hp.x_amz_cf_id.empty()) cdn = "CloudFront (X-Amz-Cf-Id=" + printable_prefix(hp.x_amz_cf_id, 22) + ", pop=" + hp.x_amz_cf_pop + ")";
                        else if (!hp.x_azure_ref.empty()) cdn = "Azure Front Door (X-Azure-Ref=" + printable_prefix(hp.x_azure_ref, 24) + ")";
                        else if (!hp.x_served_by.empty()) cdn = "Fastly (X-Served-By=" + printable_prefix(hp.x_served_by, 24) + ")";
                        if (!cdn.empty())
                            printf("        %s[cdn]%s  %s\n",
                                   col(C::CYN), col(C::RST), cdn.c_str());
                    }
                    if (!hp.alt_svc.empty())
                        printf("        %s[alt-svc]%s  %s  (QUIC endpoint advertisement)\n",
                               col(C::DIM), col(C::RST),
                               printable_prefix(hp.alt_svc, 80).c_str());
                }
            } else {
                FpResult f; f.service = "TLS-FAIL";
                f.details = tp.err;
                line(f);
                pf.tls = tp; // keep probe even on failure (ok=false) for verdict logic
            }
        }
        // HTTP
        if (o.port==80||o.port==8080||o.port==8000||o.port==8088||o.port==8880||
            o.port==8888||o.port==81||o.port==3128||o.port==8118||o.port==8123) {
            FpResult hp = fp_http_plain(R.dns.primary_ip, o.port);
            if (!hp.details.empty() || hp.silent) line(hp);
            // proxy test
            FpResult pp = fp_http_connect(R.dns.primary_ip, o.port);
            if (pp.service == "HTTP-PROXY") line(pp);
        }
        // SOCKS
        if (o.port==1080||o.port==1081||o.port==1082||o.port==9050||
            o.port==10808||o.port==10810||o.port==7890||o.port==7891) {
            line(fp_socks5(R.dns.primary_ip, o.port));
        }
        // Shadowsocks-style (8388, 8488, 443-like with empty ALPN)
        if (o.port==8388||o.port==8488||o.port==8787||o.port==8989) {
            line(fp_shadowsocks(R.dns.primary_ip, o.port));
        }
        if (!printed) {
            FpResult g; g.service = "unknown";
            if (!o.banner.empty()) g.details = "banner: " + printable_prefix(o.banner, 70);
            else                   g.details = "open but silent on connect (ambiguous: firewalled service / Shadowsocks / Trojan / Reality wrapper — inconclusive without protocol match)";
            // skip spammy unknown unless banner present OR <20 ports total
            if (!o.banner.empty() || R.open_tcp.size() < 20) line(g);
            else pf.fp = g;
        }
        R.fps.push_back(std::move(pf));
    }

    // 6) J3 active probing on each TLS-like port
    printf("\n%s[6/8] J3 / TSPU active probing%s\n", col(C::BOLD), col(C::RST));
    for (auto& o: R.open_tcp) {
        if (!is_tls_port(o.port) && o.port != 80 && o.port != 8080) continue;
        printf("  %s-> port :%d%s\n", col(C::BOLD), o.port, col(C::RST));
        auto probes = j3_probes(R.dns.primary_ip, o.port);
        int silent = 0, resp = 0;
        for (auto& p: probes) {
            const char* c = p.responded ? col(C::YEL) : col(C::GRN);
            const char* tag = p.responded ? "RESP" : "SILENT";
            printf("     %s%-7s%s  %-28s  ", c, tag, col(C::RST), p.name.c_str());
            if (p.responded) {
                printf("%dB  %s  [%s]", p.bytes,
                       printable_prefix(p.first_line, 50).c_str(),
                       p.hex_head.c_str());
                ++resp;
            } else {
                printf("(dropped)");
                ++silent;
            }
            printf("\n");
        }
        // v2.3 — compute + cache J3 analysis (canned responses, HTTP-version
        // anomalies, raw-non-HTTP replies) so the verdict engine can use it.
        J3Analysis ja = j3_analyze(probes);
        // attach
        for (auto& pf: R.fps) if (pf.port == o.port) {
            pf.j3  = std::move(probes);
            pf.j3a = ja;
            break;
        }
        const char* verdict;
        // NB: silent-on-junk is not a positive ID — ANY strict TLS endpoint
        // (nginx, Apache, CDN, etc.) drops HTTP/junk before the TLS record
        // layer. Treat it as ambiguous; only name Reality via the cert-
        // steering check in the verdict engine.
        if (silent >= 6)      verdict = "silent-on-junk (TLS-only / Reality-hidden / firewalled — ambiguous)";
        else if (resp >= 6)   verdict = "responds to arbitrary bytes (plaintext HTTP-style origin)";
        else if (silent >= 3) verdict = "mixed: partly strict, partly permissive";
        else                  verdict = "mixed behaviour";
        printf("     %s-> %s%s  (silent=%d / resp=%d)\n",
               col(C::MAG), verdict, col(C::RST), silent, resp);
        // v2.3 — J3 deep-analysis summary printed inline so the user SEES
        // the reasoning instead of waiting for the verdict block.
        //   On TLS ports, a canned 400 to raw-TCP probes is normal nginx
        //   behaviour; only escalate if the HTTP-over-TLS probe ALSO showed
        //   anomaly. See matching gate in the verdict engine.
        bool inline_is_tls = false, inline_https_anomaly = false;
        for (auto& pf: R.fps) if (pf.port == o.port) {
            inline_is_tls = (pf.tls && pf.tls->ok);
            if (pf.https && pf.https->tls_ok &&
                (!pf.https->responded || pf.https->version_anomaly ||
                 (pf.https->responded && pf.https->server_hdr.empty())))
                inline_https_anomaly = true;
            break;
        }
        bool inline_canned_hard = (ja.canned_identical >= 2) &&
                                  (!inline_is_tls || inline_https_anomaly);
        if (inline_canned_hard) {
            printf("     %s!! canned response:%s the SAME first-line (%dB '%s') came back for %d different probes — not a real web server, that's a static fallback page (classic Xray `fallback+redirect`, Trojan, or Caddy placeholder)\n",
                   col(C::RED), col(C::RST),
                   ja.canned_bytes,
                   printable_prefix(ja.canned_line, 50).c_str(),
                   ja.canned_identical);
        } else if (ja.canned_identical >= 2 && inline_is_tls) {
            printf("     %suniform reply:%s the SAME first-line (%dB '%s') for %d raw-TCP probes, but the HTTP-over-TLS probe is clean — that's normal nginx/CDN behaviour on a TLS port (not a fallback)\n",
                   col(C::DIM), col(C::RST),
                   ja.canned_bytes,
                   printable_prefix(ja.canned_line, 50).c_str(),
                   ja.canned_identical);
        }
        if (ja.http_bad_version > 0) {
            printf("     %s!! HTTP version anomaly:%s %d probe(s) came back with an invalid HTTP version string (e.g. HTTP/0.0) — signature of a stream-proxy's fallback/redirect code path, not of nginx/Apache/Caddy\n",
                   col(C::RED), col(C::RST), ja.http_bad_version);
        }
        if (ja.raw_non_http > 0 && ja.http_real == 0) {
            printf("     %s!! raw non-HTTP bytes:%s %d probe(s) got binary replies instead of HTTP — origin is speaking its own framing (Shadowsocks, Trojan, custom proxy)\n",
                   col(C::YEL), col(C::RST), ja.raw_non_http);
        }
    }

    // 7) Verdict engine (v2.3 — deep-audit model)
    //
    // v2.3 adds ACTIVE on-the-wire signals that are extremely expensive for
    // a legit web origin to fake but trivially show up in any Xray/Trojan/
    // Reality deployment:
    //
    //   * Cert impersonation — famous-brand CN (amazon/microsoft/apple/...)
    //     on an ASN that has no commercial relationship with that brand.
    //     This is the Reality "static dest" profile (dest=www.amazon.com:443)
    //     and it's a hard signal because the only way a random VPS in LV on
    //     AS42532 serves a valid Amazon cert is by proxying the TLS
    //     handshake to the real amazon.com.
    //
    //   * Short-validity cert — total_validity_days < 14 is never normal.
    //     Let's Encrypt issues 90d certs, commercial CAs 30-365d. A cert
    //     with 6 days of total lifetime is either LE staging (not used by
    //     real sites), manually generated for a proxy, or chain rot.
    //
    //   * Canned-response fallback — if two or more J3 probes get back
    //     EXACTLY the same first-line + byte count, the origin isn't a
    //     real web server, it's a stream-proxy handing out a static
    //     fallback page on every mismatch. Xray's `fallback+redirect`
    //     famously emits "HTTP/0.0 307 Temporary Redirect".
    //
    //   * HTTP-version anomaly — a response line of HTTP/0.X or HTTP/3.X
    //     (text) etc. never comes out of nginx/Apache/Caddy; it's a
    //     proxy-specific serialiser.
    //
    //   * 3x-ui / x-ui port cluster — panel installers use a stock set of
    //     Cloudflare-proxy-friendly TLS ports (2053 / 2083 / 2087 / 2096 /
    //     8443 / 8880). Two or more of these on one IP is a panel-install
    //     signature.
    //
    //   * HTTP-over-TLS response audit — after a clean TLS handshake we
    //     actually speak HTTP/1.1 and look for a real Server: header.
    //     No Server: header AND HTTP version anomaly AND/or empty response
    //     = stream-layer proxy.
    //
    // Calibration: hosting-ASN, single :443, IKE control ports,
    // single-source GeoIP tags, KEX != X25519 etc. stay informational
    // with hardening advice (not a penalty on their own).
    // ------------------------------------------------------------------

    // ---------- 7) SNITCH latency + traceroute + SSTP (v2.4) --------------
    //   * SNITCH: measure target TCP RTT and compare against the physical
    //     minimum implied by GeoIP. methodika §10.1 documents this as the
    //     canonical "latency vs geo" VPN detector.
    //   * Traceroute: count hops and look for unusual path patterns.
    //   * SSTP: TLS-over-TCP Microsoft VPN protocol probe on :443.
    printf("\n%s[7/8] SNITCH latency + traceroute + SSTP%s\n",
           col(C::BOLD), col(C::RST));

    // Compute open-port set up here too (openset is rebuilt inside
    // verdict engine — duplicated locally to keep the two phases
    // independent and not require reshuffling the verdict code).
    set<int> openset_early;
    for (auto& o: R.open_tcp) openset_early.insert(o.port);

    // Pick an open TCP port to measure RTT to. Prefer :443, else first
    // open port, else 443 (closed or not; we'll get no samples).
    int rtt_port = 443;
    if (!openset_early.count(443) && !R.open_tcp.empty()) rtt_port = R.open_tcp.front().port;

    // Consensus country code (most-common CC across GeoIP providers)
    string consensus_cc;
    {
        std::map<string,int> votes;
        for (auto& g: R.geos) if (!g.country_code.empty())
            ++votes[g.country_code];
        int best = 0;
        for (auto& [cc, v]: votes)
            if (v > best) { best = v; consensus_cc = cc; }
    }
    SnitchResult sn = snitch_check(R.dns.primary_ip, rtt_port, consensus_cc);
    R.snitch = sn;
    if (!sn.ok) {
        printf("  %sSNITCH: %s%s\n", col(C::DIM), sn.summary.c_str(), col(C::RST));
    } else {
        const char* sc_col = (sn.too_low || sn.too_high) ? col(C::RED) :
                             (sn.high_jitter || sn.anchor_ratio_off) ? col(C::YEL) : col(C::GRN);
        printf("  %sSNITCH RTT:%s  median=%.1fms  min=%.1fms  max=%.1fms  stddev=%.1fms  (%d samples)\n",
               col(C::BOLD), col(C::RST),
               sn.median_ms, sn.min_ms, sn.max_ms, sn.stddev_ms, sn.samples);
        printf("  %sAnchors:%s   Cloudflare=%s  Google=%s  Yandex=%s\n",
               col(C::DIM), col(C::RST),
               sn.cf_median_ms>=0     ? (std::to_string((int)sn.cf_median_ms)+"ms").c_str()     : "n/a",
               sn.google_median_ms>=0 ? (std::to_string((int)sn.google_median_ms)+"ms").c_str() : "n/a",
               sn.yandex_median_ms>=0 ? (std::to_string((int)sn.yandex_median_ms)+"ms").c_str() : "n/a");
        if (sn.expected_min_ms > 0)
            printf("  %sExpected:%s  country=%s  physical_min=%.0fms  (from %s observer)\n",
                   col(C::DIM), col(C::RST),
                   sn.country_code.c_str(), sn.expected_min_ms,
                   consensus_cc.empty() ? "unknown" : consensus_cc.c_str());
        printf("  %s=>%s %s%s%s\n",
               col(C::BOLD), col(C::RST), sc_col, sn.summary.c_str(), col(C::RST));
        if (sn.too_low)
            printf("  %s[!]%s Latency impossibly low for %s geo — likely anycast proxy (Cloudflare/Google) OR GeoIP lies\n",
                   col(C::RED), col(C::RST), consensus_cc.c_str());
        if (sn.too_high)
            printf("  %s[!]%s Latency significantly above expected band — extra hops in path (VPN tunnel or long middlebox chain)\n",
                   col(C::RED), col(C::RST));
        if (sn.high_jitter)
            printf("  %s[-]%s High RTT jitter — typical of tunnel queue/encryption overhead\n",
                   col(C::YEL), col(C::RST));
    }

    // Traceroute
    TraceResult tr = trace_hops(R.dns.primary_ip, 18);
    R.trace = tr;
    if (tr.ok) {
        printf("  %sTraceroute:%s %d hops, reached=%s, max_rtt_jump=%dms, long_hops(>150ms)=%d\n",
               col(C::BOLD), col(C::RST),
               tr.hop_count, tr.reached_target ? "yes" : "no",
               tr.max_rtt_jump_ms, tr.long_hops);
        // Compact hop list: ttl→addr (rtt)
        int shown = 0;
        for (auto& h: tr.hops) {
            if (shown >= 12) { printf("    ...\n"); break; }
            if (h.rtt_ms < 0)
                printf("    %2d  %s*%s\n", h.ttl, col(C::DIM), col(C::RST));
            else
                printf("    %2d  %-16s  %dms\n", h.ttl, h.addr.c_str(), h.rtt_ms);
            ++shown;
        }
    } else {
        printf("  %sTraceroute:%s no hops returned (ICMP filtered / no admin on strict hosts)\n",
               col(C::DIM), col(C::RST));
    }

    // SSTP probe on :443 if TLS-capable
    if (openset_early.count(443)) {
        FpResult sstp = sstp_probe(R.dns.primary_ip, 443);
        R.sstp = sstp;
        const char* c = sstp.is_vpn_like ? col(C::RED) : col(C::DIM);
        printf("  %sSSTP/443:%s %s%s%s  %s\n",
               col(C::BOLD), col(C::RST),
               c, sstp.service.c_str(), col(C::RST),
               printable_prefix(sstp.details, 80).c_str());
    }

    // JA3 advisory
    {
        Ja3Info j = our_openssl_ja3_signature();
        printf("  %sOur ClientHello JA3:%s %s%s%s  (OpenSSL 3.x default — real browsers use uTLS-Chrome)\n",
               col(C::BOLD), col(C::RST),
               col(C::DIM), j.ja3_hash.c_str(), col(C::RST));
        // If any Reality-like TLS port responded, note it could be uTLS-enforcing
        bool any_reality_port = false;
        for (auto& pf: R.fps) if (pf.sni && pf.sni->reality_like) any_reality_port = true;
        if (any_reality_port)
            printf("  %s  -> Reality server here accepted our non-Chrome JA3 — either uTLS-enforcement is OFF (typical Reality default), or the ACCEPT path always runs and divergence is only in fallback routing%s\n",
                   col(C::DIM), col(C::RST));
    }

    // ---------- 8) Verdict engine (v2.4 — deep-audit model) --------------
    printf("\n%s[8/8] Verdict%s\n", col(C::BOLD), col(C::RST));
    int score = 100;
    vector<string> signals_major;  // hard evidence: named VPN, open
                                   // proxy, multi-source tag, Tor, etc.
    vector<string> signals_minor;  // soft evidence: fresh cert in combo,
                                   // self-signed, TLS<1.3, Reality, etc.
    vector<std::pair<string,string>> notes;   // (tag, observation)  — no penalty
    vector<std::pair<string,string>> hardening; // (tag, advice)
    vector<std::pair<int,string>>    port_roles; // (port, role label)
    vector<std::pair<string,string>> dpi_axes;   // (axis, exposure)
    bool xray_reality_primary = false, xray_reality_hidden = false;
    int  reality_port_count   = 0;

    auto flag_minor = [&](const string& s, int penalty = 3) {
        signals_minor.push_back(s);
        score -= penalty;
    };
    auto flag_major = [&](const string& s, int penalty) {
        signals_major.push_back(s);
        score -= penalty;
    };
    auto note = [&](const string& tag, const string& s) {
        notes.push_back({tag, s});
    };

    // ---- GeoIP signals ---------------------------------------------
    // v2.3: hosting-ASN and single-source VPN tags are informational only.
    int vpn_hits = 0, proxy_hits = 0, hosting_hits = 0, tor_hits = 0;
    for (auto& g: R.geos) {
        if (g.is_hosting) ++hosting_hits;
        if (g.is_vpn)     ++vpn_hits;
        if (g.is_proxy)   ++proxy_hits;
        if (g.is_tor)     ++tor_hits;
    }
    int gprov = (int)R.geos.size();
    if (tor_hits)
        flag_major("flagged as Tor exit by " + std::to_string(tor_hits) + " GeoIP source(s)", 25);
    if (vpn_hits >= 2)
        flag_major("flagged as VPN by " + std::to_string(vpn_hits) + " GeoIP sources (multi-source consensus)", 18);
    else if (vpn_hits == 1)
        note("geo-vpn", "1 of " + std::to_string(gprov) + " GeoIP sources tagged this IP as VPN (single-source — likely a false positive)");
    if (proxy_hits >= 2)
        flag_major("flagged as proxy by " + std::to_string(proxy_hits) + " GeoIP sources (multi-source consensus)", 12);
    else if (proxy_hits == 1)
        note("geo-proxy", "1 of " + std::to_string(gprov) + " GeoIP sources tagged this IP as proxy (single-source — likely a false positive)");
    if (hosting_hits >= 1)
        note("asn-hosting", std::to_string(hosting_hits) + " of " + std::to_string(gprov) + " sources classify the ASN as hosting/datacenter "
             "(normal for any public server — not a red flag on its own)");
    if (R.geos.size() >= 2 && !R.geos[0].country_code.empty() && !R.geos[1].country_code.empty()
        && R.geos[0].country_code != R.geos[1].country_code)
        note("geo-cc-mismatch", "GeoIP country codes disagree between providers (normal GeoIP noise)");

    // ---- TCP exposure signals --------------------------------------
    // v2.3: only truly VPN/proxy-specific ports carry a penalty.
    // "Only :443 open" / "SSH/22 open" are NORMAL for a public web host —
    // moved to Informational with a Hardening entry.
    set<int> openset;
    for (auto& o: R.open_tcp) openset.insert(o.port);
    if (openset.count(3389)) flag_major("RDP/3389 reachable from Internet (attack surface, not VPN-specific)", 10);
    if (openset.count(1080) || openset.count(1081))
        flag_major("SOCKS5 exposed without wrapper (proxy signature)", 15);
    if (openset.count(3128) || openset.count(8118))
        flag_major("HTTP proxy exposed without wrapper", 12);
    if (openset.count(1194))
        flag_major("OpenVPN TCP/1194 default port open (hard protocol signature)", 15);
    if (openset.count(8388) || openset.count(8488))
        flag_major("Shadowsocks default port exposed (instantly fingerprintable)", 15);
    if (openset.count(10808) || openset.count(10809) || openset.count(10810))
        flag_major("v2ray/xray local-style inbound port exposed to WAN (misconfig)", 12);
    // Informational — not red flags, but we surface actionable hardening:
    if (openset.count(22))
        note("ssh-22", "SSH/22 open with a standard banner — visible on Shodan/ASN-sweeps as 'server host', not as VPN");
    if (openset.count(500) || openset.count(4500))
        note("ike-ports", "IKE control ports (500/4500) open — normal for any IPsec-capable router");
    if (openset.count(443) && R.open_tcp.size() == 1)
        note("single-443", "only :443 is reachable — indistinguishable from a typical reverse-proxy / corporate single-service host, but provides no web 'context' (no :80 redirect, no decoy services)");
    else if (openset.count(443) && R.open_tcp.size() <= 3 && hosting_hits)
        note("sparse-ports", std::to_string(R.open_tcp.size()) + " TCP ports open on a hosting ASN with :443 — sparse profile; common for both minimal corporate servers and single-purpose proxy VPSes");

    // ---- UDP handshake signals -------------------------------------
    for (auto& [p,u]: R.udp_probes) {
        if (!u.responded) continue;
        if (p == 1194)  flag_major("OpenVPN UDP/1194 reflects HARD_RESET (protocol-level match)", 22);
        if (p == 500)   flag_minor("IKEv2 responder on UDP/500 (IPsec endpoint)", 5);
        if (p == 4500)  flag_minor("IKEv2 NAT-T responder on UDP/4500 (IPsec endpoint)", 5);
        if (p == 51820) flag_major("WireGuard UDP/51820 answers handshake (default port signature)", 15);
        if (p == 41641) flag_minor("Tailscale UDP/41641 answers handshake (default port)", 5);
    }

    // ---- 3x-ui / x-ui / panel-installer port-cluster signature (v2.3) ---
    //   Cloudflare proxy-friendly TLS ports 2053/2083/2087/2096/8443/8880
    //   are what 3x-ui/x-ui/V2bX/Marzban panels suggest by default. Two or
    //   more of them open together on one IP is an installer fingerprint
    //   that regular webhosts do not produce.
    int xui_cluster_hits = 0;
    vector<int> xui_open;
    for (int p: {2053, 2083, 2087, 2096, 8443, 8880, 6443, 7443, 9443}) {
        if (openset.count(p)) { ++xui_cluster_hits; xui_open.push_back(p); }
    }
    bool xui_cluster_seen = false;
    if (xui_cluster_hits >= 2) {
        string portstr;
        for (size_t i=0;i<xui_open.size();++i) {
            if (i) portstr += ",";
            portstr += std::to_string(xui_open[i]);
        }
        flag_major(std::to_string(xui_cluster_hits) + " of the classical 3x-ui/x-ui/Marzban panel TLS ports are open ({" + portstr + "}) — installer fingerprint; regular webhosts rarely open this exact set", 14);
        xui_cluster_seen = true;
    } else if (xui_cluster_hits == 1) {
        note("xui-single-port", "one panel-installer TLS port open (:" + std::to_string(xui_open[0]) +
             ") — ambiguous by itself, but these ports are strongly associated with 3x-ui/x-ui proxy panels");
    }

    // ---- Silent-high-port + TLS elsewhere (v2.3 multipath detector) -----
    //   A classic Xray multi-inbound setup exposes :443 (TLS-fronted VLESS)
    //   AND a silent high port (direct VLESS/Trojan listener). That high
    //   port accepts TCP, says nothing on connect, doesn't speak TLS, and
    //   dies on any junk.  Real business services don't look like that.
    int silent_high_ports = 0;
    for (auto& o: R.open_tcp) {
        if (o.port >= 10000 && o.banner.empty()) ++silent_high_ports;
    }
    bool tls_on_443 = openset.count(443) > 0;
    if (tls_on_443 && silent_high_ports >= 1 && R.open_tcp.size() <= 6) {
        flag_minor(std::to_string(silent_high_ports) + " silent high-port(s) open alongside :443 TLS on a sparse host — classic multi-inbound proxy layout (Xray VLESS :443 + direct listener on high port)", 7);
    }

    // ---- TLS posture + cert red flags (v2.3 — adds impersonation/short-validity)
    //   * TLS<1.3 is still a weak-posture penalty (real 2026 sites are TLS1.3).
    //   * ALPN != h2 and KEX != X25519 → informational only, not a penalty.
    //   * Fresh cert <14d → penalty ONLY if the host also has (sparse-ports
    //     profile AND hosting ASN). An isolated fresh LE cert on a
    //     multi-port corporate host is just normal LE rotation.
    //   * Self-signed, expired, zero-SAN — still red flags (not normal).
    //   * total_validity_days < 14 — HARD flag (no legit CA issues <14d).
    //   * brand cert on non-brand ASN — HARD flag (Reality-static profile).
    bool any_tls = false, any_reality = false;
    bool any_impersonation = false;
    int  cert_issuers_seen_free_ca = 0;
    int  cert_fresh_ports = 0;
    int  cert_self_signed_ports = 0;
    int  cert_short_validity_ports = 0;
    int  cert_impersonation_ports = 0;
    int  tls_not_13_ports = 0;
    int  alpn_not_h2_ports = 0;
    int  group_not_x25519_ports = 0;
    bool sparse_vps_profile = (openset.count(443) && R.open_tcp.size() <= 3 && hosting_hits > 0);

    // collect all ASN-org strings across providers for brand cross-check
    vector<string> asn_orgs_all;
    for (auto& g: R.geos) if (!g.asn_org.empty()) asn_orgs_all.push_back(g.asn_org);
    for (auto& pf: R.fps) {
        if (pf.tls && pf.tls->ok) {
            any_tls = true;
            if (pf.tls->version != "TLSv1.3") {
                flag_minor("TLS < 1.3 on :" + std::to_string(pf.port) +
                           " (" + pf.tls->version + ") — weak handshake posture, modern clients expect TLS 1.3", 4);
                ++tls_not_13_ports;
            }
            if (pf.tls->alpn != "h2") {
                note("alpn", "ALPN on :" + std::to_string(pf.port) + " = '" +
                     (pf.tls->alpn.empty() ? "-" : pf.tls->alpn) +
                     "' (HTTP/1.1-only is still normal for many corporate apps; h2 is not mandatory)");
                ++alpn_not_h2_ports;
            }
            if (!pf.tls->group.empty() && pf.tls->group != "X25519") {
                note("kex", "KEX group on :" + std::to_string(pf.port) + " = '" + pf.tls->group +
                     "' (X25519 is preferred by modern browsers but ECDHE-P256 is perfectly valid)");
                ++group_not_x25519_ports;
            }
            if (pf.tls->age_days > 0 && pf.tls->age_days < 14) {
                ++cert_fresh_ports;
                if (sparse_vps_profile) {
                    flag_minor("cert on :" + std::to_string(pf.port) +
                               " is fresh (" + std::to_string(pf.tls->age_days) +
                               "d) AND open-port profile is sparse on hosting ASN — classic 'new VLESS host' fingerprint",
                               6);
                } else {
                    note("cert-fresh", "cert on :" + std::to_string(pf.port) + " is " +
                         std::to_string(pf.tls->age_days) + "d old (fresh LE certs are normal for any site rotating every 60-90d)");
                }
            }
            if (pf.tls->self_signed) {
                flag_major("self-signed cert on :" + std::to_string(pf.port) +
                           " (subject==issuer) — browsers would reject; typical of Shadowsocks/Trojan/test setups", 10);
                ++cert_self_signed_ports;
            }
            if (pf.tls->is_letsencrypt) {
                ++cert_issuers_seen_free_ca;
                // Not a signal — LE / ZeroSSL / GTS are the norm for public sites.
            }
            if (pf.tls->days_left < 0) {
                flag_minor("cert on :" + std::to_string(pf.port) +
                           " EXPIRED " + std::to_string(-pf.tls->days_left) +
                           "d ago — no legit site runs an expired cert; abandonment or misconfig signal", 8);
            }
            if (pf.tls->san_count == 0 && !pf.tls->subject_cn.empty()) {
                note("no-san", "cert on :" + std::to_string(pf.port) +
                     " has no SAN entries (only legacy CN) — unusual for modern public TLS, but some internal certs do this");
            }
            // v2.3 — short-validity cert: total lifetime < 14d is never
            // issued by real CAs to production sites. LE = 90d, commercial
            // = 30-365d. 5-14d means manually-generated internal cert or
            // LE staging, used by Xray/Trojan quickfire setups.
            if (pf.tls->total_validity_days > 0 && pf.tls->total_validity_days < 14) {
                flag_major("cert on :" + std::to_string(pf.port) +
                           " has a total validity of only " + std::to_string(pf.tls->total_validity_days) +
                           " days (notBefore→notAfter) — no public CA issues <14d certs to real sites; this is a hand-rolled internal cert or LE staging, a hard signal of a proxy/test setup",
                           15);
                ++cert_short_validity_ports;
            }
        }
        // v2.3 — brand impersonation check:
        // If the cert vouches for a famous brand but the ASN clearly has
        // nothing to do with that brand, this is Reality-static / cert
        // cloning. This is a HARD signal (the only reason a random VPS in
        // US on AS56971 serves a valid Amazon cert is because it's
        // proxying the handshake).
        if (pf.sni && pf.sni->cert_impersonation && !pf.sni->brand_claimed.empty()) {
            bool owns = asn_owns_brand(pf.sni->brand_claimed, asn_orgs_all);
            if (!owns) {
                flag_major("cert on :" + std::to_string(pf.port) +
                           " vouches for brand '" + pf.sni->brand_claimed +
                           "' but the ASN is not owned by that brand — Reality-static / "
                           "cert-cloning signature (Xray `dest=" + pf.sni->brand_claimed + "` profile)",
                           22);
                ++cert_impersonation_ports;
                any_impersonation = true;
            } else {
                // legit brand on legit ASN — no signal
                note("brand-legit", "cert on :" + std::to_string(pf.port) +
                     " is for '" + pf.sni->brand_claimed + "' and the ASN does match that brand — legitimate brand endpoint");
            }
        }
        if (pf.sni && pf.sni->reality_like) {
            any_reality = true;
            ++reality_port_count;
            // Reality IS identifiable — the very fact we can recognise it
            // as Reality means a DPI engine can too.
            if (pf.sni->passthrough_mode) {
                flag_major("Reality in passthrough mode on :" + std::to_string(pf.port) +
                           " (base cert is for '" + pf.sni->matched_foreign_sni +
                           "' — stream tunnelled to the real brand, SNI-based vhost routing "
                           "then returns different certs per SNI; cert + ASN disagree)", 14);
            } else {
                flag_major("Reality cert-steering pattern on :" + std::to_string(pf.port) +
                           " (cert covers foreign SNI '" + pf.sni->matched_foreign_sni + "')", 12);
            }
        }
        // v2.3 — Server-header brand impersonation. CloudFront / AmazonS3 /
        // gws / Microsoft-IIS / Yandex banners are only served by the real
        // brand's infrastructure. If the IP we're hitting answers with one
        // of those but the ASN doesn't own the brand — the box is proxying
        // the HTTP stream to the real brand (Reality passthrough). This
        // doubles as an independent confirmation of cert impersonation, but
        // fires even when the TLS-cert check missed it (e.g. brand not in
        // SAN but server-banner still leaks through).
        if (pf.https && pf.https->tls_ok && pf.https->responded &&
            !pf.https->server_hdr.empty()) {
            string sbr = server_header_brand(pf.https->server_hdr);
            if (!sbr.empty()) {
                bool owns = asn_owns_brand(sbr, asn_orgs_all);
                if (!owns) {
                    flag_major("HTTP-over-TLS on :" + std::to_string(pf.port) +
                               " returns `Server: " + printable_prefix(pf.https->server_hdr, 40) +
                               "` — that banner is only emitted by '" + sbr +
                               "' infrastructure, yet the ASN isn't owned by that brand "
                               "(origin is proxying the HTTP stream to the real brand = Reality passthrough)",
                               18);
                    // Also count this toward the cert-impersonation side if the
                    // TLS-cert check didn't catch the same brand already.
                    if (!(pf.sni && pf.sni->cert_impersonation)) {
                        ++cert_impersonation_ports;
                        any_impersonation = true;
                    }
                }
            }
        }
        // v2.3 — Active HTTP-over-TLS probe verdicts.
        //   * version anomaly (HTTP/0.0 etc.) = hard fake-server signal
        //   * no Server: header AND responded = likely middleware/proxy
        //   * TLS ok but HTTP empty = stream-layer proxy
        if (pf.https && pf.https->tls_ok) {
            if (pf.https->version_anomaly && pf.https->responded) {
                flag_major("HTTP-over-TLS on :" + std::to_string(pf.port) +
                           " returned an invalid HTTP version ('" +
                           printable_prefix(pf.https->first_line, 40) +
                           "') — no real web server emits that; classic Xray/Trojan fallback signature",
                           14);
            }
            if (pf.https->responded && pf.https->server_hdr.empty() && !pf.https->version_anomaly) {
                flag_minor("HTTP-over-TLS on :" + std::to_string(pf.port) +
                           " responded without a Server: header — real nginx/Apache/Caddy/CDN set one; absence is a middleware tell",
                           5);
            }
            if (!pf.https->responded) {
                flag_minor("HTTP-over-TLS on :" + std::to_string(pf.port) +
                           " — TLS handshake succeeded but origin did not return any HTTP bytes to a valid GET / request. Legitimate web origins always reply (200/301/404/502). Silence here = stream-layer proxy.",
                           8);
            }
            // v2.4 — proxy-chain header leakage (methodika §10.2)
            //   Via / Forwarded / X-Forwarded-For indicate a middle proxy.
            //   On a host whose ASN isn't a known CDN (Cloudflare /
            //   CloudFront / Azure / Fastly), this is a direct "there's
            //   a middlebox in your chain" signal.
            if (pf.https->has_proxy_leak) {
                string hdrs;
                if (!pf.https->via_hdr.empty())        hdrs += "Via=\"" + printable_prefix(pf.https->via_hdr, 32) + "\" ";
                if (!pf.https->forwarded_hdr.empty())  hdrs += "Forwarded=\"" + printable_prefix(pf.https->forwarded_hdr, 32) + "\" ";
                if (!pf.https->xff_hdr.empty())        hdrs += "X-Forwarded-For=\"" + printable_prefix(pf.https->xff_hdr, 32) + "\" ";
                if (!pf.https->xreal_ip_hdr.empty())   hdrs += "X-Real-IP=\"" + printable_prefix(pf.https->xreal_ip_hdr, 24) + "\" ";
                flag_major("HTTP-over-TLS on :" + std::to_string(pf.port) +
                           " leaks proxy-chain headers (" + hdrs +
                           ") — methodika §10.2 diagnostic: the origin IS behind (or IS) a middle proxy",
                           12);
            }
        }
        // v2.4 — Certificate Transparency absence.
        //   Real public certs MUST be in CT logs (RFC 9162, enforced by
        //   Chrome/Firefox since 2018). A SHA-256 that returns `[]` from
        //   crt.sh means the cert was never logged = private CA, internal
        //   test issuance, LE staging, or a hand-crafted clone. When
        //   combined with fresh cert (<14d), this is a strong Xray / Trojan
        //   quickfire signal.
        if (pf.ct && pf.ct->queried && !pf.ct->found && pf.ct->err.empty()) {
            if (pf.tls && pf.tls->ok && pf.tls->age_days < 30) {
                flag_major("cert on :" + std::to_string(pf.port) +
                           " is NOT in public CT logs AND is fresh (" +
                           std::to_string(pf.tls->age_days) + "d) — never issued by a public CA; "
                           "hand-rolled internal / self-signed / cloned cert typical of Xray/Trojan quickfire setups",
                           15);
            } else if (pf.tls && pf.tls->ok) {
                flag_minor("cert on :" + std::to_string(pf.port) +
                           " is NOT in public CT logs — private-CA / internal issuance / LE-staging (legitimate in corporate internal use, but suspicious on a public-facing IP)",
                           6);
            }
        }
    }

    // ---- v2.4 SSTP (Microsoft SSTP VPN on TCP/443 TLS) -------------------
    if (R.sstp && R.sstp->is_vpn_like) {
        flag_major("Microsoft SSTP VPN detected on :443 (SSTP_DUPLEX_POST / sra_{...} replied with 200 OK + 2^64-1 Content-Length) — classical SSTP endpoint", 18);
    }

    // ---- v2.4 Extra VPN probes (Hysteria2 / TUIC / L2TP / AmneziaWG) ----
    for (auto& [p, u]: R.udp_extra) {
        if (!u.responded) continue;
        if (p == 1701)
            flag_major("L2TP UDP/1701 responds to SCCRQ (L2TP control signature)", 15);
        else if (p == 36712)
            flag_major("Hysteria2 default port UDP/36712 is live (QUIC-based Hysteria tunnel)", 15);
        else if (p == 8443)
            flag_minor("TUIC v5 / QUIC on UDP/8443 answers handshake (modern QUIC-based proxy)", 7);
        else if (p == 55555)
            flag_major("AmneziaWG on UDP/55555 with Sx=8 junk prefix replies — obfuscated WireGuard", 15);
        else if (p == 51820) {
            // AmneziaWG on the default WG port ALSO replies — either
            // vanilla WG listening (already caught) or AmneziaWG default
            // port. Distinguish via vanilla-WG probe result on 51820.
            bool wg_replied = false;
            for (auto& x: R.udp_probes) if (x.first == 51820 && x.second.responded) wg_replied = true;
            if (!wg_replied) {
                // Vanilla WG didn't reply, but AmneziaWG (Sx=8 prefix) DID.
                // That's specifically AmneziaWG detected on the default port.
                flag_major("AmneziaWG on default UDP/51820 (vanilla-WG header REJECTED, Sx=8 junk-prefix ACCEPTED) — obfuscated WireGuard at 2026-standard obfuscation params", 16);
            }
        }
    }

    // ---- v2.4 SNITCH latency-vs-geo consistency --------------------------
    if (R.snitch && R.snitch->ok) {
        auto& sn = *R.snitch;
        if (sn.too_low)
            flag_major("SNITCH: RTT " + std::to_string((int)sn.median_ms) + "ms to " +
                       sn.country_code + " is impossibly low (physical min ≥" +
                       std::to_string((int)sn.expected_min_ms) +
                       "ms from a typical EU/RU observer). GeoIP lies OR anycast proxy fronts this IP",
                       15);
        else if (sn.too_high)
            flag_minor("SNITCH: RTT " + std::to_string((int)sn.median_ms) +
                       "ms is 3x+ the expected band for " + sn.country_code +
                       " — extra hops in path (tunnel / long middlebox chain)", 6);
        else if (sn.high_jitter)
            note("snitch-jitter",
                 "SNITCH: RTT stddev " + std::to_string((int)sn.stddev_ms) +
                 "ms over " + std::to_string(sn.samples) +
                 " samples — elevated jitter typical of tunnel encryption/queue overhead (not conclusive)");
        else if (sn.anchor_ratio_off)
            note("snitch-anchor",
                 "SNITCH: target RTT doesn't match the closest anchor ratio — geolocation may be off");
    }

    // ---- v2.4 Traceroute anomalies ---------------------------------------
    if (R.trace && R.trace->ok) {
        auto& tr = *R.trace;
        if (tr.hop_count >= 20)
            flag_minor("traceroute shows " + std::to_string(tr.hop_count) +
                       " hops to target — longer than typical (residential→DC = 7-12 hops); extra hops suggest tunnel / overlay",
                       5);
        else if (tr.max_rtt_jump_ms >= 100 && tr.long_hops >= 2)
            note("trace-jump",
                 "traceroute has a large RTT step (" + std::to_string(tr.max_rtt_jump_ms) +
                 "ms jump) and " + std::to_string(tr.long_hops) +
                 " hops above 150ms — may indicate a long-haul tunnel between adjacent hops");
        else
            note("trace-ok",
                 "traceroute: " + std::to_string(tr.hop_count) +
                 " hops, max RTT step " + std::to_string(tr.max_rtt_jump_ms) +
                 "ms — path looks clean");
        // v2.5.5 - tspu mgmt-subnet hops (ch. 10 of tspu-docs).
        // 10.X.Y.Z with Z in [131..235, 241..245, 254] is the standard
        // layout for tspu filter/balancer/ipmi/spfs ranges.
        if (tr.tspu_hops > 0) {
            flag_minor("traceroute goes through " + std::to_string(tr.tspu_hops) +
                       " hop(s) matching the tspu management-subnet layout "
                       "(10.X.Y.[131-235]/[241-245]/254) - indicates a tspu site "
                       "is between you and the target",
                       5 * tr.tspu_hops);
        }
    }

    // ---- v2.5.5 BGP-blackhole (tspu type B) -------------------------------
    // all ports timeout with zero RST = destination has been BGP-null-routed
    // by operator (tspu-docs ch. 7.3.2). this is a hard block, not a dead server.
    if (R.bgp_blackhole_likely) {
        flag_major("L3 BGP-blackhole pattern on target: " +
                   std::to_string(R.scan_stats.timeouts) + "/" +
                   std::to_string(R.scan_stats.scanned) +
                   " ports TIMEOUT with 0 RST - tspu type B / operator ip-list block",
                   40);
    }

    // ---- v2.5.5 TSPU redirect page on HTTP ports --------------------------
    // tspu type A redirects http/:80 to operator warning page via 302.
    // ref: tspu-docs ch. 5.1.5
    for (auto& pf: R.fps) {
        if (pf.fp.tspu_redirect && !pf.fp.redirect_marker.empty()) {
            flag_major("HTTP on :" + std::to_string(pf.port) +
                       " redirects to operator warning page '" +
                       pf.fp.redirect_marker + "' (Location: '" +
                       printable_prefix(pf.fp.redirect_target, 60) +
                       "') - tspu type A active block",
                       30);
        }
    }

    // ---- J3 active-probe roles -------------------------------------
    // v2.3: re-add the "proxy in front of origin" detection.
    //   * nginx/Apache/Caddy return HTTP/1.1 400 Bad Request (or similar
    //     4xx) on non-TLS bytes hitting a TLS port. Most CDNs do too.
    //   * A host that does TLS 1.3 cleanly but silently eats every
    //     HTTP-junk probe is almost certainly running a stream-layer
    //     proxy (Xray/Reality/Trojan/SS-AEAD) that drops anything not
    //     matching its own framing. This is NOT Reality cert-steering
    //     (which would require the cert discriminator to fire), but it
    //     IS strong evidence of middleware between you and the origin.
    int j3_silent_total = 0, j3_resp_total = 0, j3_ports_checked = 0;
    int j3_canned_ports = 0, j3_badver_ports = 0, j3_raw_nonhttp_ports = 0;
    bool proxy_middleware_seen = false;
    for (auto& pf: R.fps) {
        if (pf.j3.size() < 6) continue;
        ++j3_ports_checked;
        int sil = 0, rsp = 0;
        // Also: among responses, count how many look like real HTTP (start with "HTTP/")
        int http_like_responses = 0;
        for (auto& j: pf.j3) {
            if (j.responded) {
                ++rsp;
                if (j.first_line.rfind("HTTP/", 0) == 0) ++http_like_responses;
            } else {
                ++sil;
            }
        }
        j3_silent_total += sil;
        j3_resp_total   += rsp;

        // v2.3 — tap the J3 analysis for canned/anomaly signals.
        //   * On TLS ports, the ACTIVE HTTP-over-TLS probe is the
        //     authoritative canned-fallback signal (post-TLS decode).
        //     Raw-TCP canned replies to a TLS port are legitimate nginx
        //     behaviour ("you sent non-TLS, here's 400"); we only escalate
        //     the raw-TCP canned on a TLS port if the HTTPS-over-TLS probe
        //     ALSO shows anomaly (empty/version-anomaly/no-Server).
        //   * On non-TLS ports, canned identical replies to different
        //     probes including valid HTTP GET / are hard Xray fallback.
        bool is_tls_port        = (pf.tls && pf.tls->ok);
        bool https_probe_anomaly =
            (pf.https && pf.https->tls_ok &&
             (!pf.https->responded ||
              pf.https->version_anomaly ||
              (pf.https->responded && pf.https->server_hdr.empty())));
        bool canned_real = (pf.j3a && pf.j3a->canned_identical >= 2) &&
                           (!is_tls_port || https_probe_anomaly);
        if (canned_real) {
            ++j3_canned_ports;
            flag_major("port :" + std::to_string(pf.port) +
                       " returns a canned fallback page (same first-line '" +
                       printable_prefix(pf.j3a->canned_line, 50) +
                       "' with identical byte count " + std::to_string(pf.j3a->canned_bytes) +
                       "B for " + std::to_string(pf.j3a->canned_identical) +
                       " different probes" +
                       (is_tls_port ? " AND the HTTP-over-TLS probe is also anomalous" : "") +
                       ") — real web servers vary their replies; this is the Xray/Trojan `fallback+redirect` signature",
                       18);
        }
        if (pf.j3a) {
            if (pf.j3a->http_bad_version >= 1) {
                ++j3_badver_ports;
                flag_major("port :" + std::to_string(pf.port) +
                           " emits an HTTP reply with an invalid version (e.g. HTTP/0.0) " +
                           std::to_string(pf.j3a->http_bad_version) +
                           " time(s) — nginx/Apache/Caddy never produce this; classic Xray fallback signature",
                           14);
            }
            if (pf.j3a->raw_non_http >= 2 && pf.j3a->http_real == 0) {
                ++j3_raw_nonhttp_ports;
                flag_minor("port :" + std::to_string(pf.port) +
                           " answers with raw non-HTTP bytes (" + std::to_string(pf.j3a->raw_non_http) +
                           " probes) — stream-layer proxy framing (Shadowsocks/Trojan/custom)", 7);
            }
        }

        bool has_reality = pf.sni && pf.sni->reality_like;
        bool tls_ok      = pf.tls && pf.tls->ok;
        bool tls_failed  = pf.tls && !pf.tls->ok;

        // per-port role string — now carries TLS + cert summary
        string role;
        if (has_reality && tls_ok) {
            if (sil >= 6) {
                role = "Reality hidden-mode (silent-on-junk — strong DPI signature)";
                xray_reality_hidden = true;
                score -= 3;
            } else if (rsp >= 4) {
                role = "Reality + HTTP fallback (mimics real web server on junk)";
                xray_reality_primary = true;
            } else {
                role = "Reality (TLS endpoint)";
            }
        } else if (tls_ok) {
            // *** proxy-middleware heuristic ***
            // TLS handshake clean, but junk probes are silently dropped:
            // a real web server (nginx/Apache/Caddy/CDN) would emit
            // HTTP/1.1 400 for non-TLS bytes. Silent = middleware.
            if (sil >= 6 && rsp == 0) {
                role = "TLS endpoint that silently drops all HTTP/junk — proxy/middleware in front of origin (Xray/Trojan/SS-AEAD — nginx/Apache would return HTTP 400)";
                flag_minor("port :" + std::to_string(pf.port) +
                           " does TLS 1.3 cleanly but silently drops every HTTP junk probe — "
                           "strong signature of a stream-layer proxy sitting in front of the origin "
                           "(Xray/Trojan/SS). Normal web servers reply with HTTP 400 on non-TLS bytes.",
                           7);
                proxy_middleware_seen = true;
            } else if (rsp >= 4 && http_like_responses == 0) {
                role = "TLS endpoint that answers junk with non-HTTP replies — atypical middleware (bytes come back but not in HTTP form)";
                flag_minor("port :" + std::to_string(pf.port) +
                           " answered " + std::to_string(rsp) +
                           " junk probes but none looked like HTTP — origin is not a standard web server "
                           "(possible custom proxy framing)", 5);
                proxy_middleware_seen = true;
            } else if (rsp >= 7) {
                role = "generic HTTPS / CDN origin (junk probes get HTTP 4xx as expected)";
            } else {
                role = "TLS endpoint (not Reality, mixed probe behaviour)";
            }
            // enrich with cert summary
            bool server_brand_mismatch = false;
            if (pf.https && pf.https->tls_ok && !pf.https->server_hdr.empty()) {
                string sb = server_header_brand(pf.https->server_hdr);
                if (!sb.empty() && !asn_owns_brand(sb, asn_orgs_all))
                    server_brand_mismatch = true;
            }
            char buf[512] = {0};
            snprintf(buf, sizeof(buf),
                     " — %s / ALPN=%s / CN=%s / issuer=%s / age=%dd / validity=%dd / SAN=%d%s%s%s%s",
                     pf.tls->version.c_str(),
                     pf.tls->alpn.empty() ? "-" : pf.tls->alpn.c_str(),
                     pf.tls->subject_cn.empty() ? "(none)" : pf.tls->subject_cn.c_str(),
                     pf.tls->issuer_cn.empty() ? "(none)" : pf.tls->issuer_cn.c_str(),
                     pf.tls->age_days, pf.tls->total_validity_days, pf.tls->san_count,
                     (pf.tls->total_validity_days > 0 && pf.tls->total_validity_days < 14) ? " [!short-validity]" : "",
                     (pf.sni && pf.sni->cert_impersonation) ? " [!brand-impersonation]" : "",
                     server_brand_mismatch ? " [!server-impersonation]" : "",
                     canned_real ? " [!canned-fallback]" : "");
            role += buf;
            // Upgrade the role label for the hard-signal cases: impersonation
            // and canned-fallback take precedence over the generic role.
            // canned_real already accounts for TLS-port vs HTTPS-probe-anomaly.
            bool role_upgraded = false;
            if (pf.sni && pf.sni->cert_impersonation && !pf.sni->brand_claimed.empty()) {
                bool owns = asn_owns_brand(pf.sni->brand_claimed, asn_orgs_all);
                if (!owns) {
                    const char* label = (pf.sni->passthrough_mode)
                        ? "Reality with real passthrough (cert tunnelled from '"
                        : "Reality-static / cert-cloning (cert impersonates '";
                    role = string(label) + pf.sni->brand_claimed +
                           (pf.sni->passthrough_mode
                              ? "' via `dest=` — TLS stream transparently tunnelled) "
                              : "' on an unrelated ASN) ") + role;
                    role_upgraded = true;
                }
            }
            // Independent channel: Server-header brand mismatch. Fires when
            // the cert-cert-cert check missed it but `Server: CloudFront/gws/...`
            // on a non-owner ASN still leaks the passthrough.
            if (!role_upgraded && pf.https && pf.https->tls_ok &&
                !pf.https->server_hdr.empty()) {
                string sb = server_header_brand(pf.https->server_hdr);
                if (!sb.empty() && !asn_owns_brand(sb, asn_orgs_all)) {
                    role = "Reality with real passthrough (`Server: " +
                           printable_prefix(pf.https->server_hdr, 24) +
                           "` banner comes from '" + sb +
                           "' infrastructure on non-owner ASN) " + role;
                    role_upgraded = true;
                }
            }
            if (!role_upgraded && canned_real) {
                role = "TLS endpoint emitting canned fallback response "
                       "(Xray/Trojan `fallback+redirect` page served for every probe) " + role;
            }
        } else if (tls_failed && sil >= 6) {
            role = "TLS handshake refused AND silent on HTTP — stream-layer proxy that only speaks its own framing (Shadowsocks-AEAD / Trojan / strict-mode Reality / custom SOCKS-over-TLS) OR a firewalled service";
            flag_minor("port :" + std::to_string(pf.port) +
                       " rejects TLS AND drops HTTP junk — likely a stream-proxy that only accepts its own framing "
                       "(SS-AEAD, Trojan, Reality-strict). Not conclusive: could also be a firewalled internal service.",
                       5);
        } else if (tls_failed) {
            role = "TLS handshake failed + mixed probes (ambiguous — internal service / non-TLS-on-TLS-port misconfig)";
        }
        if (!role.empty()) port_roles.push_back({pf.port, role});
    }

    // ---- SSH role classification -----------------------------------
    for (auto& o: R.open_tcp) {
        bool is_ssh_std  = (o.port==22 || o.port==2222 || o.port==22222);
        bool has_banner  = !o.banner.empty() && o.banner.rfind("SSH-",0)==0;
        if (is_ssh_std && has_banner)
            port_roles.push_back({o.port, "SSH (advertised banner, standard port) — '" +
                                          printable_prefix(o.banner, 40) + "'"});
        else if (has_banner && !is_ssh_std)
            port_roles.push_back({o.port, "SSH on non-standard port (banner still leaks version) — '" +
                                          printable_prefix(o.banner, 40) + "'"});
    }

    // ---- HTTP-only port roles --------------------------------------
    for (auto& pf: R.fps) {
        if (pf.fp.service == "HTTP" || pf.fp.service == "HTTP?") {
            port_roles.push_back({pf.port, "plain HTTP — " +
                                          (pf.fp.details.empty() ? "no banner" : printable_prefix(pf.fp.details, 90))});
        } else if (pf.fp.service == "HTTP-PROXY") {
            port_roles.push_back({pf.port, "OPEN HTTP PROXY (accepts CONNECT) — " +
                                          printable_prefix(pf.fp.details, 80)});
            flag_major("open HTTP proxy (accepts CONNECT) on :" + std::to_string(pf.port), 20);
        } else if (pf.fp.service == "SOCKS5") {
            port_roles.push_back({pf.port, "OPEN SOCKS5 — " +
                                          printable_prefix(pf.fp.details, 80)});
            flag_major("open SOCKS5 endpoint on :" + std::to_string(pf.port), 20);
        }
    }

    // v2.3: no blanket COMBO penalty — we already combined fresh-cert
    // with sparse-port+hosting above. Blanket combo on arbitrary minors
    // over-penalised any minimal VPS.
    score = std::max(0, std::min(100, score));
    R.score = score;
    if (score >= 85)      R.label = "CLEAN";
    else if (score >= 70) R.label = "NOISY";
    else if (score >= 50) R.label = "SUSPICIOUS";
    else                  R.label = "OBVIOUSLY-VPN";

    const char* color = score>=85?C::GRN : score>=70?C::YEL : score>=50?C::YEL : C::RED;

    // ---- Stack identification (strict, no guessing) ----------------
    string stack_name;
    bool any_wg = std::any_of(R.udp_probes.begin(), R.udp_probes.end(),
                              [](auto& x){return x.first==51820 && x.second.responded;});
    bool any_ovpn_udp = std::any_of(R.udp_probes.begin(), R.udp_probes.end(),
                                    [](auto& x){return x.first==1194 && x.second.responded;});
    bool any_canned    = (j3_canned_ports > 0);
    bool any_bad_ver   = (j3_badver_ports  > 0);
    bool any_short_val = (cert_short_validity_ports > 0);
    if (any_impersonation && xui_cluster_seen)
        stack_name = "Xray-core VLESS+Reality on a 3x-ui/x-ui/Marzban panel install "
                     "(cert impersonates a major brand + multiple panel-preset TLS ports open)";
    else if (any_impersonation)
        stack_name = "Xray-core VLESS+Reality (static dest — TLS cert cloned from a major brand)";
    else if (reality_port_count >= 2)
        stack_name = "Xray-core / sing-box (VLESS+Reality, multi-port)";
    else if (xray_reality_primary)
        stack_name = "Xray-core (VLESS+Reality with HTTP fallback)";
    else if (xray_reality_hidden)
        stack_name = "Xray-core (VLESS+Reality, hidden-mode)";
    else if (any_reality)
        stack_name = "Xray / Reality-compatible TLS steering";
    else if (any_canned || any_bad_ver)
        stack_name = "TLS front + Xray/Trojan stream-layer proxy "
                     "(canned fallback response / invalid HTTP version — not a real web server)";
    else if (any_short_val)
        stack_name = "TLS endpoint with a hand-rolled short-lifetime cert "
                     "(validity < 14d — never issued by real CAs; Xray/Trojan quickfire setup)";
    else if (xui_cluster_seen)
        stack_name = "3x-ui/x-ui/Marzban panel install (multiple preset TLS ports open) — "
                     "VLESS/Trojan/Shadowsocks multiplex likely";
    else if (any_ovpn_udp || openset.count(1194) || openset.count(1193))
        stack_name = "OpenVPN (plaintext wire protocol)";
    else if (any_wg)
        stack_name = "WireGuard (default UDP port)";
    else if (openset.count(8388) || openset.count(8488))
        stack_name = "Shadowsocks (naked default port)";
    else if (proxy_middleware_seen)
        stack_name = "TLS front + stream-layer proxy (Xray / Trojan / SS-AEAD) — TLS handshake is clean, "
                     "but the origin silently drops non-TLS bytes instead of returning HTTP 400 like a real web server";
    else if (any_tls && openset.count(443))
        stack_name = "generic TLS / HTTPS origin (no direct VPN signature)";
    else
        stack_name = "no VPN protocol signature identified";

    printf("\n  %sStack identified:%s  %s%s%s\n",
           col(C::BOLD), col(C::RST),
           col(C::CYN), stack_name.c_str(), col(C::RST));

    if (!port_roles.empty()) {
        printf("\n  %sPer-port classification:%s\n", col(C::BOLD), col(C::RST));
        for (auto& [p, role]: port_roles)
            printf("    %s:%-5d%s  %s\n", col(C::CYN), p, col(C::RST), role.c_str());
    }

    // ---- DPI exposure matrix (new in v2.2) -------------------------
    auto axis = [&](const char* name, const char* level, const string& note) {
        const char* c = !strcmp(level,"HIGH")   ? C::RED :
                        !strcmp(level,"MEDIUM") ? C::YEL :
                        !strcmp(level,"LOW")    ? C::GRN :
                        !strcmp(level,"NONE")   ? C::DIM : C::CYN;
        dpi_axes.push_back({name, string(level) + " — " + note});
        printf("    %-36s %s%-6s%s  %s\n", name, col(c), level, col(C::RST), note.c_str());
    };

    // v2.3 — aggregate HTTPS-probe / panel counters used by matrix rows.
    int https_bad_ver_ports = 0, https_no_server_ports = 0, https_empty_ports = 0, https_ok_real_ports = 0;
    for (auto& pf: R.fps) if (pf.https && pf.https->tls_ok) {
        if (pf.https->responded && pf.https->version_anomaly)                                 ++https_bad_ver_ports;
        else if (pf.https->responded && pf.https->server_hdr.empty())                         ++https_no_server_ports;
        else if (!pf.https->responded)                                                        ++https_empty_ports;
        else                                                                                  ++https_ok_real_ports;
    }

    printf("\n  %sDPI exposure matrix:%s\n", col(C::BOLD), col(C::RST));
    // 1. Port-based (TSPU curated list)
    {
        int naive_hits = 0;
        for (int p: {1194, 1723, 500, 4500, 51820, 1701, 8388, 8488, 8090, 10808, 10809})
            if (openset.count(p)) ++naive_hits;
        axis("Port-based (default VPN ports)",
             naive_hits >= 2 ? "HIGH" : naive_hits == 1 ? "MEDIUM" : "LOW",
             naive_hits ? std::to_string(naive_hits) + " default VPN port(s) open" :
                          "no default VPN ports among open set");
    }
    // 2. Protocol handshake signature (plaintext VPN reply)
    {
        bool ovpn = any_ovpn_udp || openset.count(1194);
        bool wg   = any_wg;
        bool ike  = false;
        for (auto& [p,u]: R.udp_probes) if ((p==500||p==4500) && u.responded) ike = true;
        if (ovpn || wg)      axis("Protocol handshake signature", "HIGH",
                                  string(ovpn?"OpenVPN ":"") + (wg?"WireGuard":"") + " signature matched");
        else if (ike)        axis("Protocol handshake signature", "MEDIUM", "IKEv2 responds on control ports");
        else if (any_reality) axis("Protocol handshake signature", "LOW", "TLS 1.3 handshake looks normal (Reality identified by cert-steering, not handshake bytes)");
        else if (any_tls)    axis("Protocol handshake signature", "LOW", "TLS handshake looks normal");
        else                 axis("Protocol handshake signature", "NONE", "no TLS / no VPN protocol replies");
    }
    // 3. Cert-steering (Reality discriminator)
    {
        if (any_reality)            axis("Cert-steering (Reality discriminator)", "HIGH",
                                         "Reality steering pattern positively identified");
        else {
            bool same_cert_seen = false, varies_seen = false;
            for (auto& pf: R.fps) if (pf.sni) {
                if (pf.sni->same_cert_always) same_cert_seen = true;
                else if (!pf.sni->default_cert_only) varies_seen = true;
            }
            if (varies_seen)        axis("Cert-steering (Reality discriminator)", "NONE",
                                         "cert varies per SNI (multi-tenant TLS, not Reality)");
            else if (same_cert_seen) axis("Cert-steering (Reality discriminator)", "NONE",
                                          "single default cert — plain server, not Reality");
            else                    axis("Cert-steering (Reality discriminator)", "NONE",
                                         "no TLS to test");
        }
    }
    // 4. ASN classifier
    //    v2.3: hosting ASN is the NORM for public servers. TSPU does look
    //    at ASN class, but on its own it only enables further checks — it
    //    is not a positive VPN verdict. Downgrade from MEDIUM to LOW/NONE.
    {
        if (hosting_hits >= 2)   axis("ASN classifier (VPS/hosting)", "LOW",
                                      std::to_string(hosting_hits) + " sources classify the ASN as hosting/datacenter — normal for any public server");
        else if (hosting_hits == 1) axis("ASN classifier (VPS/hosting)", "LOW",
                                         "1 source classifies the ASN as hosting (ambiguous)");
        else                     axis("ASN classifier (VPS/hosting)", "NONE",
                                      "no GeoIP source classifies the ASN as hosting");
    }
    // 5. VPN/Proxy tags from threat-intel
    //    v2.3: single-source tag is noise. Only multi-source consensus is
    //    a real signal.
    {
        if (tor_hits) {
            axis("Threat-intel tags (VPN/Proxy/Tor)", "HIGH",
                 std::to_string(tor_hits) + " sources tag this IP as Tor exit");
        } else if (vpn_hits >= 2 || proxy_hits >= 2) {
            string n = std::to_string(vpn_hits) + " VPN / " + std::to_string(proxy_hits) + " proxy tags";
            axis("Threat-intel tags (VPN/Proxy/Tor)", "HIGH", n);
        } else if (vpn_hits || proxy_hits) {
            axis("Threat-intel tags (VPN/Proxy/Tor)", "NONE",
                 "1 single-source tag — false-positive rate too high to count");
        } else {
            axis("Threat-intel tags (VPN/Proxy/Tor)", "NONE", "no VPN/Proxy/Tor tag from any source");
        }
    }
    // 6. Cert freshness + short-validity (v2.3)
    //    short-validity (< 14d total) is NEVER legitimate — LE issues 90d,
    //    commercial CAs issue 30-365d. A 6-day cert is a hand-rolled
    //    short-lived self-signed or a test-CA cert typical of Xray/Trojan
    //    quickfire installs.
    {
        if (cert_short_validity_ports >= 1)
            axis("Cert freshness (new-LE watch)", "HIGH",
                 std::to_string(cert_short_validity_ports) +
                 " port(s) with impossibly short cert validity (<14d total — real CAs never issue this)");
        else if (cert_fresh_ports >= 1)
            axis("Cert freshness (new-LE watch)", "MEDIUM",
                 std::to_string(cert_fresh_ports) + " port(s) with cert <14d old");
        else
            axis("Cert freshness (new-LE watch)", "LOW", "no suspiciously fresh certs");
    }
    // 7. Active junk probing (J3)
    {
        if (j3_ports_checked == 0)   axis("Active junk probing (J3)", "NONE", "no J3 probes ran");
        else if (j3_silent_total >= j3_resp_total && j3_silent_total >= 4)
            axis("Active junk probing (J3)", "MEDIUM",
                 std::to_string(j3_silent_total) + " silent / " + std::to_string(j3_resp_total) +
                 " resp — strict TLS-only posture (fingerprintable by TSPU)");
        else if (j3_resp_total >= j3_silent_total)
            axis("Active junk probing (J3)", "LOW",
                 std::to_string(j3_resp_total) + " responses — looks like a permissive web-origin");
        else
            axis("Active junk probing (J3)", "LOW",
                 std::to_string(j3_silent_total) + " silent / " + std::to_string(j3_resp_total) + " resp");
    }
    // 8. Open-port profile
    //    v2.3: single-port :443 is NOT a red flag on its own — many
    //    corporate reverse-proxies / CDNs look identical. Downgrade.
    //    v2.3: but if the sparse set is dominated by 3x-ui/x-ui/Marzban
    //    panel preset ports, the open-port profile IS anomalous.
    {
        size_t np = R.open_tcp.size();
        if (xui_cluster_seen)
            axis("Open-port profile (sparsity)", "HIGH",
                 std::to_string(np) + " ports open, dominated by the 3x-ui/x-ui/Marzban preset TLS cluster " +
                 std::to_string(xui_cluster_hits) + " hits (2053/2083/2087/2096/8443/…) — installer fingerprint");
        else if (np == 1 && openset.count(443))
            axis("Open-port profile (sparsity)", "LOW",
                 ":443 only — common for reverse-proxies, corporate apps, and single-purpose hosts alike");
        else if (np <= 3 && openset.count(443) && hosting_hits)
            axis("Open-port profile (sparsity)", "LOW",
                 "sparse (<=3 ports) on hosting ASN — ambiguous (minimal corp server / proxy VPS)");
        else if (np >= 8)
            axis("Open-port profile (sparsity)", "NONE",
                 std::to_string(np) + " ports open — diverse service host, clearly not a dedicated proxy");
        else
            axis("Open-port profile (sparsity)", "LOW",
                 std::to_string(np) + " ports open");
    }
    // 9. TLS posture quality
    {
        int bad = tls_not_13_ports + alpn_not_h2_ports + cert_self_signed_ports;
        if (bad >= 2) axis("TLS hygiene (1.3 + h2 + trusted-CA)", "MEDIUM",
                           std::to_string(bad) + " hygiene issues (weak TLS / ALPN / self-signed)");
        else if (bad == 1) axis("TLS hygiene (1.3 + h2 + trusted-CA)", "LOW", "1 hygiene issue");
        else if (any_tls)  axis("TLS hygiene (1.3 + h2 + trusted-CA)", "LOW", "TLS posture is clean (1.3 + h2 + trusted-CA)");
        else               axis("TLS hygiene (1.3 + h2 + trusted-CA)", "NONE", "no TLS observed");
    }
    // 10. Cert impersonation (v2.3) — famous-brand CN on a non-owning ASN.
    //     This is the cheapest tell for a Reality-static setup: someone
    //     points `dest=www.amazon.com` (or Apple/Microsoft/Google/...) and
    //     Reality clones that cert. ASN-to-brand ownership check rules out
    //     legitimate CDN fronting.
    {
        if (any_impersonation) {
            int cnt = 0; string bdom;
            for (auto& pf: R.fps) if (pf.sni && pf.sni->cert_impersonation) {
                ++cnt; if (bdom.empty()) bdom = pf.sni->brand_claimed;
            }
            // Also count server-header brand hits (independent channel).
            int svr_cnt = 0;
            for (auto& pf: R.fps)
                if (pf.https && pf.https->tls_ok && !pf.https->server_hdr.empty()) {
                    string sb = server_header_brand(pf.https->server_hdr);
                    if (!sb.empty() && !asn_owns_brand(sb, asn_orgs_all)) {
                        ++svr_cnt; if (bdom.empty()) bdom = sb;
                    }
                }
            string detail = std::to_string(cnt) + " cert port(s)";
            if (svr_cnt > 0) detail += " + " + std::to_string(svr_cnt) + " Server-header port(s)";
            detail += " claim brand '" + bdom + "' on an ASN that does NOT own it — Reality `dest=` cloning signature";
            axis("Cert impersonation (Reality-static tell)", "HIGH", detail);
        } else {
            axis("Cert impersonation (Reality-static tell)", "NONE",
                 "no cert claims a major-brand domain the ASN doesn't own");
        }
    }
    // 11. Active HTTP-over-TLS probe (v2.3) — after the TLS handshake we
    //     actually send `GET / HTTP/1.1` and read the reply. Real web
    //     origins always answer (200/301/404/502 with a Server: header).
    //     Silence, missing Server, or a malformed HTTP version are the
    //     hard tells for middleware / Xray fallback.
    {
        if (https_bad_ver_ports >= 1) {
            axis("Active HTTP-over-TLS probe", "HIGH",
                 std::to_string(https_bad_ver_ports) +
                 " port(s) returned an invalid HTTP version (HTTP/0.0 or malformed) — no real web server emits this");
        } else if (https_empty_ports >= 1) {
            axis("Active HTTP-over-TLS probe", "MEDIUM",
                 std::to_string(https_empty_ports) +
                 " port(s) accept TLS but return 0 bytes to a valid GET / — stream-layer proxy tell");
        } else if (https_no_server_ports >= 1) {
            axis("Active HTTP-over-TLS probe", "MEDIUM",
                 std::to_string(https_no_server_ports) +
                 " port(s) responded without a Server: header — nginx/Apache/Caddy always set one");
        } else if (https_ok_real_ports >= 1) {
            axis("Active HTTP-over-TLS probe", "LOW",
                 std::to_string(https_ok_real_ports) +
                 " port(s) returned a well-formed HTTP reply with a Server: header — looks like a real web origin");
        } else {
            axis("Active HTTP-over-TLS probe", "NONE", "no TLS port to probe");
        }
    }
    // 12. 3x-ui / x-ui / Marzban panel-port cluster (v2.3) — the panel
    //     installers preset an exact TLS-port set that regular web hosts
    //     almost never open together.
    {
        if (xui_cluster_hits >= 2)
            axis("Panel-port cluster (3x-ui/x-ui/Marzban)", "HIGH",
                 std::to_string(xui_cluster_hits) + " of the preset panel TLS ports are open "
                 "(2053/2083/2087/2096/8443/8880/6443/7443/9443)");
        else if (xui_cluster_hits == 1)
            axis("Panel-port cluster (3x-ui/x-ui/Marzban)", "MEDIUM",
                 "1 panel-preset TLS port open — ambiguous (could be Cloudflare-Origin anyway)");
        else
            axis("Panel-port cluster (3x-ui/x-ui/Marzban)", "NONE",
                 "no panel-preset TLS ports among open set");
    }
    // 13. J3 canned-fallback / HTTP-anomaly aggregate (v2.3) — real web
    //     servers vary their replies per request (different URIs, methods,
    //     headers). An identical byte-exact reply to multiple distinct
    //     probes is a static fallback page that Xray/Trojan wire up.
    {
        int worst = std::max({j3_canned_ports, j3_badver_ports, j3_raw_nonhttp_ports});
        if (j3_canned_ports >= 1 || j3_badver_ports >= 1)
            axis("J3 canned/anomaly aggregate", "HIGH",
                 std::to_string(j3_canned_ports) + " canned / " +
                 std::to_string(j3_badver_ports) + " bad-version / " +
                 std::to_string(j3_raw_nonhttp_ports) + " raw-non-HTTP port(s) — static fallback signature");
        else if (j3_raw_nonhttp_ports >= 1)
            axis("J3 canned/anomaly aggregate", "MEDIUM",
                 std::to_string(j3_raw_nonhttp_ports) + " port(s) return non-HTTP bytes — Shadowsocks/Trojan/custom proxy");
        else if (j3_ports_checked)
            axis("J3 canned/anomaly aggregate", "LOW", "no canned / bad-version / raw-non-HTTP replies");
        else
            axis("J3 canned/anomaly aggregate", "NONE", "no J3 probes ran");
        (void)worst;
    }

    // ---- Signal lists ----------------------------------------------
    printf("\n  %sStrong signals (%zu)%s  [%s!%s = real evidence of VPN/proxy]\n",
           col(C::BOLD), signals_major.size(), col(C::RST), col(C::RED), col(C::RST));
    if (signals_major.empty()) printf("    (none)\n");
    else for (auto& s: signals_major) printf("    %s[!]%s %s\n", col(C::RED), col(C::RST), s.c_str());

    printf("\n  %sSoft signals (%zu)%s  [%s-%s = suggestive pattern, not proof]\n",
           col(C::BOLD), signals_minor.size(), col(C::RST), col(C::YEL), col(C::RST));
    if (signals_minor.empty()) printf("    (none)\n");
    else for (auto& s: signals_minor) printf("    %s[-]%s %s\n", col(C::YEL), col(C::RST), s.c_str());

    printf("\n  %sInformational (%zu)%s  [%si%s = observation only, no penalty — normal sites can have these]\n",
           col(C::BOLD), notes.size(), col(C::RST), col(C::CYN), col(C::RST));
    if (notes.empty()) printf("    (none)\n");
    else for (auto& [tag, s]: notes)
        printf("    %s[i]%s %s%s%s  %s\n",
               col(C::CYN), col(C::RST),
               col(C::DIM), tag.c_str(), col(C::RST), s.c_str());

    printf("\n  %sFinal score:%s %s%d/100%s  verdict: %s%s%s\n",
           col(C::BOLD), col(C::RST), col(C::BOLD), score, col(C::RST),
           col(color), R.label.c_str(), col(C::RST));

    // ---- Hardening suggestions (actionable) ------------------------
    // Built from strong/soft signals AND from informational observations —
    // so every "[i] single-443" etc. comes with a concrete fix even
    // though it didn't cost any score.
    printf("\n  %sHardening suggestions:%s\n", col(C::BOLD), col(C::RST));
    auto sug = [](const char* tag, const char* body) {
        printf("    %s[%s]%s\n      %s\n", col(C::GRN), tag, col(C::RST), body);
    };

    bool any_sug = false;
    auto has_note = [&](const string& t) {
        for (auto& [k,_]: notes) if (k == t) return true;
        return false;
    };

    // Protocol-level hardening
    if (xray_reality_primary && xray_reality_hidden) {
        sug("reality-mixed",
            "Mixed Reality config: one port uses HTTP-fallback, another is hidden-mode.\n"
            "      The hidden port exposes the silent-on-junk DPI signature. Either drop\n"
            "      the duplicate listener, or configure the Reality `fallback` block so\n"
            "      EVERY port returns HTTP 400/502 on non-handshake traffic (match nginx).");
        any_sug = true;
    } else if (xray_reality_hidden) {
        sug("reality-hidden",
            "Reality hidden-mode: TLS handshake ok, but non-TLS bytes are silently dropped.\n"
            "      That pattern is DPI-detectable (TSPU/GFW fingerprint it).\n"
            "      Fix: set `dest=` to a real HTTPS site you don't control, and configure\n"
            "      `fallback` so the server returns its own 400/502 page on unrecognised bytes.");
        any_sug = true;
    } else if (xray_reality_primary) {
        sug("reality-ok",
            "Reality HTTP-fallback is wired correctly: junk bytes get HTTP 400, which is\n"
            "      indistinguishable from nginx/Apache. No action needed.");
        any_sug = true;
    }
    if (proxy_middleware_seen) {
        sug("proxy-middleware",
            "TLS is clean on this port, but the origin silently drops every HTTP-junk probe\n"
            "      instead of returning HTTP 400 like nginx/Apache/Caddy would. That silence\n"
            "      is the proxy-middleware signature TSPU actively tests for. Fix: put a real\n"
            "      nginx in front that handles both the TLS handshake AND the HTTP fallback,\n"
            "      so non-TLS bytes hit nginx's own 400 page.");
        any_sug = true;
    }
    if (reality_port_count >= 2) {
        char buf[256];
        snprintf(buf, sizeof(buf),
            "Reality is listening on %d ports of the same IP. ASN/port sweeps flag multi-port\n"
            "      TLS-steering anomalies; keep Reality on a single port and populate the\n"
            "      other ports with real services (or close them).", reality_port_count);
        sug("reality-multiport", buf);
        any_sug = true;
    }

    // Hardened-VPN-protocol hardening
    if (any_ovpn_udp || openset.count(1194) || openset.count(1193)) {
        sug("openvpn",
            "OpenVPN on default port 1194: TSPU/GFW drop this on the first HARD_RESET.\n"
            "      Wrap in TLS (stunnel / Cloak) or migrate to VLESS+Reality on :443.");
        any_sug = true;
    }
    if (any_wg) {
        sug("wireguard",
            "WireGuard on UDP/51820 answers its handshake — the handshake is a fixed-offset\n"
            "      signature TSPU already has. Use amneziawg (obfuscated WG) or tunnel WG\n"
            "      inside a TCP-TLS wrapper if you need to survive active DPI.");
        any_sug = true;
    }
    if (openset.count(8388) || openset.count(8488)) {
        sug("shadowsocks",
            "Shadowsocks on its default port is trivially probed via AEAD-length oracle.\n"
            "      Wrap it with v2ray/xray stream-settings + TLS, or drop it for VLESS+Reality.");
        any_sug = true;
    }
    if (openset.count(3389)) {
        sug("rdp",
            "RDP/3389 is reachable from the Internet — not a VPN issue, but a critical\n"
            "      attack surface. Firewall it; expose only through a jump host or VPN.");
        any_sug = true;
    }

    // --- v2.3 hardening ------------------------------------------------
    if (any_impersonation) {
        // Brand domain: prefer the TLS-cert brand if we caught it there,
        // else fall back to the Server-header-derived brand.
        string bdom;
        for (auto& pf: R.fps)
            if (pf.sni && pf.sni->cert_impersonation && !pf.sni->brand_claimed.empty()) {
                bdom = pf.sni->brand_claimed; break;
            }
        if (bdom.empty())
            for (auto& pf: R.fps)
                if (pf.https && pf.https->tls_ok && !pf.https->server_hdr.empty()) {
                    string sb = server_header_brand(pf.https->server_hdr);
                    if (!sb.empty()) { bdom = sb; break; }
                }
        string body =
            "Reality `dest=` points at '" + bdom + "', so the endpoint serves a cert (and/or\n"
            "      `Server:` banner) for that brand on an ASN that doesn't own it. This is the\n"
            "      cheapest tell in the book — DPI engines cross-reference cert subject + HTTP\n"
            "      Server-header + ASN ownership. Pick a `dest=` on the SAME ASN/CDN as your VPS\n"
            "      (e.g. a small regional site on the same hosting provider's netblock), or —\n"
            "      safer — move to a real domain you own with its own full LE chain. Never pick\n"
            "      amazon/apple/microsoft/google/cloudflare on a random VPS.";
        sug("cert-impersonation", body.c_str());
        any_sug = true;
    }
    if (cert_short_validity_ports > 0) {
        sug("cert-short-validity",
            "One of the certs has total validity < 14 days. Real CAs never issue that:\n"
            "      Let's Encrypt = 90d, commercial = 30d+. A sub-14d cert is a hand-rolled\n"
            "      short-lifetime self-signed or a test-CA issuance — classic Xray/Trojan\n"
            "      quickfire setup. Fix: switch to LE (certbot / lego / acme.sh) with auto-renew,\n"
            "      OR front the origin behind a CDN so visitors see the CDN's cert instead.");
        any_sug = true;
    }
    if (j3_canned_ports > 0 || j3_badver_ports > 0) {
        sug("canned-fallback",
            "At least one port returns a canned fallback (same byte-exact first line for\n"
            "      different probes) or a malformed HTTP version — classic Xray `fallback` /\n"
            "      Trojan default handler. Real nginx/Apache/Caddy vary their replies per\n"
            "      request (different URIs -> different statuses, different bodies). Fix:\n"
            "      put a real nginx in front with a proper error-page map, and make the Xray\n"
            "      `fallbacks` point at that nginx so non-handshake bytes get REAL HTTP.");
        any_sug = true;
    }
    if (https_bad_ver_ports > 0) {
        sug("http-version-anomaly",
            "Active HTTP-over-TLS probe got back an invalid HTTP version (HTTP/0.0 or\n"
            "      similar). No real web server emits that — it's generated by Xray/Trojan's\n"
            "      stream handler when it partially decodes a non-protocol request. Same fix as\n"
            "      above: wire the `fallback` block to a real nginx so it emits `HTTP/1.1 400`.");
        any_sug = true;
    }
    if (https_empty_ports > 0 && !any_reality) {
        sug("http-silent-origin",
            "Active HTTP-over-TLS probe completed the handshake but got zero response bytes\n"
            "      back to a plain `GET /`. A legitimate web origin always answers (200 / 301 /\n"
            "      404 / 502). Silence is the stream-layer-proxy signature (Xray/Trojan/SS-AEAD\n"
            "      that only speaks its own framing). Fix: add an HTTP `fallback` that proxies\n"
            "      to a real web root so `GET /` always returns something with a `Server:` header.");
        any_sug = true;
    }
    if (https_no_server_ports > 0 && !any_reality) {
        sug("http-missing-server-header",
            "The origin replies to HTTP but without a `Server:` header. nginx/Apache/Caddy/CDNs\n"
            "      set one unambiguously. Absence is a middleware / custom-handler tell — fix by\n"
            "      fronting the origin with a real nginx that sets `server_tokens on` (or even\n"
            "      forges a plausible `Server: cloudflare` / `Server: nginx/1.24.0`).");
        any_sug = true;
    }
    if (xui_cluster_seen) {
        sug("xui-panel",
            "The open-port profile matches the 3x-ui / x-ui / Marzban panel installer set\n"
            "      (2053/2083/2087/2096/8443/8880/6443/7443/9443). That exact cluster is the\n"
            "      single strongest fingerprint a TSPU-class DPI engine looks for. Fix: close\n"
            "      the unused panel ports (keep ONE listener on :443 on the real Reality inbound),\n"
            "      firewall the panel UI to admin source IPs only, and avoid the defaults.");
        any_sug = true;
    }

    // TLS hygiene
    for (auto& pf: R.fps)
        if (pf.tls && pf.tls->ok && pf.tls->version != "TLSv1.3") {
            char buf[256];
            snprintf(buf, sizeof(buf),
                "Upgrade TLS to 1.3 on :%d (current: %s). Modern clients expect TLS 1.3;\n"
                "      VLESS/Reality requires it. Bump the OpenSSL/nginx config.",
                pf.port, pf.tls->version.c_str());
            sug("tls-version", buf);
            any_sug = true;
        }
    if (cert_self_signed_ports > 0) {
        sug("tls-self-signed",
            "Self-signed TLS cert: browsers reject it instantly, and it is the classic\n"
            "      Shadowsocks/Trojan/test-setup signature. Issue a real cert (Let's\n"
            "      Encrypt on a real domain) or front the endpoint with a CDN.");
        any_sug = true;
    }

    // Observation-driven hardening (from notes[])
    if (has_note("single-443")) {
        sug("port-profile",
            "Only :443 is reachable. Not a red flag on its own — TSPU classifies by the\n"
            "      bytes on the wire, not by how many ports you open. But if you want to\n"
            "      look like a typical corporate web host, open :80 with a 301 HTTP→HTTPS\n"
            "      redirect, serve a real-looking page on `/` (not the default nginx page),\n"
            "      and optionally add a firewalled :22 or :25 so the host has 'context'.");
        any_sug = true;
    }
    if (has_note("ssh-22")) {
        sug("ssh-banner",
            "SSH/22 is open with a default banner. It doesn't tag you as a VPN, but it\n"
            "      does tell every ASN-sweep that you run a real server. Move SSH to a\n"
            "      high port (40000+) and firewall it to known admin source IPs.");
        any_sug = true;
    }
    if (cert_fresh_ports > 0 && sparse_vps_profile) {
        sug("cert-fresh",
            "Fresh cert (<14d) on a sparse-port hosting host is a classical 'new VLESS\n"
            "      instance' fingerprint. Fix: use a long-lived wildcard cert on a domain\n"
            "      you've owned >90d, or front the origin behind a CDN (Cloudflare free\n"
            "      tier) so visitors see the CDN's cert instead of yours.");
        any_sug = true;
    } else if (has_note("cert-fresh")) {
        sug("cert-fresh",
            "Fresh cert (<14d) is normal LE rotation on its own. Only becomes a signal\n"
            "      when combined with hosting-ASN + sparse port profile. No action needed\n"
            "      unless you're also on a single-purpose VPS profile.");
        any_sug = true;
    }
    if (has_note("asn-hosting") && !any_reality && !proxy_middleware_seen) {
        sug("asn-hosting",
            "Being on a hosting ASN is the norm for every public server — this alone is\n"
            "      NOT a VPN signal. TSPU does use ASN as a gate for deeper checks, but\n"
            "      what it then verifies is the TLS/HTTP behaviour, not the ASN itself.\n"
            "      If you want to escape the 'hosting ASN' category entirely, the only\n"
            "      clean move is a residential-ASN proxy in front (rare) or a CDN.");
        any_sug = true;
    }
    if (has_note("geo-vpn") || has_note("geo-proxy")) {
        sug("threat-intel",
            "One of the 9 GeoIP providers (3 EU / 3 RU / 3 global) tagged this IP as\n"
            "      VPN/proxy. Single-source tags are very noisy (false positives are common).\n"
            "      Fix only if it blocks you in practice: rotate to a fresh IP, or if IP\n"
            "      reputation really matters to your use-case, use an IP on a residential /\n"
            "      business ASN instead of hosting.");
        any_sug = true;
    }

    if (!any_sug)
        printf("    (no actionable hardening — protocol posture looks clean)\n");

    // ---- v2.4 — TSPU / ТСПУ emulation verdict ----------------------------
    // Emulates what Roskomnadzor's TSPU classifier would decide for this
    // destination. The ТСПУ rule set (as reconstructed from traffic-analysis
    // research and the methodika) uses three tiers:
    //   (A) Immediate-block: named protocol signatures detected, known-bad
    //       ports, direct VPN/proxy handshake replies.
    //   (B) Throttle / QoS: Reality-like patterns without a direct
    //       signature, identified obfuscation (AmneziaWG, canned fallback,
    //       cert impersonation on known-foreign ASN).
    //   (C) Allow: no anomalous wire behaviour, legit-looking TLS+HTTP.
    //
    // This section translates our verdict signals into the 3-tier TSPU
    // output a Russian DPI operator would emit for this host.
    // ---------------------------------------------------------------------
    printf("\n  %sТСПУ / TSPU classification (emulated Russian DPI verdict):%s\n",
           col(C::BOLD), col(C::RST));
    {
        struct TspuRule { const char* name; bool hit; const char* why; };
        vector<TspuRule> rules;
        // A-tier (immediate block)
        bool ovpn_hit = any_ovpn_udp || openset.count(1194);
        bool wg_hit   = any_wg;
        bool ike_hit  = false;
        bool l2tp_hit = false, hysteria_hit = false, amnezia_hit = false;
        for (auto& [p,u]: R.udp_probes) if ((p==500||p==4500) && u.responded) ike_hit = true;
        for (auto& [p,u]: R.udp_extra) {
            if (p==1701 && u.responded) l2tp_hit = true;
            if (p==36712 && u.responded) hysteria_hit = true;
            if ((p==55555 || p==51820) && u.responded) amnezia_hit = true;
        }
        rules.push_back({"OpenVPN wire signature",      ovpn_hit,     "UDP/1194 HARD_RESET_CLIENT reply OR TCP/1194 open"});
        rules.push_back({"WireGuard wire signature",    wg_hit,       "UDP/51820 MessageInitiation reply"});
        rules.push_back({"AmneziaWG obfuscation",       amnezia_hit,  "WireGuard with Sx=8 junk prefix accepted (obfuscation params detected)"});
        rules.push_back({"Hysteria2 default port",      hysteria_hit, "UDP/36712 replied to QUIC-initial"});
        rules.push_back({"L2TP SCCRQ reply",            l2tp_hit,     "UDP/1701 L2TP control-channel signature"});
        rules.push_back({"IKE responder",               ike_hit,      "UDP/500 or UDP/4500 IKEv2 SA_INIT reply (IPsec endpoint)"});
        rules.push_back({"SSTP VPN (TLS-wrapped)",      R.sstp && R.sstp->is_vpn_like, "HTTPS/443 SSTP_DUPLEX_POST / sra_{BA195980-...} replied"});
        bool shadowsocks_default = openset.count(8388) > 0 || openset.count(8488) > 0;
        rules.push_back({"Shadowsocks default port",    shadowsocks_default, "TCP/8388 or TCP/8488 open"});
        bool socks_open = openset.count(1080) > 0 || openset.count(1081) > 0;
        rules.push_back({"Open SOCKS5 proxy",           socks_open,   "TCP/1080 SOCKS5 greeting accepted"});
        // v2.5.5 - direct tspu-observable a-tier rules.
        // keep these BEFORE b-tier starts; update A_end below if count changes.
        bool tspu_redirect_a = false;
        for (auto& pf: R.fps) if (pf.fp.tspu_redirect) { tspu_redirect_a = true; break; }
        rules.push_back({"TSPU http redirect to warning", tspu_redirect_a,
                         "HTTP 302 Location: matches operator block/warning page"});
        rules.push_back({"BGP-blackhole (tspu type B)",    R.bgp_blackhole_likely,
                         "all ports TIMEOUT with zero RST - operator ip-list block"});

        // B-tier (throttle / QoS / mark)
        bool reality_hit = any_reality;
        rules.push_back({"Reality/XTLS cert-steering",  reality_hit,  "Reality cert-steering pattern detected"});
        rules.push_back({"Cert impersonation",          any_impersonation, "Cert vouches for a famous brand on non-owning ASN"});
        bool panel_hit = xui_cluster_seen;
        rules.push_back({"3x-ui/x-ui/Marzban panel",    panel_hit,    "Panel-installer preset TLS-port cluster open"});
        bool canned_hit = (j3_canned_ports > 0 || j3_badver_ports > 0);
        rules.push_back({"Canned-fallback / HTTP/0.0",  canned_hit,   "J3 canned-response or invalid HTTP version"});
        bool cert_short = (cert_short_validity_ports > 0);
        rules.push_back({"Short-validity cert (<14d)",  cert_short,   "Cert total_validity < 14d (hand-rolled)"});
        bool proxy_leak_any = false;
        for (auto& pf: R.fps) if (pf.https && pf.https->has_proxy_leak) proxy_leak_any = true;
        rules.push_back({"HTTP proxy-chain leak (§10.2)", proxy_leak_any, "Via / Forwarded / X-Forwarded-For set by origin"});
        bool ct_absent = false;
        for (auto& pf: R.fps) if (pf.ct && pf.ct->queried && !pf.ct->found && pf.ct->err.empty()) ct_absent = true;
        rules.push_back({"CT-log absence",              ct_absent,    "Cert SHA-256 not found in crt.sh — never publicly logged"});
        bool geo_conflict = (R.snitch && R.snitch->ok && (R.snitch->too_low || R.snitch->too_high));
        rules.push_back({"SNITCH geo conflict (§10.1)", geo_conflict, "RTT doesn't match claimed GeoIP country"});
        rules.push_back({"Multi-source VPN/proxy tag",  (vpn_hits >= 2 || proxy_hits >= 2),
                         "≥2 GeoIP providers tag the IP as VPN/proxy"});
        rules.push_back({"Tor exit relay",              (tor_hits >= 1), "At least 1 GeoIP provider tags the IP as Tor exit"});
        // v2.5.5 - b-tier accumulating rule for tspu site-on-path
        bool tspu_hops_hit = (R.trace && R.trace->ok && R.trace->tspu_hops > 0);
        rules.push_back({"TSPU mgmt-subnet in traceroute", tspu_hops_hit,
                         "hop(s) in 10.X.Y.[131-235]/[241-245]/254 range - tspu site on path"});

        // Print rule hit list
        int A_hits = 0, B_hits = 0;
        const int A_end = 11; // first 11 rules = A-tier (9 protocol + 2 tspu direct)
        for (size_t i = 0; i < rules.size(); ++i) {
            if (!rules[i].hit) continue;
            if ((int)i < A_end) ++A_hits; else ++B_hits;
        }

        const char* tier_col   = C::GRN;
        const char* tier_name  = "PASS / ALLOW";
        const char* tier_desc  = "no TSPU-level signatures matched — this host passes inspection";
        if (A_hits > 0) {
            tier_col  = C::RED;
            tier_name = "IMMEDIATE BLOCK";
            tier_desc = "a named VPN/proxy protocol signature matched — this host would be DROPPED on the first TSPU handshake inspection";
        } else if (B_hits >= 2) {
            tier_col  = C::RED;
            tier_name = "BLOCK (accumulative)";
            tier_desc = "≥2 B-tier anomalies matched — TSPU-class classifiers accumulate soft signals and this would cross the block threshold";
        } else if (B_hits == 1) {
            tier_col  = C::YEL;
            tier_name = "THROTTLE / QoS";
            tier_desc = "1 B-tier anomaly — TSPU would tag this host for further monitoring / rate-limiting but not instant block";
        }

        printf("    %sVerdict:%s %s%s%s  —  %s\n",
               col(C::BOLD), col(C::RST),
               col(tier_col), tier_name, col(C::RST), tier_desc);
        printf("    %sTSPU-tier hits:%s A=%d (protocol block) / B=%d (soft anomaly)\n",
               col(C::DIM), col(C::RST), A_hits, B_hits);
        if (A_hits + B_hits > 0) {
            printf("    %sTriggered rules:%s\n", col(C::DIM), col(C::RST));
            for (size_t i = 0; i < rules.size(); ++i) {
                if (!rules[i].hit) continue;
                const char* tag = ((int)i < A_end) ? "A" : "B";
                const char* tc  = ((int)i < A_end) ? C::RED : C::YEL;
                printf("      %s[%s]%s %-36s  %s\n",
                       col(tc), tag, col(C::RST),
                       rules[i].name, rules[i].why);
            }
        }
        printf("    %sWhat the operator sees:%s\n", col(C::DIM), col(C::RST));
        if (A_hits > 0) {
            printf("      The destination matches a protocol signature in the TSPU ruleset. SYN/\n"
                   "      handshake packets to this IP are dropped at the PE router level. End\n"
                   "      users get connection-reset or timeout on every attempt.\n");
        } else if (B_hits >= 2) {
            printf("      The destination accumulates multiple B-tier anomalies. The classifier\n"
                   "      raises confidence above threshold; the IP gets added to the reputation\n"
                   "      list and future flows are dropped/throttled until the signature changes.\n");
        } else if (B_hits == 1) {
            printf("      The destination is flagged but not blocked. Flows are logged, RTT +\n"
                   "      handshake patterns are sampled over time. If the anomaly persists or\n"
                   "      converges with other hosts in the same /24, the block threshold trips.\n");
        } else {
            printf("      The destination looks like a normal TLS web origin. TSPU sampling at\n"
                   "      the TLS-handshake layer finds no named protocol match, no cert-steering,\n"
                   "      no static fallback page. Traffic passes without classifier intervention.\n");
        }
    }

    // ---- Threat-model note ------------------------------------------
    printf("\n  %sThreat-model note:%s\n", col(C::BOLD), col(C::RST));
    printf("    TSPU/GFW classify a destination by what the IP actually does on the wire —\n"
           "    TLS handshake bytes, cert-steering, active HTTP-over-TLS reply shape,\n"
           "    reactions to junk, default-port replies. IP 'reputation' (hosting ASN /\n"
           "    GeoIP VPN tag) is only a coarse pre-filter, so this tool treats it as\n"
           "    informational and focuses the score on the actual protocol signatures at\n"
           "    the endpoint. v2.4 strong signals are: cert impersonation (brand CN on\n"
           "    non-owning ASN), short-validity certs (<14d), canned-fallback pages,\n"
           "    HTTP-version anomalies, 3x-ui/x-ui/Marzban panel-port clusters, CT-log\n"
           "    absence on fresh certs, proxy-chain header leakage (Via/Forwarded/XFF),\n"
           "    SNITCH geo-latency inconsistency (§10.1), modern tunnels (AmneziaWG /\n"
           "    Hysteria2 / TUIC / L2TP / SSTP) — these are expensive-to-fake tells that\n"
           "    map directly to Xray / Reality / Trojan / modern obfuscated VPN stacks.\n"
           "    If every strong signal is 'none' and soft signals are quiet, the host is\n"
           "    essentially invisible to passive DPI regardless of what the ASN looks like.\n"
           "    Reference methodology: Russian OCR методика выявления VPN/Proxy (§5-10).\n");

    return R;
}

// ============================================================================
// CLI helpers
// ============================================================================
static void help() {
    printf("ByeByeVPN — full TSPU/DPI/VPN detectability scanner\n\n");
    printf("Usage:\n");
    printf("  byebyevpn                      interactive menu\n");
    printf("  byebyevpn <ip-or-host>         full scan (recommended)\n");
    printf("  byebyevpn scan <ip>            full scan same\n");
    printf("  byebyevpn ports <ip>           TCP port scan only\n");
    printf("  byebyevpn udp <ip>             UDP probes only\n");
    printf("  byebyevpn tls <ip> [port]      TLS + SNI consistency only\n");
    printf("  byebyevpn j3 <ip> [port]       J3 active probing only\n");
    printf("  byebyevpn geoip <ip>           GeoIP only\n");
    printf("  byebyevpn snitch <ip> [port]   SNITCH RTT/GeoIP consistency (methodika §10.1)\n");
    printf("  byebyevpn trace <ip>           Traceroute hop-count analysis\n");
    printf("  byebyevpn local                scan THIS machine (split-tunnel / VPN procs)\n\n");
    printf("Port-scan modes (default: --full):\n");
    printf("  --full              scan ALL ports 1-65535  (default)\n");
    printf("  --fast              205 curated VPN/proxy/TLS/admin ports\n");
    printf("  --range 1000-2000   scan a port range\n");
    printf("  --ports 80,443,8443 scan explicit port list\n\n");
    printf("Tuning:\n");
    printf("  --threads N     parallel TCP connects   (default 500)\n");
    printf("  --tcp-to MS     TCP connect timeout      (default 800)\n");
    printf("  --udp-to MS     UDP recv timeout         (default 900)\n");
    printf("  --no-color      disable ANSI colors\n");
    printf("  -v / --verbose  verbose\n\n");
    printf("Stealth / privacy (opt-outs for 3rd-party-service leakage and\n");
    printf("behavioural-burst fingerprint — default OFF, full scan behaviour):\n");
    printf("  --stealth       enable --no-geoip + --no-ct + --udp-jitter together\n");
    printf("  --no-geoip      skip all 9 3rd-party GeoIP/ASN lookups (target IP stays local)\n");
    printf("  --no-ct         skip crt.sh Certificate Transparency lookup (cert SHA stays local)\n");
    printf("  --udp-jitter    add 50-300ms random delay between UDP probes (smears port burst)\n\n");
    printf("Save scan output to file (#7):\n");
    printf("  --save           write the scan to '<target>.md' in the current directory\n");
    printf("  --save <path>    write the scan to <path> (still wrapped as markdown)\n");
    printf("                   ANSI colors are stripped from the file; terminal output is unchanged\n\n");
    printf("GeoIP sources (9 providers, 3 EU / 3 RU / 3 global):\n");
    printf("  EU:     ipapi.is, iplocate.io, freeipapi.com\n");
    printf("  RU:     2ip.io/2ip.me, ip-api.com/ru, sypexgeo.net\n");
    printf("  global: ip-api.com, ipwho.is, ipinfo.io\n");
}

static void pause_for_enter() {
    printf("\n%s[Enter] to continue...%s", col(C::DIM), col(C::RST));
    fflush(stdout);
    int c; while ((c = getchar()) != EOF && c != '\n') {}
}

static string ask(const string& prompt) {
    printf("%s", prompt.c_str()); fflush(stdout);
    char buf[256] = {0};
    if (!fgets(buf, sizeof(buf), stdin)) return {};
    return trim(buf);
}

static void interactive() {
    for (;;) {
        system("cls");
        banner();
        printf("  %s[1]%s  Full scan             — end-to-end scan of an IP/hostname\n", col(C::CYN), col(C::RST));
        printf("  %s[2]%s  TCP port scan         — TCP port-scan only\n", col(C::CYN), col(C::RST));
        printf("  %s[3]%s  UDP probes            — OpenVPN / WireGuard / IKE / QUIC / DNS\n", col(C::CYN), col(C::RST));
        printf("  %s[4]%s  TLS + SNI consistency — TLS audit on a single port (Reality discriminator)\n", col(C::CYN), col(C::RST));
        printf("  %s[5]%s  J3 active probing     — TSPU/GFW-style probes on one port\n", col(C::CYN), col(C::RST));
        printf("  %s[6]%s  GeoIP lookup          — country / ASN / VPN-flag aggregation\n", col(C::CYN), col(C::RST));
        printf("  %s[7]%s  Local analysis        — this machine: VPN adapters, split-tunnel, processes\n", col(C::CYN), col(C::RST));
        printf("  %s[8]%s  SNITCH latency check  — RTT + GeoIP consistency (methodika §10.1)\n", col(C::CYN), col(C::RST));
        printf("  %s[9]%s  Traceroute            — ICMP hop count analysis (ttl sweep)\n", col(C::CYN), col(C::RST));
        printf("  %s[0]%s  Exit\n\n", col(C::CYN), col(C::RST));
        string s = ask("  > ");
        if (s.empty()) continue;
        char c = s[0];
        if (c == '0' || c == 'q' || c == 'Q') break;
        else if (c == '1') {
            string t = ask("  target (IP or hostname): ");
            if (!t.empty()) run_full_target(t);
            pause_for_enter();
        } else if (c == '2') {
            string t = ask("  target IP: ");
            if (!t.empty()) {
                auto rs = resolve_host(t);
                auto op = scan_tcp(rs.primary_ip.empty()?t:rs.primary_ip, build_tcp_ports(), g_threads, g_tcp_to);
                for (auto& o: op) printf("  :%-5d  %lldms  %s%s\n", o.port, o.connect_ms,
                                          port_hint(o.port), o.banner.empty()?"":(" banner="+printable_prefix(o.banner,60)).c_str());
            }
            pause_for_enter();
        } else if (c == '3') {
            string t = ask("  target IP: ");
            if (!t.empty()) {
                auto rs = resolve_host(t); string ip = rs.primary_ip.empty()?t:rs.primary_ip;
                auto show=[&](const char*n,int p,UdpResult u){
                    printf("  UDP:%-5d  %-22s  %s\n", p, n,
                        u.responded?("RESP "+std::to_string(u.bytes)+"B "+u.reply_hex).c_str()
                                    :("no answer ("+u.err+")").c_str());
                };
                show("DNS",       53,    dns_probe(ip,53));
                show("IKEv2",     500,   ike_probe(ip,500));
                show("IKE NAT-T", 4500,  ike_probe(ip,4500));
                show("OpenVPN",   1194,  openvpn_probe(ip,1194));
                show("QUIC",      443,   quic_probe(ip,443));
                show("WireGuard", 51820, wireguard_probe(ip,51820));
                show("Tailscale", 41641, wireguard_probe(ip,41641));
            }
            pause_for_enter();
        } else if (c == '4') {
            string t = ask("  target host (used as SNI): ");
            string ps = ask("  port (default 443): ");
            int port = ps.empty() ? 443 : atoi(ps.c_str());
            if (!t.empty()) {
                auto rs = resolve_host(t);
                string ip = rs.primary_ip.empty()?t:rs.primary_ip;
                auto tp = tls_probe(ip, port, t);
                if (!tp.ok) printf("  TLS fail: %s\n", tp.err.c_str());
                else {
                    printf("  %s%s%s / %s / ALPN=%s / %s / %lldms\n",
                           col(C::BOLD), tp.version.c_str(), col(C::RST),
                           tp.cipher.c_str(), tp.alpn.c_str(), tp.group.c_str(), tp.handshake_ms);
                    printf("  cert: %s\n", tp.cert_subject.c_str());
                    printf("  issuer: %s\n", tp.cert_issuer.c_str());
                    printf("  sha256: %s\n", tp.cert_sha256.c_str());
                    auto sc = sni_consistency(ip, port, t);
                    for (auto& e: sc.entries)
                        printf("    alt SNI %-35s  %s  %s\n",
                               e.sni.c_str(),
                               e.ok ? ("sha:"+e.sha.substr(0,16)).c_str() : "fail",
                               (e.ok && e.sha == sc.base_sha) ? "SAME" : "diff");
                    if (sc.reality_like)
                        printf("  %s=> Reality/XTLS pattern: cert covers foreign SNI '%s'%s\n",
                               col(C::GRN), sc.matched_foreign_sni.c_str(), col(C::RST));
                    else if (sc.default_cert_only)
                        printf("  %s=> plain TLS server with a single default cert (NOT Reality)%s\n",
                               col(C::CYN), col(C::RST));
                    else if (sc.same_cert_always)
                        printf("  %s=> identical cert for all SNIs but covers no foreign SNI (inconclusive)%s\n",
                               col(C::YEL), col(C::RST));
                    else
                        printf("  %s=> cert varies per SNI (multi-tenant TLS, NOT Reality)%s\n",
                               col(C::YEL), col(C::RST));
                }
            }
            pause_for_enter();
        } else if (c == '5') {
            string t = ask("  target IP: ");
            string ps = ask("  port: ");
            if (!t.empty() && !ps.empty()) {
                int port = atoi(ps.c_str());
                auto rs = resolve_host(t); string ip = rs.primary_ip.empty()?t:rs.primary_ip;
                auto probes = j3_probes(ip, port);
                for (auto& p: probes) {
                    printf("  %-30s  %s  %dB %s\n", p.name.c_str(),
                        p.responded?"RESP":"SILENT",
                        p.bytes,
                        p.responded ? printable_prefix(p.first_line,60).c_str() : "(dropped)");
                }
            }
            pause_for_enter();
        } else if (c == '6') {
            string t = ask("  IP (blank = your IP): ");
            auto f1 = std::async(std::launch::async, geo_ipapi_is,   t);   // EU
            auto f2 = std::async(std::launch::async, geo_iplocate,   t);
            auto f3 = std::async(std::launch::async, geo_freeipapi,  t);
            auto f4 = std::async(std::launch::async, geo_2ip_ru,     t);   // RU
            auto f5 = std::async(std::launch::async, geo_ipapi_ru,   t);
            auto f6 = std::async(std::launch::async, geo_sypex,      t);
            auto f7 = std::async(std::launch::async, geo_ip_api_com, t);   // global
            auto f8 = std::async(std::launch::async, geo_ipwho_is,   t);
            auto f9 = std::async(std::launch::async, geo_ipinfo_io,  t);
            printf("  %s-- EU --%s\n", col(C::BOLD), col(C::RST));
            print_geo(f1.get()); print_geo(f2.get()); print_geo(f3.get());
            printf("  %s-- RU --%s\n", col(C::BOLD), col(C::RST));
            print_geo(f4.get()); print_geo(f5.get()); print_geo(f6.get());
            printf("  %s-- global --%s\n", col(C::BOLD), col(C::RST));
            print_geo(f7.get()); print_geo(f8.get()); print_geo(f9.get());
            pause_for_enter();
        } else if (c == '7') {
            run_local_analysis();
            pause_for_enter();
        } else if (c == '8') {
            string t = ask("  target IP or host: ");
            string ps = ask("  TCP port (default 443): ");
            int port = ps.empty() ? 443 : atoi(ps.c_str());
            if (!t.empty()) {
                auto rs = resolve_host(t);
                string ip = rs.primary_ip.empty() ? t : rs.primary_ip;
                auto g = geo_ip_api_com(ip);
                string cc = g.country_code;
                auto sn = snitch_check(ip, port, cc);
                printf("  Country (ip-api.com): %s  /  Target port: %d\n", cc.c_str(), port);
                printf("  median=%.1fms  min=%.1fms  max=%.1fms  stddev=%.1fms  samples=%d\n",
                       sn.median_ms, sn.min_ms, sn.max_ms, sn.stddev_ms, sn.samples);
                printf("  Anchors:  Cloudflare=%.1fms  Google=%.1fms  Yandex=%.1fms\n",
                       sn.cf_median_ms, sn.google_median_ms, sn.yandex_median_ms);
                printf("  Expected physical_min for %s: %.0fms\n",
                       cc.c_str(), sn.expected_min_ms);
                printf("  %s%s%s\n",
                       (sn.too_low || sn.too_high) ? col(C::RED) :
                       (sn.high_jitter || sn.anchor_ratio_off) ? col(C::YEL) : col(C::GRN),
                       sn.summary.c_str(), col(C::RST));
            }
            pause_for_enter();
        } else if (c == '9') {
            string t = ask("  target IP or host: ");
            if (!t.empty()) {
                auto rs = resolve_host(t);
                string ip = rs.primary_ip.empty() ? t : rs.primary_ip;
                auto tr = trace_hops(ip, 20);
                if (!tr.ok) { printf("  no hops returned (ICMP filtered)\n"); }
                else {
                    for (auto& h: tr.hops) {
                        if (h.rtt_ms < 0)
                            printf("  %2d  *\n", h.ttl);
                        else
                            printf("  %2d  %-16s  %dms\n", h.ttl, h.addr.c_str(), h.rtt_ms);
                    }
                    printf("  => %d hops, reached=%s, max_rtt_jump=%dms, long_hops>150ms=%d\n",
                           tr.hop_count, tr.reached_target ? "yes" : "no",
                           tr.max_rtt_jump_ms, tr.long_hops);
                }
            }
            pause_for_enter();
        }
    }
}

// ============================================================================
// main
// ============================================================================
int main(int argc, char** argv) {
    enable_vt();
    WSADATA ws; WSAStartup(MAKEWORD(2,2), &ws);
    SSL_library_init(); SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    vector<string> pos;
    for (int i=1;i<argc;++i) {
        string a = argv[i];
        if (a == "--no-color") g_no_color = true;
        else if (a == "--verbose" || a == "-v") g_verbose = true;
        // clamp, negative wraps SO_TIMEO to like 49 days
        else if (a == "--threads" && i+1<argc) g_threads = std::max(1, atoi(argv[++i]));
        else if (a == "--tcp-to" && i+1<argc)  g_tcp_to  = std::max(1, atoi(argv[++i]));
        else if (a == "--udp-to" && i+1<argc)  g_udp_to  = std::max(1, atoi(argv[++i]));
        else if (a == "--stealth") {
            g_stealth = true;
            g_no_geoip = true;
            g_no_ct = true;
            g_udp_jitter = true;
        }
        else if (a == "--no-geoip")  g_no_geoip = true;
        else if (a == "--no-ct")     g_no_ct = true;
        else if (a == "--udp-jitter") g_udp_jitter = true;
        else if (a == "--save") {
            // --save           -> auto-derive <target>.md  (path stays empty here)
            // --save <path>    -> explicit path; only consumed if next arg is
            //                     not another flag (so '--save --no-color' still
            //                     triggers auto-naming with --no-color preserved)
            g_save_requested = true;
            if (i + 1 < argc) {
                string nxt = argv[i + 1];
                if (!nxt.empty() && nxt[0] != '-') {
                    g_save_path = nxt;
                    ++i;
                }
            }
        }
        else if (a == "--full")  g_port_mode = PortMode::FULL;
        else if (a == "--fast")  g_port_mode = PortMode::FAST;
        else if (a == "--range" && i+1<argc) {
            string v = argv[++i];
            size_t dash = v.find('-');
            if (dash != string::npos) {
                g_range_lo = atoi(v.substr(0, dash).c_str());
                g_range_hi = atoi(v.substr(dash+1).c_str());
                g_port_mode = PortMode::RANGE;
            }
        }
        else if (a == "--ports" && i+1<argc) {
            string v = argv[++i]; g_port_list.clear();
            size_t p = 0;
            while (p < v.size()) {
                size_t c = v.find(',', p);
                string tok = v.substr(p, c==string::npos?string::npos:c-p);
                if (!tok.empty()) g_port_list.push_back(atoi(tok.c_str()));
                if (c==string::npos) break;
                p = c+1;
            }
            if (!g_port_list.empty()) g_port_mode = PortMode::LIST;
        }
        else if (a == "--help" || a == "-h" || a == "/?") { help(); return 0; }
        else pos.push_back(a);
    }

    // --save: open the output file BEFORE banner() so the banner is captured
    // too. Auto-derive <target>.md if no path was given. Skip if there's no
    // target on the cli (interactive mode has no single target).
    if (g_save_requested) {
        string path = g_save_path;
        if (path.empty()) {
            string target;
            if (!pos.empty()) {
                static const set<string> cmds = {
                    "scan","full","ports","udp","tls","j3","geoip",
                    "snitch","trace","traceroute","local","me","self","help"
                };
                if (pos.size() >= 2 && cmds.count(pos[0])) target = pos[1];
                else                                       target = pos[0];
            }
            if (target.empty() || target == "local" || target == "me" || target == "self")
                path = "byebyevpn-scan.md";
            else {
                // sanitize filename: replace path / wildcard chars
                string safe;
                for (char c: target) {
                    if (c==':'||c=='/'||c=='\\'||c=='*'||c=='?'||c=='"'||
                        c=='<'||c=='>'||c=='|') safe += '_';
                    else                        safe += c;
                }
                path = safe + ".md";
            }
        }
        g_save_fp = fopen(path.c_str(), "w");
        if (!g_save_fp) {
            fprintf(stderr, "warn: --save: cannot open '%s' for writing (%s); continuing without save\n",
                    path.c_str(), strerror(errno));
        } else {
            g_save_path = path;
            // Note: the scan body itself starts with the ascii banner,
            // which already identifies the tool. We deliberately keep this
            // file header brand-free so the public-audit grep over this
            // source (see README "Audit" section) stays at the existing
            // 2 matches (file banner comment + --help printf), neither of
            // which can leak through the save-file path either.
            time_t now = time(nullptr);
            struct tm* lt = localtime(&now);
            fprintf(g_save_fp, "# Scan report\n\n");
            if (lt) fprintf(g_save_fp,
                            "**Date:** %04d-%02d-%02d %02d:%02d:%02d  \n",
                            1900 + lt->tm_year, 1 + lt->tm_mon, lt->tm_mday,
                            lt->tm_hour, lt->tm_min, lt->tm_sec);
            if (!pos.empty())
                fprintf(g_save_fp, "**Target:** `%s`  \n", pos.back().c_str());
            fprintf(g_save_fp, "**Scanner version:** v2.5.7  \n\n");
            fprintf(g_save_fp, "```\n");
        }
    }

    banner();
    int rc = 0;
    if (pos.empty()) {
        interactive();
    } else {
        string cmd = pos[0];
        if (cmd == "scan" || cmd == "full") {
            if (pos.size() < 2) { printf("need target\n"); rc = 2; goto done; }
            run_full_target(pos[1]);
        } else if (cmd == "ports") {
            if (pos.size() < 2) { printf("need target\n"); rc = 2; goto done; }
            auto rs = resolve_host(pos[1]);
            auto op = scan_tcp(rs.primary_ip.empty()?pos[1]:rs.primary_ip, build_tcp_ports(), g_threads, g_tcp_to);
            for (auto& o: op) printf("  :%-5d  %lldms  %s\n", o.port, o.connect_ms, port_hint(o.port));
        } else if (cmd == "udp") {
            if (pos.size() < 2) { printf("need target\n"); rc = 2; goto done; }
            auto rs = resolve_host(pos[1]); string ip = rs.primary_ip.empty()?pos[1]:rs.primary_ip;
            auto show=[&](const char*n,int p,UdpResult u){
                printf("  UDP:%-5d  %-22s  %s\n", p, n,
                    u.responded?("RESP "+std::to_string(u.bytes)+"B "+u.reply_hex).c_str()
                                :("no answer ("+u.err+")").c_str());
            };
            show("DNS",       53,    dns_probe(ip,53));
            show("IKEv2",     500,   ike_probe(ip,500));
            show("IKE NAT-T", 4500,  ike_probe(ip,4500));
            show("OpenVPN",   1194,  openvpn_probe(ip,1194));
            show("QUIC",      443,   quic_probe(ip,443));
            show("WireGuard", 51820, wireguard_probe(ip,51820));
            show("Tailscale", 41641, wireguard_probe(ip,41641));
        } else if (cmd == "tls") {
            if (pos.size() < 2) { printf("need target\n"); rc = 2; goto done; }
            int port = pos.size() >= 3 ? atoi(pos[2].c_str()) : 443;
            auto rs = resolve_host(pos[1]);
            string ip = rs.primary_ip.empty()?pos[1]:rs.primary_ip;
            auto tp = tls_probe(ip, port, pos[1]);
            if (!tp.ok) { printf("TLS fail: %s\n", tp.err.c_str()); rc = 1; goto done; }
            printf("  %s / %s / ALPN=%s / %s / %lldms\n",
                   tp.version.c_str(), tp.cipher.c_str(), tp.alpn.c_str(),
                   tp.group.c_str(), tp.handshake_ms);
            printf("  cert:   %s\n", tp.cert_subject.c_str());
            printf("  issuer: %s\n", tp.cert_issuer.c_str());
            printf("  sha256: %s\n", tp.cert_sha256.c_str());
            auto sc = sni_consistency(ip, port, pos[1]);
            for (auto& e: sc.entries)
                printf("    %-35s  %s  %s\n", e.sni.c_str(),
                       e.ok ? ("sha:"+e.sha.substr(0,16)).c_str() : "fail",
                       (e.ok && e.sha == sc.base_sha) ? "SAME" : "diff");
            if (sc.reality_like)
                printf("  => Reality/XTLS pattern (cert covers foreign SNI '%s')\n",
                       sc.matched_foreign_sni.c_str());
            else if (sc.default_cert_only)
                printf("  => plain TLS server with single default cert (NOT Reality)\n");
            else if (sc.same_cert_always)
                printf("  => identical cert across SNIs but covers no foreign SNI (inconclusive)\n");
            else
                printf("  => cert varies per SNI (multi-tenant TLS, NOT Reality)\n");
        } else if (cmd == "j3") {
            if (pos.size() < 2) { printf("need target\n"); rc = 2; goto done; }
            int port = pos.size() >= 3 ? atoi(pos[2].c_str()) : 443;
            auto rs = resolve_host(pos[1]); string ip = rs.primary_ip.empty()?pos[1]:rs.primary_ip;
            auto probes = j3_probes(ip, port);
            for (auto& p: probes)
                printf("  %-28s  %s  %dB %s\n", p.name.c_str(),
                    p.responded?"RESP":"SILENT", p.bytes,
                    p.responded ? printable_prefix(p.first_line,60).c_str() : "(dropped)");
        } else if (cmd == "geoip") {
            string ip = pos.size()>=2 ? pos[1] : "";
            auto f1 = std::async(std::launch::async, geo_ipapi_is,   ip);   // EU
            auto f2 = std::async(std::launch::async, geo_iplocate,   ip);
            auto f3 = std::async(std::launch::async, geo_freeipapi,  ip);
            auto f4 = std::async(std::launch::async, geo_2ip_ru,     ip);   // RU
            auto f5 = std::async(std::launch::async, geo_ipapi_ru,   ip);
            auto f6 = std::async(std::launch::async, geo_sypex,      ip);
            auto f7 = std::async(std::launch::async, geo_ip_api_com, ip);   // global
            auto f8 = std::async(std::launch::async, geo_ipwho_is,   ip);
            auto f9 = std::async(std::launch::async, geo_ipinfo_io,  ip);
            printf("  %s-- EU --%s\n", col(C::BOLD), col(C::RST));
            print_geo(f1.get()); print_geo(f2.get()); print_geo(f3.get());
            printf("  %s-- RU --%s\n", col(C::BOLD), col(C::RST));
            print_geo(f4.get()); print_geo(f5.get()); print_geo(f6.get());
            printf("  %s-- global --%s\n", col(C::BOLD), col(C::RST));
            print_geo(f7.get()); print_geo(f8.get()); print_geo(f9.get());
        } else if (cmd == "local" || cmd == "me" || cmd == "self") {
            run_local_analysis();
        } else if (cmd == "snitch") {
            if (pos.size() < 2) { printf("need target\n"); rc = 2; goto done; }
            int port = pos.size() >= 3 ? atoi(pos[2].c_str()) : 443;
            auto rs = resolve_host(pos[1]);
            string ip = rs.primary_ip.empty() ? pos[1] : rs.primary_ip;
            auto g = geo_ip_api_com(ip);
            string cc = g.country_code;
            auto sn = snitch_check(ip, port, cc);
            printf("  target=%s  port=%d  geoip=%s  asn=%s\n",
                   ip.c_str(), port, cc.c_str(), g.asn_org.c_str());
            printf("  median=%.1fms  min=%.1fms  max=%.1fms  stddev=%.1fms  samples=%d\n",
                   sn.median_ms, sn.min_ms, sn.max_ms, sn.stddev_ms, sn.samples);
            printf("  anchors: cf=%.1fms  google=%.1fms  yandex=%.1fms\n",
                   sn.cf_median_ms, sn.google_median_ms, sn.yandex_median_ms);
            printf("  expected-min for %s = %.0fms\n", cc.c_str(), sn.expected_min_ms);
            printf("  => %s\n", sn.summary.c_str());
        } else if (cmd == "trace" || cmd == "traceroute") {
            if (pos.size() < 2) { printf("need target\n"); rc = 2; goto done; }
            auto rs = resolve_host(pos[1]);
            string ip = rs.primary_ip.empty() ? pos[1] : rs.primary_ip;
            int maxh = pos.size() >= 3 ? atoi(pos[2].c_str()) : 18;
            auto tr = trace_hops(ip, maxh);
            if (!tr.ok) { printf("  no hops returned\n"); rc = 1; goto done; }
            for (auto& h: tr.hops) {
                if (h.rtt_ms < 0) printf("  %2d  *\n", h.ttl);
                else              printf("  %2d  %-16s  %dms\n", h.ttl, h.addr.c_str(), h.rtt_ms);
            }
            printf("  => %d hops, reached=%s, max_rtt_jump=%dms, long_hops>150ms=%d\n",
                   tr.hop_count, tr.reached_target?"yes":"no",
                   tr.max_rtt_jump_ms, tr.long_hops);
        } else if (cmd == "help" || cmd == "--help") {
            help();
        } else {
            // treat as target for full scan
            run_full_target(cmd);
        }
    }
done:
    if (g_save_fp) {
        fprintf(g_save_fp, "```\n");
        fclose(g_save_fp);
        g_save_fp = nullptr;
        fprintf(stderr, "saved to %s\n", g_save_path.c_str());
    }
    WSACleanup();
    return rc;
}
