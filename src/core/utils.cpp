#include "utils.h"
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cctype>

#ifdef _WIN32
#include <windows.h>
#endif

using std::string;
using std::vector;

bool g_no_color = false;
bool g_verbose  = false;
int  g_threads  = 500;
int  g_tcp_to   = 800;
int  g_udp_to   = 900;
bool g_stealth    = false;
bool g_no_geoip   = false;
bool g_no_ct      = false;
bool g_udp_jitter = false;

bool   g_save_requested = false;
FILE*  g_save_fp        = nullptr;
string g_save_path;

PortMode    g_port_mode = PortMode::FULL;
int         g_range_lo  = 1;
int         g_range_hi  = 65535;
std::vector<int> g_port_list;

namespace C {
    const char* RST  = "\x1b[0m";
    const char* BOLD = "\x1b[1m";
    const char* DIM  = "\x1b[2m";
    const char* RED  = "\x1b[31m";
    const char* GRN  = "\x1b[32m";
    const char* YEL  = "\x1b[33m";
    const char* BLU  = "\x1b[34m";
    const char* MAG  = "\x1b[35m";
    const char* CYN  = "\x1b[36m";
    const char* WHT  = "\x1b[97m";
}
const char* col(const char* c) { return g_no_color ? "" : c; }

void save_write_stripped(const char* s, size_t n) {
    if (!g_save_fp || !s || !n) return;
    for (size_t i = 0; i < n; ) {
        if (s[i] == '\x1b' && i + 1 < n && s[i+1] == '[') {
            i += 2;
            while (i < n && !(s[i] >= '@' && s[i] <= '~')) ++i;
            if (i < n) ++i;
        } else {
            fputc((unsigned char)s[i], g_save_fp);
            ++i;
        }
    }
}

int tee_printf(const char* fmt, ...) {
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

int tee_puts(const char* s) {
    if (!s) return 0;
    fputs(s, stdout);
    fputc('\n', stdout);
    if (g_save_fp) {
        save_write_stripped(s, strlen(s));
        fputc('\n', g_save_fp);
    }
    return 0;
}

void enable_vt() {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleOutputCP(CP_UTF8);
#endif
}

void banner() {
    tee_printf("%s%s", col(C::BOLD), col(C::MAG));
    tee_puts(" ____             ____           __     ______  _   _ ");
    tee_puts("| __ ) _   _  ___| __ ) _   _  __\\ \\   / /  _ \\| \\ | |");
    tee_puts("|  _ \\| | | |/ _ \\  _ \\| | | |/ _ \\ \\ / /| |_) |  \\| |");
    tee_puts("| |_) | |_| |  __/ |_) | |_| |  __/\\ V / |  __/| |\\  |");
    tee_puts("|____/ \\__, |\\___|____/ \\__, |\\___| \\_/  |_|   |_| \\_|");
    tee_puts("       |___/            |___/                          ");
    tee_printf("%s", col(C::RST));
    tee_printf("%s  Full TSPU/DPI/VPN detectability scanner  v2.5.7%s\n\n",
           col(C::DIM), col(C::RST));
}

string tolower_s(string s) {
    for (auto& c: s) c = (char)tolower((unsigned char)c);
    return s;
}
bool contains(const string& h, const string& n) { return h.find(n) != string::npos; }
bool starts_with(const string& s, const string& p) {
    return s.size() >= p.size() && std::memcmp(s.data(), p.data(), p.size()) == 0;
}
string trim(const string& s) {
    size_t a=0,b=s.size();
    while(a<b && isspace((unsigned char)s[a])) ++a;
    while(b>a && isspace((unsigned char)s[b-1])) --b;
    return s.substr(a,b-a);
}
vector<string> split(const string& s, char sep) {
    vector<string> r; string cur;
    for (char c: s) {
        if (c == sep) { r.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    r.push_back(cur);
    return r;
}
string hex_s(const unsigned char* d, size_t n, bool spaces) {
    static const char* hex = "0123456789abcdef";
    string s; s.reserve(n*(spaces?3:2));
    for (size_t i=0;i<n;++i) {
        s += hex[(d[i]>>4)&0xF]; s += hex[d[i]&0xF];
        if (spaces && i+1<n) s += ' ';
    }
    return s;
}

string json_get_str(const string& body, const string& key) {
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
