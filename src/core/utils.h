#pragma once
#include <string>
#include <vector>
#include <optional>
#include <set>
#include <map>
#include <chrono>

using std::string;
using std::vector;
using std::optional;
using std::set;

extern bool g_no_color;
extern bool g_verbose;
extern int  g_threads;
extern int  g_tcp_to;
extern int  g_udp_to;

extern bool g_stealth;
extern bool g_no_geoip;
extern bool g_no_ct;
extern bool g_udp_jitter;

extern bool   g_save_requested;
extern FILE*  g_save_fp;
extern string g_save_path;

enum class PortMode { FULL, FAST, RANGE, LIST };
extern PortMode    g_port_mode;
extern int         g_range_lo;
extern int         g_range_hi;
extern std::vector<int> g_port_list;

namespace C {
    extern const char* RST;
    extern const char* BOLD;
    extern const char* DIM;
    extern const char* RED;
    extern const char* GRN;
    extern const char* YEL;
    extern const char* BLU;
    extern const char* MAG;
    extern const char* CYN;
    extern const char* WHT;
}
const char* col(const char* c);

int tee_printf(const char* fmt, ...);
int tee_puts(const char* s);
#define printf tee_printf
#define puts   tee_puts

void enable_vt();
void banner();

string tolower_s(string s);
bool contains(const string& h, const string& n);
bool starts_with(const string& s, const string& p);
string trim(const string& s);
vector<string> split(const string& s, char sep);
string hex_s(const unsigned char* d, size_t n, bool spaces = false);

string json_get_str(const string& body, const string& key);

#ifndef _WIN32
#include <strings.h>
#define _stricmp strcasecmp
#endif
