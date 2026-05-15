// SPDX-License-Identifier: GPL-3.0-or-later
// generic helpers: string ops, hex, json scrape, name matching, etc.
// nothing here knows about networking or scanning specifics.
#pragma once

#include <string>
#include <vector>
#include <cstddef>

std::string tolower_s(std::string s);
bool        contains(const std::string& h, const std::string& n);
bool        starts_with(const std::string& s, const std::string& p);
std::string trim(const std::string& s);
std::vector<std::string> split(const std::string& s, char sep);
std::string hex_s(const unsigned char* d, size_t n, bool spaces = false);

// utf-16 <-> utf-8 (windows api glue)
std::string  ws2s(const wchar_t* w);
std::wstring s2ws(const std::string& s);

// dumb but bounded JSON-string scraper. NOT a real parser.
// returns the value of "<key>" if present, "" otherwise. accepts both
// quoted strings and bare booleans/numbers (returns the literal text).
std::string json_get_str(const std::string& body, const std::string& key);

// case-insensitive substring check. needle must be ASCII.
bool icontains(const std::string& hay, const char* needle);

// printable preview of bytes (escapes \r\n, dots for non-printables, lim cap).
std::string printable_prefix(const std::string& s, std::size_t lim = 80);

// percentile over a vector<double>. sorts a copy.
double percentile(std::vector<double> v, double pct);

// MAC + sockaddr stringification (used by net + local modules)
std::string mac_to_str(const unsigned char* mac, int len);

// case-insensitive DNS-name match with wildcard ("*.example.com") support.
bool dns_name_match(const std::string& name, const std::string& pat);

// extract CN= from /C=US/.../CN=foo subject_oneline form.
std::string extract_cn(const std::string& subject_oneline);
std::string extract_cn_from_subject(const std::string& subj);

// stealth-mode timing jitter. sleeps a random duration in [min_ms, max_ms]
// using OpenSSL RAND_bytes for the choice. NO-OP when g_stealth is off.
// used between probes (J3, SNI consistency, uTLS, AmneziaWG sweep) so
// scanner-shaped bursts get smeared in time.
void stealth_sleep_ms(int min_ms, int max_ms);

// CSPRNG-backed Fisher-Yates shuffle for a vector<int> of indices. used by
// the J3 probe-order randomizer and similar. no std::mt19937, no LCG.
template <typename T>
void crypto_shuffle(std::vector<T>& v) {
    void csprng_bytes(unsigned char* buf, int n);
    if (v.size() < 2) return;
    for (size_t i = v.size() - 1; i > 0; --i) {
        unsigned char r[4];
        csprng_bytes(r, 4);
        unsigned long rv = ((unsigned long)r[0] << 24) | ((unsigned long)r[1] << 16) |
                           ((unsigned long)r[2] << 8) | (unsigned long)r[3];
        size_t j = (size_t)(rv % (unsigned long)(i + 1));
        std::swap(v[i], v[j]);
    }
}

// expose the CSPRNG byte filler used by crypto_shuffle so the template can
// stay header-only without dragging in <openssl/rand.h>.
void csprng_bytes(unsigned char* buf, int n);