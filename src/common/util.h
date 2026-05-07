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
