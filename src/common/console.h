// SPDX-License-Identifier: GPL-3.0-or-later
// console output: ansi helpers, banner, tee_printf/tee_puts (--save support).
//
// every cpp file that prints to stdout must include this header. the
// "#define printf tee_printf" macro at the bottom redirects every printf
// call into the tee_printf wrapper so it's mirrored into the save file.
//
// rule: include <cstdio> before this header in cpp files. that way the
// macro replaces printf inside the project but not inside <cstdio> itself.
#pragma once

#include <cstdio>
#include <string>

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
    extern const char* ACC;    // accent, section markers
    extern const char* RULE;   // thin rules
    extern const char* ORG;    // between yellow and red
}

const char* col(const char* c);

// enable vt mode + utf-8 console codepage on windows.
void enable_vt();

// print the ascii banner.
void banner();

// "▌ 3/8  title   detail" step header
void section(int step, int total, const char* title, const std::string& detail = std::string());

// rounded one-line box; head and text must be ascii
void card(const char* color, const std::string& head, const std::string& text);

// tee output: stdout (with colors) + g_save_fp (with ansi stripped).
int tee_printf(const char* fmt, ...);
int tee_puts(const char* s);

// project-wide redirect. cpp files that include this get printf -> tee_printf
// transparently. fprintf/fputs/fwrite aren't macroed so stderr stays clean.
#define printf tee_printf
#define puts   tee_puts