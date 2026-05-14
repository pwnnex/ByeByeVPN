// SPDX-License-Identifier: GPL-3.0-or-later
// console output: ANSI helpers, banner, tee_printf/tee_puts (--save support).
//
// note: every cpp file that prints to stdout MUST include this header. the
// "#define printf tee_printf" macro at the bottom redirects every printf
// call into the tee_printf wrapper so it's mirrored into the save file.
//
// rule: include <cstdio> BEFORE this header in cpp files. that way the
// macro replaces printf inside the project but not inside <cstdio> itself.
#pragma once

#include <cstdio>

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

// enable VT mode + UTF-8 console codepage on windows.
void enable_vt();

// print the ascii banner.
void banner();

// tee output: stdout (with colors) + g_save_fp (with ANSI stripped).
int tee_printf(const char* fmt, ...);
int tee_puts(const char* s);

// project-wide redirect. cpp files that include this get printf -> tee_printf
// transparently. fprintf/fputs/fwrite are NOT macroed so stderr stays clean.
#define printf tee_printf
#define puts   tee_puts