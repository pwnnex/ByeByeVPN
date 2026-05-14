// SPDX-License-Identifier: GPL-3.0-or-later
#include "console.h"
#include "config.h"
#include "winhdr.h"

#include <cstdarg>
#include <cstring>
#include <vector>

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

void enable_vt() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleOutputCP(CP_UTF8);
}

// strip ANSI CSI / SGR sequences (ESC '[' ... letter) when teeing to file.
// we only emit CSI sequences in the codebase, so this is sufficient.
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

int tee_printf(const char* fmt, ...) {
    // in --json mode the human-readable scan output is moved to stderr so
    // stdout carries only the final JSON object. the save file still gets
    // the full ANSI-stripped human output regardless.
    FILE* sink = g_json ? stderr : stdout;
    va_list ap;
    va_start(ap, fmt);
    int n = vfprintf(sink, fmt, ap);
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
    FILE* sink = g_json ? stderr : stdout;
    fputs(s, sink);
    fputc('\n', sink);
    if (g_save_fp) {
        save_write_stripped(s, strlen(s));
        fputc('\n', g_save_fp);
    }
    return 0;
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
    tee_printf("%s  Full TSPU/DPI/VPN detectability scanner  v2.6.0%s\n\n",
               col(C::DIM), col(C::RST));
}