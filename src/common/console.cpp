// SPDX-License-Identifier: GPL-3.0-or-later
#include "console.h"
#include "config.h"
#include "winhdr.h"

#include <algorithm>
#include <cstdarg>
#include <cstring>
#include <string>
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
    // 256-colour accents, every vt console since windows 10 1607
    const char* ACC  = "\x1b[38;5;81m";
    const char* RULE = "\x1b[38;5;60m";
    const char* ORG  = "\x1b[38;5;208m";
}

const char* col(const char* c) { return g_no_color ? "" : c; }

void enable_vt() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleOutputCP(CP_UTF8);
}

// strip ansi csi / sgr sequences (esc '[' ... letter) when teeing to file.
// we only emit csi sequences in the codebase, so this is sufficient.
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
    if (!fmt) return 0;
    // in --json mode the human-readable scan output is moved to stderr so
    // stdout carries only the final json object. the save file still gets
    // the full ansi-stripped human output regardless.
    FILE* sink = g_json ? stderr : stdout;
    va_list ap;
    va_start(ap, fmt);
    int n = vfprintf(sink, fmt, ap);
    va_end(ap);
    if (g_save_fp) {
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

namespace {
// fixed width so the rules line up with the logo
const int BANNER_WIDTH = 55;

void rule_line(int width) {
    tee_printf("  %s", col(C::RULE));
    for (int i = 0; i < width; ++i) tee_printf("\xe2\x94\x80");
    tee_printf("%s\n", col(C::RST));
}
}

void banner() {
    static const char* const LOGO[] = {
        " ____             ____           __     ______  _   _ ",
        "| __ ) _   _  ___| __ ) _   _  __\\ \\   / /  _ \\| \\ | |",
        "|  _ \\| | | |/ _ \\  _ \\| | | |/ _ \\ \\ / /| |_) |  \\| |",
        "| |_) | |_| |  __/ |_) | |_| |  __/\\ V / |  __/| |\\  |",
        "|____/ \\__, |\\___|____/ \\__, |\\___| \\_/  |_|   |_| \\_|",
        "       |___/            |___/                          ",
    };
    // cyan to violet, top to bottom
    static const int SHADE[] = {87, 81, 75, 69, 63, 99};
    tee_printf("\n");
    for (int i = 0; i < 6; ++i) {
        if (g_no_color) tee_printf("  %s\n", LOGO[i]);
        else tee_printf("  \x1b[1;38;5;%dm%s\x1b[0m\n", SHADE[i], LOGO[i]);
    }
    rule_line(BANNER_WIDTH);
    tee_printf("  %s%s%s%s  %s\xc2\xb7  your node through a DPI box's eyes%s\n",
               col(C::BOLD), col(C::ACC), SCANNER_VERSION, col(C::RST), col(C::DIM), col(C::RST));
    rule_line(BANNER_WIDTH);
}

void section(int step, int total, const char* title, const std::string& detail) {
    tee_printf("\n%s\xe2\x96\x8c%s %s%d/%d%s  %s%s%s", col(C::ACC), col(C::RST), col(C::DIM), step, total,
               col(C::RST), col(C::BOLD), title, col(C::RST));
    if (!detail.empty()) tee_printf("   %s%s%s", col(C::DIM), detail.c_str(), col(C::RST));
    tee_printf("\n");
}

void card(const char* color, const std::string& head, const std::string& text) {
    // ascii inside, so byte length is display width
    const size_t inner = std::max<size_t>(56, head.size() + text.size() + 6);
    const size_t pad = inner - head.size() - text.size() - 4;
    auto edge = [&](const char* l, const char* r) {
        tee_printf("  %s%s", col(color), l);
        for (size_t i = 0; i < inner; ++i) tee_printf("\xe2\x94\x80");
        tee_printf("%s%s\n", r, col(C::RST));
    };
    edge("\xe2\x95\xad", "\xe2\x95\xae");
    tee_printf("  %s\xe2\x94\x82%s  %s%s%s%s  %s%*s%s\xe2\x94\x82%s\n", col(color), col(C::RST), col(C::BOLD), col(color),
               head.c_str(), col(C::RST), text.c_str(), (int)pad, "", col(color), col(C::RST));
    edge("\xe2\x95\xb0", "\xe2\x95\xaf");
}