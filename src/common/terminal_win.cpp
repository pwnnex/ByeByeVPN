// SPDX-License-Identifier: GPL-3.0-or-later
#include "terminal.h"
#include "winhdr.h"

#include <cstdio>
#include <io.h>

namespace {

constexpr const char* ALT_ON = "\x1b[?1049h\x1b[?25l";
constexpr const char* ALT_OFF = "\x1b[?25h\x1b[?1049l";

BOOL WINAPI restore_terminal(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        std::fputs(ALT_OFF, stdout);
        std::fflush(stdout);
    }
    return FALSE;
}

} // namespace

bool terminal_available() {
    DWORD mode = 0;
    if (!_isatty(_fileno(stdin)) || !_isatty(_fileno(stdout))) return false;
    if (!GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode)) return false;
    if (!GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode)) return false;
    return (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
}

TerminalSize terminal_size() {
    TerminalSize size;
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info)) {
        size.w = info.srWindow.Right - info.srWindow.Left + 1;
        size.h = info.srWindow.Bottom - info.srWindow.Top + 1;
    }
    return size;
}

TerminalKey terminal_read_key() {
    TerminalKey key;
    wint_t character = _getwch();
    if (character == 0 || character == 0xE0) {
        switch (_getwch()) {
        case 72: key.k = TerminalKeyCode::Up; break;
        case 80: key.k = TerminalKeyCode::Down; break;
        case 75: key.k = TerminalKeyCode::Left; break;
        case 77: key.k = TerminalKeyCode::Right; break;
        case 71: key.k = TerminalKeyCode::Home; break;
        case 79: key.k = TerminalKeyCode::End; break;
        case 73: key.k = TerminalKeyCode::PgUp; break;
        case 81: key.k = TerminalKeyCode::PgDn; break;
        default: break;
        }
        return key;
    }
    if (character == 13) key.k = TerminalKeyCode::Enter;
    else if (character == 27) key.k = TerminalKeyCode::Esc;
    else if (character == 8) key.k = TerminalKeyCode::Back;
    else if (character == 9) key.k = TerminalKeyCode::Tab;
    else { key.k = TerminalKeyCode::Char; key.ch = static_cast<wchar_t>(character); }
    return key;
}

std::string terminal_utf8(wchar_t character) {
    char bytes[8]{};
    const int size = WideCharToMultiByte(CP_UTF8, 0, &character, 1,
                                         bytes, sizeof(bytes), nullptr, nullptr);
    return std::string(bytes, size > 0 ? size : 0);
}

void terminal_session_begin() {
    SetConsoleCtrlHandler(restore_terminal, TRUE);
    terminal_show_ui();
}

void terminal_show_ui() {
    std::fputs(ALT_ON, stdout);
    std::fflush(stdout);
}

void terminal_hide_ui() {
    std::fputs(ALT_OFF, stdout);
    std::fflush(stdout);
}

void terminal_session_end() {
    terminal_hide_ui();
    SetConsoleCtrlHandler(restore_terminal, FALSE);
}
