// SPDX-License-Identifier: GPL-3.0-or-later
#include "terminal.h"

#include <csignal>
#include <cstdio>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

namespace {

constexpr const char* ALT_ON = "\x1b[?1049h\x1b[?25l";
constexpr const char* ALT_OFF = "\x1b[?25h\x1b[?1049l";
termios saved_terminal{};
bool terminal_mode_active = false;
using SignalHandler = void (*)(int);
SignalHandler previous_interrupt = SIG_DFL;
SignalHandler previous_terminate = SIG_DFL;

void restore_terminal(int signal) {
    if (terminal_mode_active) tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_terminal);
    ::write(STDOUT_FILENO, ALT_OFF, 14);
    std::signal(signal, SIG_DFL);
    std::raise(signal);
}

bool input_ready(int timeout_ms) {
    fd_set input;
    FD_ZERO(&input);
    FD_SET(STDIN_FILENO, &input);
    timeval wait{};
    wait.tv_sec = timeout_ms / 1000;
    wait.tv_usec = (timeout_ms % 1000) * 1000;
    return select(STDIN_FILENO + 1, &input, nullptr, nullptr, &wait) > 0;
}

} // namespace

bool terminal_available() {
    return isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
}

TerminalSize terminal_size() {
    TerminalSize result;
    winsize size{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0) {
        if (size.ws_col) result.w = size.ws_col;
        if (size.ws_row) result.h = size.ws_row;
    }
    return result;
}

TerminalKey terminal_read_key() {
    TerminalKey key;
    unsigned char character = 0;
    if (::read(STDIN_FILENO, &character, 1) != 1) return key;
    if (character == '\x1b') {
        if (!input_ready(20)) { key.k = TerminalKeyCode::Esc; return key; }
        unsigned char sequence[2]{};
        if (::read(STDIN_FILENO, &sequence[0], 1) != 1 || sequence[0] != '[' ||
            ::read(STDIN_FILENO, &sequence[1], 1) != 1) {
            key.k = TerminalKeyCode::Esc;
            return key;
        }
        switch (sequence[1]) {
        case 'A': key.k = TerminalKeyCode::Up; break;
        case 'B': key.k = TerminalKeyCode::Down; break;
        case 'C': key.k = TerminalKeyCode::Right; break;
        case 'D': key.k = TerminalKeyCode::Left; break;
        case 'H': key.k = TerminalKeyCode::Home; break;
        case 'F': key.k = TerminalKeyCode::End; break;
        case '1': case '4': case '5': case '6': case '7': case '8': {
            unsigned char terminator = 0;
            if (!input_ready(20) || ::read(STDIN_FILENO, &terminator, 1) != 1 || terminator != '~') {
                key.k = TerminalKeyCode::Esc;
                break;
            }
            if (sequence[1] == '1' || sequence[1] == '7') key.k = TerminalKeyCode::Home;
            else if (sequence[1] == '4' || sequence[1] == '8') key.k = TerminalKeyCode::End;
            else if (sequence[1] == '5') key.k = TerminalKeyCode::PgUp;
            else key.k = TerminalKeyCode::PgDn;
            break;
        }
        default: key.k = TerminalKeyCode::Esc; break;
        }
    } else if (character == '\r' || character == '\n') key.k = TerminalKeyCode::Enter;
    else if (character == 127 || character == 8) key.k = TerminalKeyCode::Back;
    else if (character == '\t') key.k = TerminalKeyCode::Tab;
    else {
        unsigned codepoint = character;
        int remaining = 0;
        if ((character & 0xe0) == 0xc0) { codepoint = character & 0x1f; remaining = 1; }
        else if ((character & 0xf0) == 0xe0) { codepoint = character & 0x0f; remaining = 2; }
        else if ((character & 0xf8) == 0xf0) { codepoint = character & 0x07; remaining = 3; }
        for (int i = 0; i < remaining; ++i) {
            unsigned char continuation = 0;
            if (::read(STDIN_FILENO, &continuation, 1) != 1 || (continuation & 0xc0) != 0x80) {
                key.k = TerminalKeyCode::None;
                return key;
            }
            codepoint = (codepoint << 6) | (continuation & 0x3f);
        }
        key.k = TerminalKeyCode::Char;
        key.ch = static_cast<wchar_t>(codepoint);
    }
    return key;
}

std::string terminal_utf8(wchar_t character) {
    const unsigned value = static_cast<unsigned>(character);
    if (value <= 0x7f) return std::string(1, static_cast<char>(value));
    if (value <= 0x7ff)
        return {static_cast<char>(0xc0 | (value >> 6)), static_cast<char>(0x80 | (value & 0x3f))};
    if (value <= 0xffff)
        return {static_cast<char>(0xe0 | (value >> 12)), static_cast<char>(0x80 | ((value >> 6) & 0x3f)),
                static_cast<char>(0x80 | (value & 0x3f))};
    if (value <= 0x10ffff)
        return {static_cast<char>(0xf0 | (value >> 18)), static_cast<char>(0x80 | ((value >> 12) & 0x3f)),
                static_cast<char>(0x80 | ((value >> 6) & 0x3f)), static_cast<char>(0x80 | (value & 0x3f))};
    return {};
}

void terminal_session_begin() {
    if (tcgetattr(STDIN_FILENO, &saved_terminal) == 0) {
        termios raw = saved_terminal;
        raw.c_lflag &= static_cast<tcflag_t>(~(ICANON | ECHO));
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        terminal_mode_active = tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == 0;
    }
    previous_interrupt = std::signal(SIGINT, restore_terminal);
    previous_terminate = std::signal(SIGTERM, restore_terminal);
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
    if (terminal_mode_active) tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_terminal);
    terminal_mode_active = false;
    std::signal(SIGINT, previous_interrupt);
    std::signal(SIGTERM, previous_terminate);
}
