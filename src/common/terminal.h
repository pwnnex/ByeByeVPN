// SPDX-License-Identifier: GPL-3.0-or-later
// Interactive terminal primitives used by the full-screen TUI.
#pragma once

#include <string>

struct TerminalSize {
    int w = 80;
    int h = 25;
};

enum class TerminalKeyCode {
    None, Up, Down, Left, Right, Enter, Esc, Back,
    Home, End, PgUp, PgDn, Tab, Char
};

struct TerminalKey {
    TerminalKeyCode k = TerminalKeyCode::None;
    wchar_t ch = 0;
};

bool terminal_available();
TerminalSize terminal_size();
TerminalKey terminal_read_key();
std::string terminal_utf8(wchar_t character);
void terminal_show_ui();
void terminal_hide_ui();

// Enters immediate-input mode, installs emergency cleanup handling, and
// switches to the alternate screen. Calls may be nested only by the TUI's
// explicit screen transitions; one TerminalSession owns each UI run.
void terminal_session_begin();
void terminal_session_end();

class TerminalSession {
public:
    TerminalSession() { terminal_session_begin(); }
    ~TerminalSession() { terminal_session_end(); }
    TerminalSession(const TerminalSession&) = delete;
    TerminalSession& operator=(const TerminalSession&) = delete;
};
