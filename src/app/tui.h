// SPDX-License-Identifier: GPL-3.0-or-later
// full-screen interactive panel. every action goes through run_command(),
// so the panel sends exactly the probes the command line sends.
#pragma once

#include <string>
#include <vector>

// stdin and stdout are a real console with vt output
bool tui_available();
void tui_run();

// one frame as it would be drawn, for layout checks
std::string tui_preview(int w, int h, int sel);

// pure layout helpers, unit tested
size_t tui_visible_width(const std::string& s);
std::string tui_fit(const std::string& s, size_t width);
std::vector<std::string> tui_wrap(const std::string& text, size_t width);
