// SPDX-License-Identifier: GPL-3.0-or-later
#include "tui.h"

namespace {
bool is_csi_start(const std::string& s, size_t i) {
    return s[i] == '\x1b' && i + 1 < s.size() && s[i + 1] == '[';
}
size_t skip_csi(const std::string& s, size_t i) {
    i += 2;
    while (i < s.size() && !(s[i] >= '@' && s[i] <= '~')) ++i;
    return i < s.size() ? i + 1 : i;
}
// one column per code point; box drawing and cyrillic are single width
bool is_lead(unsigned char c) { return (c & 0xC0) != 0x80; }
}

size_t tui_visible_width(const std::string& s) {
    size_t w = 0;
    for (size_t i = 0; i < s.size();) {
        if (is_csi_start(s, i)) { i = skip_csi(s, i); continue; }
        if (is_lead((unsigned char)s[i])) ++w;
        ++i;
    }
    return w;
}

std::string tui_fit(const std::string& s, size_t width) {
    const size_t w = tui_visible_width(s);
    if (w <= width) return s + std::string(width - w, ' ');
    if (width == 0) return {};
    // cut at width-1 columns, then an ellipsis; keep escapes intact
    std::string out;
    size_t cols = 0, i = 0;
    while (i < s.size()) {
        if (is_csi_start(s, i)) { size_t e = skip_csi(s, i); out.append(s, i, e - i); i = e; continue; }
        if (is_lead((unsigned char)s[i])) {
            if (cols == width - 1) break;
            ++cols;
        }
        out += s[i++];
    }
    // finish a split code point
    while (i < s.size() && !is_lead((unsigned char)s[i])) out += s[i++];
    out += "\xE2\x80\xA6";
    // reset only when something was colored
    if (out.find('\x1b') != std::string::npos) out += "\x1b[0m";
    return out;
}

std::vector<std::string> tui_wrap(const std::string& text, size_t width) {
    std::vector<std::string> lines;
    if (width == 0) return lines;
    size_t start = 0;
    while (start <= text.size()) {
        size_t nl = text.find('\n', start);
        std::string para = text.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
        std::string line;
        size_t pos = 0;
        while (pos < para.size()) {
            size_t sp = para.find(' ', pos);
            std::string word = para.substr(pos, sp == std::string::npos ? std::string::npos : sp - pos);
            pos = sp == std::string::npos ? para.size() : sp + 1;
            while (tui_visible_width(word) > width) {
                if (!line.empty()) { lines.push_back(line); line.clear(); }
                lines.push_back(tui_fit(word, width));
                word.clear();
            }
            if (word.empty()) continue;
            const size_t need = tui_visible_width(line) + (line.empty() ? 0 : 1) + tui_visible_width(word);
            if (need > width && !line.empty()) { lines.push_back(line); line.clear(); }
            line += (line.empty() ? "" : " ") + word;
        }
        lines.push_back(line);
        if (nl == std::string::npos) break;
        start = nl + 1;
    }
    return lines;
}
