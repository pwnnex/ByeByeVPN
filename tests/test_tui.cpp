// SPDX-License-Identifier: GPL-3.0-or-later
// panel layout helpers: a wrong width tears every frame
#include "doctest.h"
#include "../src/app/tui.h"

TEST_CASE("visible width skips escapes and counts code points") {
    CHECK(tui_visible_width("abc") == 3);
    CHECK(tui_visible_width("\x1b[1;32mok\x1b[0m") == 2);
    CHECK(tui_visible_width("\xE2\x94\x80\xE2\x94\x80") == 2);   // two box lines
    CHECK(tui_visible_width("\xD0\xBF\xD1\x80\xD0\xB8") == 3);   // cyrillic
    CHECK(tui_visible_width("") == 0);
}

TEST_CASE("fit pads short text and cuts long text to the exact width") {
    CHECK(tui_fit("ab", 5) == "ab   ");
    const auto cut = tui_fit("abcdefgh", 5);
    CHECK(tui_visible_width(cut) == 5);
    CHECK(cut.substr(0, 4) == "abcd");
    const auto colored = tui_fit("\x1b[31mabcdefgh\x1b[0m", 4);
    CHECK(tui_visible_width(colored) == 4);
    CHECK(colored.find("\x1b[0m") != std::string::npos);
    // never split a utf-8 sequence
    const auto cyr = tui_fit("\xD0\xBF\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82", 3);
    CHECK(tui_visible_width(cyr) == 3);
    CHECK(tui_fit("x", 0).empty());
}

TEST_CASE("wrap keeps words whole and respects the width") {
    const auto lines = tui_wrap("the quick brown fox jumps over the lazy dog", 10);
    REQUIRE(lines.size() >= 4);
    for (const auto& l : lines) CHECK(tui_visible_width(l) <= 10);
    CHECK(lines[0] == "the quick");
    CHECK(tui_wrap("a\nb", 10).size() == 2);
    CHECK(tui_wrap("", 10).size() == 1);
    for (const auto& l : tui_wrap("averyveryverylongword short", 6)) CHECK(tui_visible_width(l) <= 6);
}
