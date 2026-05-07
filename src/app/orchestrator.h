// drives the 8-phase scan pipeline against one target and returns the
// fully-populated report (including the verdict block).
#pragma once

#include "report.h"
#include <string>

FullReport run_full_target(const std::string& target);
