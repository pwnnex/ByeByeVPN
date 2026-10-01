// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "report.h"

// no network or printing; repeated evaluation replaces derived fields.
void evaluate_report(FullReport& report);
void print_verdict(const FullReport& report);
int report_exit_code(const FullReport& report);
