#ifndef CLI_ORCHESTRATOR_H
#define CLI_ORCHESTRATOR_H

#include <string>
#include "../analysis/verdict.h"

FullReport run_full_target(const std::string& target);

#endif // CLI_ORCHESTRATOR_H