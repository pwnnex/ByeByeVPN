// pretty-print helpers for the scan banner and per-provider GeoIP lines.
#pragma once

#include "../geoip/geoip.h"
#include <string>

void print_banner_scan(const std::string& t);
void print_geo(const GeoInfo& g);
