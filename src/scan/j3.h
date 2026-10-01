// SPDX-License-Identifier: GPL-3.0-or-later
// j3-style active probing: 8 distinct probes per tls port (empty/close,
// http get, connect, ssh banner, random bytes, tls-ch-invalid-sni,
// abs-uri proxy get, 0xFF junk).
//
// response groups describe observed bytes, not server software.
#pragma once

#include "../net/read_end.h"

#include <string>
#include <vector>
#include <cstdint>

struct J3Result {
    std::string name;
    bool        responded = false;
    int         bytes     = 0;
    std::string first_line;
    std::string hex_head;
    int64_t     ms        = 0;
    ReadEnd     end       = ReadEnd::NoConnect;
    bool        client_first = true;   // empty probe expects silence
};

struct J3Analysis {
    int silent              = 0;   // no bytes, any cause
    int resp                = 0;
    int closed              = 0;
    int reset               = 0;
    int held                = 0;
    int no_connect          = 0;
    int http_real           = 0;
    // legacy name; includes invalid status codes and other start-line errors.
    int http_bad_version    = 0;
    int raw_non_http        = 0;
    // matching first line and captured length; bodies may differ.
    int canned_identical    = 0;
    std::string canned_line;
    int canned_bytes        = 0;
};

std::vector<J3Result> j3_probes(const std::string& host, int port);
J3Analysis            j3_analyze(const std::vector<J3Result>& probes);

// our-openssl ja3 fingerprint metadata for the verdict advisory.
struct Ja3Info {
    std::string version;
    std::string ciphers;
    std::string extensions;
    std::string groups;
    std::string ec_formats;
    std::string ja3_hash;
};
Ja3Info our_openssl_ja3_signature();
