// SPDX-License-Identifier: GPL-3.0-or-later
// names --ct: every host name under a domain that certificate transparency
// logs already publish, run through the hostname markers, and optionally
// which of them share an address. ct logs are public; this shows the owner
// what anyone can list without sending a packet to the node.
#pragma once

#include "hostname_marks.h"

#include <string>
#include <utility>
#include <vector>

struct CtName {
    std::string name;            // lowercase, no trailing dot, "*." stripped
    bool        wildcard = false;
    int         certificates = 0;
    std::string first_seen;      // earliest not_before, yyyy-mm-dd
    HostnameAnalysis marks;
};

struct CtNames {
    std::string domain;
    bool        lookup_complete = false;
    int         certificates = 0;
    std::vector<CtName> names;   // strongest marks first, then by name
    std::string err;
};

// crt.sh ?q=%.domain&output=json; names outside the domain and non-host
// entries (mail addresses in s/mime certs) are dropped
CtNames parse_ct_names(const std::string& body, const std::string& domain);

struct SharedAddress {
    std::string ip;
    std::vector<std::string> names;
    bool marked = false;         // at least one name carries a strong or moderate mark
    bool node = false;           // the address given with --node
};

// resolved: name -> addresses. only addresses with two or more names, or the node
std::vector<SharedAddress> ct_shared_addresses(const CtNames& ct,
                                               const std::vector<std::pair<std::string, std::vector<std::string>>>& resolved,
                                               const std::string& node_ip);

std::string ct_names_json(const CtNames& ct, const std::vector<SharedAddress>& shared);
