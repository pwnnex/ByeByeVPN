// SPDX-License-Identifier: GPL-3.0-or-later
// entry point: WSAStartup + openssl init, cli arg parsing, dispatch.
#include "common/winhdr.h"
#include "common/console.h"
#include "common/config.h"
#include "common/util.h"
#include "net/dns.h"
#include "net/icmp.h"
#include "scan/ports.h"
#include "scan/tcp_scan.h"
#include "scan/udp_probes.h"
#include "scan/tls.h"
#include "scan/sni.h"
#include "scan/j3.h"
#include "scan/grpc.h"
#include "scan/dpi_probe.h"
#include "scan/ech.h"
#include "scan/hostname_marks.h"
#include "scan/snitch.h"
#include "geoip/geoip.h"
#include "local/local.h"
#include "app/cli.h"
#include "app/orchestrator.h"
#include "app/target.h"
#include "app/verdict.h"
#include "app/preflight.h"
#include "app/json_report.h"
#include "app/sweep.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <future>
#include <set>
#include <string>
#include <vector>

using std::string;
using std::vector;
using std::set;

int main(int argc, char** argv) {
    enable_vt();
    WSADATA ws; WSAStartup(MAKEWORD(2, 2), &ws);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    vector<string> pos;
    for (int i = 1; i < argc; ++i) {
        string a = argv[i];
        if      (a == "--no-color")              g_no_color = true;
        else if (a == "--verbose" || a == "-v")  g_verbose = true;
        else if (a == "--threads" && i + 1 < argc) g_threads = std::max(1, std::atoi(argv[++i]));
        else if (a == "--tcp-to"  && i + 1 < argc) g_tcp_to  = std::max(1, std::atoi(argv[++i]));
        else if (a == "--udp-to"  && i + 1 < argc) g_udp_to  = std::max(1, std::atoi(argv[++i]));
        else if (a == "--stealth") {
            g_stealth = true;
            g_no_geoip = true;
            g_no_ct = true;
            g_udp_jitter = true;
        }
        else if (a == "--no-geoip")   g_no_geoip = true;
        else if (a == "--no-ct")      g_no_ct = true;
        else if (a == "--udp-jitter") g_udp_jitter = true;
        else if (a == "--passive")    g_passive = true;
        else if (a == "--j3-subset" && i + 1 < argc) {
            int n = std::atoi(argv[++i]);
            if (n > 0 && n < 8) g_j3_subset = n;
        }
        else if (a == "--json")       g_json = true;
        else if (a == "--i-know-what-i-am-doing") g_override_preflight = true;
        else if (a == "--expect-ip" && i + 1 < argc) g_expect_ip = argv[++i];
        else if (a == "--wg-pubkey" && i + 1 < argc) g_wg_pubkey = argv[++i];
        else if (a == "--wg-key"    && i + 1 < argc) g_wg_key    = argv[++i];
        else if (a == "--wg-psk"    && i + 1 < argc) g_wg_psk    = argv[++i];
        else if (a == "--volume"    && i + 1 < argc) g_volume_path    = argv[++i];
        else if (a == "--control"   && i + 1 < argc) g_volume_control = argv[++i];
        else if (a == "--sni"       && i + 1 < argc) g_dpi_sni        = argv[++i];
        else if (a == "--ct")                        g_names_ct       = true;
        else if (a == "--ct-file"   && i + 1 < argc) { g_ct_file = argv[++i]; g_names_ct = true; }
        else if (a == "--resolve")                   g_resolve        = true;
        else if (a == "--node"      && i + 1 < argc) { g_node_ip = argv[++i]; g_resolve = true; }
        else if (a == "--real"      && i + 1 < argc) g_dpi_real       = argv[++i];
        else if (a == "--wg-port"   && i + 1 < argc) {
            int p = std::atoi(argv[++i]);
            if (p > 0 && p < 65536) g_wg_port = p;
        }
        else if (a == "--save") {
            g_save_requested = true;
            if (i + 1 < argc) {
                string nxt = argv[i + 1];
                if (!nxt.empty() && nxt[0] != '-') {
                    g_save_path = nxt;
                    ++i;
                }
            }
        }
        else if (a == "--full")  g_port_mode = PortMode::FULL;
        else if (a == "--fast")  g_port_mode = PortMode::FAST;
        else if (a == "--range" && i + 1 < argc) {
            string v = argv[++i];
            size_t dash = v.find('-');
            if (dash != string::npos) {
                g_range_lo = std::atoi(v.substr(0, dash).c_str());
                g_range_hi = std::atoi(v.substr(dash + 1).c_str());
                g_port_mode = PortMode::RANGE;
            }
        }
        else if (a == "--ports" && i + 1 < argc) {
            string v = argv[++i]; g_port_list.clear();
            size_t p = 0;
            while (p < v.size()) {
                size_t c = v.find(',', p);
                string tok = v.substr(p, c == string::npos ? string::npos : c - p);
                if (!tok.empty()) g_port_list.push_back(std::atoi(tok.c_str()));
                if (c == string::npos) break;
                p = c + 1;
            }
            if (!g_port_list.empty()) g_port_mode = PortMode::LIST;
        }
        else if (a == "--help" || a == "-h" || a == "/?") { help(); return 0; }
        else pos.push_back(a);
    }

    // open save file before banner so it captures the banner too.
    save_begin(pos);

    banner();
    int rc = pos.empty() ? (interactive(), 0) : run_command(pos);
    save_end();
    WSACleanup();
    return rc;
}
