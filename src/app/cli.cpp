// SPDX-License-Identifier: GPL-3.0-or-later
#include "cli.h"
#include "orchestrator.h"
#include "config_audit.h"
#include "target.h"
#include "tui.h"
#include "../common/console.h"
#include "../common/config.h"
#include "../common/util.h"
#include "../net/dns.h"
#include "../net/icmp.h"
#include "../scan/ports.h"
#include "../scan/tcp_scan.h"
#include "../scan/udp_probes.h"
#include "../scan/tls.h"
#include "../scan/sni.h"
#include "../scan/j3.h"
#include "../scan/snitch.h"
#include "../geoip/geoip.h"
#include "../local/local.h"

#include <cstdio>
#include <cstdlib>
#include <future>
#include <string>

using std::string;

static string read_whole_file(const string& path, bool& ok) {
    ok = false;
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return {};
    string out;
    char buf[8192];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) {
        if (out.size() + n > 16u * 1024u * 1024u) { std::fclose(f); return {}; }
        out.append(buf, n);
    }
    bool failed = std::ferror(f) != 0;
    std::fclose(f);
    ok = !failed;
    return out;
}

static int show_audit(const ConfigAudit& a, const string& path);

static bool read_config(const string& path, string& text) {
    bool ok = false;
    text = read_whole_file(path, ok);
    if (ok) return true;
    if (g_json) {
        ConfigAudit error;
        error.err = "cannot read config file (missing, read error or over 16 MiB)";
        std::fputs(config_audit_to_json(error).c_str(), stdout);
    } else
        printf("%scannot read config file '%s' (limit 16 MiB)%s\n", col(C::RED), path.c_str(), col(C::RST));
    return false;
}

int run_config_audit(const string& path) {
    string text;
    if (!read_config(path, text)) return 64;
    return show_audit(audit_config_text(text), path);
}

int run_config_pair(const string& server_path, const string& client_path) {
    string server, client;
    if (!read_config(server_path, server) || !read_config(client_path, client)) return 64;
    return show_audit(audit_config_pair(server, client), server_path + " + " + client_path);
}

static int show_audit(const ConfigAudit& a, const string& path) {
    if (g_json) {
        // machine-readable: emit the json object and exit with the tier code.
        std::fputs(config_audit_to_json(a).c_str(), stdout);
        if (!a.ok)                                  return 64;
        if (a.compatibility_errors)                 return 65;
        // unknown input must not fall through to a scored verdict
        if (a.tspu_tier.rfind("UNKNOWN", 0) == 0)   return 64;
        if (a.tspu_tier.rfind("PASS", 0) == 0)      return 0;
        if (a.tspu_tier.rfind("THROTTLE", 0) == 0)  return 1;
        if (a.tspu_tier.rfind("BLOCK", 0) == 0)     return 2;
        return 3;
    }
    printf("\n%s== Config audit: %s ==%s\n", col(C::BOLD), path.c_str(), col(C::RST));
    if (!a.ok) {
        printf("  %serror: %s%s\n", col(C::RED), a.err.c_str(), col(C::RST));
        return 64;
    }
    printf("  format: %s%s%s   inbounds: %d\n",
             col(C::CYN), a.format.c_str(), col(C::RST), a.inbound_count);
    printf("  evidence: configuration only; runtime and network not verified\n");
    for (const auto& p : a.protocols)
        printf("  inbound[%d]: %s / %s / %s; flow=%s (vision=%d, plain=%d, invalid=%d); encryption=%s\n",
               p.inbound, p.protocol.c_str(), p.transport.c_str(), p.security.c_str(),
               p.flow.c_str(), p.vision_users, p.plain_users, p.invalid_flow_users, p.encryption.c_str());
    if (a.compatibility_errors)
        printf("  compatibility errors: %d (exit 65)\n", a.compatibility_errors);
    size_t hygiene = 0;
    for (const auto& f : a.findings) hygiene += f.category == "hygiene";
    if (a.findings.size() == hygiene)
        printf("  %sno detectability tells found in the config%s\n",
               col(C::GRN), col(C::RST));
    auto show = [](const AuditFinding& f) {
        const char* sc;
        const char* tag;
        switch (f.sev) {
            case AuditFinding::Sev::High:   sc = col(C::RED); tag = "[!] HIGH"; break;
            case AuditFinding::Sev::Medium: sc = col(C::YEL); tag = "[-] MED "; break;
            default:                        sc = col(C::CYN); tag = "[i] INFO"; break;
        }
        printf("  %s%s%s %s%-22s%s %s%s%s%s\n",
               sc, tag, col(C::RST),
               col(C::BOLD), f.tag.c_str(), col(C::RST),
               col(C::DIM), f.where.c_str(), col(C::RST),
               f.named ? "  [named-protocol]" : "");
        printf("       %s\n", f.title.c_str());
        printf("       %sfix:%s %s\n", col(C::GRN), col(C::RST), f.fix.c_str());
    };
    for (const auto& f : a.findings) if (f.category != "hygiene") show(f);
    if (hygiene) {
        printf("\n  %sHygiene%s (does not change what an observer sees; not in the tier)\n",
               col(C::BOLD), col(C::RST));
        for (const auto& f : a.findings) if (f.category == "hygiene") show(f);
    }
    const char* tc =(a.tspu_tier.rfind("PASS", 0) == 0)     ? col(C::GRN)
                   : (a.tspu_tier.rfind("THROTTLE", 0) == 0) ? col(C::YEL)
                   : (a.tspu_tier.rfind("UNKNOWN", 0) == 0)  ? col(C::DIM)
                                                             : col(C::RED);
    printf("\n  %sLegacy exposure heuristic (unvalidated):%s %s%s%s  (A=%d named / B=%d soft)\n",
           col(C::BOLD), col(C::RST), tc, a.tspu_tier.c_str(), col(C::RST),
           a.a_hits, a.b_hits);
    printf("  %s%s%s\n", col(C::DIM), a.verdict_line.c_str(), col(C::RST));

    if (a.compatibility_errors) return 65;
    if (a.tspu_tier.rfind("UNKNOWN", 0) == 0)  return 64;
    if (a.tspu_tier.rfind("PASS", 0) == 0)     return 0;
    if (a.tspu_tier.rfind("THROTTLE", 0) == 0) return 1;
    if (a.tspu_tier.rfind("BLOCK", 0) == 0)    return 2;   // "BLOCK (accumulative)"
    return 3;                                              // "IMMEDIATE BLOCK"
}

void help() {
    printf("ByeByeVPN - full TSPU/DPI/VPN detectability scanner\n\n");
    printf("Usage:\n");
    printf("  byebyevpn                      interactive menu\n");
    printf("  byebyevpn <ip-or-host>         full scan (recommended)\n");
    printf("  byebyevpn scan <ip>            full scan same\n");
    printf("  byebyevpn ports <ip>           TCP port scan only\n");
    printf("  byebyevpn udp <ip>             UDP probes only\n");
    printf("  byebyevpn tls <ip> [port]      TLS + SNI consistency only\n");
    printf("  byebyevpn j3 <ip> [port]       J3 active probing only\n");
    printf("  byebyevpn grpc <ip> [port]     HTTP/2 + gRPC transport probe (VLESS/VMess-gRPC)\n");
    printf("  byebyevpn dpi <host> [port]    SNI path probe: does YOUR ISP/TSPU reset or silently drop this SNI\n");
    printf("                                 exit 0 reply, 2 SNI-specific reset/drop, 4 inconclusive,\n");
    printf("                                 5 preflight failed, 64 fake-IP tunnel; --json\n");
    printf("  byebyevpn dpi <node> [port] --sni NAME --real IP|auto\n");
    printf("                                 the same name to your node and to the address it really lives on:\n");
    printf("                                 fails to the node and passes to its own address = a name+address\n");
    printf("                                 rule on this path. exit 0 passes, 2 fails, 4 inconclusive\n");
    printf("  byebyevpn dpi <host> [port] --volume /path --control host[:port]/path\n");
    printf("                                 volume check from THIS client: does the path stop carrying\n");
    printf("                                 bytes on an open connection (16-20 KB freeze)? /path must\n");
    printf("                                 serve 64 KB or more; the control must be a host you know\n");
    printf("                                 carries volume. exit 0 carried, 2 stalled, 4 inconclusive or\n");
    printf("                                 not applicable. measures this path now, not the node\n");
    printf("  byebyevpn ech <domain>         DNS HTTPS-RR / ECH probe (does this domain hide its SNI via ECH)\n");
    printf("  byebyevpn names <host...>      offline hostname markers; supports --json\n");
    printf("                                 protocol/panel names and provider conventions; no score impact\n");
    printf("                                 exit 3 strong, 2 moderate, 0 weak/none/IP, 64 invalid input\n");
    printf("  byebyevpn names <domain> --ct  every name under the domain in public CT logs (crt.sh),\n");
    printf("                                 with markers; --ct-file F reads a saved crt.sh JSON instead;\n");
    printf("                                 --resolve shows names sharing an address, --node IP marks yours;\n");
    printf("                                 exit 4 when the CT lookup failed\n");
    printf("  byebyevpn geoip <ip>           GeoIP only\n");
    printf("  byebyevpn snitch <ip> [port]   SNITCH RTT/GeoIP consistency (methodika §10.1)\n");
    printf("  byebyevpn trace <ip>           Traceroute hop-count analysis\n");
    printf("  byebyevpn local                scan THIS machine (split-tunnel / VPN procs), plus IPv6\n");
    printf("                                 and DNS leaving beside the tunnel; exit 2 on a leak\n");
    printf("  byebyevpn awg-entropy <pcap>   offline AmneziaWG-compatible traffic heuristic (PCAP/PCAPNG)\n");
    printf("                                 entropy + repeated UDP trains; supports --json; no version proof\n");
    printf("  byebyevpn pcap <file> [--node IP]\n");
    printf("                                 your own client capture as a box on the link reads it: client\n");
    printf("                                 hellos (SNI, JA4, GREASE, ECH, post-quantum), a TLS handshake\n");
    printf("                                 inside the tunnel (record sizes), DNS in the clear, traffic\n");
    printf("                                 beside the node. offline; exit 2 something readable, 0 quiet\n");
    printf("  byebyevpn audit-config <file>  identify configured Xray protocols/flows and audit settings\n");
    printf("  byebyevpn audit-config <server> <client>\n");
    printf("                                 check a client config against its server: port, transport,\n");
    printf("                                 security, path, user, flow, REALITY name/shortId/key pair\n");
    printf("                                 static, no network; --json; exit 65 for compatibility errors\n");
    printf("  byebyevpn batch <targets.txt> [--out DIR]\n");
    printf("                                 full scan of every node in the file (one per line, # comments),\n");
    printf("                                 a summary table at the end; --out keeps one --json report per\n");
    printf("                                 node. exit is the worst node's verdict code\n");
    printf("  byebyevpn diff <old> <new>     what changed between two --json reports, or two --out\n");
    printf("                                 directories: verdict, ports, certificates, JA4S, GeoIP tags.\n");
    printf("                                 offline; exit 2 verdict changed, 1 other change, 0 same\n");
    printf("  byebyevpn sweep <cidr>         light-probe a subnet (e.g. 1.2.3.0/24) and cluster\n");
    printf("                                 hosts by TLS fingerprint (JA4S + cert)\n\n");
    printf("Before a scan turn off every VPN, Zapret, GoodbyeDPI and proxy on this host.\n");
    printf("Preflight checks it: a tunnel on the target route, a local stack that accepts\n");
    printf("every SYN, or a packet rewriter stops the scan with UNRELIABLE (exit 5).\n");
    printf("  --i-know-what-i-am-doing  scan anyway; the verdict is marked overridden\n");
    printf("  --expect-ip A             fail preflight if lookup services see another address\n");
    printf("'byebyevpn local' shows active adapters and routes.\n\n");
    printf("WireGuard self-check (scan and udp; only for nodes you hold keys for):\n");
    printf("  --wg-pubkey K|FILE  server public key, as text or a file\n");
    printf("  --wg-key FILE       private key of a peer configured on that server\n");
    printf("  --wg-psk FILE       that peer's preshared key, if it has one\n");
    printf("  --wg-port N         WireGuard UDP port (default 51820)\n");
    printf("                      a responder drops unknown peers, so both keys are needed.\n");
    printf("                      keys are never printed or written to JSON. the node moves\n");
    printf("                      this peer's endpoint here until its own client sends again;\n");
    printf("                      use a spare peer. it measures this path at this moment.\n\n");
    printf("Port-scan modes (default: --full):\n");
    printf("  --full              scan ALL ports 1-65535  (default)\n");
    printf("  --fast              205 curated VPN/proxy/TLS/admin ports\n");
    printf("  --range 1000-2000   scan a port range\n");
    printf("  --ports 80,443,8443 scan explicit port list\n\n");
    printf("Tuning:\n");
    printf("  --threads N     parallel TCP connects   (default 500)\n");
    printf("  --tcp-to MS     TCP connect timeout      (default 800)\n");
    printf("  --udp-to MS     UDP recv timeout         (default 900)\n");
    printf("  --no-color      disable ANSI colors\n");
    printf("  -v / --verbose  verbose\n\n");
    printf("Stealth / privacy (opt-outs for 3rd-party-service leakage and\n");
    printf("behavioural-burst fingerprint, default OFF, full scan behaviour):\n");
    printf("  --stealth       enable --no-geoip + --no-ct + --udp-jitter + inter-probe\n");
    printf("                  timing jitter across J3 / SNI / uTLS / AmneziaWG sweep (v2.7.0)\n");
    printf("  --no-geoip      skip all 3rd-party GeoIP/ASN lookups (target IP stays local)\n");
    printf("  --no-ct         skip crt.sh Certificate Transparency lookup (cert SHA stays local)\n");
    printf("  --udp-jitter    add 50-300ms random delay between UDP probes (smears port burst)\n");
    printf("  --j3-subset N   send a random N-probe subset (1..7) of the eight J3 probes\n");
    printf("                  per port instead of all eight (v2.7.0)\n");
    printf("  --passive       minimal-probe mode: SKIPS J3, uTLS dual-probe, SNI consistency\n");
    printf("                  loop and AmneziaWG S1 sweep entirely. one TLS handshake + GeoIP +\n");
    printf("                  CT-log only. fewest scanner-shaped patterns on the wire (v2.7.0)\n\n");
    printf("Output:\n");
    printf("  --json           emit a machine-readable JSON report on stdout; the human\n");
    printf("                   scan output is moved to stderr so stdout is pipe-clean\n");
    printf("  --save           write the scan to '<target>.md' in the current directory\n");
    printf("  --save <path>    write the scan to <path> (still wrapped as markdown)\n");
    printf("                   ANSI colors are stripped from the file; terminal output is unchanged\n\n");
    printf("Exit codes (full scan):\n");
    printf("  0  CLEAN (score >= 85)        2  SUSPICIOUS (50-69)\n");
    printf("  1  NOISY (70-84)              3  OBVIOUSLY-VPN (< 50)\n");
    printf("  4  INCONCLUSIVE (the report lists why no verdict was given)\n");
    printf("  5  UNRELIABLE (preflight failed, nothing was sent to the target)\n");
    printf("  64 usage/runtime error\n\n");
    printf("GeoIP sources (5 HTTPS-only providers, reference only, never scored):\n");
    printf("  ipapi.is, iplocate.io, freeipapi.com, ipwho.is, ipinfo.io\n");
    printf("External address check (preflight, off with --no-geoip):\n");
    printf("  api.ipify.org, icanhazip.com, ifconfig.me\n");
}

static string ask(const string& prompt) {
    printf("%s", prompt.c_str()); std::fflush(stdout);
    char buf[256] = {0};
    if (!std::fgets(buf, sizeof(buf), stdin)) return {};
    return trim(buf);
}

void interactive() {
    if (tui_available()) { tui_run(); return; }
    // no console: one command line per input line, cli syntax
    printf("  type a command as on the command line, e.g. 'scan 1.2.3.4' or 'dpi example.com'\n");
    printf("  'help' lists commands, 'quit' leaves\n");
    for (;;) {
        string line = ask("\nbyebyevpn> ");
        if (line.empty()) { if (std::feof(stdin)) break; continue; }
        if (line == "quit" || line == "exit" || line == "q") break;
        std::vector<string> args;
        for (const auto& a : split(line, ' ')) if (!trim(a).empty()) args.push_back(trim(a));
        if (args.empty()) continue;
        printf("  exit %d\n", run_command(args));
    }
}
