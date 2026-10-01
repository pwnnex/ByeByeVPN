# ByeByeVPN

Клиентский сканер детектируемости VPN / DPI / Reality / ТСПУ. Одна
статическая `byebyevpn.exe` под Windows (работает через Wine на Linux
и macOS), без прав администратора, без DLL-зависимостей.

```
 ____             ____           __     ______  _   _
| __ ) _   _  ___| __ ) _   _  __\ \   / /  _ \| \ | |
|  _ \| | | |/ _ \  _ \| | | |/ _ \ \ / /| |_) |  \| |
| |_) | |_| |  __/ |_) | |_| |  __/\ V / |  __/| |\  |
|____/ \__, |\___|____/ \__, |\___| \_/  |_|   |_| \_|
       |___/            |___/
  ──────────────────────────────────────────────────────
  v3.2.0  ·  your node through a DPI box's eyes
  ──────────────────────────────────────────────────────
```

**Languages:** [English](#english) · [Русский](#русский) · [简体中文](README.zh-CN.md) · [فارسی](README.fa.md)

**Discussion / report issues:**
[ntc.party/t/byebyevpn/24325](https://ntc.party/t/byebyevpn/24325) ·
[GitHub Issues](https://github.com/pwnnex/ByeByeVPN/issues) ·
[Telegram](https://t.me/byebyevpn_github)

<a href="https://nowpayments.io/donation/byebyevpn" target="_blank" rel="noreferrer noopener">
    <img src="https://nowpayments.io/images/embeds/donation-button-black.svg" alt="Crypto donation button by NOWPayments">
</a>

---

## English

### Purpose

Given an IP or hostname, run the full Russian OCR методика (§5-10) plus
modern 2026 tunnel fingerprints against it from an external vantage
point. Output: a detection score, the identified stack, and what a
TSPU-class classifier would decide. No VPN connection to the target
is needed - the scanner looks at the destination as a third-party
observer, the way an ISP or DPI middlebox sees it.

### Prerequisites (read before scanning)

> **Disable any active VPN / Zapret / proxy on the host running the
> scanner before you start.** The scanner now checks this itself
> (preflight, step 1b) and refuses to give a verdict when its own stack
> is compromised:
>
> | preflight finding | effect |
> |---|---|
> | the route to the target leaves through a tunnel adapter (Wintun, WireGuard, TAP, sing-tun, PPP) | **blocked**: no probe is sent, label `UNRELIABLE`, exit 5 |
> | a TCP connect to `192.0.2.1` (RFC 5737, routed nowhere) succeeds on the target's route | **blocked**: a local stack accepts every SYN, every "open port" would be fake |
> | zapret (winws), GoodbyeDPI or clumsy running | **blocked**: our packets are rewritten in flight |
> | target resolves to a fake-IP or CGNAT address | **blocked** |
> | `--expect-ip A` given and lookup services see another address | **blocked** |
> | tunnel adapters up but the target route is direct | warning: GeoIP, CT and RTT anchors may go through the tunnel |
> | proxy clients running, system proxy or `HTTP(S)_PROXY` set | warning |
> | lookup services (ipify, icanhazip, ifconfig.me) disagree on our address | warning: egress depends on destination |
>
> `--i-know-what-i-am-doing` runs the scan anyway; the verdict is then
> marked as overridden in the report and in JSON. The external address
> check is skipped under `--no-geoip` / `--stealth`. The `local` mode
> (`byebyevpn local`) is the one place where an active VPN is the point.

### Pipeline

| # | Module                          | What it does                                                            |
|---|---------------------------------|-------------------------------------------------------------------------|
| 1  | DNS resolve                     | A + AAAA, IPv4 preferred                                                |
| 1b | Preflight                       | Tunnel on the target route, local ack-all, packet rewriters, proxies, external address; blocks the verdict when the scanner itself is compromised |
| 2  | GeoIP aggregation               | 5 HTTPS-only providers in parallel, ASN + flags; reference only, never scored |
| 3a | TCP port scan                   | Connect-scan 1-65535 (default) or 205 curated ports, 500 threads; no SYN retransmission, so a closed port reads as refused, not timeout |
| 3a | Path check + ack-all control    | 10 connects to the first open port (loss, RTT); 3 random dynamic-range ports that must refuse |
| 3b | TCP stack fingerprint           | Handshake distribution + SIO_TCP_INFO peer window/MSS + closed-port reply, no admin; reference only, no OS guess |
| 4  | UDP probes                      | WireGuard / AmneziaWG / QUIC: replies validated against each protocol's response layout |
| 4b | AmneziaWG S1 deep-probe (v2.6.0)| Junk-prefix size sweep on :51820, response experiment only; cannot confirm AWG/S1  |
| 5  | Service fingerprint + CT        | SSH, HTTP, TLS + SNI consistency, SOCKS5, CONNECT, Shadowsocks, crt.sh, proxy-header leak |
| 5b | uTLS dual-probe + JA4 + JA4S    | Two ClientHellos per TLS port (synthetic Chrome-style hello vs openssl-default), JA4 / JA4S extracted from raw CH/SH bytes, JA4S classified against a backend-stack table |
| 6  | J3 / TSPU active probing        | 8 probes per TLS port; reply / closed / reset / held open per probe, reference only |
| 7  | SNITCH + traceroute + SSTP      | RTT vs GeoIP (methodika §10.1), ICMP hop-count, Microsoft SSTP          |
| 8  | Verdict                         | Checks with passports, coverage, score 0-100 or INCONCLUSIVE / UNRELIABLE with reasons, blind spots |

### UDP handshakes

v2.6.0 narrowed the UDP set to the modern signature-less tunnels.
the legacy OpenVPN / IKEv2 / L2TP / TUIC / plain-QUIC / DNS probes were
removed: those protocols carry fixed-port / fixed-header signatures any
DPI already catches, so probing for them cost scan time without adding
detection value for this niche.

| Port       | Protocol           | Payload                                               |
|------------|--------------------|-------------------------------------------------------|
| 51820      | WireGuard          | 148-byte MessageInitiation, randomized body           |
| 51820      | AmneziaWG Sx=8     | Delta-probe: vanilla WG rejected, Sx=8 prefix accepted |
| 55555      | AmneziaWG Sx=8     | 8-byte junk prefix + WG init                          |
| 51820      | AmneziaWG S1 sweep | 12-step junk-prefix size sweep, does not identify AWG or S1 |
| 36712      | Hysteria2          | QUIC v1 Initial, random DCID                          |
| 443        | Hysteria2          | QUIC v1 Initial on :443                               |
| 51820 or `--wg-port` | WireGuard keyed | full MessageInitiation from the owner's peer key; only with `--wg-pubkey` and `--wg-key` |

#### What a UDP reply is allowed to prove

A datagram coming back is not evidence of a protocol: echo services,
reflectors and generic middleboxes all answer. Every reply is matched
against the protocol's real response layout before it can move the score
(`src/scan/udp_validate.h`), and any verbatim echo of our own payload is
discarded outright:

- **WireGuard**: accepted only on a valid `MessageResponse` (type `0x02`,
  three reserved zero bytes, exactly 92 bytes) or a cookie reply (type
  `0x03`, 64 bytes) whose receiver index equals the sender index of our
  probe. Before this check, 92 bytes of unrelated `02 00 00 00` garbage
  scored `IMMEDIATE BLOCK` (lab stand K). A reply triggers two more probes;
  two agreeing replies are required. Real WireGuard and AmneziaWG never
  answer a probe without the server key and a known peer key, so on real
  servers this stays silent and is reported as not measured. The owner can
  check a WireGuard node with keys, see below.
- **AmneziaWG**: accepted on a WG `MessageResponse` sitting behind a junk
  prefix, which is what AmneziaWG emits with default `H1`-`H4`. This is
  reported as *AmneziaWG-consistent*, not confirmed: it is unauthenticated,
  and a custom `H1`-`H4` set rewrites the type byte and will not match at
  all. The S1 sweep is a response experiment; it does not recover S1.
- **QUIC**: a valid QUIC packet confirms a **QUIC endpoint**, nothing more.
  HTTP/3 is ordinary web traffic and every QUIC stack answers an Initial
  identically, so this is a note and never moves the score, on any port.
  The seven preset ports are probed before open TCP ports; ports cut by
  the 12-port cap are listed as not probed.

None of these authenticates the peer: the scanner holds no key. They rule
out the accidental false positives, which is the most a score is entitled
to rest on. For real AmneziaWG evidence use `awg-entropy` on captured
traffic (see below).

#### WireGuard self-check with your own keys

```
byebyevpn scan <your-node> --wg-pubkey server.pub --wg-key peer.key [--wg-psk peer.psk] [--wg-port 51820]
byebyevpn udp  <your-node> --wg-pubkey <base64> --wg-key peer.key
```

A WireGuard server answers nobody without keys: mac1 needs the server
public key, and after mac1 the server decrypts the initiator's static key
and silently drops a peer it does not know. So the check needs the server
public key **and** the private key of a peer configured on that server,
both from your own configs. With them the scanner sends a normal
148-byte initiation (fresh ephemeral, TAI64N timestamp rounded like
wireguard-go) and checks the reply cryptographically: a response whose mac1
verifies can only come from the holder of the server private key. Two
agreeing answers, 1 to 1.5 s apart, give `wg-keyed` positive (tier A, -15,
counted once together with `wg-family`). Silence is inconclusive: a wrong
key, a filter and no listener look the same. A preshared key that differs
is reported as such and still counts, since mac1 already proved the server.

- the public key may be given as text or a file; the private key and the
  preshared key only as files, so they never sit in the process list;
- keys are never printed and never written to JSON (`wg_self_check` holds
  `requested`, `ran` and `port`);
- the server moves that peer's endpoint to this machine until the peer's
  own client sends again: use a spare peer for the check;
- it measures the path from this machine to the node at this moment. It
  does not cover AmneziaWG with junk or custom headers, which drops a plain
  initiation (inconclusive, not "hidden").

### J3 probes

Eight probe types fired at every TLS-capable port:

1. Empty TCP connect (no bytes)
2. `GET /` with a real Host header
3. `CONNECT example.com:443`
4. Plausible OpenSSH banner
5. 512 random bytes (via `RAND_bytes`)
6. TLS ClientHello with random `.invalid` SNI
7. Absolute-URI proxy-style `GET`
8. `0xFF × 128`

Each probe ends in one of: reply, closed by peer (FIN), reset (RST), no
reply with the connection held open, or no connect. Earlier builds printed
all non-replies as `SILENT (dropped)` and called six of them
"silent-on-junk (TLS-only / Reality-hidden)" on a plain nginx-like site.
The counts are only read when a well-formed TLS or HTTP exchange worked on
the same port (control); on a lossy path silence is declared not evidence.
J3 is reference output: it never moves the score and does not identify
Reality, Vision or any other protocol.

TLS certificates, HTTPS parsing and crt.sh lookup limits are documented in
[TLS/HTTP observations](docs/WEB_OBSERVATIONS.md). Short-lived certificates,
missing `Server` headers and CT lookup misses do not reduce the score.

### Verdict scale

| Score  | Label          | Meaning                                           |
|--------|----------------|---------------------------------------------------|
| 85-100 | `CLEAN`        | Few or no weighted indicators matched |
| 70-84  | `NOISY`        | Some weighted indicators matched |
| 50-69  | `SUSPICIOUS`   | More weighted indicators matched |
| < 50   | `OBVIOUSLY VPN`| Many or heavily weighted indicators matched |

| -      | `INCONCLUSIVE` | The scan did not happen in a way that supports a verdict; reasons are listed |
| -      | `UNRELIABLE`   | Preflight failed; the results describe this machine, not the target |

These are legacy heuristic labels, not protocol confirmation or detection
probabilities. `CLEAN` means that no named signature answered. It does not
mean the node is invisible to DPI: every report lists what these probes
cannot see (Reality with a working target, Shadowsocks AEAD/2022,
WireGuard without the owner's keys, AmneziaWG, Trojan or VLESS behind a
real site).

Only four signals move the score, each with a passport in
[docs/SIGNALS.md](docs/SIGNALS.md): `wg-family` (-15), `wg-keyed` (-15,
owner self-check, one score together with `wg-family`), `sstp` (-18),
`socks5` (-20), all tier A. Every check ends as positive, negative,
inconclusive or not applicable; only positives move the score, and a
positive needs two agreeing observations out of at most three. GeoIP tags,
junk probes, TCP stack data, JA4S families and RTT are reference output.

No verdict is given when: preflight failed; 2 of 3 random control ports
accepted a connection (ack-all path); the path check lost 50% or more;
more than half of the applicable signature checks were inconclusive; the
TCP scan was interrupted; or no service answered in an attributable way.

Any tier A match caps the score at 69, so the label is at least
`SUSPICIOUS` and the exit code at least 2. Earlier builds could print
`CLEAN 85` next to `IMMEDIATE BLOCK` for a single WireGuard-shaped reply.
The error matrix of every signal against known targets is in
[docs/GROUNDTRUTH.md](docs/GROUNDTRUTH.md) and
[docs/CALIBRATION.md](docs/CALIBRATION.md).

### TSPU emulation

| Tier | Verdict          | Meaning                                                 |
|------|------------------|---------------------------------------------------------|
| A≥1  | `IMMEDIATE BLOCK`| At least one legacy tier A rule matched |
| B≥2  | `BLOCK` (cumul.) | At least two legacy tier B rules matched |
| B=1  | `THROTTLE / QoS` | One legacy tier B rule matched |
| 0    | `PASS / ALLOW`   | No rules in this model matched |

This model does not reproduce a verified operator classifier. These category
names are retained for compatibility and do not establish actual blocking,
throttling or allowance. JSON marks `thresholds_validated` and `blocking_verified`
as `false`. No current signal is tier B, so the two middle rows cannot occur;
see [docs/TSPU-MODEL.md](docs/TSPU-MODEL.md) for why nothing supports an
accumulative tier on the box.

### On-the-wire posture

The tool does not impersonate a browser. Every outbound HTTP request
(to IP-intel services, to the target during HTTP-over-TLS audit, to
crt.sh) goes out with zero tool-specific headers.

For `http_get()` - the one used against IP-intel services, crt.sh and
the DoH lookup of the `ech` command - the request is byte-wise
(captured on loopback):

```
GET /path HTTP/1.1
Connection: Keep-Alive
Host: <host>
```

`Connection: Keep-Alive` is added by WinHTTP itself. The Cloudflare DoH
fallback of `ech` adds `Accept: application/dns-json`, nothing else does.
No `User-Agent`, no `Accept-Language`, no `Accept-Encoding`, no
`Sec-Fetch-*`, no `Upgrade-Insecure-Requests`. Builds before this fix
also sent `Accept-Encoding: gzip, deflate`. A compressed reply is now
rejected instead of decoded.

For `https_probe()` - the target HTTP-over-TLS audit - headers are
also minimal (`Host`, `Accept: */*`, `Connection: close`). `dpi --volume`
sends the same three headers to the node and to the control host.

The WireGuard self-check (`--wg-pubkey`, `--wg-key`) sends a full
148-byte initiation built like a real client's: RAND_bytes ephemeral key
and sender index, TAI64N timestamp with the low 24 bits of nanoseconds
cleared as wireguard-go and the Linux module do, mac2 zero. Up to three,
1.0 to 1.5 s apart.

Earlier versions (v2.5 - v2.5.4) emitted a Chrome-131 header block
intended to look "browser-like". That was itself a unique static
fingerprint and has been dropped (see
[issue #5](https://github.com/pwnnex/ByeByeVPN/issues/5)).

For protocol probes (UDP handshakes, TLS ClientHello, ICMP) every
field that a real client would randomize is filled via OpenSSL
`RAND_bytes`: WireGuard MessageInitiation body, AmneziaWG junk prefix +
WG body, Hysteria2 QUIC DCID, TLS ClientRandom, invalid-SNI prefix.

ICMP traceroute payload is the Windows `ping.exe` pattern
(`abcdefghijklmnopqrstuvwabcdefghi`, 32 bytes). Builds before this fix
sent 33 bytes (the C string terminator went out too), which no Windows
tool emits.

The uTLS dual-probe (v2.6.0) sends two different ClientHellos per TLS
port. The "chrome" side is a synthetic hello built by hand
(`src/scan/chrome_ch.cpp`): the Chrome extension set from before
X25519MLKEM768, GREASE at the spec positions, a GREASE-prefixed x25519
key_share and the padding extension. Its JA4 is
`t13d1516h2_8daaf6152771_e5627efa2ab1`, the FoxIO example value. It is
not what a current Chrome sends: the extension order is fixed (Chrome
permutes it per connection), there is no X25519MLKEM768 key share and no
ECH GREASE. Treat it as its own fingerprint, not as browser traffic.
The "openssl" side is the default OpenSSL ClientHello, same as the
existing `tls_probe`. SNI is the target's hostname in both.
ClientHello / ServerHello bytes stay in-process; JA4 / JA4S hashes are
computed locally and never transmitted.

The TCP stack fingerprint (3b) does not change anything on the wire.
It runs 6 sequential `SOCK_STREAM` connects to an already-known open
port, calls `WSAIoctl(SIO_TCP_INFO_v0)` on the local handle, and (if
asked) tries one connect to a closed port. No raw socket, no admin,
no extra packet shapes.

Measurement-health traffic added for the false-positive work: preflight
sends one SYN to `192.0.2.1` on a random port (only when the target shares
its route) and, unless `--no-geoip`, one GET each to `api.ipify.org`,
`icanhazip.com` and `ifconfig.me/ip` through `http_get()`. After the port
scan: 10 connects to the first open port (path check) and one connect to
each of 3 random ports in 49152-65535 (ack-all control). SOCKS5 greetings
and SSTP setup requests are repeated until two agree (at most three);
a WireGuard or AmneziaWG probe that gets a reply is sent twice more.
Every connect is made with SYN retransmission off (`SIO_TCP_INITIAL_RTO`).

`local` sends nothing unless a tunnel adapter is up. Then, only when a
non-tunnel adapter holds a global IPv6 address, one TCP connect each to
`[2606:4700:4700::1111]:443` and `[2001:4860:4860::8888]:443`, closed at
once with no payload; and to each resolver the system would use beside the
tunnel (at most three), two standard queries for `example.com` A with a
RAND_bytes id. `pcap`, `diff` and `audit-config` read files only.

TLS clients no longer put an IP literal into SNI (RFC 6066 section 3): with
an IP target the OpenSSL probes send no SNI, the synthetic Chrome-style
hello omits `server_name` (so its JA4 starts `t13i`), and the SSTP request
uses the host name or no SNI plus a random correlation GUID instead of
`{00000000-...}`.

### Audit

Grep the modular source tree for tool-identifying strings. Since
v2.5.8 the source is split across `src/**/*.cpp` and `src/**/*.h`
under `src/common`, `src/net`, `src/scan`, `src/local`, `src/app`,
plus `src/main.cpp`. Expected matches: only the `--help` printf in
`src/app/cli.cpp` (cap is 3 to leave headroom).

```
$ grep -rnE 'ByeByeVPN|BYEBYEVPN|BBVPN|BBV|pwnnex' \
    src --include='*.cpp' --include='*.h'
src/app/cli.cpp:131:    printf("ByeByeVPN - full TSPU/DPI/VPN ...
```

None of these reach a socket. The CI workflow
(`.github/workflows/release.yml`) fails the build if more than three
matches appear.

### Install

Windows: download `byebyevpn-v3.2.0-win64.zip` from
[Releases](../../releases), extract, run `byebyevpn.exe` - either
double-click for the interactive panel, or pass an IP/hostname from
the terminal.

Runtime: Windows 10 1803+ / 11 / Server 2019+. No admin, no DLLs, no
.NET, no VC++ Redistributable. Internet access for GeoIP, CT-log, the
preflight external-address check and the `ech` DoH lookup; all of them
are optional (`--no-geoip`, `--no-ct`, `--stealth`). The panel needs a
console with VT support (Windows Terminal or conhost on Windows 10+).

Linux / macOS: run through Wine. Everything except `local`
(host-side adapter enumeration) works identically.

Verify what you downloaded: every release ships a SHA256 in the
release notes, a CycloneDX SBOM (`byebyevpn-sbom.json`), and -
when the project signing key is configured - matching `.minisig`
signatures. See `BUILD.md` for the verify recipe.

### CLI

```bash
byebyevpn                        # interactive panel
byebyevpn <host>                 # full scan
byebyevpn scan 1.2.3.4           # same, explicit
byebyevpn <host> --json          # full scan, JSON on stdout (v2.6.0)
byebyevpn ports my.server.ru     # tcp scan only
byebyevpn udp my.server.ru       # udp probes only
byebyevpn tls my.server.ru 443   # tls + sni consistency
byebyevpn j3 my.server.ru 443    # j3 active probing
byebyevpn geoip 8.8.8.8          # geoip aggregation
byebyevpn snitch my.server.ru    # rtt vs geo (methodika §10.1)
byebyevpn trace my.server.ru     # icmp hop-count
byebyevpn local                  # scan this machine, IPv6 and DNS leaks included
byebyevpn audit-config cfg.json  # identify configured protocols and audit settings
byebyevpn sweep 1.2.3.0/24       # cluster a subnet by TLS fingerprint (v2.8.0)
byebyevpn names sub.mysite.ru    # does the NAME give you away? offline, no packets
byebyevpn pcap client.pcapng --node 1.2.3.4   # your own capture as the box reads it
byebyevpn batch nodes.txt --out today         # every node in the file, one report each
byebyevpn diff yesterday today   # what changed per node, offline
```

Every command that sends packets to a target (`scan`, `ports`, `udp`,
`tls`, `j3`, `grpc`, `snitch`, `trace`, `dpi`) runs the preflight first and
exits 5 without sending anything when it fails.

### Interactive panel

Run `byebyevpn` with no arguments (or double-click it) for a full-screen
panel:

```
  ● byebyevpn v3.2.0   your node through a DPI box's eyes
 machine  ● direct via Ethernet   public targets pass preflight
╭─ menu ──────────────────────╮╭─ SCAN ─────────────────────────────────────────╮
│ SCAN                        ││ Full scan                                      │
│ ▸ Full scan                 ││ Preflight, TCP ports, path check, UDP, TLS,    │
│   Quick scan (205 ports)    ││ junk probes, verdict. ...                      │
│   DPI path test (SNI)       ││                                                │
│ PROBES                      ││ sends: Preflight, then every probe ...         │
│   TCP ports                 ││ settings  (S to change)                        │
│   ...                       ││ ports all 65535   timeout 800 ms   ...         │
│                             ││ last full scan                                 │
│                             ││  CLEAN   100/100   tier PASS / ALLOW           │
╰─────────────────────────────╯╰────────────────────────────────────────────────╯
 ↑↓ move   ←→ section   Enter run   S settings   L last scan   R refresh   Q quit
```

- the status bar shows, without sending anything, whether public traffic
  from this machine leaves through a tunnel, and whether proxy clients,
  packet rewriters or a system proxy are active;
- each item says what it does and **what it sends**, before you run it;
- Settings (`S`): port range (all, 205 curated, custom list), timeout,
  threads, stealth, passive, GeoIP and CT lookups, junk probes per port,
  saving each run to `<target>.md`, preflight override;
- a run leaves the panel so the full output scrolls normally, then shows a
  result card; the panel keeps the last verdict and the target history
  (memory only, nothing is written to disk unless saving is on).

Every action calls the same code as the command line, so the panel sends
exactly the same probes. Without a console (pipe, redirect) the program
falls back to a prompt that takes command lines such as `scan 1.2.3.4`.

### Hostname markers (`names` and full scans)

```bash
byebyevpn names sub.example.com vless-de1.example.com
byebyevpn names wg01.example.com us8360.nordvpn.com --json
```

This offline check finds protocol, panel and subscription naming conventions.
It accepts ASCII hostnames and Punycode (`xn--`), validates label boundaries,
and uses a bundled Public Suffix List, including private hosting suffixes.
Generic words match whole components: `sub2` matches, `subaru` does not.
Distinctive names such as `amneziawg` also match within combined labels.

`strong`, `moderate` and `weak` describe a naming association, not measured
accuracy or proof of a running protocol. **No hostname finding changes the
full scan score or TSPU verdict.** Certificate names may describe another
service; the report retains each source (`target`, `cert_cn:port`, `cert_san:port`).

Provider-domain and node-pattern rules cover selected Mullvad, IVPN, NordVPN
and Cloudflare WARP names. A provider's website is not necessarily a VPN endpoint.
`workers.dev` is reported as shared application hosting, not VPN evidence.
Plain `names` does not resolve names, enumerate subdomains or query CT logs.

`names example.com --ct` lists every name under your domain that public
certificate transparency logs already hold (via crt.sh), with the same
markers: `panel.`, `sub.`, `remnawave.` and the rest are exactly what
anyone finds there without touching your node. `--ct-file saved.json`
reads a crt.sh JSON you saved instead, with no network at all.
`--resolve` asks DNS from this machine for those names and shows which
share an address; `--node IP` marks your node (behind a CDN a shared
address means nothing, and the output says so). A failed lookup exits 4
and is never read as "no names"; crt.sh is often overloaded, retry later
or use `--ct-file`.

Exit codes: **3** strong naming hints, **2** moderate, **0** weak/none/IP input,
**64** invalid input. Exit 0 does not certify a clean server. Invalid names
have explicit errors in JSON; mixed inputs are all reported and exit 64.
See [matching rules, sources and limitations](docs/HOSTNAME_ANALYSIS.md).

A completed full scan exits with the verdict tier so wrapper scripts
can branch without parsing output (v2.6.0):

```
0  CLEAN (score >= 85)        2  SUSPICIOUS (50-69)
1  NOISY (70-84)              3  OBVIOUSLY-VPN (< 50)
4  INCONCLUSIVE (no verdict)  5  UNRELIABLE (preflight failed)
64 usage error (no target)
```

`dpi` runs the same preflight and exits 5 when it fails. `ech` exits 4
when the DoH lookup itself failed; "no HTTPS RR" (exit 1) is printed only
when a resolver answered NOERROR without one.

#### Client-side checks: `dpi` and `dpi --volume`

Run these from your ordinary connection against your own node. They
measure the path between this machine and that host at this moment; the
result does not carry over to another connection, operator or day, and
every result says so.

- `dpi <host> [port]`: SNI reset or silent drop on the first flight. Prints
  `SNI check: positive / negative / inconclusive / not applicable`, exit
  codes as before, `--json` for scripts.
- `dpi <host> [port] --volume /path --control host[:port]/path`: the 16-20 KB
  freeze field reports describe (F7). The tool downloads `/path` from your
  node over TLS (the path must serve 64 KB or more) and the control path
  from a host you know carries volume, control before and after. Positive
  means bytes stopped on an open connection for 8 s in two transfers at the
  same offset while the control carried 64 KB or more; the text says
  whether the offset lies in the 16-20 KB band. No control, a failing
  control, stalls at different offsets, or a connection closed by FIN or
  RST give inconclusive; a resource under 64 KB gives not applicable. Exit
  0 carried, 2 stalled, 4 inconclusive or not applicable. The request is
  `GET` with Host, Accept and Connection, the same header set as the HTTPS
  probe.
- `dpi <node> [port] --sni NAME --real IP|auto`: the name your node serves
  (for Reality, its serverName) goes to the node and to the address the
  name really lives on (`auto` resolves it). If it fails to the node and
  passes to its own address while a benign name to the node works, this
  path ties the name to its address, the rule field reports blame for
  Reality with brand targets. If it fails to both, the name itself is
  blocked here. Two agreeing rounds out of three; exit 0 passes, 2 fails,
  4 inconclusive.

Hostnames are resolved via `getaddrinfo`; IPv4 is always preferred,
and the chosen IP is printed in phase [1/8]. On IPv4-only links (RU /
CIS consumer internet) this avoids the happy-eyeballs AAAA trap where
an unreachable v6 silently burns every timeout.

### AmneziaWG entropy/sequence analysis (PCAP/PCAPNG)

```powershell
byebyevpn awg-entropy connection.pcapng --json
```

Offline analysis of the **outer UDP traffic of an actual connection**. Reports
per-flow byte/nibble entropy and repeated variable-size packet trains followed
by bidirectional traffic. Designed with the examined AWG 2.x, 3.0 and latest
3.1 sources in mind; does not rely on fixed headers, handshake sizes or timers.

`AWG_COMPATIBLE_HEURISTIC` is a compatibility hint, **not protocol proof**.
Entropy cannot determine the AWG version. Ordinary encrypted UDP can also
match, and a missing pattern does not exclude AWG. This command does not change
the live scan score. Exit 0 means analysis completed; 64 is an input error.

See [source research, thresholds, capture requirements and limitations](docs/AMNEZIAWG_ANALYSIS.md).

### Your own capture: `pcap`

```powershell
byebyevpn pcap client.pcapng --node 203.0.113.5
byebyevpn pcap client.pcapng --node 203.0.113.5 --json
```

Capture your own client on the **physical interface** (Wireshark, `tcpdump`,
`pktmon` + `etl2pcap`), open a few sites through the tunnel, stop, and
give the file to `pcap`. It reads what a box on that link reads before any
key, and sends nothing:

- **client hellos**: SNI, JA4 (TCP, and QUIC from the decrypted Initial),
  GREASE, the ECH extension, a post-quantum key share, ALPN. No GREASE
  means not Chromium or Safari. `ech-ext yes` can be Chromium's GREASE ECH,
  which still carries the real name;
- **a TLS handshake inside the tunnel**: per server, the sizes of the first
  flights after the outer handshake. An inner ClientHello, a certificate
  flight back, then a client record of exactly an inner TLS 1.3 Finished
  (58, 64, 74 or 80 B). Positive needs two matching flows. Calibrated on
  real xray: VLESS and Trojan over TLS without Vision match 4 of 4 flows,
  Vision and plain HTTPS 0 of 4. A size rule only; a negative is not
  "invisible";
- **DNS in the clear**: queries on port 53 and the resolvers they went to;
  DoH to well-known resolver names is marked;
- **traffic beside the node** (`--node`): public addresses other than your
  node, IPv6 counted apart.

Exit 2 when any of the last three is positive, 0 otherwise, 64 on a file it
cannot read. Files up to 64 MiB; TCP is rebuilt for the first 64 KB of each
direction.

### Leaks on this machine: `local`

`byebyevpn local` lists adapters, routes and VPN software as before and
adds two checks that matter only while a tunnel adapter is up:

- **IPv6 beside the tunnel**: if a non-tunnel adapter has a global IPv6
  address, the tool connects to two public resolvers over IPv6 (a plain
  TCP connect, closed at once) and looks at which local address the system
  picked. No global IPv6 outside the tunnel: negative with no packets.
- **DNS beside the tunnel**: Windows asks every adapter's resolver in
  parallel unless a policy turns it off. The tool lists the resolvers the
  system would use beside the tunnel and asks each twice for
  `example.com`; an answer there means names leave in the clear. A kill
  switch that drops them gives silence (inconclusive) or a refused send
  (negative), never a leak.

Exit 2 when either leaks, 0 otherwise. Windows only.

### Several nodes: `batch` and `diff`

```powershell
byebyevpn batch nodes.txt --out 2026-10-01 --fast
byebyevpn diff 2026-09-24 2026-10-01
```

`batch` runs the full scan on every line of the file (`#` starts a
comment, duplicates are skipped, at most 256), prints a summary table and
with `--out DIR` keeps one `--json` report per node. Scan options apply to
every node; exit is the worst node's verdict code. `diff` compares two
reports or two such directories, file by file: verdict (label, tier,
checks, scored signals), surface (address, open ports, certificates,
JA4S) and context (score, GeoIP tags). Offline; exit 2 when a verdict
changed, 1 for any other change, 0 when nothing changed.

### Config audit

```powershell
byebyevpn audit-config server.json
byebyevpn audit-config server.json --json
```

Reads an Xray, sing-box or WireGuard/AmneziaWG configuration offline. The Xray
report identifies configured protocols, transports and Vision users, and checks
selected compatibility and exposure issues. It supports both the current
`method`/`users` fields and legacy `network`/`clients` aliases.

Removed XTLS, legacy HTTP/QUIC transports, invalid Vision flows, old VMess and
Shadowsocks settings, REALITY short IDs and proxy authentication are covered.
Both cores: two listeners on one port and socket layer (TCP and UDP may
share a number), a TLS version range with nothing left in it, and a control
API on a public address (Xray `api`, sing-box Clash or V2Ray API). Xray only:
duplicate inbound tags and duplicate user emails, which stop the core.
sing-box gets the REALITY short ID and handshake-server checks Xray already
had, and REALITY with `tls.enabled` off is now reported as plaintext: before,
the brand rule fired on a handshake server sing-box never used.

Findings that do not change what an observer sees print in a separate
**Hygiene** block and never move the tier: settings for another transport
or security mode that the core ignores, two users with one id or password,
debug logging, REALITY `show`.

Client configs (proxy outbounds) are checked too: VLESS or Trojan without
TLS, no browser fingerprint (Go ClientHello), no server name, certificate
checks off, a malformed REALITY key or shortId.
`byebyevpn audit-config server.json client.json` checks a client against
its server, Xray and sing-box in any mix: port, protocol, transport,
security, path, user, flow, REALITY serverName and shortId, and whether the
client's publicKey really belongs to the server's privateKey. Each
mismatch is a compatibility error; no key, id or password is printed.
Compatibility errors exit with **65** and don't count as network signatures.
File/parse errors exit with **64**; **0-3** retain the legacy exposure tiers.
The file size limit is 16 MiB.

Results come from configuration only. Keys, certificate files, routing and
firewalls are not validated; no remote connection is made. Default ports,
entropy and TLS negotiation differences do not confirm Xray or Vision.
The legacy `tspu_tier` field is an unvalidated heuristic, not a measured block.

See [Xray source research, checks and limits](docs/XRAY_AUDIT.md).

### Port scan modes

```
--full                    all ports 1-65535 (default)
--fast                    205 curated VPN / proxy / TLS / admin ports
--range 8000-9000 ports   port range
--ports 80,443,8443       explicit list
```

### Tuning

```
--threads N       parallel TCP connects      (default 500)
--tcp-to MS       TCP connect timeout         (default 800)
--udp-to MS       UDP recv timeout            (default 900)
--no-color        disable ANSI colors
-v / --verbose    verbose output
--expect-ip A     preflight: the external address lookup services must see
--i-know-what-i-am-doing
                  scan despite a failed preflight; verdict marked overridden
```

### Stealth / privacy

```
--stealth         --no-geoip + --no-ct + --udp-jitter, AND adds
                  inter-probe timing jitter across J3 / SNI consistency /
                  uTLS dual-probe / AmneziaWG sweep (v2.7.0)
--no-geoip        skip all HTTPS GeoIP lookups
--no-ct           skip crt.sh CT-log query
--udp-jitter      50-300ms random delay between UDP probes
--j3-subset N     send a random N-probe subset (1..7) of the eight J3
                  probes per port instead of all eight (v2.7.0)
--passive         minimal-probe mode: SKIPS J3, uTLS dual-probe, SNI
                  consistency loop and AmneziaWG S1 sweep entirely. one
                  base TLS handshake + GeoIP + CT-log + traceroute +
                  SNITCH only. fewest scanner-shaped patterns on the
                  wire (v2.7.0)
```

All default off. Default scan emits the same bytes v2.6.0 emitted.

Anti-fingerprint context: v2.7.0 randomizes the J3 probe order with a
CSPRNG-backed Fisher-Yates per scan, so the fixed `empty -> GET ->
CONNECT -> SSH -> rand -> tls-invalid -> abs-URI -> 0xff` sequence is
no longer on the wire. The synthetic ClientHello randomness also moved
to `RAND_bytes` (away from `std::mt19937`).

### Save scan output

```
--save            write the scan to <target>.md in the current directory
--save <path>     write the scan to <path> (markdown-wrapped)
```

ANSI colors are stripped from the file; terminal output is unchanged.
The file is wrapped in a markdown code block so it renders cleanly in
any md viewer.

### Build

See [BUILD.md](BUILD.md) for full instructions, OpenSSL provenance,
and SHA256s. Short form:

```bash
# msys2 UCRT64
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-make
git clone https://github.com/pwnnex/ByeByeVPN.git && cd ByeByeVPN
make windows-static
```

Release zips are produced by
[`.github/workflows/release.yml`](.github/workflows/release.yml) from
a pinned msys2 image. SHA256 of the exe and zip are printed in each
release's notes for verification.

### Limitations

- Connect-scan, not SYN-scan. Full TCP handshake seen by the target.
- Cloudflare WARP / CGNAT / corporate proxies / local TUN clients can
  ACK every port. Preflight tests the local side with `192.0.2.1`; after
  the scan, 3 random dynamic-range ports must refuse. Two accepted ports
  (or one plus >60 open ports with RTT spread <80 ms) void the verdict.
- The uTLS dual-probe sends a synthetic Chrome-style ClientHello that
  is not byte-identical to any current Chrome (see above). The
  raw-socket path does not run the TLS 1.3 key schedule, so it has
  no peer cert for the Chrome side - cert-steering detection still
  relies on the openssl-side handshake. The main `tls_probe` hello is
  the OpenSSL default.
- QUIC probes (v2.8.0) send a real RFC 9001 protected Initial - the
  Initial key schedule, AEAD payload protection and header protection
  are byte-exact against the RFC 9001 Appendix A test vectors, and a
  TLS ClientHello rides in a CRYPTO frame. a QUIC listener decrypts it
  and answers. the ClientHello carries ALPN `h3` and the
  quic_transport_parameters extension (0x39) with
  initial_source_connection_id. the probe confirms a QUIC endpoint and
  captures its response shape, but does not drive a full QUIC handshake
  to completion.
- GeoIP providers disagree and share upstream feeds. Their VPN, proxy
  and Tor tags are printed for reference and never move the score.
- An active scan cannot see what the classifier sees passively (address
  lists, SNI policy, first-packet heuristics, the volume freeze). See
  [docs/COVERAGE.md](docs/COVERAGE.md).

### License

GPL-3.0-or-later. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Releases up to v2.5.9 were MIT. From v2.6.0 onward the project is
GPL-3.0-or-later. Old MIT releases keep their MIT grant; nothing is
revoked retroactively. The relicense was done by the sole copyright
holder (every commit up to v2.6.0 was authored by pwnnex).

---

## Русский

### Назначение

Получив IP или hostname, программа прогоняет полную методику
Роскомнадзора (§5-10) + современные 2026 сигнатуры обфусцированных
туннелей против этой цели, работая как внешний наблюдатель. На выходе:
score детектируемости, определённый стек, и решение, которое принял
бы ТСПУ-классификатор. Подключаться к VPN цели не нужно - сканер
смотрит на неё так же, как видит провайдер или DPI-middlebox.

### Подготовка (читай до запуска)

> **Перед запуском выключи на хосте любой активный VPN / Zapret /
> GoodbyeDPI / прокси.** Теперь сканер проверяет это сам (preflight,
> шаг 1b) и отказывается выдавать вердикт, если его собственный стек
> скомпрометирован:
>
> | что нашёл preflight | что будет |
> |---|---|
> | маршрут до цели идёт через туннельный адаптер (Wintun, WireGuard, TAP, sing-tun, PPP) | **стоп**: ни одной пробы, метка `UNRELIABLE`, код 5 |
> | TCP-connect на `192.0.2.1` (RFC 5737, никуда не маршрутизируется) прошёл на маршруте цели | **стоп**: локальный стек принимает любой SYN, все «открытые порты» фальшивые |
> | запущен zapret (winws), GoodbyeDPI или clumsy | **стоп**: пакеты переписываются на лету |
> | цель резолвится в fake-IP или CGNAT | **стоп** |
> | задан `--expect-ip A`, а сервисы видят другой адрес | **стоп** |
> | туннель поднят, но маршрут до цели прямой | предупреждение: GeoIP, CT и RTT-якоря могут идти через туннель |
> | запущены прокси-клиенты, задан системный прокси или `HTTP(S)_PROXY` | предупреждение |
> | ipify, icanhazip и ifconfig.me видят разные адреса | предупреждение: выход зависит от назначения |
>
> `--i-know-what-i-am-doing` сканирует всё равно, вердикт помечается как
> overridden в отчёте и в JSON. Проверка внешнего адреса выключается
> `--no-geoip` / `--stealth`. Режим `local` (`byebyevpn local`) как раз
> для просмотра своих адаптеров.

### Пайплайн

| # | Модуль                          | Что делает                                                            |
|---|---------------------------------|-----------------------------------------------------------------------|
| 1  | DNS resolve                      | A + AAAA, приоритет IPv4                                              |
| 1b | Preflight                        | Туннель на маршруте до цели, локальный ack-all, переписчики пакетов, прокси, внешний адрес; без вердикта, если скомпрометирован сам сканер |
| 2  | GeoIP aggregation                | 5 HTTPS-only провайдеров параллельно, ASN + флаги; справочно, в score не входит |
| 3a | TCP port scan                    | Connect-scan 1-65535 (дефолт) или 205 curated, 500 потоков; без повтора SYN, закрытый порт читается как refused, а не timeout |
| 3a | Проверка канала + контроль ack-all | 10 connect'ов на первый открытый порт (потери, RTT); 3 случайных порта из 49152-65535 обязаны отказать |
| 3b | TCP stack fingerprint            | Распределение handshake-времени + SIO_TCP_INFO peer window/MSS + ответ закрытого порта, без админа; справочно, ОС не угадывается |
| 4  | UDP probes                       | WireGuard / AmneziaWG / QUIC: ответ сверяется с реальным layout'ом ответа протокола |
| 4b | AmneziaWG S1 deep-probe (v2.6.0) | Sweep размера junk-prefix на :51820, не подтверждает AWG или S1    |
| 5  | Service fingerprint + CT         | SSH, HTTP, TLS + SNI consistency, SOCKS5, CONNECT, Shadowsocks, crt.sh, proxy-headers |
| 5b | uTLS dual-probe + JA4 + JA4S     | По два ClientHello на TLS-порт (синтетический hello в стиле Chrome vs openssl-default), JA4 / JA4S из захваченных байт CH/SH, JA4S классифицируется по таблице стеков |
| 6  | J3 / ТСПУ active probing         | 8 probe'ов на каждый TLS-порт; для каждого reply / closed / reset / held open, справочно |
| 7  | SNITCH + traceroute + SSTP       | RTT vs GeoIP (§10.1), ICMP hop-count, Microsoft SSTP                  |
| 8  | Вердикт                          | Проверки с паспортами, покрытие, score 0-100 или INCONCLUSIVE / UNRELIABLE с причинами, слепые зоны |

### UDP handshake'и

v2.6.0 сузил UDP-набор до современных signature-less туннелей. legacy
пробы OpenVPN / IKEv2 / L2TP / TUIC / plain-QUIC / DNS убраны: эти
протоколы несут fixed-port / fixed-header сигнатуры, которые любой DPI
и так ловит, так что probe'инг по ним съедал время скана не давая
детект-ценности для этой ниши.

| Порт      | Протокол           | Payload                                              |
|-----------|--------------------|------------------------------------------------------|
| 51820     | WireGuard          | 148-байтный MessageInitiation, рандомное тело        |
| 51820     | AmneziaWG Sx=8     | Двойная проба: vanilla WG отвергается, Sx=8 принят   |
| 55555     | AmneziaWG Sx=8     | 8-байт junk-prefix + WG init                         |
| 51820     | AmneziaWG S1 sweep | Sweep из 12 размеров junk-prefix, не подтверждает AWG или S1 |
| 36712     | Hysteria2          | QUIC v1 Initial, рандомный DCID                      |
| 443       | Hysteria2          | QUIC v1 Initial на :443                              |
| 51820 или `--wg-port` | WireGuard keyed | полный MessageInitiation от ключа пира владельца; только с `--wg-pubkey` и `--wg-key` |

### J3 probe'ы

Восемь probe-типов на каждый TLS-порт:

1. Пустой TCP (ничего не шлём)
2. `GET /` с реальным Host-заголовком
3. `CONNECT example.com:443`
4. Плаузабельный OpenSSH-баннер
5. 512 байт `RAND_bytes`
6. TLS ClientHello с рандомным `.invalid` SNI
7. HTTP absolute-URI (proxy-style)
8. `0xFF × 128`

Каждая проба заканчивается одним из исходов: ответ, закрыто сервером (FIN),
сброс (RST), нет ответа при открытом соединении, нет соединения. Раньше все
неответы печатались как `SILENT (dropped)`, а шесть таких на обычном
nginx-подобном сайте давали «silent-on-junk (TLS-only / Reality-hidden)».
Счётчики читаются, только если на том же порту прошёл нормальный TLS- или
HTTP-обмен (контроль); на канале с потерями молчание уликой не считается.
J3 справочный: в score не входит и никакой протокол не определяет.

Для WireGuard ответ засчитывается, только если его receiver index равен
sender index нашей пробы; ответ вызывает ещё две пробы, нужны два
согласных. Настоящие WireGuard и AmneziaWG без ключей не отвечают никогда,
это печатается как «не измерено». QUIC-ответ это заметка и в score не
входит ни на каком порту.

#### Self-check WireGuard своими ключами

```
byebyevpn scan <своя-нода> --wg-pubkey server.pub --wg-key peer.key [--wg-psk peer.psk] [--wg-port 51820]
```

Сервер WireGuard без ключей не отвечает никому: mac1 считается от
публичного ключа сервера, а после mac1 сервер расшифровывает статический
ключ инициатора и молча отбрасывает неизвестного пира. Поэтому нужны
публичный ключ сервера **и** приватный ключ пира, который на этом сервере
настроен, оба из твоих конфигов. С ними сканер шлёт обычный 148-байтный
initiation (свежий эфемерный ключ, TAI64N с тем же округлением, что у
wireguard-go) и проверяет ответ криптографически: ответ с верным mac1 может
прислать только владелец приватного ключа сервера. Два согласных ответа с
интервалом 1-1.5 с дают `wg-keyed` positive (tier A, -15, вместе с
`wg-family` считается один раз). Тишина это inconclusive: неверный ключ,
фильтр и отсутствие слушателя неотличимы. Несовпадающий preshared key
печатается отдельно и всё равно засчитывается, mac1 уже доказал сервер.

- публичный ключ можно текстом или файлом, приватный и preshared только
  файлом, чтобы они не попадали в список процессов;
- ключи не печатаются и не пишутся в JSON (`wg_self_check`: `requested`,
  `ran`, `port`);
- сервер переносит endpoint этого пира на эту машину, пока его собственный
  клиент снова не отправит трафик: для проверки заведи отдельного пира;
- измеряется путь от этой машины до ноды в этот момент. AmneziaWG с junk
  или своими заголовками обычный initiation отбрасывает (inconclusive, а не
  «скрыт»).

Ограничения анализа сертификатов, HTTPS и crt.sh описаны в
[TLS/HTTP observations](docs/WEB_OBSERVATIONS.md). Короткий срок сертификата,
отсутствие `Server` и пустой результат поиска в CT не снижают score.

### Шкала verdict

| Score  | Label           | Смысл                                                  |
|--------|-----------------|--------------------------------------------------------|
| 85-100 | `CLEAN`         | Мало или нет учитываемых признаков |
| 70-84  | `NOISY`         | Совпала часть учитываемых признаков |
| 50-69  | `SUSPICIOUS`    | Совпало больше учитываемых признаков |
| < 50   | `OBVIOUSLY VPN` | Много признаков или признаки с большим весом |

| -      | `INCONCLUSIVE`  | Скан не состоялся так, чтобы на нём строить вердикт; причины перечислены |
| -      | `UNRELIABLE`    | Preflight не прошёл; результаты описывают эту машину, а не цель |

Это прежние названия эвристических категорий, не подтверждение протокола и не
вероятность детекта. `CLEAN` значит «ни одна именованная сигнатура не
ответила», а не «DPI эту ноду не видит»: каждый отчёт перечисляет, чего пробы
не видят (Reality с рабочим target, Shadowsocks AEAD/2022, WireGuard без
ключей владельца, AmneziaWG, Trojan или VLESS за настоящим сайтом).

Score двигают только четыре сигнала, у каждого паспорт в
[docs/SIGNALS.md](docs/SIGNALS.md): `wg-family` (-15), `wg-keyed` (-15,
self-check владельца, вместе с `wg-family` считается один раз), `sstp`
(-18), `socks5` (-20), все tier A. Каждая проверка заканчивается как positive,
negative, inconclusive или not applicable; score двигает только positive, и
для него нужны два согласных наблюдения из не более чем трёх. GeoIP-теги,
J3, данные TCP-стека, JA4S и RTT справочные.

Вердикта нет, если: не прошёл preflight; 2 из 3 случайных контрольных портов
приняли соединение (ack-all); проверка канала потеряла 50% и больше; больше
половины применимых проверок inconclusive; скан прерван; ни один сервис не
ответил так, чтобы это можно было атрибутировать. Матрица ошибок по стендам с
известной истиной: [docs/GROUNDTRUTH.md](docs/GROUNDTRUTH.md),
[docs/CALIBRATION.md](docs/CALIBRATION.md).

Любое совпадение группы A ниже ограничивает score значением 69, то есть метка
не лучше `SUSPICIOUS`, код выхода не меньше 2. Раньше один ответ в форме
WireGuard давал `CLEAN 85` рядом с `IMMEDIATE BLOCK`.

### Вердикт ТСПУ

| Tier | Вердикт          | Что это значит                                          |
|------|------------------|---------------------------------------------------------|
| A≥1  | `IMMEDIATE BLOCK`| Совпало хотя бы одно правило прежней группы A |
| B≥2  | `BLOCK` (cumul.) | Совпало хотя бы два правила прежней группы B |
| B=1  | `THROTTLE / QoS` | Совпало одно правило прежней группы B |
| 0    | `PASS / ALLOW`   | Правила этой модели не сработали |

Модель не воспроизводит проверенный классификатор оператора. Названия сохранены
для совместимости и не доказывают блокировку, замедление или пропуск трафика.
В JSON поля `thresholds_validated` и `blocking_verified` равны `false`. Сейчас
ни один сигнал не относится к группе B, две средние строки не возникают; почему
у коробки нет накопительного tier, см. [docs/TSPU-MODEL.md](docs/TSPU-MODEL.md).

### Как тулза выглядит на проводе

Программа не притворяется браузером. Каждый исходящий HTTP-запрос (к
IP-intel сервисам, к target при HTTP-over-TLS аудите, к crt.sh)
уходит **без** tool-specific заголовков.

Для `http_get()` - функция которая ходит в IP-intel, crt.sh и в DoH
команды `ech` - запрос побайтово (снят на loopback) выглядит так:

```
GET /path HTTP/1.1
Connection: Keep-Alive
Host: <host>
```

`Connection: Keep-Alive` добавляет сам WinHTTP. Резервный DoH Cloudflare
в `ech` добавляет `Accept: application/dns-json`, больше ничего. Никаких
`User-Agent`, `Accept-Language`, `Accept-Encoding`, `Sec-Fetch-*`,
`Upgrade-Insecure-Requests`. Сборки до этого исправления ещё слали
`Accept-Encoding: gzip, deflate`. Сжатый ответ теперь отвергается, а не
распаковывается.

Для `https_probe()` - аудит target'а через HTTP-over-TLS - хедеры
тоже минимальные (`Host`, `Accept: */*`, `Connection: close`).
`dpi --volume` шлёт те же три заголовка на ноду и на контрольный хост.

Self-check WireGuard (`--wg-pubkey`, `--wg-key`) шлёт полный 148-байтный
initiation, собранный как у настоящего клиента: эфемерный ключ и sender
index из RAND_bytes, TAI64N с обнулёнными младшими 24 битами наносекунд,
как у wireguard-go и модуля Linux, mac2 нулевой. До трёх штук с
интервалом 1-1.5 с.

Предыдущие версии (v2.5 - v2.5.4) отправляли блок заголовков "как
Chrome 131", чтобы "выглядеть как браузер". Это само по себе было
уникальным статическим fingerprint'ом и удалено (см.
[issue #5](https://github.com/pwnnex/ByeByeVPN/issues/5)).

Для protocol-probe'ов (UDP handshake'и, TLS ClientHello, ICMP) каждое
поле, которое реальный клиент рандомизирует, заполняется через
OpenSSL `RAND_bytes`: тело WireGuard MessageInitiation, junk-prefix +
WG-тело AmneziaWG, Hysteria2 QUIC DCID, TLS ClientRandom, префикс
invalid-SNI.

ICMP traceroute шлёт payload Windows `ping.exe`
(`abcdefghijklmnopqrstuvwabcdefghi`, 32 байта). Сборки до этого
исправления слали 33 байта (в сеть уходил завершающий ноль C-строки),
такого не шлёт ни одна утилита Windows.

uTLS dual-probe (v2.6.0) шлёт два разных ClientHello на TLS-порт.
Сторона "chrome" это синтетический hello, собранный вручную
(`src/scan/chrome_ch.cpp`): набор расширений Chrome до X25519MLKEM768,
GREASE на позициях из спеки, x25519 key_share с GREASE-префиксом,
padding. Его JA4 `t13d1516h2_8daaf6152771_e5627efa2ab1`, это пример из
спеки FoxIO. Текущий Chrome шлёт другое: порядок расширений у нас
фиксирован (Chrome перемешивает его на каждое соединение), нет
X25519MLKEM768 и нет ECH GREASE. Это отдельный отпечаток, а не трафик
браузера. Сторона "openssl" это дефолтный ClientHello OpenSSL, как в
`tls_probe`. Байты CH/SH не покидают процесс, JA4 / JA4S считаются
локально.

Служебный трафик для проверки самого измерения: preflight шлёт один SYN
на `192.0.2.1` на случайный порт (только если цель идёт тем же маршрутом)
и, если не задан `--no-geoip`, по одному GET на `api.ipify.org`,
`icanhazip.com` и `ifconfig.me/ip` через `http_get()`. После скана портов:
10 connect'ов на первый открытый порт (проверка канала) и по одному
connect'у на 3 случайных порта из 49152-65535 (контроль ack-all).
SOCKS5-приветствие и SSTP-запрос повторяются до двух согласных ответов
(не больше трёх); проба WireGuard или AmneziaWG, получившая ответ,
отправляется ещё дважды. Все connect'ы идут без повтора SYN
(`SIO_TCP_INITIAL_RTO`).

`local` ничего не шлёт, пока не поднят туннельный адаптер. Тогда, только
если у нетуннельного адаптера есть глобальный IPv6, по одному TCP connect'у
на `[2606:4700:4700::1111]:443` и `[2001:4860:4860::8888]:443`, сразу
закрытых, без данных; и каждому резолверу, которого система спросит мимо
туннеля (не больше трёх), два обычных запроса `example.com` A с id из
RAND_bytes. `pcap`, `diff` и `audit-config` только читают файлы.

TLS-клиенты больше не кладут IP-адрес в SNI (RFC 6066, раздел 3): при
цели-адресе OpenSSL-пробы идут без SNI, синтетический hello в стиле Chrome
не содержит `server_name` (JA4 начинается с `t13i`), а SSTP-запрос берёт
имя хоста или идёт без SNI, со случайным GUID вместо `{00000000-...}`.

### Аудит

Грепнуть модульное дерево исходников на tool-identifying строки.
Ожидается одно совпадение, `--help` printf в `src/app/cli.cpp`, лимит 3
оставлен как запас. В сеть оно не уходит:

```
$ grep -rnE 'ByeByeVPN|BYEBYEVPN|BBVPN|BBV|pwnnex' \
    src --include='*.cpp' --include='*.h'
src/app/cli.cpp:131:    printf("ByeByeVPN - full TSPU/DPI/VPN ...
```

CI workflow (`.github/workflows/release.yml`) проваливает сборку, если
совпадений больше трёх.

### Установка

Windows: скачать `byebyevpn-v3.2.0-win64.zip` со страницы
[Releases](../../releases), распаковать, запустить `byebyevpn.exe`
(двойной клик = интерактивная панель, либо IP/hostname из терминала).

Требования: Windows 10 1803+ / 11 / Server 2019+. Прав администратора
не нужно. DLL не нужно. Интернет нужен для GeoIP, CT-log, проверки
внешнего адреса в preflight и DoH-запроса `ech`; всё это отключается
(`--no-geoip`, `--no-ct`, `--stealth`). Панели нужна консоль с VT
(Windows Terminal или conhost на Windows 10+).

Linux / macOS: через Wine. Всё кроме `local` (адаптеры хоста)
работает идентично.

Проверка скачанного: каждый релиз идёт с SHA256 в release notes,
CycloneDX-SBOM (`byebyevpn-sbom.json`) и - когда выставлен ключ
подписи проекта - с `.minisig` подписями. Рецепт верификации в
`BUILD.md`.

### CLI

```bash
byebyevpn                        # интерактивная панель
byebyevpn <host>                 # полный скан
byebyevpn scan 1.2.3.4           # то же, явно
byebyevpn <host> --json          # полный скан, JSON в stdout (v2.6.0)
byebyevpn ports my.server.ru     # только tcp
byebyevpn udp my.server.ru       # только udp
byebyevpn tls my.server.ru 443   # TLS + SNI consistency
byebyevpn j3 my.server.ru 443    # J3 active probing
byebyevpn geoip 8.8.8.8          # GeoIP
byebyevpn snitch my.server.ru    # RTT vs geo (§10.1)
byebyevpn trace my.server.ru     # ICMP hop-count
byebyevpn local                  # сканировать свою машину, вместе с утечками IPv6 и DNS
byebyevpn audit-config cfg.json  # протоколы, Vision и ошибки настроек; без сетевых запросов
byebyevpn sweep 1.2.3.0/24       # кластеризация подсети по TLS-отпечатку (v2.8.0)
byebyevpn names sub.mysite.ru    # признаки в имени, офлайн
byebyevpn pcap client.pcapng --node 1.2.3.4   # свой дамп глазами коробки
byebyevpn batch nodes.txt --out today         # все ноды из файла, по отчёту на каждую
byebyevpn diff yesterday today   # что поменялось по каждой ноде, офлайн
```

`audit-config` для обоих ядер ловит два listener'а на одном порту и слое
(TCP и UDP могут делить номер), диапазон версий TLS, в котором ничего не
осталось, и управляющий API на публичном адресе (Xray `api`, Clash/V2Ray API
sing-box); только для Xray: повтор тега inbound и email пользователя, с
которыми ядро не стартует. sing-box получил проверки short ID и handshake
server, которые были у Xray; REALITY при выключенном `tls.enabled` теперь
печатается как plaintext. То, что не меняет картину для наблюдателя
(настройки чужого транспорта, которые ядро игнорирует, два пользователя с
одним id, debug-лог, REALITY `show`), выводится отдельным блоком
**Hygiene** и на tier не влияет.

Клиентские конфиги (прокси-outbounds) тоже проверяются: VLESS или Trojan
без TLS, нет браузерного отпечатка (уходит ClientHello от Go), нет имени
сервера, отключена проверка сертификата, битый ключ или shortId REALITY.
`byebyevpn audit-config server.json client.json` сверяет клиента с его
сервером, Xray и sing-box в любом сочетании: порт, протокол, транспорт,
защита, путь, пользователь, flow, serverName и shortId REALITY и то, что
publicKey клиента действительно от privateKey сервера. Каждое расхождение
это ошибка совместимости (выход 65); ключи, id и пароли не печатаются.

`names example.com --ct` показывает все имена под вашим доменом, которые
уже лежат в публичных логах Certificate Transparency (через crt.sh), с теми
же маркерами: `panel.`, `sub.`, `remnawave.` и прочее, что любой найдёт там,
не трогая ноду. `--ct-file saved.json` читает сохранённый JSON crt.sh,
совсем без сети. `--resolve` резолвит имена с этой машины и показывает,
какие сидят на одном адресе; `--node IP` отмечает вашу ноду (за CDN общий
адрес ничего не значит, вывод это пишет). Неудачный запрос выходит с 4 и
никогда не читается как «имён нет»; crt.sh часто перегружен, повторите
позже или используйте `--ct-file`.

Каждая команда, которая шлёт пакеты на цель (`scan`, `ports`, `udp`, `tls`,
`j3`, `grpc`, `snitch`, `trace`, `dpi`), сначала делает preflight и при
провале выходит с кодом 5, ничего не отправив.

### Интерактивная панель

`byebyevpn` без аргументов (или двойной клик) открывает панель на весь
экран: слева меню по разделам, справа описание выбранного пункта, **что он
отправит в сеть**, текущие настройки и карточка последнего скана.

- строка состояния без единого пакета показывает, уходит ли публичный
  трафик этой машины через туннель и запущены ли прокси-клиенты,
  переписчики пакетов или системный прокси;
- клавиши: стрелки вверх/вниз по пунктам, влево/вправо по разделам, Enter
  запуск, `S` настройки, `L` последний скан, `R` обновить статус, `Q` выход;
- настройки: диапазон портов (все, 205 отобранных, свой список), таймаут,
  потоки, stealth, passive, GeoIP и CT, junk-пробы на порт, сохранение
  каждого запуска в `<target>.md`, обход preflight;
- запуск выходит из панели, чтобы вывод прокручивался как обычно, потом
  показывает карточку результата. История целей хранится только в памяти.

Панель вызывает тот же код, что и командная строка, пробы байт в байт те же.
Без консоли (pipe, перенаправление) работает построчный режим: вводятся
команды вида `scan 1.2.3.4`.

### Признаки в именах (`names` и полный скан)

```bash
byebyevpn names sub.example.com vless-de1.example.com
byebyevpn names wg01.example.com us8360.nordvpn.com --json
```

Офлайн-проверка ищет названия протоколов, панелей и подписочных сервисов.
Поддерживаются ASCII-имена и Punycode (`xn--`); границы доменов определяются
по встроенному Public Suffix List с частными зонами хостингов.
`sub2` совпадает с `sub`, а `subaru` нет. Названия вроде `amneziawg` также
ищутся внутри составных меток.

Уровни `strong`, `moderate`, `weak` обозначают характер совпадения, а не
измеренную точность. **Имя не подтверждает протокол и не меняет score или
вердикт ТСПУ.** CN/SAN может принадлежать другому сервису. В отчёте остаются
источники каждого имени: `target`, `cert_cn:порт`, `cert_san:порт`.

Есть отдельные правила зон и имён узлов Mullvad, IVPN, NordVPN и Cloudflare WARP.
Домен провайдера может быть сайтом или API. `workers.dev` отмечается как общий
хостинг приложений, а не доказательство VPN. Команда не резолвит имена,
не перебирает поддомены и не обращается к CT-логам.

Коды выхода: **3** strong, **2** moderate, **0** weak/нет совпадений/IP,
**64** некорректный ввод. Код 0 не означает, что сервер чистый. При смешанном
вводе программа показывает все результаты и возвращает 64, если есть ошибка.
[Правила, источники и ограничения](docs/HOSTNAME_ANALYSIS.md).

Завершённый full scan выходит с кодом по уровню вердикта, чтобы
обёртки могли ветвиться без парсинга вывода (v2.6.0):

```
0  CLEAN (score >= 85)        2  SUSPICIOUS (50-69)
1  NOISY (70-84)              3  OBVIOUSLY-VPN (< 50)
4  INCONCLUSIVE (без вердикта) 5  UNRELIABLE (preflight не прошёл)
64 ошибка использования (нет цели)
```

`dpi` делает тот же preflight и выходит с 5, если он не прошёл. `ech`
выходит с 4, если не удался сам DoH-запрос; «no HTTPS RR» (код 1)
печатается, только если резолвер ответил NOERROR без записи.

#### Проверки со стороны клиента: `dpi` и `dpi --volume`

Запускаются с обычного подключения против своей ноды. Измеряют путь между
этой машиной и этим хостом в этот момент; на другое подключение, другого
оператора и другой день результат не переносится, и каждый вывод это
пишет.

- `dpi <host> [port]`: сброс или тихий дроп по SNI на первом полёте.
  Печатает `SNI check: positive / negative / inconclusive / not applicable`,
  коды выхода прежние, `--json` для скриптов.
- `dpi <host> [port] --volume /path --control host[:port]/path`: заморозка
  на 16-20 КБ из полевых отчётов (F7). Тулза качает `/path` с твоей ноды по
  TLS (путь должен отдавать от 64 КБ) и контрольный путь с хоста, который
  заведомо передаёт объём, контроль до и после. Positive значит, что байты
  перестали идти при открытом соединении на 8 с в двух передачах на одном
  смещении, а контроль передал 64 КБ и больше; текст пишет, попало ли
  смещение в полосу 16-20 КБ. Нет контроля, контроль не прошёл, остановки
  на разных смещениях, соединение закрыто FIN или RST дают inconclusive;
  ресурс меньше 64 КБ даёт not applicable. Выход 0 передал, 2 встал,
  4 inconclusive или not applicable. Запрос `GET` с Host, Accept и
  Connection, тот же набор заголовков, что у HTTPS-пробы.
- `dpi <нода> [port] --sni ИМЯ --real IP|auto`: имя, которое обслуживает
  нода (для Reality её serverName), уходит на ноду и на адрес, где это имя
  живёт на самом деле (`auto` резолвит его). Если до ноды не проходит, а до
  своего адреса проходит, и безобидное имя до ноды работает, значит путь
  связывает имя с адресом, то самое правило, на которое жалуются для
  Reality с брендовым target. Если не проходит никуда, режется само имя.
  Два согласных раунда из трёх; выход 0 проходит, 2 не проходит,
  4 inconclusive.

#### Свой дамп трафика: `pcap`

```powershell
byebyevpn pcap client.pcapng --node 203.0.113.5
```

Сними дамп своего клиента на **физическом интерфейсе** (Wireshark,
`tcpdump`, `pktmon` + `etl2pcap`), открой пару сайтов через туннель,
останови и отдай файл `pcap`. Он читает то, что коробка на этом канале
видит до любого ключа, и ничего не отправляет:

- **ClientHello**: SNI, JA4 (TCP и QUIC из расшифрованного Initial),
  GREASE, расширение ECH, постквантовый key share, ALPN. Нет GREASE значит
  не Chromium и не Safari. `ech-ext yes` может быть GREASE ECH от Chromium,
  в нём настоящее имя всё равно открыто;
- **TLS-рукопожатие внутри туннеля**: по каждому серверу размеры первых
  полётов после внешнего рукопожатия. Внутренний ClientHello, обратно
  полёт с сертификатом, потом запись клиента ровно размера внутреннего
  TLS 1.3 Finished (58, 64, 74 или 80 Б). Positive нужно два совпавших
  потока. Откалибровано на настоящем xray: VLESS и Trojan поверх TLS без
  Vision совпадают в 4 потоках из 4, Vision и обычный HTTPS в 0 из 4.
  Это правило по размерам; negative не значит "невидимо";
- **DNS в открытую**: запросы на порт 53 и резолверы, куда они ушли; DoH к
  известным резолверам отмечается;
- **трафик мимо ноды** (`--node`): публичные адреса кроме твоей ноды,
  IPv6 отдельно.

Выход 2, если что-то из трёх последних positive, иначе 0, 64 если файл не
читается. Файлы до 64 МиБ; TCP собирается на первые 64 КБ в каждую сторону.

#### Утечки на этой машине: `local`

`byebyevpn local` как раньше показывает адаптеры, маршруты и VPN-софт и
добавляет две проверки, которые имеют смысл только при поднятом
туннельном адаптере:

- **IPv6 мимо туннеля**: если у нетуннельного адаптера есть глобальный
  IPv6, тулза подключается к двум публичным резолверам по IPv6 (обычный
  TCP connect, сразу закрыт) и смотрит, какой локальный адрес выбрала
  система. Глобального IPv6 вне туннеля нет: negative без единого пакета.
- **DNS мимо туннеля**: Windows спрашивает резолверы всех адаптеров
  параллельно, если политика это не выключила. Тулза перечисляет
  резолверы, которых система спросит мимо туннеля, и спрашивает каждый
  дважды про `example.com`; ответ оттуда значит, что имена уходят в
  открытую. Kill switch, который их режет, даёт тишину (inconclusive) или
  отказ отправки (negative), но не утечку.

Выход 2, если течёт хоть что-то, иначе 0. Только Windows.

#### Несколько нод: `batch` и `diff`

```powershell
byebyevpn batch nodes.txt --out 2026-10-01 --fast
byebyevpn diff 2026-09-24 2026-10-01
```

`batch` гоняет полный скан по каждой строке файла (`#` начинает
комментарий, повторы пропускаются, не больше 256), печатает сводную
таблицу и с `--out DIR` сохраняет `--json` отчёт на каждую ноду. Опции
скана действуют на все ноды; выход равен худшему коду вердикта. `diff`
сравнивает два отчёта или две такие папки по именам файлов: вердикт
(label, tier, проверки, сработавшие сигналы), поверхность (адрес,
открытые порты, сертификаты, JA4S) и контекст (score, метки GeoIP).
Офлайн; выход 2, если поменялся вердикт, 1 при любом другом изменении,
0 если ничего не поменялось.

Hostname резолвится через `getaddrinfo`; IPv4 выбирается всегда, а
выбранный IP печатается в фазе [1/8]. На IPv4-only каналах (РФ / СНГ)
это чинит баг happy-eyeballs, когда недоступный IPv6 тихо съедал
весь timeout.

### Режимы TCP-скана

```
--full                    все порты 1-65535 (дефолт)
--fast                    205 curated VPN / proxy / TLS / admin
--range 8000-9000 ports   диапазон
--ports 80,443,8443       явный список
```

### Тюнинг

```
--threads N       параллельных TCP-connect'ов  (default 500)
--tcp-to MS       TCP connect timeout           (default 800)
--udp-to MS       UDP recv timeout              (default 900)
--no-color        без ANSI-цветов
-v / --verbose    подробный вывод
--expect-ip A     preflight: адрес, который должны видеть сервисы
--i-know-what-i-am-doing
                  сканировать несмотря на проваленный preflight; вердикт помечается overridden
```

### Stealth / приватность

```
--stealth         --no-geoip + --no-ct + --udp-jitter, и плюс
                  inter-probe timing jitter по J3 / SNI consistency /
                  uTLS dual-probe / AmneziaWG sweep (v2.7.0)
--no-geoip        не дёргать HTTPS GeoIP-провайдеров
--no-ct           не дёргать crt.sh
--udp-jitter      50-300ms случайная задержка между UDP probe'ами
--j3-subset N     отправить N (1..7) случайных проб из восьми J3 на порт
                  вместо всех восьми (v2.7.0)
--passive         минимальный профиль: ПРОПУСКАЕТ J3, uTLS dual-probe,
                  SNI consistency и AmneziaWG sweep целиком. только
                  один TLS handshake + GeoIP + CT + traceroute + SNITCH.
                  меньше всего scanner-образных паттернов на проводе
                  (v2.7.0)
```

Все по умолчанию OFF. Дефолтный скан шлёт ровно то же что v2.6.0.

Анти-фингерпринт контекст: v2.7.0 рандомизирует порядок J3-проб через
CSPRNG-Fisher-Yates per scan, фиксированной последовательности `empty
-> GET -> CONNECT -> SSH -> rand -> tls-invalid -> abs-URI -> 0xff` на
проводе больше нет. Рандом в синтетическом ClientHello тоже переехал на
`RAND_bytes` (с `std::mt19937`).

### Сохранение результата в файл

```
--save            записать скан в <target>.md в текущей папке
--save <path>     записать скан в <path> (тоже как markdown)
```

ANSI-цвета вырезаются при записи в файл; вывод в терминале не меняется.
Содержимое обёрнуто в markdown code-block, так что файл нормально
открывается в любом md-вьювере.

### Сборка

Смотрите [BUILD.md](BUILD.md) - полные инструкции, provenance OpenSSL,
SHA256. Коротко:

```bash
# msys2 UCRT64
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-make
git clone https://github.com/pwnnex/ByeByeVPN.git && cd ByeByeVPN
make windows-static
```

Релизные zip собираются через
[`.github/workflows/release.yml`](.github/workflows/release.yml) из
pinned msys2 образа. SHA256 exe и zip печатаются в release notes
для верификации.

### Ограничения

- Connect-scan, не SYN-scan. Target видит полный TCP handshake.
- Cloudflare WARP / CGNAT / корпоративный proxy / локальный TUN-клиент
  могут ACK'ать любой порт. Preflight проверяет локальную сторону через
  `192.0.2.1`; после скана 3 случайных порта из 49152-65535 обязаны
  отказать. Два принятых (или один плюс >60 открытых портов с разбросом
  RTT < 80 мс) аннулируют вердикт.
- uTLS dual-probe шлёт синтетический ClientHello в стиле Chrome, он
  не совпадает байт в байт ни с одним текущим Chrome (см. выше).
  Raw-socket путь не гоняет TLS 1.3 key schedule, так что для
  Chrome-стороны нет сертификата peer'а - детект cert-steering
  всё ещё опирается на openssl-handshake. Hello основного `tls_probe`
  это дефолт OpenSSL.
- QUIC-пробы (v2.8.0) шлют настоящий защищённый Initial по RFC 9001 -
  key schedule, AEAD-защита payload и header protection байт-в-байт
  совпадают с тест-векторами RFC 9001 Appendix A, а внутри CRYPTO-фрейма
  едет TLS ClientHello. QUIC-сервер расшифровывает его и отвечает. В
  ClientHello есть ALPN `h3` и расширение quic_transport_parameters
  (0x39) с initial_source_connection_id. Проба подтверждает
  QUIC-эндпоинт и снимает форму ответа, но не доводит полный
  QUIC-handshake до конца.
- GeoIP-провайдеры расходятся и берут данные из общих источников. Их
  теги VPN, proxy и Tor печатаются справочно и в score не входят.
- Активный скан не видит того, что классификатор видит пассивно (списки
  адресов, SNI-политика, эвристики первых пакетов, заморозка по объёму).
  См. [docs/COVERAGE.md](docs/COVERAGE.md).

### Лицензия

GPL-3.0-or-later. См. [LICENSE](LICENSE) и [NOTICE](NOTICE).

Релизы до v2.5.9 включительно были под MIT. С v2.6.0 проект под
GPL-3.0-or-later. Старые MIT-релизы сохраняют свою MIT-лицензию,
ретроактивно ничего не отзывается. Релиценз сделан единоличным
правообладателем (все коммиты до v2.6.0 написаны pwnnex).
