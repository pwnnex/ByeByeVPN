# Changelog

## v2.5.6 - 2026-04-21

small feature drop on top of v2.5.5. inspired by DanielLavrushin/tspu-docs
methodology (operator-level tspu documentation) and one user request.

### q-skip for tcp scan phase (#6)

during phase [3/8] (tcp port scan) press `q`/`Q`/`Esc` and the remaining
ports are skipped, pipeline moves to the next phase. useful on `--full`
1-65535 when you already see the relevant open ports are below some
threshold. kb-poll thread via `_kbhit()` + `_getch()` (conio.h), atomic
abort flag, pending-key drain so Enter from target prompt doesn't skip.
progress line says `scan SKIPPED at N/TOTAL` when aborted.

### bgp-blackhole detector (tspu type B)

tspu type B blocks hosts not via DPI but via bgp-pushed ip-lists on
the operator balancer (tspu-docs ch. 7.3.2). visible as "all ports
timeout, zero RST" - a regular firewalled host either sends RST on
closed ports or at least some RST'ed ports. `tcp_connect()` now
distinguishes `timeout`/`refused`/`other` error reasons, `scan_tcp()`
counts them, and the verdict engine raises tier A +40 when ≥99% of
≥1000 scanned ports timed out with zero RST.

### tspu mgmt-subnet hops in traceroute

tspu sites use a stable `10.<region>.<site>.Z` layout where
`Z ∈ [131..235, 241..245, 254]` for filters/balancers/ipmi/spfs
(tspu-docs ch. 10). `trace_hops()` now counts private hops matching
this layout and the verdict engine flags them as tier B (+5 per hop).

### http redirect-page blacklist (tspu type A)

tspu type A redirects HTTP/:80 via 302 to an operator warning page
(`rkn.gov.ru`, `warning.rt.ru`, `blocked.rt.ru`, `185.76.180.75`,
etc. - tspu-docs ch. 5.1.5). `fp_http_plain()` now parses the
`Location:` header from the 2KB response, checks against a hardcoded
blacklist, and the verdict engine flags matches as tier A (+30).

### nothing else changed

no build-system changes, no openssl bump, no header tweaks, no
fingerprint-class changes.

---

## v2.5.5 - 2026-04-21

fixes on top of the ntc.party thread
(https://ntc.party/t/byebyevpn/24325, #5, #4).

### headers (#5)

the chrome-131 header blob was itself a static fingerprint - scanner
users all emitted the same header order that no real browser actually
sends. switched `http_get()` to zero extra headers on the wire: bare
`GET /path HTTP/1.1` + `Host:`, nothing else. no ua, no accept,
no accept-encoding, no sec-fetch, no upgrade-insecure. ip-intel
endpoints all work on a plain GET, same as `curl -sS
https://ipwho.is/8.8.8.8` with no flags.

winhttp quirks: `WinHttpOpen(L"", ...)` still leaks a default ua on
some builds, so we also force-override via `WINHTTP_OPTION_USER_AGENT`
to empty, and send the request with `WINHTTP_NO_ADDITIONAL_HEADERS`.
auto-gzip stays via `WINHTTP_OPTION_DECOMPRESSION` in case a server
chooses gzip on its own.

`https_probe()` (target audit): minimal `Host` + `Accept: */*`
+ `Connection: close`. `fp_http_plain()`: same.

### 2ip.io (#5)

2ip.io's anti-bot html page was breaking the parser. removed.
`geo_2ip_ru()` hits `api.2ip.me/geo.json` directly now.

### build (#4)

- new `.github/workflows/release.yml` - tag push triggers a msys2
  ucrt64 build, verifies `build-win/*.a` are bit-identical to the
  pacman pkg, checks no mingw/openssl dll leaks via objdump, greps
  source for tool-fingerprint strings, writes exe + zip sha256 into
  the release body.
- `build-win/libssl.a` + `libcrypto.a` now tracked in git and are
  the real static archives from the public msys2 package.
- openssl `3.6.1-3` -> `3.6.2-2` (current upstream).
- `BUILD.md` sha256 match the actual msys2 pkg.

### audit fixes

- `fp_socks5`: 1-byte reply was reading `reply[1]` past end.
- `main`: 9 error exits skipped `WSACleanup` - single `done:` label now.
- `--threads`/`--tcp-to`/`--udp-to`: clamp negatives (would wrap
  `SO_*TIMEO` to ~49 days).
- `scan_tcp`: `open.size()` read outside the mutex - snapshot under
  lock.
- verdict engine: unreadable `!err.empty() == false` -> plain
  `err.empty()`.

### docs

readme rewrite - dropped faq / marketing. new translations:
`README.zh-CN.md` (simplified chinese), `README.fa.md` (persian, rtl).
`SECURITY.md` pruned.

### note on v2.5.4

the v2.5.4 release binary was ~200 kb heavier than a clean public
rebuild - can't fix that retroactively. v2.5.5+ comes out of the ci
workflow with sha256 in the release body, so anyone can rebuild and
diff.

---

## v2.5.4 — hotfix — 2026-04-20

**Critical hotfix.** v2.5 / v2.5.1 / v2.5.2 / v2.5.3 release binaries
were silently linked against OpenSSL DLLs (`libssl-3-x64.dll`,
`libcrypto-3-x64.dll`) instead of being statically linked, despite the
README and Makefile claiming "single self-contained .exe". Users who
downloaded the release zip and ran the exe got "missing DLL" errors
because the zip never shipped those DLLs. **Everyone on v2.5.x must
re-download v2.5.4.**

### Root cause

The `build-win/libssl.a` and `build-win/libcrypto.a` files used by the
build were **import libraries** (`.dll.a`-style stubs that resolve to
DLL imports) renamed to `.a`, not real static archives. The build
command `ld build-win/libssl.a build-win/libcrypto.a ...` therefore
emitted `IMPORT` references to `libssl-3-x64.dll` and
`libcrypto-3-x64.dll` rather than baking the OpenSSL code into the
exe. `objdump -p byebyevpn.exe | grep 'DLL Name'` on the v2.5.3 binary
shows the smoking gun.

Fix:

* `build-win/libssl.a` / `build-win/libcrypto.a` replaced with real
  static archives from msys2's `mingw-w64-ucrt-x86_64-openssl-3.6.1`
  package (`/ucrt64/lib/libssl.a` ≈ 1.7 MB, `/ucrt64/lib/libcrypto.a`
  ≈ 9.6 MB — actual machine code, not import stubs).
* `Makefile` `windows-static` target switched from
  `-static-libgcc -static-libstdc++ -Wl,-Bstatic -lwinpthread -Wl,-Bdynamic`
  to a simple `-static` — the previous flag set was leaving
  `libwinpthread-1.dll` as a dynamic dependency because the linker
  preferred the system import lib over the static archive at the same
  path. `-static` forces the static archive everywhere it's available.
* `BUILD.md` updated with verification steps:
  `objdump -p byebyevpn.exe | grep "DLL Name"` should show only OS
  DLLs (KERNEL32, USER32, WS2_32, IPHLPAPI, WINHTTP, CRYPT32, ADVAPI32)
  plus `api-ms-win-crt-*` (UCRT). **No** `libssl-*` / `libcrypto-*` /
  `libwinpthread-*` / `libgcc_*` / `libstdc++-*` should appear.

### Effect

* Release exe size grew from ≈ 1.1 MB to ≈ 8.5 MB — that's the OpenSSL
  code now actually inside the binary.
* Zip is `byebyevpn-v2.5.4-win64.zip` ≈ 2.6 MB (compressed).

### Runtime requirement

The binary now depends only on OS DLLs and the **Universal CRT**
(`api-ms-win-crt-*.dll`). Universal CRT is built into Windows 10 1803+
and Windows 11 by default. On older systems (Windows 7, 8, 8.1, or
stripped Win10 LTSC variants), users may need to install the
**Universal C Runtime** redistributable from Microsoft once:
https://www.microsoft.com/en-us/download/details.aspx?id=49093

This is documented in `README` and the `BUILD.md` verification block.

### Apologies

This regression was in every v2.5.x release zip up to and including
v2.5.3. The issue went undetected because the build host had the
OpenSSL DLLs in `PATH` from msys2, so the exe ran fine locally — only
end-users without OpenSSL DLLs hit the error. Verifying the binary
with `objdump -p` is now part of the release procedure.

---

## v2.5.3 — 2026-04-20

Bugfix release. The Chrome-header set introduced in v2.5 included
`Accept-Encoding: gzip, deflate, br, zstd`, but the WinHTTP-based
`http_get()` wrapper never actually decompressed responses — so half
the GeoIP providers (`ipapi.is`, `iplocate.io`, `freeipapi.com`,
`ipwho.is`, `ipinfo.io`, the HTTPS ones) returned blank fields or
timed out because the server-sent gzip/brotli body arrived as raw
compressed bytes that the JSON parser couldn't read.

### Fixes

* **`http_get()`** (`src/byebyevpn.cpp` ~L427) — enable
  **`WINHTTP_OPTION_DECOMPRESSION`** with `GZIP | DEFLATE` flags right
  after `WinHttpOpen()`. WinHTTP now transparently decompresses the
  response body for the downstream parser.

* **`Accept-Encoding` header** trimmed from `gzip, deflate, br, zstd`
  to **`gzip, deflate`** — the two encodings WinHTTP can decode
  natively. Brotli and zstd would require shipping their respective
  decoders. This is a minor fingerprint relaxation (real Chrome would
  advertise br/zstd too), but the alternative is broken parsing on
  any server that picks brotli over gzip.

### Effect

Re-running a full scan now populates all 9 GeoIP providers correctly
(network errors and rate-limits aside). Reality-cert / CT-log lookup
through `crt.sh` (also gzipped by default) likewise works again.

No changes to detection logic, scoring, or any protocol-level probes.
Pure HTTP-client plumbing.

---

## v2.5.2 — 2026-04-20

Second audit-follow-up pass after a community deep-dive turned up four
more protocol-layer constants I had missed in the v2.5 scrub, all in the
same class as the bytes v2.5 cleaned (constant values in fields a real
client would randomize). v2.5.2 closes them and adds opt-out flags for
the behavioural-fingerprint surfaces that can't be closed at the
per-byte layer.

Thanks again to the ntc.party reviewer for the catch.

### Protocol-layer constants → randomized

* **DNS probe transaction ID** (`src/byebyevpn.cpp` ~L2072) — was
  hardcoded `0xBEEF`. RFC 5452 literally requires DNS resolvers to
  randomize the txn ID for cache-poisoning resistance; a constant
  0xBEEF was both a tool signature and protocol-incorrect. Now
  `RAND_bytes(q, 2)` per probe.

* **OpenVPN HARD_RESET timestamp** (`src/byebyevpn.cpp` ~L2029) — was
  `time(nullptr)` verbatim, meaning the session-creation timestamp
  exactly matched packet emission time. Real OpenVPN clients stamp the
  session at session object creation and emit the first packet some
  milliseconds to seconds later. Now `time(nullptr) - rand(0..255)`
  seconds.

* **L2TP SCCRQ Assigned Tunnel ID** (`src/byebyevpn.cpp` ~L2946) —
  was fixed `0x0001`. Real L2TP clients allocate tunnel IDs
  pseudo-randomly from `[1, 0xFFFF]`. Now `RAND_bytes()` with a reject
  on all-zero.

* **TLS ClientHello SNI** (`src/byebyevpn.cpp` ~L1865) — was hardcoded
  `foo.invalid`. The `.invalid` TLD stays (RFC 6761 guarantees
  NXDOMAIN, which is the point of this probe), but the 3-char prefix
  is now randomized per-probe (`a-z`). So each scan's invalid-SNI
  probe sends a different hostname under `.invalid`, not the literal
  `foo.invalid` signature.

Note: the overall ClientHello shape (single cipher suite, OpenSSL-style
extensions, no GREASE values) is still **not** Chrome-uTLS compatible.
Full JA3-Chrome mimicry requires porting uTLS to C++, which is out of
scope for a bugfix release — see `SECURITY.md §Known open threats`.

### Stealth / privacy opt-out flags

Four new CLI flags, all default OFF (full scan behaviour unchanged).
They close the behavioural-fingerprint surfaces listed in
`SECURITY.md §Known open threats`:

* `--stealth` — master toggle. Equivalent to `--no-geoip --no-ct
  --udp-jitter` at once. For scanning your own VPS without leaking the
  event to 3rd parties.
* `--no-geoip` — skip all 9 3rd-party GeoIP/ASN lookups (ipapi.is,
  iplocate.io, freeipapi.com, 2ip.io/2ip.me, ip-api.com/ru,
  sypexgeo.net, ip-api.com, ipwho.is, ipinfo.io). None of them will
  have a log line correlating your source IP with the target IP you're
  scanning.
* `--no-ct` — skip crt.sh Certificate Transparency lookup. Cert SHA256
  of whatever TLS services the target runs stays local.
* `--udp-jitter` — add a 50-300ms random delay before each UDP probe
  (inside `udp_probe()`). Breaks the "one source IP hit 12 canonical
  VPN ports in a 2-second window" burst signature into a
  ~3-4-second smear. Not a complete fix — the port set itself is still
  unusual — but removes the trivial timing rule.

### Updated `--help`

New "Stealth / privacy" section lists all four flags with one-line
explanations of what each leak they close.

### What v2.5.2 does NOT do

See `SECURITY.md` table for the full list. Headline items remaining:

* TLS JA3 ≠ Chrome even with `--stealth` — needs uTLS port.
* Scanning a target from the same source IP repeatedly still
  correlates across scans — that's inherent.
* Build is still not byte-reproducible — needs Dockerfile.build.
* No Authenticode, no GPG-signed commits — needs certs/keys.

---

## v2.5.1 — 2026-04-20

Audit-driven cleanup pass on top of v2.5. No new features, no
behavioural changes to the verdict engine. Three concrete improvements:

### Replaced `rand()` with `RAND_bytes()` for outbound random bytes

Two probes still used `rand()` (Windows LCG, seeded with `time(nullptr)`)
to fill payload bytes that are sent to the target:

* `src/byebyevpn.cpp` ~L995 — Shadowsocks probe: 64 bytes of garbage
  sent to test "silent-on-junk" pattern.
* `src/byebyevpn.cpp` ~L1813 — J3 probe #5: 512 bytes of random data
  sent to test how the endpoint reacts to noise.

Two issues with the previous code:

1. `rand()` is a linear-congruential PRNG with terrible statistical
   properties. Output passes a casual eyeball test but fails standard
   PRNG suites — visible structure to anyone fingerprinting payload
   distributions.
2. Seed was `time(nullptr)` (one-second granularity ≈ 17 bits of
   real entropy). An observer who knows when the scan ran (timestamp on
   the receiving side ± a few seconds) can brute-force the exact bytes
   the tool emitted. That's a uniqueness fingerprint by construction.

Both call sites now use OpenSSL's `RAND_bytes()` — same cryptographic
PRNG that the rest of the codebase already uses for protocol-layer
random fields (TLS ClientRandom, QUIC DCID, WireGuard handshake
material). Output is uniformly random and unpredictable.

The unused `srand((unsigned)time(nullptr))` in `main()` is removed
since nothing in the binary calls `rand()` anymore.

### `BUILD.md` — OpenSSL provenance + reproducibility documentation

New `BUILD.md` documents:

* Exact build environment for the v2.5.1 release (compiler version,
  OpenSSL version, host OS, target flags).
* SHA256 of the static `libssl.a` / `libcrypto.a` actually used.
* Three reproduction paths: msys2 (recommended), build-OpenSSL-from-source
  (audit chain "I trust nothing pre-built"), Linux cross-compile.
* Caveats around byte-reproducibility (currently no PE-timestamp
  stripping; functionally reproducible, byte-wise not yet).
* Why static linking was chosen and what the trade-offs are.

The Makefile comment claiming `build-win/` archives were "shipped" in
the repo was misleading — they're `.gitignore`d. Comment now points at
`BUILD.md` instead.

### `SECURITY.md` — disclosure policy + known-threats table

New `SECURITY.md` documents:

* How to report a vulnerability (GitHub Security Advisory preferred).
* What counts as security-sensitive (with fingerprinting as the
  primary class).
* Realistic response timelines for a single-maintainer project.
* **Known open threats table** — explicit acknowledgement of the
  remaining attack surfaces that v2.5.1 does NOT close: TLS JA3 ≠
  Chrome, behavioral burst pattern across IP-intel APIs, no
  byte-reproducible build, no Authenticode signing, no GPG-signed
  commits, OpenSSL CVE patchability via static linking.

Listing them publicly removes them from the "potential audit gotcha"
category — they're now documented limitations on the roadmap.

---

## v2.5 — 2026-04-19

Security hygiene pass. v2.4 embedded several identifying patterns into
low-level protocol fields (TLS ClientRandom, QUIC DCID, L2TP Host Name,
ICMP payload, SSH version banner) that were meant as debug-time sentinels
but read as covert fingerprints to anyone auditing the source. v2.5
removes all such markers from on-the-wire protocol bodies. Log-layer
markers (HTTP `User-Agent: Mozilla/5.0 ByeByeVPN`) stay — they're
application-level, not protocol-level, and are the intentional way to
separate the scanner's own traffic from real user traffic in `nginx`
access logs.

### Removed protocol-layer fingerprints

* **J3 probe #6 — TLS ClientHello** (`src/byebyevpn.cpp` ~L1784)
  The 32-byte ClientRandom field used to carry a hardcoded ASCII pattern
  (`RUSSIAN\0BYEBYEVPNACTIVEPROBEJ3\0\0`) mislabelled in the code as
  `// 32 bytes random`. It is now filled with `RAND_bytes()` per probe,
  matching what any real TLS client emits.

* **QUIC Initial probe DCID** (`src/byebyevpn.cpp` ~L1924)
  Destination Connection ID was a fixed `0xBB ×8`. Now `RAND_bytes(8)`.

* **Hysteria2 probe DCID** (`src/byebyevpn.cpp` ~L2795)
  Destination Connection ID was a sequential `0xA1..0xA8`. Now
  `RAND_bytes(8)`.

* **L2TP SCCRQ Host Name AVP** (`src/byebyevpn.cpp` ~L2828)
  Host Name field was `"BBV"`. Now `"lac"` (generic L2TP Access
  Concentrator, matches what real clients send).

* **ICMP traceroute payload** (`src/byebyevpn.cpp` ~L2698)
  Echo payload was the string `"ByeByeVPN"`. Now the standard 32-byte
  Windows `ping.exe` pattern `"abcdefghijklmnopqrstuvwabcdefghi"`.

* **J3 probe #4 — SSH banner** (`src/byebyevpn.cpp` ~L1773)
  Banner was `SSH-2.0-ByeByeVPN`. Now `SSH-2.0-OpenSSH_8.9p1` — a
  plausible real-client banner, which is what we want DPI to classify as
  "SSH" for the active-probe test.

### Outgoing HTTP traffic fully de-identified (full Chrome header set)

Earlier draft notes for v2.5 had the UA marker kept "for log-matching on
the user's own server." That reasoning was wrong — **all** external
IP-intel services this tool queries (ipify, 2ip.me, ipinfo.io,
sypexgeo, ip-api.com, ipapi.is, etc.) also log User-Agent strings, and
anyone with access to those logs (a censor, or the service operator
under subpoena / informal request) could do `grep ByeByeVPN` and
enumerate the set of source IPs belonging to people running this
scanner. On plain-HTTP services a transit-layer observer (ТСПУ) sees
the marker in cleartext even without server cooperation.

The threat model an auditor raised was explicit: *"a backdoored utility
distributed to collect user IPs would do exactly this — embed a unique
marker in outgoing requests so the attacker can `grep` the logs of the
services the tool hits and enumerate users."* v2.5 closes that door
end-to-end.

Every outbound HTTP request the tool emits — to third-party IP-intel
services, to the target under test during the TLS-HTTP audit probe,
and to CT endpoints (`crt.sh`) — now sends the **full** Chrome-131 /
Windows 10 header set in the exact order a real browser emits it:

```
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
            AppleWebKit/537.36 (KHTML, like Gecko)
            Chrome/131.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,
        image/avif,image/webp,image/apng,*/*;q=0.8,
        application/signed-exchange;v=b3;q=0.7
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Upgrade-Insecure-Requests: 1
```

Changed files:

* `http_get()` wrapper (`src/byebyevpn.cpp` ~L387) — WinHTTP session
  name was `ByeByeVPN/2.5`, now `Mozilla/5.0`; request headers are
  now the full Chrome set above (previously just `UA + Accept: */*`).

* TLS-over-HTTP active audit probe (`src/byebyevpn.cpp` ~L1425) —
  same header set; previously emitted `UA with ByeByeVPN/2.3` plus
  `Accept: */*`.

Net effect: **no outbound HTTP request — to any service, over any
protocol — carries a tool-identifying string anywhere in headers,
paths, or bodies**. A censor or log-aggregating service has no
`grep`-able way to enumerate scanner users from its access logs.

No operator-log marker is provided. If you want to separate scanner
traffic in your own nginx `access.log`, correlate by source IP and
timestamp with the scanner's own verbose output (`-v`), which prints
each URL + timing. Fingerprinting your own traffic should be done at
your server (where you control the correlation), not by giving a
unique outgoing fingerprint to the entire internet.

### Audit-verified: zero tool-identifying bytes on the wire

Running `grep -E 'ByeByeVPN|BYEBYEVPN|BBVPN|BBV|pwnnex'` on the full
source tree now matches only three lines, all non-network:

1. Source file banner comment (`// ByeByeVPN — full VPN…`, L1)
2. An explanatory comment inside `http_get()` documenting *why* the UA
   was scrubbed (L402)
3. The CLI `--help` printf that displays the tool's name on the local
   terminal (L4974)

None of these three lines ever touches a socket.

### Why this matters

A clean protocol-body emission is how a real WireGuard / QUIC / TLS /
L2TP client actually looks on the wire. Any non-random constant in a
field specified as random (ClientRandom, DCID, key material) is
statistically distinguishable and contradicts the tool's own thesis that
"a clean tunnel should be indistinguishable from a clean non-tunnel."
v2.5 is what v2.4 should have been.

### No behavioural change

All detection logic, verdict engine, signal weights and pipeline phases
are identical to v2.4. Only the raw byte contents of probe payloads
changed. Test surface on the target server is the same — DPI still sees
"TLS ClientHello with invalid SNI", "QUIC Initial with unknown DCID",
"L2TP SCCRQ with generic hostname", etc.

---

## v2.4 — 2026-04-19

v2.4 brings the full Russian ТСПУ methodology under one roof. The prior
v2.3 covered the on-the-wire behaviour (cert impersonation, canned
fallback, J3 probing, HTTP-over-TLS audit); v2.4 adds everything the
official OCR methodika (§5-10) also calls out as canonical VPN tells but
that v2.3 didn't yet implement:

* **SNITCH-style latency analysis (§10.1)**
* **HTTP proxy-chain header leakage (§10.2)**
* **Certificate Transparency (crt.sh) absence**
* **Modern 2026 tunnels — AmneziaWG / Hysteria2 / TUIC v5 / L2TP / SSTP**
* **Traceroute hop-count anomaly (ICMP, userland)**
* **TSPU / ТСПУ emulation verdict — explicit Russian-DPI ruling**
* **Extended brand table — Yandex/VK/Tinkoff/Sber/Telegram/Discord/…**

Pipeline grows from 7 phases to 8 (phase 7 = SNITCH+trace+SSTP). The
verdict now ends with a Russian-DPI-style 3-tier block/throttle/allow
ruling that mirrors what TSPU actually does on production lines.

### New — phase `[7/8] SNITCH + traceroute + SSTP`

A whole new pipeline stage between J3 probing and the verdict engine.
Three independent measurements, all userland (no admin needed).

#### 1. SNITCH latency-vs-geo consistency (methodika §10.1)

Methodika §10.1 literally names SNITCH (Server-side Non-intrusive
Identification of Tunnelled Characteristics) as the canonical "latency
vs GeoIP" VPN detector. Until now the tool had no counterpart.

v2.4 implements a simplified single-observer version:

* Six TCP handshakes to the target on :443 (or first open port),
  outlier-trimmed, median / min / max / stddev computed.
* Three **anchor** RTT batches in parallel: 1.1.1.1 (Cloudflare
  anycast), 8.8.8.8 (Google anycast), 77.88.8.8 (Yandex). Anchors give
  a vantage-point baseline independent of which continent the user sits
  on.
* Country-code → physical RTT-minimum table for ~46 countries. Based
  on fibre-speed-of-light: Moscow→Frankfurt ≈ 2000km one-way = ~10ms
  one-way = ~20ms RTT floor. Table is calibrated for a typical RU/EU
  observer.
* Three anomaly tests:
  * `too_low`  — median < 50% of the physical minimum for the claimed
    country → **GeoIP lies** OR anycast proxy
  * `too_high` — median > 3x the expected max → **extra hops in path**
    (tunnel / long middlebox chain)
  * `high_jitter` — stddev > 40ms → typical of tunnel queue/encryption
    overhead
  * `anchor_ratio_off` — target_RTT / closest_anchor ratio doesn't
    match what the claimed geolocation would produce

Each anomaly gets its own signal (major for `too_low`, minor for the
others) and maps to a specific ТСПУ B-tier rule in the final verdict.
The classic detectable case is a Cloudflare-fronted VPN showing as
"country=US" with RTT=14ms to a Moscow observer — physically impossible
without anycast.

#### 2. Traceroute hop-count analysis

Windows `IcmpSendEcho2` with TTL sweep 1..18, no raw sockets, no admin.
Tracks:

* `hop_count` — number of replying hops (≥20 flags as anomalous)
* `max_rtt_jump_ms` — biggest RTT delta between consecutive hops
  (tunnel endpoints show as big jumps)
* `long_hops` — count of hops > 150ms (overlays / intercontinental
  tunnels)

Informational by default; fires as a minor signal only at ≥20 hops or
on suspicious jump-pattern combinations.

#### 3. SSTP probe (TCP/443 TLS-wrapped)

Microsoft Secure Socket Tunneling Protocol is a VPN that runs over
HTTPS on :443. Handshake is `SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-...}/`
with the magic `Content-Length: 18446744073709551615` header (2⁶⁴-1).
A real SSTP server replies `HTTP/1.1 200 OK` with the same magic length.

Hard signal (-18 to score) on positive match — SSTP is old enough that
every DPI engine has a dedicated ruleset for it.

#### 4. JA3 advisory

Reports the tool's own OpenSSL ClientHello JA3 hash so the user
understands what fingerprint the target saw. Notes whether the target
appeared to accept our non-Chrome JA3 (Reality servers in uTLS-enforcing
mode would reject OpenSSL-default CH at the handshake layer).

### New — phase 4 extras: Hysteria2 / TUIC / L2TP / AmneziaWG

The classic VPN-protocol probe set (OpenVPN / WireGuard / IKE / QUIC /
Tailscale / DNS) is extended with the modern 2026-standard tunnels:

| Port     | Protocol                        | Detection payload |
|----------|---------------------------------|-------------------|
| UDP/1701 | L2TP control (SCCRQ)            | Full SCCRQ with mandatory AVPs (message type / protocol version / framing caps / host name / tunnel id) |
| UDP/36712| Hysteria2 (QUIC-based)          | QUIC v1 Initial with custom DCID — vanilla QUIC version-neg differs from Hysteria's salamander-obfuscated handshake |
| UDP/8443 | TUIC v5                         | QUIC Initial |
| UDP/55555| AmneziaWG Sx=8                  | 8-byte random prefix + valid WG MessageInitiation payload |
| UDP/51820| AmneziaWG on default WG port    | Distinguishes vanilla-WG vs AmneziaWG by two-probe comparison (vanilla rejected, Sx=8 accepted) |

Each responding probe maps to a named protocol in the TSPU ruleset with
its own penalty and hardening suggestion.

### New — Certificate Transparency (crt.sh) lookup

Real public certs (Let's Encrypt, ZeroSSL, any commercial CA) are
required by RFC 9162 to be submitted to CT logs — enforced by Chrome
and Firefox since 2018. A cert SHA-256 that returns `[]` from
`https://crt.sh/?q=<sha256>&output=json` was never logged = it's
either:

* Self-signed (private CA) — never reached a public CA
* Internal corporate test-CA issuance
* LE-staging (intentionally unlogged)
* Hand-rolled clone (copied bytes lose the original CT entry because
  the SHA-256 changes) — classic Xray `dest=` cloning artefact

v2.4 queries crt.sh for every TLS cert we see. CT-absence is:

* **HIGH** signal (-15) when combined with cert-age < 30d
* **MEDIUM** signal (-6) on its own (internal corp certs are a
  legitimate non-CT case)

### New — HTTP proxy-chain header leakage (methodika §10.2)

Methodika §10.2 names `Via`, `Forwarded`, and `X-Forwarded-For` as
diagnostic markers: if the origin sets them, a middle proxy is in path.

v2.4 extends `https_probe()` to parse **fifteen** proxy-relevant
headers across every TLS response:

* Proxy leak: `Via` / `Forwarded` / `X-Forwarded-For` / `X-Real-IP` /
  `X-Forwarded-Proto` / `X-Forwarded-Host`
* CDN markers: `CF-Ray` / `CF-Cache-Status` (Cloudflare),
  `X-Amz-Cf-Id` / `X-Amz-Cf-Pop` (CloudFront), `X-Azure-Ref` /
  `X-Azure-ClientIP` (Azure AFD), `X-Cache` / `X-Served-By` (Fastly)
* `Alt-Svc` (QUIC endpoint advertisement)

Classification:

* `has_proxy_leak = true` + non-CDN ASN  → **-12 major** signal, maps
  to methodika §10.2 directly
* `has_cdn_hdr = true` → informational only (CDN doing its job)
* `Alt-Svc` set → noted for QUIC-endpoint detection

### New — ТСПУ / TSPU emulation verdict block

The verdict section now ends with a **dedicated Russian-DPI classifier
emulation** that grades this host as a real TSPU middlebox would. It's
a 3-tier ruling with rule-hit transparency:

| Tier | Verdict          | What it means                                               |
|------|------------------|-------------------------------------------------------------|
| A    | IMMEDIATE BLOCK  | Named VPN/proxy signature matched — SYN/handshake drop       |
| B≥2  | BLOCK            | ≥2 soft anomalies — accumulative classifier trips block      |
| B=1  | THROTTLE / QoS   | 1 soft anomaly — flagged for monitoring / rate-limit         |
| 0    | PASS / ALLOW     | No signatures — traffic passes unhindered                    |

A-tier (protocol-level signatures):

* OpenVPN wire signature (UDP/1194 HARD_RESET reply)
* WireGuard wire signature (UDP/51820 handshake reply)
* AmneziaWG obfuscation (Sx=8 accepted)
* Hysteria2 default port (UDP/36712 live)
* L2TP SCCRQ reply (UDP/1701)
* IKE responder (UDP/500 or 4500)
* SSTP VPN (TLS-wrapped on :443)
* Shadowsocks default port (TCP/8388, 8488)
* Open SOCKS5 proxy

B-tier (accumulative soft anomalies):

* Reality / XTLS cert-steering
* Cert impersonation (brand CN on non-owning ASN)
* 3x-ui / x-ui / Marzban panel-installer port cluster
* Canned-fallback page or HTTP/0.0 malformed version
* Short-validity cert (<14d)
* HTTP proxy-chain leak (Via / Forwarded / X-Forwarded-For)
* CT-log absence on fresh cert
* SNITCH geo-latency conflict (§10.1)
* Multi-source VPN/proxy threat-intel tag
* Tor exit relay

The block prints:

* The 3-tier verdict
* Every triggered A-tier and B-tier rule with its reason
* **"What the operator sees"** — a plain-English description of how
  the TSPU ruling manifests on the wire for end users (drop vs
  throttle vs log vs pass)

### Extended — brand table (27 → 94 entries)

Added Russian-context brands for cert-impersonation detection:

* **RU tech**: yandex, mail.ru, vk, ok.ru, avito, ozon, wildberries,
  kinopoisk, rutube, dzen, habr, rambler, ya.ru
* **RU banks + state**: sberbank, tinkoff/tbank, vtb, alfabank,
  gazprombank, rosbank, gosuslugi, mos.ru, rt.ru (Rostelecom),
  nalog.gov.ru
* **RU telecom**: mts, megafon, beeline, rostelecom, tele2
* **Messengers**: telegram/t.me, discord, slack, zoom, signal, threads
* **Tech expansion**: icloud, googleapis, gitlab, bitbucket, outlook,
  office365, azure, onedrive, tiktok, messenger
* **Finance / SaaS**: stripe, paypal, shopify, adobe, salesforce,
  dropbox
* **Media / gaming**: spotify, twitch, vimeo, reddit, steam*,
  playstation, xbox, nintendo, epicgames, battle.net

Any TLS cert on a public IP claiming `CN=tinkoff.ru` or `CN=vk.com`
etc. will now trigger cert-impersonation on an ASN that isn't
registered to that brand — matching the Reality `dest=` tactic
operators use to hide behind Russian-friendly names.

### New — CLI sub-commands `snitch` and `trace`

Standalone invocations for the two new measurement tools:

```bash
byebyevpn snitch my.vpn.server 443    # RTT/GeoIP consistency check only
byebyevpn trace  my.vpn.server        # hop-count trace only
```

Interactive menu grows to 10 options (adds [8] SNITCH and [9]
Traceroute).

### Score calibration additions

New penalties (added to v2.3 table):

* SSTP detected: **-18** (protocol-level signature)
* AmneziaWG on UDP/55555: **-15**
* AmneziaWG on UDP/51820 (vanilla-WG rejected, Sx=8 accepted): **-16**
* Hysteria2 on UDP/36712: **-15**
* L2TP SCCRQ reply on UDP/1701: **-15**
* TUIC v5 on UDP/8443: **-7**
* HTTP proxy-chain leak (Via/Forwarded/XFF): **-12** per port
* Certificate Transparency absence + fresh cert: **-15** per port
* CT absence alone: **-6** per port
* SNITCH `too_low` (impossible latency for GeoIP): **-15**
* SNITCH `too_high` (extra hops): **-6**
* Traceroute > 20 hops: **-5**

### Build

All additions are pure userland — no raw sockets, no admin, no new
external dependencies. `IcmpSendEcho2` is in `iphlpapi` which was
already linked; everything else is pure C++ / OpenSSL / WinHTTP.

Build command is unchanged from v2.3.

## v2.3 — 2026-04-19

v2.3 is a ground-up rework of the verdict engine in two movements:
first a **calibration pass** that stopped v2.2 from flagging every
cloud-hosted server as suspicious, then a **deep-audit pass** that
re-introduces hard signals — but only ones a legitimate web origin
literally cannot produce.

### Part 1 — calibrated signal model (v2.2 regression fix)

v2.2 went too hard on accumulative red-flagging: any cloud-hosted public
server ended up in the 60–75 range ("NOISY"), because hosting-ASN by
itself was worth a penalty, a single open :443 port was worth a penalty,
and single-source GeoIP VPN tags were counted as evidence. Real TSPU /
GFW classifiers don't work that way — they grade a destination by what
its IP actually does **on the wire** (TLS handshake bytes, cert steering,
reactions to junk, default-port replies). The IP's reputation is at most
a coarse pre-filter.

v2.3 rebalances:

* **Hosting-ASN is no longer a red flag.** Almost every public server on
  the Internet is on a hosting / datacenter ASN. It now appears in a
  new **Informational `[i]`** section with no score impact, and drives
  a concrete hardening suggestion (prefer residential / mobile / CDN
  egress if you're trying to blend in).
* **Single open :443 port is no longer a red flag.** Normal
  reverse-proxies and corporate VLESS-Reality fronts look exactly like
  that. Still shown under Informational, with advice to mirror additional
  TLS ports (8443 / 2053 / 2083 / 2087 / 2096) if the profile looks too
  thin.
* **Single-source GeoIP VPN/proxy tags demoted.** One source out of
  nine calling an IP "VPN" is close to noise. Only a ≥2-source
  consensus now counts as a hard signal.
* **ALPN ≠ h2**, **KEX ≠ X25519**, **IKE control ports open**,
  **country-code mismatch across GeoIPs**, **zero-SAN cert** — all moved
  to Informational, each with its own matching hardening suggestion.
* **Fresh cert (<14d) is now conditional.** Only penalises in
  combination with a sparse hosting-ASN :443 profile; isolated fresh
  certs are normal Let's Encrypt rotation.
* **Blanket COMBO penalty removed.** v2.2 took an extra hit for any 3+
  / 5+ soft flags; with hosting-ASN moved out, this over-counted.

### Part 2 — deep-audit signals (the ones TSPU/GFW actually use)

The calibration pass above made v2.3 gentler on corporate web hosts,
but it also made it too gentle on real Xray installs. A real-world
Reality-static setup on `185.92.181.205` (US / CGI-GLOBAL hosting,
`CN=www.amazon.com` on a random VPS, :2096 returning `HTTP/0.0 307`
with identical byte-exact canned replies) would otherwise have scored
**93/100 CLEAN** — exactly the kind of DPI-evadable setup the tool
should catch.

So v2.3 also adds **hard signals** that are *expensive to fake* —
signals a legitimate web origin literally cannot produce:

**1. Cert impersonation (brand CN on non-owning ASN).**
Reality-static setups point `dest=` at a famous brand (amazon / microsoft
/ apple / google / cloudflare / yandex / github / …) and the server
returns that brand's cert. The tool now builds a 27-entry brand table,
matches the cert CN/SAN against it, and cross-references against the ASN
organisation string from all 9 GeoIP providers. Brand CN on an ASN that
doesn't own the brand = **HIGH** signal. The check runs on the base
(SNI-less) TLS probe and fires even when per-SNI probes return different
certs — that's **Reality in passthrough mode**, where the TLS stream is
transparently tunnelled to the real brand and the real brand then does
its own SNI-based vhost routing. Detecting this is the whole point,
because passthrough-Reality is the stealth-optimised config that
vanilla cert-steering detection (which wanted identical certs across
SNIs) would miss.

Independent confirmation channel: **HTTP `Server:` header brand
mapping.** After TLS handshake we speak HTTP/1.1 and parse the reply.
`Server: CloudFront`, `Server: AmazonS3`, `Server: AWSELB`, `Server:
gws`, `Server: GFE/*`, `Server: Microsoft-IIS/*`, `Server: Yandex*`,
`Server: cloudflare` are only ever emitted by that brand's actual
infrastructure — so the same banner on a non-owner ASN is another
Reality-passthrough tell, counted separately from the TLS-cert channel
in the DPI matrix.

**2. Short-validity cert (<14d total validity).**
Let's Encrypt issues 90d, commercial CAs issue 30–365d. A cert with total
validity under 14 days is never issued by a real CA — it's a hand-rolled
short-lifetime self-signed / test-CA issuance, classic Xray/Trojan
quickfire setup. Flagged **HIGH**.

**3. Active HTTP-over-TLS probe.**
After the TLS handshake we now actually send `GET / HTTP/1.1\r\nHost:…\r\n\r\n`
and parse the reply. New structured detection:
  * `HTTP/0.0` / `HTTP/3.x` text / malformed version = Xray fallback
    stream handler partially decoding a non-protocol request
  * TLS completes but origin sends **0 bytes** back to plain `GET /` =
    stream-layer proxy signature (Xray/Trojan/SS-AEAD)
  * Reply has **no `Server:` header** = middleware tell
    (nginx/Apache/Caddy/CDN always set one)

**4. J3 canned-fallback detection.**
Real web servers vary their replies per request (different URIs →
different statuses). The tool now tracks first-line + byte count across
the 8-probe J3 matrix. Same byte-exact reply for ≥2 different probes
(including at least one valid `GET /`) = static Xray `fallback+redirect`
/ Trojan default page. Flagged **HIGH**. On TLS ports the detection is
gated on the HTTP-over-TLS probe also being anomalous, so a strict nginx
returning uniform 400 to raw-TCP junk is not a false positive.

**5. 3x-ui / x-ui / Marzban panel-port cluster.**
The panel installers preset exactly this TLS-port set:
`2053, 2083, 2087, 2096, 8443, 8880, 6443, 7443, 9443`. Regular web
hosts almost never open this combination together. ≥2 hits = **HIGH**.

**6. Silent-high-port + TLS multipath.**
VLESS on :443 combined with a silent open TLS high port is the classic
Xray multi-inbound layout. Flagged as soft signal.

### New — proxy-middleware detection on the TLS path

v2.1 had a popular signal v2.2 accidentally dropped: a TLS 1.3 endpoint
that handshakes cleanly but **silently drops every HTTP/junk probe** is
almost certainly a stream-layer proxy (Xray / Trojan / Shadowsocks-AEAD)
sitting in front of the origin — a real nginx/Apache would return
`HTTP 400 Bad Request` on non-TLS bytes. v2.3 reintroduces this.

### New — Reality discriminator extended

The SNI consistency test now probes 10 common `dest=` SNIs instead of 4:
adds `bing.com`, `github.com`, `mozilla.org`, `yandex.ru`, plus the
existing amazon/apple/microsoft/google/cloudflare set. The
`cert_impersonation` flag is raised whenever the base cert covers any
famous-brand domain we detect via the brand table, even if we didn't
probe that exact SNI.

### New — 9 GeoIP providers (3 EU / 3 RU / 3 global)

The previous 7-provider stack had one dead endpoint (`2ip.io` → HTTP 429
on every request) and no real RU coverage. v2.3 replaces the stack with
geographically balanced endpoints:

* **EU (3)**: `ipapi.is`, `iplocate.io`, `freeipapi.com`
* **RU (3)**: `2ip.io`/`2ip.me` (fallback chain), `ip-api.com?lang=ru`,
  `sypexgeo.net`
* **Global (3)**: `ip-api.com`, `ipwho.is`, `ipinfo.io`

All 9 queried in parallel; ASN org strings from every successful provider
feed the brand-impersonation cross-check.

### New — DPI exposure matrix expanded to 13 axes

Added four new rows to the matrix:
* **Cert impersonation (Reality-static tell)** — count of ports with
  brand-CN on non-owning ASN
* **Active HTTP-over-TLS probe** — version-anomaly / empty-reply /
  no-Server / looks-real
* **Panel-port cluster (3x-ui/x-ui/Marzban)** — panel hit count
* **J3 canned/anomaly aggregate** — canned/bad-version/raw-non-HTTP
  per-port totals

Existing axes updated:
* **Cert freshness** now escalates to **HIGH** when total validity < 14d
* **Open-port profile** escalates to **HIGH** when dominated by the
  3x-ui preset cluster

### New — Informational section + Hardening suggestions + Threat-model note

The verdict section is split into four blocks:

* **Strong signals `[!]`** — real VPN/proxy evidence (protocol-level
  signature, Reality cert-steering, cert impersonation, canned-fallback,
  short-validity cert, HTTP-version anomaly, 3x-ui cluster, multi-source
  GeoIP consensus, Tor).
* **Soft signals `[-]`** — suggestive patterns that cost a small
  penalty (self-signed cert, expired cert, TLS < 1.3, fresh cert in
  combination with a sparse profile, proxy-middleware on the TLS path,
  silent-high-port + TLS, missing `Server:` header).
* **Informational `[i]`** — pure observation, no penalty, no verdict
  weight. Hosting-ASN, single :443, ALPN, KEX, IKE-ports,
  single-source GeoIP tags, country-code mismatch, zero-SAN all live
  here. Normal public sites can and do produce these.
* **Hardening suggestions** — a concrete, tagged, actionable remedy
  for every observation that could help a censor classify the host
  (`reality-mixed`, `reality-hidden`, `reality-ok`, `proxy-middleware`,
  `reality-multiport`, `openvpn`, `wireguard`, `shadowsocks`, `rdp`,
  `tls-version`, `tls-self-signed`, `port-profile`, `ssh-banner`,
  `cert-fresh`, `asn-hosting`, `threat-intel`,
  `cert-impersonation`, `cert-short-validity`, `canned-fallback`,
  `http-version-anomaly`, `http-silent-origin`,
  `http-missing-server-header`, `xui-panel`).

A final **Threat-model note** is now printed at the end of the verdict,
explaining the principle behind the rebalance — TSPU/GFW grade an IP
by its wire behaviour, not by its reputation, so a VPN front on a
hosting ASN is fine as long as its on-the-wire profile blends in.

### New — stack-identification priority rewritten

Priority order (first match wins):
1. Impersonation + xui-cluster → "Xray-core VLESS+Reality on a 3x-ui panel install"
2. Impersonation only → "Xray-core VLESS+Reality (static dest — cloned brand cert)"
3. Multi-port Reality
4. Reality with HTTP fallback (primary)
5. Reality hidden-mode
6. Generic Reality cert-steering
7. Canned / bad-version → "TLS front + Xray/Trojan stream-layer proxy"
8. Short-validity → "TLS endpoint with hand-rolled short-lifetime cert"
9. 3x-ui cluster only → "3x-ui/x-ui/Marzban panel install"
10. OpenVPN / WireGuard / Shadowsocks / proxy-middleware / generic / none

### Score calibration

Penalties (additive, score starts at 100):
* Cert impersonation: **-22** per port
* J3 canned response: **-18** per port
* Cert short validity: **-15** per port
* HTTP version anomaly: **-14** per port
* 3x-ui panel cluster (≥2 hits): **-14**
* J3 bad HTTP version: **-14**
* Reality cert-steering: **-12**
* HTTP empty response: **-8** per port
* Silent-high-port + TLS: **-7**
* J3 raw non-HTTP: **-7** per port
* HTTP no-Server header: **-5** per port

### Fixed

* `2ip.io` was returning HTTP 429 — replaced with a fallback chain that
  tries `https://2ip.io/geoip/X/` first then `http://api.2ip.me/geo.json?ip=X`.
* `help()` now lists all 9 GeoIP providers grouped by region.
* `geoip` CLI subcommand + interactive-menu option [6] updated to call
  the new 9-provider set (were still on the old 7).

### New — proxy-middleware detection on the TLS path

v2.1 had a popular signal v2.2 accidentally dropped: a TLS 1.3 endpoint
that handshakes cleanly but **silently drops every HTTP/junk probe** is
almost certainly a stream-layer proxy (Xray / Trojan / Shadowsocks-AEAD)
sitting in front of the origin — a real nginx/Apache would return
`HTTP 400 Bad Request` on non-TLS bytes.

v2.3 reintroduces this with a dedicated heuristic:

* Per-port classification now flags
  `TLS endpoint that silently drops all HTTP/junk — proxy/middleware
  in front of origin (Xray/Trojan/SS-AEAD — nginx/Apache would return
  HTTP 400)` when clean TLS + ≥6 silent junk probes and 0 responses.
* When the same kind of port responds with non-HTTP bytes instead of an
  HTTP status line, it's flagged as a custom stream-layer endpoint.
* Either pattern names the stack as
  `TLS front + stream-layer proxy (Xray / Trojan / SS-AEAD)` when it's
  the most specific thing the evidence supports (even without Reality
  cert-steering).

### New — Informational section + Hardening suggestions + Threat-model note

The verdict section is split into four blocks:

* **Strong signals `[!]`** — real VPN/proxy evidence (protocol-level
  signature, Reality cert-steering, multi-source GeoIP consensus, Tor).
* **Soft signals `[-]`** — suggestive patterns that cost a small
  penalty (self-signed cert, expired cert, TLS < 1.3, fresh cert in
  combination with a sparse profile, proxy-middleware on the TLS path).
* **Informational `[i]`** — pure observation, no penalty, no verdict
  weight. Hosting-ASN, single :443, ALPN, KEX, IKE-ports,
  single-source GeoIP tags, country-code mismatch, zero-SAN all live
  here. Normal public sites can and do produce these.
* **Hardening suggestions** — a concrete, tagged, actionable remedy
  for every observation that could help a censor classify the host
  (`reality-mixed`, `reality-hidden`, `reality-ok`, `proxy-middleware`,
  `reality-multiport`, `openvpn`, `wireguard`, `shadowsocks`, `rdp`,
  `tls-version`, `tls-self-signed`, `port-profile`, `ssh-banner`,
  `cert-fresh`, `asn-hosting`, `threat-intel`).

A final **Threat-model note** is now printed at the end of the verdict,
explaining the principle behind the rebalance — TSPU/GFW grade an IP
by its wire behaviour, not by its reputation, so a VPN front on a
hosting ASN is fine as long as its on-the-wire profile blends in.

### Changed — DPI exposure matrix recalibrated

Axes that no longer carry real classification weight on their own:

* `ASN classifier (VPS/hosting)` — most exposures now LOW / NONE.
* `Threat-intel tags (VPN/Proxy/Tor)` — LOW for single-source.
* `Open-port profile (sparsity)` — single :443 now LOW, not MEDIUM.

Axes that matter stay as-is: port-based, protocol handshake, Reality
cert-steering, cert freshness (in combination), J3 junk-probing, TLS
hygiene.

### Build command (unchanged from v2.2)

```bash
g++ -O2 -std=c++20 -D_WIN32_WINNT=0x0A00 \
    -I/c/msys64/ucrt64/include \
    -static -static-libgcc -static-libstdc++ \
    src/byebyevpn.cpp -o byebyevpn.exe \
    /c/msys64/ucrt64/lib/libssl.a \
    /c/msys64/ucrt64/lib/libcrypto.a \
    /c/msys64/ucrt64/lib/libwinpthread.a \
    -lws2_32 -liphlpapi -lwinhttp -lcrypt32 -lbcrypt -ldnsapi -luser32 -ladvapi32
```

## v2.2 — 2026-04-18

### New — verdict engine is **accumulative** now

v2.1 was too permissive: after rewriting the Reality discriminator the
scoring lost sensitivity to soft signals. Any TLS origin with a single
default cert — including obvious single-purpose VPS fronts — ended up
with 80+/100 and a generic "no VPN signature" verdict.

v2.2 keeps the Reality false-positive fix, but reintroduces
**accumulative red-flagging**:

* **Cert intel.** Each TLS port now surfaces subject CN, issuer CN,
  age-in-days, days-left, SAN count, wildcard/self-signed flags, and
  free-CA detection (Let's Encrypt / ZeroSSL / Buypass / GTS).
* **Red-flag model.** Every soft indicator — hosting-ASN, fresh cert
  (<14d), self-signed cert, expired cert, TLS < 1.3, ALPN != h2,
  KEX != X25519, zero-SAN cert, single-port profile with :443, sparse
  open-port profile on hosting ASN, IKE control ports open,
  single-source VPN/proxy tag, country-code mismatch across GeoIPs —
  adds a soft flag with its own penalty.
* **COMBO penalty.** Three or more independent soft flags trigger an
  extra penalty; five or more trigger a harder one. The pattern as a
  whole starts to look like a single-purpose proxy host even when no
  single signal is conclusive.
* **Strong vs soft signals separated.** `[!]` for strong, `[-]` for
  soft. Counts are shown in the section headers.
* **TLS posture checks now fire per port** (1.3 / h2 / X25519),
  each contributing a soft flag when absent.

### New — DPI exposure matrix

A 9-axis table that spells out by which DPI/classification method the
host can be picked up, and at what level (NONE / LOW / MEDIUM / HIGH):

| Axis                                     | What it checks |
|------------------------------------------|----------------|
| Port-based (default VPN ports)           | 1194/1723/500/4500/51820/… in the open set |
| Protocol handshake signature             | OpenVPN/WG/IKE replies on their wire protocols |
| Cert-steering (Reality discriminator)    | v2.1 Reality test — positive / plain / varies |
| ASN classifier (VPS/hosting)             | how many GeoIP sources flag hosting |
| Threat-intel tags (VPN/Proxy/Tor)        | how many sources put a VPN/Proxy/Tor tag |
| Cert freshness (new-LE watch)            | cert age <14d count |
| Active junk probing (J3)                 | silent-on-junk vs responds-to-junk ratio |
| Open-port profile (sparsity)             | single-port :443 / sparse / diverse |
| TLS hygiene (1.3 + h2 + trusted-CA)      | count of weak-TLS indicators |

### Changed — per-port classification carries cert summary

Each TLS port role now includes TLS version, ALPN, CN, issuer, cert age
and SAN count. Example:

```
  :443   generic HTTPS / CDN origin — TLSv1.3 / ALPN=h2 / CN=*.example.com
         / issuer=R3 / age=42d / SAN=3
```

### Changed — fingerprint line prints cert intel inline

```
  :443   TLS               TLSv1.3 / TLS_AES_128_GCM_SHA256 / ALPN=h2 / X25519 / 87ms
                           cert CN=example.com  issuer=R3  age=42d left=48d  SAN=2 [free-CA]
```

### Fixed

* Scoring was too flat: `hosting` was -5 per source and summed linearly
  with no ceiling. v2.2 splits into hits-counted-once-per-class and adds
  a dedicated COMBO term for >=3/>=5 independent soft flags.
* `single open port = :443 only` is now an explicit soft flag with its
  own penalty, regardless of GeoIP classification.
* Expired certs now contribute a soft flag (v2.1 silently accepted
  them).

### Build command (unchanged from v2.1)

```bash
g++ -O2 -std=c++20 -D_WIN32_WINNT=0x0A00 \
    -I/c/msys64/ucrt64/include \
    -static -static-libgcc -static-libstdc++ \
    src/byebyevpn.cpp -o byebyevpn.exe \
    /c/msys64/ucrt64/lib/libssl.a \
    /c/msys64/ucrt64/lib/libcrypto.a \
    /c/msys64/ucrt64/lib/libwinpthread.a \
    -lws2_32 -liphlpapi -lwinhttp -lcrypt32 -lbcrypt -ldnsapi -luser32 -ladvapi32
```

## v2.1 — 2026-04-18

### Fixes (false-positive class)

* **Reality discriminator rewrite.** Previous versions flagged any TLS server
  that returned the same cert for every SNI as "Reality/XTLS" — which matched
  the real microsoft.com, every plain nginx default-vhost, and most CDN origins.
  New discriminator:
  1. Same cert returned for ≥3 foreign SNIs (unchanged),
  2. Cert does NOT cover the base SNI (rules out normal TLS hosting),
  3. Cert DOES cover a different foreign SNI (positive Reality steering signal).
  All three must hold. Plain `microsoft.com` → `generic TLS / HTTPS origin`,
  actual Reality with `dest=www.microsoft.com` → `Xray-core (VLESS+Reality)`.
* **J3 silent-on-junk relabelled.** Dropping HTTP/junk before the TLS record
  layer is normal for any strict TLS endpoint; it is no longer rendered as
  "Reality/XTLS-like" in the J3 verdict.
* **Shadowsocks probe softened.** "Accepts junk, never replies" is now
  reported as ambiguous instead of `vpn-like`; the pattern also matches any
  firewalled TCP service.
* **TLS-handshake-failed + silent-on-junk** no longer claims "Reality strict-
  mode" by itself. Reported as ambiguous ("Reality strict / SS-AEAD / Trojan /
  firewall") in the per-port classification with a small score penalty.
* **`pf.tls` is now stored on handshake failure** too, so the verdict engine
  can distinguish "TLS attempted and failed" from "no TLS attempted here".

### Changes (output)

* Entire `[7/7] Verdict` section rewritten: technical English tone, strict
  protocol-level stack naming ("no VPN protocol signature identified" is now
  a valid conclusion), per-port role table, numbered recommendation flags
  (`[!]` / `[+]` / `[-]` / `[i]`).
* SNI consistency output now prints one of four explicit states:
  `Reality/XTLS pattern` / `plain server (single default cert)` /
  `identical cert, covers no foreign SNI (inconclusive)` / `cert varies per
  SNI (multi-tenant TLS)`.
* Interactive menu, help text, and the entire `byebyevpn local` module are
  now in English.
* Scoring tuned: Reality detection now costs a small penalty (being
  identifiable as Reality is itself a detection surface), plain TLS with a
  default cert costs nothing.

### Build / packaging

* **Single-file static Windows release.** `byebyevpn.exe` is now 8 MB and
  has zero runtime dependencies: OpenSSL, libgcc, libstdc++, libwinpthread
  are all statically linked. No more `libssl-3-x64.dll` / `libcrypto-3-x64.dll`
  / MinGW sidecar DLLs next to the executable.
* New `make windows-static` target. Produces the truly standalone `.exe`.
* New `make release-zip` target. Builds and zips `byebyevpn.exe` + `LICENSE`
  + `README.md` into `byebyevpn-win64.zip`.

### Build command (Windows, MinGW-w64 UCRT)

```bash
g++ -O2 -std=c++20 -D_WIN32_WINNT=0x0A00 \
    -I/c/msys64/ucrt64/include \
    -static -static-libgcc -static-libstdc++ \
    src/byebyevpn.cpp -o byebyevpn.exe \
    /c/msys64/ucrt64/lib/libssl.a \
    /c/msys64/ucrt64/lib/libcrypto.a \
    /c/msys64/ucrt64/lib/libwinpthread.a \
    -lws2_32 -liphlpapi -lwinhttp -lcrypt32 -lbcrypt -ldnsapi -luser32 -ladvapi32
```

## v2.0 — initial public release

* 7 GeoIP providers in parallel.
* Full 1–65535 TCP scan (default) with configurable port modes.
* UDP protocol probes: OpenVPN HARD_RESET, WireGuard handshake, IKEv2, QUIC,
  Tailscale, DNS.
* J3 / TSPU-style active probing suite.
* `byebyevpn local` — local-host VPN posture (adapters, routes, split-tunnel,
  VPN processes + installed config dirs).
* Interactive menu, CLI sub-commands, verdict engine with per-port role
  classification.
