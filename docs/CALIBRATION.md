# Calibration log

Every release tag needs a lab run (see [GROUNDTRUTH.md](GROUNDTRUTH.md)) and
an entry here. Release gate:

- zero FP on every stand for every scored signal, for the verdict itself
  and for every printed claim the matrix has a truth for; the `groundtruth`
  CI job enforces it on the release build (`run.py` exit 1);
- every id that can reach the score has a passport in
  [SIGNALS.md](SIGNALS.md) (enforced by `test_verdict_engine.cpp`);
- the INCONCLUSIVE share on normal stands does not grow without a written
  reason in this file.

## 2026-09-30, v2.8.3 + unreleased

Machine: Windows x64, no admin, local w64devkit build (msvcrt, not the UCRT
release build). A sing-box TUN client was up during both runs; the
lab is on loopback and does not cross it, H2 does.

### Before (HEAD b085cb7 + earlier unreleased work)

Run `before-1`, rescored with the current rules.

| stand | label | score | scored |
|---|---|---|---|
| A clean origin | CLEAN | 100 | - |
| B origin on :4711 | INCONCLUSIVE | - | - |
| C Reality, target A | CLEAN | 100 | - |
| D Reality, target microsoft | INCONCLUSIVE | - | - |
| E Shadowsocks | INCONCLUSIVE | - | - |
| F WireGuard | INCONCLUSIVE | - | - |
| H1 all RST | INCONCLUSIVE | - | - |
| H2 192.0.2.1 via TUN | INCONCLUSIVE, after 93 s of probes into the tunnel | - | - |
| I ack-all | INCONCLUSIVE | - | - |
| J lossy A | CLEAN | 100 | - |
| **K udp garbage** | **SUSPICIOUS** | **69** | **wg-family, IMMEDIATE BLOCK** |
| S SOCKS5 | SUSPICIOUS | 69 | socks5 |
| W synthetic WG | SUSPICIOUS | 69 | wg-family |
| G synthetic AWG | SUSPICIOUS | 69 | wg-family |
| X synthetic SSTP | SUSPICIOUS | 69 | sstp |

| signal or claim | TP | FP | TN | FN | INC |
|---|---|---|---|---|---|
| wg-family | 2 | **1** | 12 | 0 | 0 |
| socks5 | 1 | 0 | 14 | 0 | 0 |
| sstp | 1 | 0 | 14 | 0 | 0 |
| verdict-flag | 4 | **1** | 2 | 1 | 7 |
| closed-port-drop | 0 | **9** | 0 | 0 | 0 |
| reality-hint | 2 | **7** | 6 | 0 | 0 |
| ack-all-warning | 2 | 0 | 13 | 0 | 0 |
| os-guess-wrong | 0 | 0 | 9 | 0 | 0 (but 0 of 9 said Windows) |

### After

Run `after-2`, same lab, same rules.

| stand | label | score | scored |
|---|---|---|---|
| A | CLEAN | 100 | - |
| B | CLEAN | 100 | - |
| C | CLEAN | 100 | - |
| D | CLEAN | 100 | - |
| E | INCONCLUSIVE | - | - |
| F | INCONCLUSIVE | - | - |
| H1 | INCONCLUSIVE | - | - |
| H2 | UNRELIABLE, stopped at preflight, 0 probes sent | - | - |
| I | INCONCLUSIVE | - | - |
| J | INCONCLUSIVE (SSTP 1 of 3 answered, coverage 0/1) | - | - |
| K | INCONCLUSIVE (wg-family negative: receiver index mismatch) | - | - |
| S | SUSPICIOUS | 69 | socks5 |
| W | SUSPICIOUS | 69 | wg-family |
| G | SUSPICIOUS | 69 | wg-family |
| X | SUSPICIOUS | 69 | sstp |

| signal or claim | TP | FP | TN | FN | INC |
|---|---|---|---|---|---|
| wg-family | 2 | 0 | 13 | 0 | 0 |
| socks5 | 1 | 0 | 13 | 0 | 1 |
| sstp | 1 | 0 | 12 | 0 | 2 |
| verdict-flag | 4 | 0 | 3 | 2 | 6 |
| closed-port-drop | 0 | 0 | 9 | 0 | 0 |
| reality-hint | 0 | 0 | 13 | 2 | 0 |
| ack-all-warning | 2 | 0 | 13 | 0 | 0 |

Reading it:

- all false positives on clean stands are gone: K no longer gets
  IMMEDIATE BLOCK, no closed port reads as "drop", no clean host is told
  it might be Reality;
- verdict FN 2 are C and D (Reality). They were FN before too; active
  probes cannot see them, and every report now says so. reality-hint FN 2
  is the same fact: the scanner no longer hints at Reality anywhere;
- INCONCLUSIVE: 7 before, 6 after on the verdict row. B moved to CLEAN (one
  TLS handshake on an unlisted port), J moved to INCONCLUSIVE (a flaky path
  now refuses a verdict instead of printing CLEAN 100), H2 moved to
  UNRELIABLE. Normal stands A and B stay conclusive;
- correlation (rule 6): `wireguard` and `amnezia` were one piece of
  evidence (a MessageResponse layout on the same port) under two ids; merged
  into `wg-family`, scored once. socks5 and sstp never co-fired and read
  different ports and protocols;
- GeoIP: 6 clean hosting addresses, 0 VPN or proxy tags. Tags no longer
  score regardless (SIGNALS.md#geoip-tags).

### Re-run after the interactive panel (`after-3-panel`)

Same matrix, 0 FP on every row, all 15 stands inside their accepted
labels. J came out CLEAN this time instead of INCONCLUSIVE: its stalls are
random (30% of connections), and this run none of the SSTP probes hit one.
Both labels are accepted for J; the verdict row shows it as TN 4, INC 5.

## 2026-09-30, baseline before the QUIC, WireGuard and volume work (`baseline-0930`)

Baseline before this work, same tree as `after-3-panel`, same
machine and the same TUN client. Recorded before any change; rescored later with
the `quic-endpoint` row, which reads TN on all 15 stands.

| stand | label | score | tier | scored | s |
|---|---|---|---|---|---|
| A | CLEAN | 100 | PASS / ALLOW | - | 7 |
| B | CLEAN | 100 | PASS / ALLOW | - | 1 |
| C | CLEAN | 100 | PASS / ALLOW | - | 2 |
| D | CLEAN | 100 | PASS / ALLOW | - | 14 |
| E | INCONCLUSIVE | - | UNKNOWN | - | 3 |
| F | INCONCLUSIVE | - | UNKNOWN | - | 18 |
| H1 | INCONCLUSIVE | - | UNKNOWN | - | 0 |
| H2 | UNRELIABLE (preflight, 0 probes) | - | UNKNOWN | - | 0 |
| I | INCONCLUSIVE | - | UNKNOWN | - | 81 |
| J | INCONCLUSIVE | - | UNKNOWN | - | 63 |
| K | INCONCLUSIVE | - | UNKNOWN | - | 0 |
| S | SUSPICIOUS | 69 | IMMEDIATE BLOCK | socks5 | 7 |
| W | SUSPICIOUS | 69 | IMMEDIATE BLOCK | wg-family | 15 |
| G | SUSPICIOUS | 69 | IMMEDIATE BLOCK | wg-family | 15 |
| X | SUSPICIOUS | 69 | IMMEDIATE BLOCK | sstp | 2 |

| signal or claim | TP | FP | TN | FN | INC |
|---|---|---|---|---|---|
| wg-family | 2 | 0 | 13 | 0 | 0 |
| socks5 | 1 | 0 | 13 | 0 | 1 |
| sstp | 1 | 0 | 12 | 0 | 2 |
| verdict-flag | 4 | 0 | 3 | 2 | 6 |
| closed-port-drop | 0 | 0 | 9 | 0 | 0 |
| reality-hint | 0 | 0 | 13 | 2 | 0 |
| ack-all-warning | 2 | 0 | 13 | 0 | 0 |

0 FP, 15 of 15 labels accepted, exit 0, 230 s. J is INCONCLUSIVE here and
CLEAN in `after-3-panel`: the same random stalls as before (SSTP 1 of 3
answered), both labels accepted. The verdict INC 6 against 5 in
`after-3-panel` is that J.

### QUIC stands and a stricter gate (`quic-0930`)

Two stands added: Q (xray Hysteria2 on UDP 443, real quic-go) and U
(QUIC-shaped traps). New matrix row `quic-endpoint`. `run.py` now exits 1
on a false positive in any row with a truth, not only the scored ids and
the verdict; `baseline-0930` rescored under that rule still exits 0.

U found one false claim before the fix (run `quic-trial`, old exe):
the line under the hex dump printed "QUIC Initial packet" and "QUIC
Version-Negotiation" for datagrams addressed to connection ids the probe
never chose, while the JSON already said `udp-unmatched`. quic-endpoint
FP 1 there, exit 1. Fixed in `quic_reply_summary()`; the VN follow-up
probe now goes only to a port with a validated reply.

| stand | label | notes |
|---|---|---|
| A B C D | CLEAN 100 | unchanged |
| E F H1 I K | INCONCLUSIVE | unchanged |
| H2 | UNRELIABLE, preflight | unchanged |
| J | CLEAN 100 | random stalls missed the SSTP probes this run |
| S W G X | SUSPICIOUS 69 | unchanged |
| Q | INCONCLUSIVE | no TCP service to attribute; QUIC note present, VN lists ba9a5aaa, 00000001, 6b3343cf |
| U | INCONCLUSIVE | two `udp-unmatched` notes, no QUIC claim, no VN probe sent |

| signal or claim | TP | FP | TN | FN | INC |
|---|---|---|---|---|---|
| wg-family | 2 | 0 | 15 | 0 | 0 |
| socks5 | 1 | 0 | 15 | 0 | 1 |
| sstp | 1 | 0 | 15 | 0 | 1 |
| verdict-flag | 4 | 0 | 4 | 2 | 7 |
| closed-port-drop | 0 | 0 | 9 | 0 | 0 |
| reality-hint | 0 | 0 | 15 | 2 | 0 |
| ack-all-warning | 2 | 0 | 15 | 0 | 0 |
| quic-endpoint | 1 | 0 | 16 | 0 | 0 |

0 FP, 17 of 17 labels accepted, exit 0, 190 s of scans. Verdict INC 7
against 6: J moved out (CLEAN), Q and U moved in; both new stands have no
TCP service and are INCONCLUSIVE by design.

### WireGuard self-check (`wg-1001`, 2026-10-01)

The TUN client was off from here on: H2 goes to the real path,
gets no answer and is INCONCLUSIVE after 63 s instead of UNRELIABLE at
preflight; ack-all-warning TP drops from 2 to 1 for the same reason (the
truth for H2 follows the machine's path, `run.py` probes it).

Five self-check runs added (same addresses, scanned with keys): FK, FS
SUSPICIOUS 69 on `wg-keyed`; FW INCONCLUSIVE (unknown peer, silence); WK
SUSPICIOUS 69 on `wg-family` only, `wg-keyed` negative (mac1 fails); KK
INCONCLUSIVE, `wg-keyed` negative (index mismatch). The first trial
(`wg-trial`) lost the second of three keyed initiations: wireguard-go's
20 ms flood window. Spacing is now 1.0 to 1.5 s; FK then settles on two
authenticated answers. No key string appears in any saved result.

| signal or claim | TP | FP | TN | FN | INC |
|---|---|---|---|---|---|
| wg-family | 3 | 0 | 19 | 0 | 0 |
| wg-keyed | 2 | 0 | 19 | 0 | 1 |
| socks5 | 1 | 0 | 20 | 0 | 1 |
| sstp | 1 | 0 | 20 | 0 | 1 |
| verdict-flag | 7 | 0 | 3 | 2 | 10 |
| closed-port-drop | 0 | 0 | 9 | 0 | 0 |
| reality-hint | 0 | 0 | 20 | 2 | 0 |
| ack-all-warning | 1 | 0 | 21 | 0 | 0 |
| quic-endpoint | 1 | 0 | 21 | 0 | 0 |

0 FP, 22 of 22 accepted, exit 0, 339 s of scans. Verdict INC 10 against
7: FW and KK are INCONCLUSIVE by design (silence, and K's own label), and
H2 moved from UNRELIABLE, which the matrix counts as TN, to INCONCLUSIVE
because the tunnel is gone; TN 4 to 3 is that H2.

### Config audit (no lab change)

Offline rules are checked by `tests/test_audit_fixtures.py` over 34 files.
Before (the build without these rules): 31 failures, every one
a missing new rule or the sing-box case below; every look-alike passed.
After: 0 failures. One old false positive found on the way: sing-box
REALITY under `tls.enabled: false` raised `reality-dest-brand` for a
handshake server sing-box never uses, and missed `plaintext-proto`.

### Everything above plus `dpi --volume` (`final-1001`, 2026-10-01)

Scan stands as in `wg-1001`, labels identical; seven client-side volume
runs added.

| run | outcome | expected | notes |
|---|---|---|---|
| VZ | positive | positive | two stalls at 16594 and 16595 B on the wire, controls 128 KB, inside the 16-20 KB band |
| VV | negative | negative | 128 KB read limit every time |
| VY | negative | negative | 3 s pause at 16 KB, 8 s stall timeout not reached |
| VT | inconclusive | inconclusive | FIN after 16.6 KB, a freeze leaves the connection open |
| VA | not applicable | not applicable | 75 B page |
| VC | inconclusive | inconclusive | the control (Z) stalled before and after |
| VN | inconclusive | inconclusive | no control |

| signal or claim | baseline-0930 TP/FP/TN/FN/INC | final-1001 TP/FP/TN/FN/INC |
|---|---|---|
| wg-family | 2/0/13/0/0 | 3/0/19/0/0 |
| wg-keyed | n/a | 2/0/19/0/1 |
| socks5 | 1/0/13/0/1 | 1/0/20/0/1 |
| sstp | 1/0/12/0/2 | 1/0/20/0/1 |
| verdict-flag | 4/0/3/2/6 | 7/0/3/2/10 |
| closed-port-drop | 0/0/9/0/0 | 0/0/9/0/0 |
| reality-hint | 0/0/13/2/0 | 0/0/20/2/0 |
| ack-all-warning | 2/0/13/0/0 | 1/0/21/0/0 |
| quic-endpoint | n/a | 1/0/21/0/0 |
| volume-freeze | n/a | 1/0/2/0/4 |

0 FP before and after; 15 of 15 then, 29 of 29 now; exit 0. 340 s of
scans plus 44 s of volume runs. No key string in any saved result.
INCONCLUSIVE growth on the verdict row (6 to 10), each one explained:
Q and U have no TCP service, FW is the unknown-peer trap, KK inherits K,
H2 lost the local tunnel that used to make it UNRELIABLE; J went the
other way (CLEAN) by chance. The volume row's INC 4 are the four runs
designed to refuse a verdict.

## 2026-10-01, v3.0.0

Run `release-3.0.0` on a clean rebuild (w64devkit GCC 16.2 with msvcrt,
OpenSSL archives matching the pins in release.yml). The CI build is UCRT64
and runs the same lab in the `groundtruth` job.

0 FP in every row, 29 of 29 runs inside their accepted labels or expected
outcome, exit 0, 347 s of scans. Same table as `final-1001`; J came out
CLEAN this time, which it may. No key string and no long dash in any saved
output.

Same tree: unit 238/238 (8535 checks), Python 8/8, audit fixtures 34/34,
tool-name grep 1 (`cli.cpp:131`), no MinGW or OpenSSL DLL imported.
cppcheck 2.13 and clang-tidy 18 (the ubuntu-24.04 versions CI uses) found
four issues before the release, all fixed without behaviour change: a
string passed by value, a self-assigning `substr`, a widening cast in
`ports.cpp`, and a cppcheck misreading of `std::array` copies in
`wg_handshake.cpp`.

## 2026-10-01, unreleased: names --ct, client and pair audit, dpi --real

Run `v3.1-sni-ct-pair`: the 29 runs of v3.0.0 plus five `dpi --sni --real`
runs on an emulated box that drops one name.

| run | outcome | expected |
|---|---|---|
| SM | positive (node silent, real address replies, two rounds) | positive |
| SP | negative | negative |
| SB | inconclusive, name blocked | inconclusive, name blocked |
| SD | inconclusive (node down) | inconclusive |
| SR | inconclusive (real address down) | inconclusive |

| signal or claim | TP | FP | TN | FN | INC |
|---|---|---|---|---|---|
| sni-address | 1 | 0 | 1 | 0 | 3 |

Every other row as in the v3.0.0 entry; J was INCONCLUSIVE this time
(sstp INC 2, verdict INC 11), both labels accepted. 0 FP, 34 of 34, exit 0.

Offline checks: audit fixtures 57 files, 0 failures (23 new client and
pair files, look-alikes included); `names --ct` from saved crt.sh
answers, look-alikes `subway.`, `notexample.com`, `example.com.evil.net`
and a mail address all dropped or unmarked. A live crt.sh query could not
be made on 2026-10-01: crt.sh answered 502 to every request, including
plain ones outside this tool; the command exits 4 there, as designed.

## 2026-10-01, unreleased: pcap, leaks in local, batch and diff

Run `v3.2-pcap-leaks`: the 34 runs above plus four `pcap` runs on captures
recorded through real xray 26.7.28 (`capture_lab.py`, four connections per
case, Python OpenSSL 3.5 inside the tunnel).

Before: no rule. The first draft of the inner-handshake rule accepted any
client record of 50 to 110 B after the server flight; plain HTTP/1.1
keep-alive from scripted clients sends requests in that range, so the
draft would have flagged ordinary HTTPS. It never shipped. The rule was narrowed to the
exact plaintext sizes of an inner TLS 1.3 Finished (58, 64, 74, 80 B)
before the first run. The plain case was then made harder: browser-sized
requests (about 490 B) so that the hello-size threshold no longer saves
it and only the Finished-size test separates it.

After:

| run | capture | first flights (client, server, then client) | matched | outcome | expected |
|---|---|---|---|---|---|
| PV | VLESS over TLS | 1558, 1895, then 80 B | 4 of 4 | positive | positive |
| PT | Trojan over TLS | 1600, 1893, then 80 B | 4 of 4 | positive | positive |
| PX | VLESS with Vision | 1618, 2162, then 1170 B | 0 of 4 | negative | negative |
| PH | plain HTTPS, keep-alive | 492, 12581, then 492 B | 0 of 4 | negative | negative |

80 B is the inner CCS plus a SHA-384 Finished: OpenSSL picks
TLS_AES_256_GCM_SHA384. Vision pads the same flight to a random size.

| signal or claim | TP | FP | TN | FN | INC |
|---|---|---|---|---|---|
| inner-handshake | 2 | 0 | 2 | 0 | 0 |
| pcap-dns-clear | 0 | 0 | 4 | 0 | 0 |
| pcap-outside-node | 0 | 0 | 4 | 0 | 0 |

Every other row as in the entry above (J INCONCLUSIVE this time, both
labels accepted). 0 FP, 38 of 38, exit 0.

`local` leaks have no lab stand (they need a machine with a tunnel
client). On one Windows machine with a TUN client: no global IPv6 beside
the tunnel, negative without a packet; the LAN resolver beside the tunnel
stayed silent to both queries while the tunnel client was up,
inconclusive, which is what a firewall that drops port 53 beside the
tunnel looks like. `batch` on stands A and S twice and `diff` of the two
directories: no change, exit 0; `diff` of A against S: label, tier,
checks, the socks5 signal and the ports, exit 2.

Same tree: unit 257/257 (8763 checks), Python 9/9, cppcheck 0 and
clang-tidy 0 on the new modules.

## Field log

Your own nodes: date, scanner version, verdict, what happened to the node
afterwards. A scanner that says CLEAN about nodes that die a week later is
miscalibrated even when the lab is green. Addresses stay out of this file;
use a label only you can map.

| date | version | node label | verdict | coverage | later |
|---|---|---|---|---|---|
| | | | | | |
