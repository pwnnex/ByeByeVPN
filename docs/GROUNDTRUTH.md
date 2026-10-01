# Ground-truth lab

Targets with a known answer, so false positives can be counted instead of
argued about. Everything runs on one Windows machine without admin rights:
each stand gets its own loopback address `127.0.1.x`, so stands never share
a port and a scan of one address sees only that stand.

## Run it

```
python tools/groundtruth/run.py ./byebyevpn.exe --tag <name>
python tools/groundtruth/run.py ./byebyevpn.exe --tag <name> --only A,K,H1
python tools/groundtruth/run.py ./byebyevpn.exe --tag <name> --rescore
python tools/groundtruth/smoke.py
```

`run.py` starts every stand, scans each one with
`scan <ip> --json --no-geoip --no-ct --ports <107 ports>`, stores stdout,
stderr and exit code under `tools/groundtruth/.run/results/<tag>/`, and
writes `matrix.md` there. Exit code 1 means a stand got a label outside its
accepted set or any matrix row with a known truth has a false positive,
printed claims included. `--rescore` recomputes the matrix from stored
results, so old runs are judged by the current rules, and returns the same
exit code. `--require-all` also fails when a stand could not start.
`smoke.py` touches each stand once.

Requirements: Python 3.10+, `xray.exe` (found via `BBV_XRAY`,
`tools/groundtruth/bin/xray.exe` or `xray` on PATH). Without xray the stands
C, D, E, F, S and Q are skipped and listed in the matrix notes; an xray
without the hysteria inbound skips Q only. Keys, UUIDs and certificates are
generated into `tools/groundtruth/.run/` on each start and never printed.

## In CI

The `groundtruth` job in `.github/workflows/release.yml` runs after the
Windows build on the exe that job produced (UCRT64, the release build),
fetches xray v26.7.28 pinned by the sha256 of `Xray-windows-64.zip`, and
runs `run.py --tag ci --require-all`. The matrix and raw results are
uploaded as the `groundtruth-matrix` artifact. Under Actions, `run.py`
also prints every reason it fails (a stand that did not start, a port the
host refused, a label outside the set, a false positive) as an `::error`
annotation, readable on the run page without opening the log. A port the
host refuses disables that stand instead of crashing the lab; stand I
tolerates refused filler ports in 1000-1099 while more than 70 of its
ports stay open, since Hyper-V hosts reserve port blocks there. A release tag needs the job
green; the manual run and the entry in [CALIBRATION.md](CALIBRATION.md)
stay, because the CI runner has no tunnel and never exercises the
ack-all branch of H2.

## Stands

| stand | address | what runs | truth | accepted labels |
|---|---|---|---|---|
| A | 127.0.1.1 | nginx-shaped TLS origin on 443, HTTP on 8000 | clean | CLEAN |
| B | 127.0.1.2 | same origin on 4711 only | clean | CLEAN, NOISY |
| C | 127.0.1.3 | xray VLESS + Reality on 443, target = stand A | VPN, no active signature | CLEAN, NOISY, INCONCLUSIVE |
| D | 127.0.1.4 | xray VLESS + Reality on 443, target = www.microsoft.com | VPN, brand certificate on a foreign address | CLEAN, NOISY, SUSPICIOUS, INCONCLUSIVE |
| E | 127.0.1.5 | xray Shadowsocks aes-256-gcm on 8388 | VPN, no active signature | CLEAN, NOISY, INCONCLUSIVE |
| F | 127.0.1.6 | xray WireGuard inbound on UDP 51820, no TCP | VPN, silent to unkeyed probes | INCONCLUSIVE |
| H1 | 127.0.1.8 | nothing, every port answers RST | nothing there | INCONCLUSIVE |
| H2 | 192.0.2.1 | RFC 5737 address, nothing should answer | nothing there | INCONCLUSIVE; UNRELIABLE when the machine's path accepts every SYN |
| I | 127.0.1.9 | ack-all: 107 ports accept and stay silent | nothing there | INCONCLUSIVE |
| J | 127.0.1.10 | stand A behind a relay: 30% of connections stall, 0-150 ms jitter | clean | CLEAN, NOISY, INCONCLUSIVE |
| K | 127.0.1.14 | UDP traps: 51820 answers 92 B type-2 garbage unrelated to the probe, 55555 echoes | clean | CLEAN, NOISY, INCONCLUSIVE |
| S | 127.0.1.11 | xray SOCKS5 no-auth on 10808, HTTP on 8000 | VPN, SOCKS5 answers | SUSPICIOUS or worse |
| W | 127.0.1.13 | synthetic WireGuard responder, valid response to our index | parser positive | SUSPICIOUS or worse |
| G | 127.0.1.16 | synthetic AmneziaWG responder, S1 = 8, S2 = 16 | parser positive | SUSPICIOUS or worse |
| X | 127.0.1.15 | synthetic SSTP setup responder on 443 | parser positive | SUSPICIOUS or worse |
| Q | 127.0.1.17 | xray Hysteria2 on UDP 443 (quic-go, TLS ALPN h3), no TCP | VPN, a real QUIC stack answers | CLEAN, NOISY, INCONCLUSIVE |
| U | 127.0.1.18 | QUIC-shaped UDP traps: 443 answers a well-formed v1 Initial for connection ids the probe never chose, 8443 answers version negotiation with the client DCID where its SCID belongs | clean, no QUIC | CLEAN, NOISY, INCONCLUSIVE |

Owner self-check runs: the same addresses scanned again with
`--wg-pubkey` and `--wg-key` (key files generated into `.run/`, passed by
path; FS passes the public key as text to cover that branch).

| run | address | keys | truth | accepted labels |
|---|---|---|---|---|
| FK | F | server public key, configured peer key | wg-keyed true | SUSPICIOUS or worse |
| FS | F | as FK plus a preshared key the server does not have | wg-keyed true (mac1 proves the server key) | SUSPICIOUS or worse |
| FW | F | server public key, a peer key the server does not know | silent, wg-keyed inconclusive | INCONCLUSIVE |
| WK | W | as FK; W copies our index but has no key | wg-keyed false, wg-family true | as W |
| KK | K | as FK; K answers unrelated type 2 | wg-keyed false | as K |

H, I, J, K, U, FW, WK and KK are the false-positive traps and matter more
than the positive stands. Q has no TCP service, so the honest label is INCONCLUSIVE
("no service answered in a way that can be attributed"); the `quic-endpoint`
row checks the QUIC observation itself.

Client-side volume runs (`dpi <ip> 443 --volume <path> --control <ip>/big
--json`), against TLS servers that are not scanned:

| server | address | behaviour |
|---|---|---|
| V | 127.0.1.19 | 256 KB with Content-Length, no pause |
| V2 | 127.0.1.21 | same, used as the control |
| Z | 127.0.1.20 | 14000 B of body, then silence on an open connection (F7 emulation) |
| Y | 127.0.1.22 | 16 KB, a 3 s pause inside the freeze band, then the rest |
| T | 127.0.1.23 | 14000 B of body, then FIN |

| run | target | control | expected |
|---|---|---|---|
| VZ | Z | V2 | positive |
| VV | V | V2 | negative |
| VY | Y | V2 | negative |
| VT | T | V2 | inconclusive |
| VA | A (`/`, 75 B page) | V2 | not applicable |
| VC | V | Z | inconclusive (control fails) |
| VN | V | none | inconclusive |

Matrix row `volume-freeze` counts these; a run whose outcome differs from
the expected one fails the gate like a stand outside its labels. The lab
emulates the node's side of a freeze; it cannot emulate the operator.

Client-side name and address runs (`dpi <node> 443 --sni brand.lab.test
--real <ip> --json`). A box that drops one name is emulated by a server
that reads the ClientHello SNI without consuming it and holds the
connection silently for that name:

| server | address | behaviour |
|---|---|---|
| N | 127.0.1.24 | the node: drops `brand.lab.test` silently, answers every other name |
| R | 127.0.1.25 | the real site: answers `brand.lab.test` |
| RB | 127.0.1.26 | a real site that drops `brand.lab.test` too |

| run | node | real address | expected |
|---|---|---|---|
| SM | N | R | positive |
| SP | A (answers every name) | R | negative |
| SB | N | RB | inconclusive, name blocked (exit 2) |
| SD | H1 (nothing listens) | R | inconclusive |
| SR | N | H1 | inconclusive |

Matrix row `sni-address` counts these the same way.

## Where the lab disagrees with first expectations

The first plan expected a detection on C, E and F, a tier A hit on E and
F, and a correct S1 guess on G. Those expectations contradict both the
protocols and the rule that silence never leads to tier A:

- **C** serves stand A's certificate byte for byte (sha256 `31225196...`
  on both) and relays every junk probe to A. Any rule that flags C flags A.
- **E** Shadowsocks AEAD reads, fails authentication and drains or closes.
  There is no reply to match; flagging it means flagging silence.
- **F** WireGuard ignores every initiation without a valid mac1, which
  needs the server public key, and every initiation from a peer it does
  not know. No unkeyed probe gets an answer; the owner's keys do (FK).
- **G** real AmneziaWG is WireGuard underneath and stays silent the same
  way; S1 cannot be recovered from silence. Stand G is synthetic and tests
  the response parser only.

These stands are kept as honest false negatives. They show the blind spots
the report now prints on every scan.

## Limits of the lab

- Loopback has no packet loss. J emulates stalls after accept, not SYN loss;
  real loss needs WinDivert or clumsy (admin) or a remote node.
- The ack-all stand I listens on the scanned ports only. A real ack-all
  path also accepts the random control ports, which is what the scanner
  now checks; I therefore shows the flat-RTT warning, not the ack-all
  failure. H2 on a machine with an ack-all tunnel shows the real thing.
- Every stand runs on the same Windows kernel. Anything about the target's
  TCP stack is untestable here beyond "does not name the wrong OS".
- GeoIP is off (`--no-geoip`): loopback has no ASN. GeoIP false positives
  were measured separately with `byebyevpn geoip` on known hosting
  addresses (see CALIBRATION.md).
- No Linux targets, no real SSTP server. The only QUIC server is xray's
  Hysteria2 (quic-go); HTTP/3 servers built on other stacks (msquic,
  quiche, ngtcp2) are not in the lab.

## Matrix rows

| row | counts |
|---|---|
| wg-family, wg-keyed, socks5, sstp | scored signal fired (JSON `signals.scored`, or legacy text) against `detectable` |
| verdict-flag | label SUSPICIOUS or worse, or any tier A hit, against "a VPN or proxy listens there" |
| closed-port-drop | tcpfp printed "drop" for a loopback closed port that answers RST |
| os-guess-wrong | OS guess named a non-Windows stack |
| reality-hint | a line pinning Reality or XTLS on the target (port hints, junk verdicts) |
| ack-all-warning | ack-all or flat-RTT warning, true on I and on H2 when the machine's path is ack-all |
| quic-endpoint | JSON note `quic-endpoint` or a printed QUIC classification line, true on Q only |
| volume-freeze | `dpi --volume` outcome positive, true on VZ only; inconclusive and not applicable count as INC |
| sni-address | `dpi --sni --real` outcome positive, true on SM only; inconclusive counts as INC |
| silent-on-junk-claim | informational, counts the old "silent-on-junk" verdict line |
