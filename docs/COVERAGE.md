# Coverage matrix

Snapshot 2026-10-01, tree b085cb7 plus uncommitted work. One row per
observable the scanner claims to measure. "Model" points at the feature in
[TSPU-MODEL.md](TSPU-MODEL.md) that makes the observable matter; "lab" at
the stand in [GROUNDTRUTH.md](GROUNDTRUTH.md) that checks it.

Status values:

- **wire**: behaviour checked against real bytes (loopback lab or capture)
- **unit**: covered by unit tests or spec vectors, not by the lab
- **ref**: printed for reference, never scored
- **gap**: the model says it matters, the scanner cannot see it
- **wrong**: known to be incorrect (file:line)

| # | Observable | Model | Module | Lab / test | Status |
|---|---|---|---|---|---|
| 1 | SNI reset after ClientHello (client side) | F3 | scan/dpi_probe.cpp | tests/test_dpi_socket.py | wire |
| 2 | SNI silent drop after ClientHello | F3 | scan/dpi_probe.cpp | tests/test_dpi_socket.py | wire |
| 3 | Closed vs filtered vs unreachable TCP port | F2 | net/tcp.cpp | H1, closed-port-drop row; 2030 ms became 1 ms | wire |
| 4 | Closed-port reply timing | none | scan/tcpfp.cpp | H1, A | wire, ref |
| 5 | OS or stack guess | none | removed | 0/9 correct on the lab | removed |
| 6 | WireGuard-family response layout | F5 | scan/udp_validate.cpp, app/verdict.cpp | W, G, K, F; test_verdict_engine | wire (synthetic) |
| 7 | WireGuard on a real server | F5 | scan/wg_handshake.cpp, `--wg-pubkey` + `--wg-key` (owner self-check) | FK, FS, FW, WK, KK; test_wg_handshake | wire (self-check); gap for anyone without the keys, by design |
| 8 | SOCKS5 negotiation | F6, F11 | scan/fingerprint.cpp | S, I | wire |
| 9 | SSTP setup | F6, F11 | scan/fingerprint.cpp, scan/protocol_response.cpp | X, A | wire (synthetic) |
| 10 | HTTP CONNECT accepted | F6 | scan/fingerprint.cpp | none | unit, ref |
| 11 | QUIC endpoint | F4 | scan/udp_validate.cpp | Q (xray Hysteria2), U (QUIC-shaped traps) | wire, ref |
| 12 | Reality with a working target | F10 | none | C: byte-identical to A | gap by design |
| 13 | Brand certificate on a foreign address | F10 | scan/sni.cpp, scan/brand.cpp | D | ref (cert-brand note) |
| 14 | Shadowsocks AEAD / 2022 | F9 | scan/fingerprint.cpp | E | gap: silent by design |
| 15 | Junk-probe handling | none (GFW technique) | scan/j3.cpp | A, I, J | wire, ref |
| 16 | JA4S family | none | scan/ja4s_db.cpp | sh_order.py on 6 public hosts | wire, ref |
| 17 | GeoIP VPN/proxy/Tor tags | not F1 | geoip/geoip.cpp | 6 hosting addresses, 0 tags | ref |
| 18 | RTT vs GeoIP band | none from server side | scan/snitch.cpp | A (no country: no claim) | ref |
| 19 | Address block lists | F1 | none | none | gap |
| 20 | SNI allow/block policy | F3, F8, F10 | scan/dpi_probe.cpp, scan/sni_mismatch.cpp, `dpi` and `dpi --sni --real` | test_dpi_socket.py, test_volume.cpp; SM, SP, SB, SD, SR | client side only |
| 21 | Volume freeze after 16-20 KB | F7 | scan/volume_probe.cpp, `dpi --volume` | VZ, VV, VY, VT, VA, VC, VN; test_volume.cpp | client side; lab emulates the node side only, no real freeze measured yet |
| 22 | Local tunnel on the target route | preflight | app/preflight.cpp | H2 on this machine | wire |
| 23 | Local ack-all stack | preflight | app/preflight.cpp | H2 on this machine | wire |
| 24 | Ack-all path near the target | preflight | app/orchestrator.cpp control ports | test_verdict_engine; I shows flat-RTT only | unit |
| 25 | Path loss before silence-based output | none | app/verdict.cpp assess_channel | test_verdict_engine; J stalls | unit |
| 26 | Hostname markers | none | scan/hostname_marks.cpp | test_hostname_marks.cpp | unit, ref |
| 27 | Control API on a public address (config) | F11 | app/config_audit.cpp `api-public` | tests/fixtures/audit (xray api tag and listen, sing-box Clash API) | offline |
| 28 | Listeners that cannot start: one port and layer twice, duplicate tag or email, empty TLS version range (config) | none | app/config_audit.cpp | tests/fixtures/audit | offline, compatibility |
| 29 | Settings the core ignores, REALITY under disabled sing-box TLS (config) | F6 for the plaintext case | app/config_audit.cpp `settings-ignored`, `plaintext-proto` | tests/fixtures/audit | offline; hygiene except the plaintext case |
| 30 | Names under the owner's domain in public CT logs, and which share an address | none (what any observer can list) | scan/ct_names.cpp, `names --ct` | test_ct_names.cpp, tests/fixtures/ct | ref; network only to crt.sh, or none with `--ct-file` |
| 31 | Client config: plaintext, missing browser fingerprint, missing SNI, disabled certificate checks, malformed REALITY key or shortId | F3 (the ClientHello the box reads) | app/config_audit.cpp `client-*` | tests/fixtures/audit `client-*` | offline |
| 32 | Server and client configs that cannot connect: port, protocol, transport, security, path, user, flow, REALITY serverName, shortId, key pair | none (breakage, not observability) | app/config_audit.cpp `pair-*`, `audit-config <server> <client>` | tests/fixtures/audit `pair-*` | offline, compatibility |

Rows 27 to 29 come from the offline audit: the input is a file, nothing
goes on the wire, and a false positive can only come from a logic error.
Each rule has a fixture where it fires and a look-alike where it must not,
checked by `tests/test_audit_fixtures.py` in CI. They do not close rows 12,
14, 19 or 21: a config says what the server would answer, not what the
operator's box does with client traffic.

What the gaps mean for a user: a CLEAN report from an active scan covers
rows 6, 8 and 9 and nothing else that the box acts on; row 7 only when the
owner passes the WireGuard keys. Rows 12, 14 and 19 are exactly where real
nodes get blocked and stay out of reach by design; the report names them on
every run. Row 21 is measurable only from the owner's own client
(`dpi --volume`), for that client's path at that moment.

Not covered, with the reason:

- 12 Reality with a working target: stand C serves stand A's certificate
  byte for byte; any server-side rule that flags C flags A.
- 14 Shadowsocks AEAD/2022: silent to every unauthenticated probe; a flag
  would rest on silence. `audit-config` checks the owner's cipher and port
  offline; the wire stays uncovered.
- 19 Address block lists: the lists live in the operator; GeoIP tags are a
  different list (SIGNALS.md#geoip-tags).
