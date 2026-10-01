# Xray protocol and server-config audit

```powershell
byebyevpn audit-config server.json
byebyevpn audit-config server.json --json
```

The command reads a local file, up to 16 MiB. It identifies configured inbound
protocols and flows, checks selected compatibility and exposure problems, and
does not connect to a server. Credentials are not included in its report.

The `protocols` array currently covers Xray inbounds: VLESS, VMess, Trojan,
Shadowsocks, WireGuard, Hysteria, SOCKS, mixed, HTTP, tunnel/dokodemo-door and TUN.
Existing sing-box and WireGuard/AmneziaWG config checks remain available.
This is a settings audit, not full schema validation: it does not check key
material, certificates on disk, routing, firewall rules or whether a listener
is actually running. Use the installed core's `xray run -test -config server.json`
and an authenticated connection to validate deployment.

## Source snapshot

Research date: 2026-09-14. The official repository was cloned to
`../xray-core-source`, at
[`c412e77a9b712082ac9ebf27fa793951cb5a7d85`](https://github.com/XTLS/Xray-core/tree/c412e77a9b712082ac9ebf27fa793951cb5a7d85),
dated 2026-09-12. This is the examined source revision, not a claim about the
version installed on any server. These compatibility rules target that snapshot;
other cores and older releases can accept different settings.

| Area | Source | Audit behavior |
| --- | --- | --- |
| Protocol registry | [infra/conf/xray.go](https://github.com/XTLS/Xray-core/blob/c412e77a9b712082ac9ebf27fa793951cb5a7d85/infra/conf/xray.go) | Keeps Xray and sing-box protocol names separate; recognizes local proxy inbounds. |
| Transport/security | [infra/conf/transport_internet.go](https://github.com/XTLS/Xray-core/blob/c412e77a9b712082ac9ebf27fa793951cb5a7d85/infra/conf/transport_internet.go) | `method` overrides `network`; TCP/RAW, WS/WebSocket, KCP/mKCP and SplitHTTP/XHTTP aliases are normalized. Legacy HTTP/H2/H3, QUIC and `security=xtls` are errors. WS, gRPC and HTTPUpgrade remain supported with deprecation warnings. |
| VLESS users | [infra/conf/vless.go](https://github.com/XTLS/Xray-core/blob/c412e77a9b712082ac9ebf27fa793951cb5a7d85/infra/conf/vless.go) | A non-null `clients` list overrides `users`, including an empty list. An empty user flow inherits `settings.flow`. Inbound flows must be empty or exactly `xtls-rprx-vision`. |
| Vision connection | [proxy/vless/inbound/inbound.go](https://github.com/XTLS/Xray-core/blob/c412e77a9b712082ac9ebf27fa793951cb5a7d85/proxy/vless/inbound/inbound.go) | Checks RAW/TCP + TLS/REALITY, and TLS 1.3 for Vision without VLESS Encryption. Reports mixed Vision/plain users. |
| VMess | [infra/conf/vmess.go](https://github.com/XTLS/Xray-core/blob/c412e77a9b712082ac9ebf27fa793951cb5a7d85/infra/conf/vmess.go) | Reports legacy `alterId` that the current core no longer reads. Missing outer TLS does not mean that VMess itself is plaintext. |
| Shadowsocks | [infra/conf/shadowsocks.go](https://github.com/XTLS/Xray-core/blob/c412e77a9b712082ac9ebf27fa793951cb5a7d85/infra/conf/shadowsocks.go) | Distinguishes AEAD and 2022; flags unsupported stream ciphers and checks effective per-user methods. The default port alone has no detection score. |
| REALITY | [infra/conf/transport_security.go](https://github.com/XTLS/Xray-core/blob/c412e77a9b712082ac9ebf27fa793951cb5a7d85/infra/conf/transport_security.go) | Honors `target` precedence; checks supported transports and short-ID syntax. A missing/empty list differs from a list containing `""`. |
| Local proxies | [infra/conf/socks.go](https://github.com/XTLS/Xray-core/blob/c412e77a9b712082ac9ebf27fa793951cb5a7d85/infra/conf/socks.go), [infra/conf/http.go](https://github.com/XTLS/Xray-core/blob/c412e77a9b712082ac9ebf27fa793951cb5a7d85/infra/conf/http.go) | Warns about disabled authentication outside loopback/Unix listeners. This is potential exposure; routing and firewall access are unverified. |

VLESS Encryption settings are recognized by their scheme prefix and explicitly
marked `vless-encryption-unverified`. Key and padding syntax still require the
core's own validator. The auditor does not call arbitrary nonempty `decryption`
values encrypted. It flags VLESS Encryption combined with a non-null fallback
list, which the examined core rejects.

## What a remote probe can establish

[VLESS request decoding](https://github.com/XTLS/Xray-core/blob/c412e77a9b712082ac9ebf27fa793951cb5a7d85/proxy/vless/encoding/encoding.go)
validates the user ID before accepting request add-ons. Vision then checks the
configured flow. Its padding implementation is in
[proxy/proxy.go](https://github.com/XTLS/Xray-core/blob/c412e77a9b712082ac9ebf27fa793951cb5a7d85/proxy/proxy.go):
it adds per-block lengths, padding and control commands, with a transition to
direct copying in eligible connections. Those fields are carried inside the
protected connection, not exposed as a fixed public banner.

Consequently, this scanner has **no confirmed unauthenticated TCP Vision
detector**. Entropy, packet lengths, TLS fingerprints, open ports and a working
WebSocket/gRPC endpoint do not by themselves identify the inner proxy protocol.
That conclusion follows from the authentication and transport layering above;
it is not a claim that traffic analysis is impossible.

The active TLS comparison now reports observations without a VPN score penalty.
The raw Chrome probe receives only ServerHello; it does not complete TLS or
verify a peer certificate. OpenSSL attempts the full handshake. JSON includes
both stages and `protocol_confirmed: false`; differing responses are diagnostic.

The [REALITY documentation](https://xtls.github.io/en/config/transports/reality.html)
describes forwarding unauthenticated traffic to `target`. Therefore, a missing
VLESS `settings.fallbacks` does not establish that a REALITY endpoint is silent
to unauthenticated probes. That old warning was removed for REALITY. An empty
short ID does not disable REALITY's cryptographic authentication either.

## Results and exit codes

Every JSON audit includes `evidence_source: "configuration"`,
`network_confirmed: false` and `runtime_validated: false`. Compatibility findings
have their own category and do not add to DPI scores. Their error count is
`compatibility_errors`.

| Exit | Meaning |
| --- | --- |
| 0-3 | Existing exposure heuristic tiers, preserved for scripts; not measured filtering behavior. |
| 64 | Unreadable, oversized, malformed or unsupported input. |
| 65 | One or more compatibility errors; the network verdict is `UNKNOWN`. |

The legacy `tspu_tier` strings remain for compatibility. A `PASS / ALLOW` result
means no scored exposure warning was found in the covered settings; it is not a
guarantee of invisibility, security or successful deployment. Single inbound
ports are supported; port-range configs need to be expanded before this audit.

## Checks added 2026-10-01

| Tag | Category | Basis | Fires on | Must not fire on |
| --- | --- | --- | --- | --- |
| `duplicate-listener` | compatibility | the second bind fails with address in use | one port, one socket layer, equal or wildcard listen addresses (Xray and sing-box) | TCP and UDP on one number (VLESS plus Hysteria2 on 443); two distinct explicit addresses |
| `duplicate-tag` | compatibility | Xray inbound manager: "existing tag found" | two Xray inbounds with one nonempty tag | several untagged inbounds |
| `duplicate-email` | compatibility | Xray user validators lowercase the email and refuse a repeat per inbound | `Alice@x` and `alice@x` in one inbound | one email in two inbounds |
| `tls-version-range` | compatibility | Go TLS: no version between min and max, every handshake fails | min 1.3, max 1.2 (Xray `tlsSettings`, sing-box `tls`) | min 1.2, max 1.3 |
| `api-public` | exposure, High | an open control port answers anyone and shows in a scan (F11) | Xray `api.listen` or the API-tagged inbound off loopback; sing-box Clash or V2Ray API off loopback, `:9090` included | the same on 127.0.0.1 |
| `reality-shortid-invalid`, `reality-target-missing` (sing-box) | compatibility | parity with the Xray checks of the same name | `short_id` not even-length hex up to 16; no `handshake.server` | `["0123abcd", ""]` |
| `settings-ignored` | hygiene | the core builds and then ignores settings for another transport or security | `wsSettings` on RAW, `tlsSettings` with `security: none`, sing-box `reality.enabled` with `tls.enabled` off | `tcpSettings` on RAW, `splithttpSettings` on XHTTP (current aliases) |
| `duplicate-user` | hygiene | one id or password twice in an inbound: one entry wins | two clients with one id | one id in two inbounds |
| `debug-log` | hygiene | debug logs on the node keep client addresses | Xray `loglevel: debug`, sing-box `level: debug` or `trace` | `warning` |

`reality-show` moved to hygiene. Hygiene findings print in their own block
and never reach `tspu_tier`.

Fixed: sing-box REALITY with `tls.enabled` false was audited as REALITY.
sing-box only reads the REALITY block inside enabled TLS, so the listener
runs without TLS. The brand rule fired on a handshake server that is never
used, and `plaintext-proto` was missed. Now it is plaintext plus a hygiene
note.

Each row has a fixture where it fires and one where it must not in
`tests/fixtures/audit/`, with expectations in `expect.txt`. Against the
build from before this change all look-alikes passed and every new
positive failed, as expected; the one old false positive was the sing-box
case above.

## Client configs and server/client pairs

A config with proxy outbounds (Xray `outbounds[].protocol`, sing-box
`outbounds[].type`: vless, vmess, trojan, shadowsocks, hysteria2, tuic)
gets client checks, with or without inbounds:

| Tag | Category | Fires on | Must not fire on |
| --- | --- | --- | --- |
| `client-plaintext` | exposure, High | VLESS or Trojan without TLS or REALITY to a remote address | VMess without outer TLS (own crypto); a loopback address |
| `client-fingerprint` | exposure, Medium | TLS or REALITY without `fingerprint` (Xray) or `tls.utls` (sing-box): the Go ClientHello, or a refused REALITY, depending on the core | `fingerprint: chrome`; sing-box `utls.enabled` without a name (chrome) |
| `client-sni-missing` | exposure, Medium | TLS or REALITY without a server name | a set serverName |
| `client-insecure` | hygiene, High | `allowInsecure` / `insecure`: anyone on the path can pose as the server | certificate checks on |
| `client-reality-key`, `client-shortid` | compatibility | publicKey not a 32-byte base64url key; shortId not even-length hex up to 16 | a real key, `0123abcd` |

`audit-config <server> <client>` normalises both sides (Xray or sing-box,
in any combination) and matches each client outbound to the server
inbound on its port. Every mismatch is a compatibility error (exit 65):
`pair-no-inbound`, `pair-protocol`, `pair-transport`, `pair-security`,
`pair-path` (ws, httpupgrade, xhttp path or gRPC serviceName), `pair-user`,
`pair-flow`, `pair-reality-sni`, `pair-reality-shortid`, and
`pair-reality-key`, which derives the X25519 public key from the server's
privateKey and compares it with the client's publicKey. No id, password
or key is printed or written to JSON, only whether it matches. Fixtures:
`tests/fixtures/audit/pair-*` with `client-*`, keys from the RFC 7748
vectors.

## Verification

```powershell
make test
python tests/test_xray_cli.py ./byebyevpn.exe
python tests/test_awg_cli.py ./byebyevpn.exe
python tests/test_audit_fixtures.py ./byebyevpn.exe
```

The unit tests cover aliases and precedence, mixed/default/invalid flows,
removed versus still-supported transports, legacy VMess/SS settings, REALITY
short IDs, loopback handling, malformed types, credential omission and partial
TLS handshakes. CLI checks exercise JSON/text reports and exit codes against the
built executable. These use synthetic local inputs. No remote server audit or
accuracy measurement on labeled Xray traffic is implied.
