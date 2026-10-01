# TSPU classifier model

Working engineering model, written 2026-09-30 for the false-positive work.
It is the reference that every entry in [SIGNALS.md](SIGNALS.md) points to.
It is a model, not a leak: where a statement rests on field reports or on
the 2021 lecture notes ([tspu-docs](https://github.com/DanielLavrushin/tspu-docs),
net4people/bbs#578) it says so, and where it is a guess it says that too.

Confidence marks used below:

- **doc**: stated in tspu-docs (2021 lecture, secondhand compilation)
- **field**: repeated independent field reports 2024-2026
- **inferred**: follows from how inline DPI must work, not observed directly
- **guess**: plausible, unverified; nothing in this tool may rest on it

## 1. What the box is

An inline stateful DPI appliance in the operator network, centrally managed.
It sees both directions of user traffic at line rate and acts per flow:
pass, drop (silent, `send_RST off` by default, doc), inject RST, police
(throttle), or match an address list. **doc**

The decisive property for this tool: **the box classifies the traffic of
real clients passively.** It does not need to connect to a server to block
it. Active probing of servers is a separate capability (GFW has it, public
evidence for TSPU doing it at scale is thin, **guess**). A server-side scan
such as ours therefore measures what an *active prober* could learn, which
is a subset of what the classifier acts on.

## 2. Features, by layer

| # | Feature | Layer | Seen by | Confidence |
|---|---|---|---|---|
| F1 | Destination IP in a block list (by address or ASN) | L3 | passive | doc, field |
| F2 | Destination port and transport | L4 | passive | doc |
| F3 | TLS ClientHello SNI against block and allow lists | handshake | passive | doc, field |
| F4 | QUIC Initial decrypted, SNI read | handshake | passive | field (QUIC to foreign hosts throttled or dropped since 2024) |
| F5 | Fixed-layout protocol headers: OpenVPN opcodes, WireGuard type 1/2/3/4 with fixed sizes, IKE, L2TP, PPTP/GRE | first packets | passive | doc, field |
| F6 | Plaintext proxy handshakes: SOCKS5 greeting, HTTP CONNECT, SSTP_DUPLEX_POST | first packets | passive, and active if probed | inferred |
| F7 | Freeze after ~16-20 KB on TCP to hosting ASNs abroad | flow volume | passive | field (2024-2025) |
| F8 | Allow-list mode: only listed IPs/SNIs pass (regional mobile, 2025+) | policy | passive | field |
| F9 | Fully-encrypted first packet heuristics (entropy, printable ratio, length) | first packets | passive | guess for TSPU, documented for GFW |
| F10 | SNI and IP mismatch: brand SNI to an address outside the brand's ASN | handshake + L3 | passive | field reports on Reality with brand targets, mechanism unconfirmed |
| F11 | Server answers to unauthenticated probes (proxy handshakes, VPN setup) | server behaviour | active only | inferred |

## 3. How a decision is made

Per flow, rule based, first match wins: address lists, then protocol
signatures on the first packets, then SNI policy, then volume rules (F7).
**inferred** from the action set in tspu-docs; nothing indicates weighted
accumulation of weak signals.

The 0-100 score in this tool is the author's abstraction for a human
reader, not a model of the box. Consequences for the verdict engine:

- only features that map to a rule the box can apply may carry weight;
- a named protocol signature (F5, F6) is binary for the box, so in the tool
  it is tier A;
- there is no evidence of an accumulative tier on the box. The tool keeps
  tier B in code for compatibility, and no current signal uses it.

## 4. What an active server scan can and cannot see

| Feature | Visible to this scan | Why |
|---|---|---|
| F1 address lists | no | GeoIP "VPN" tags are commercial databases, not the box's lists |
| F2 port | yes, but meaningless alone | a port number proves nothing about the service |
| F3 SNI policy | only with `dpi` from the client side | a server scan does not traverse the user's operator; `dpi` reports the shared four outcomes and `--json` |
| F4 QUIC | partly | a QUIC reply proves a QUIC endpoint, not a tunnel |
| F5 WireGuard | no for strangers; yes for the owner with `--wg-pubkey` and `--wg-key` | WireGuard drops any initiation without a valid mac1, which needs the server public key. mac1 alone is not enough: the responder then decrypts the initiator's static key and drops a peer it does not know (whitepaper 5.4.2; wireguard-go `ConsumeMessageInitiation`). An answer needs a configured peer's private key too. **doc**, confirmed on lab stand FK |
| F5 OpenVPN | not probed | tls-auth/tls-crypt servers stay silent to unauthenticated packets |
| F6 SOCKS5, SSTP, CONNECT | yes | these answer an unauthenticated first message by design |
| F7 freeze | no from the server side; yes from the owner's client with `dpi --volume` | needs sustained traffic through the operator. The owner downloads a resource of 64 KB or more from the node and from a control host and records where bytes stop on an open connection. The observation is about this path at this moment (**field** for the rule; the check itself is lab-verified on an emulated freeze only) |
| F8 allow lists | no | policy on the client side |
| F9 entropy | no | passive property of client traffic |
| F10 SNI/IP mismatch | partly | the scan sees which certificate the address serves; the ASN comes from GeoIP, and whether the box uses the rule is unconfirmed |
| F11 | yes | this is exactly what the scan does |

Conclusion that drives the whole tool: **CLEAN from an active scan means
"no answering signature", never "invisible to the box".** Reality with a
working target, Shadowsocks AEAD/2022, WireGuard/AmneziaWG and Trojan behind
a real site all stay silent or look like the site they front. The lab
confirms it: stand C (Reality, target = stand A) serves the certificate of
stand A byte for byte.

## 5. Out of date by 2026

- tspu-docs describes a 2021 deployment: no allow-list mode, no QUIC
  handling, no volume freeze. Anything citing only tspu-docs describes a
  floor, not the current box.
- J3-style junk probing (malformed first flights) is a GFW active-probing
  technique. It says how a server handles garbage; nothing ties that to a
  TSPU rule. Reference output only.
- TCP stack fingerprints and OS guesses have no known TSPU rule; on the
  lab they also failed to name the one OS every stand ran on.
- JA4S families describe the TLS terminator; the box is not known to act on
  server hellos.
- RTT and GeoIP consistency ("snitch") is a detection idea from the lecture
  for the *client* side; from the server side it measures the observer's own
  routing more than the target.

## 6. Open questions

1. Does the box act on F10 (brand SNI outside the brand ASN) or only on
   list membership of the address? Field reports on Reality with
   `www.microsoft.com` targets are consistent with both.
2. Does any active scanning by the operator side exist at scale, and what
   does it probe? If yes, F6/F11 matter more than this model assumes.
3. F9 on TSPU: no direct evidence. Must not be scored until there is.
