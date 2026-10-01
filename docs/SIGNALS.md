# Signal passports

One entry per signal that can change the score or the tier, plus the
reference outputs people most often read as findings. The registry in
`src/app/signals.cpp` must match this file: an id without a passport never
reaches `evaluate_report()`. Model references (F1..F13) point to
[TSPU-MODEL.md](TSPU-MODEL.md); test cases point to
[GROUNDTRUTH.md](GROUNDTRUTH.md).

Shared rules for every scored signal:

- the check has four results: positive, negative, inconclusive, not
  applicable. inconclusive never turns into negative and never moves the
  score;
- a positive needs two agreeing observations out of at most three, and no
  contradicting one (`combine_observations`, `src/common/outcome.cpp`);
- a positive must rest on bytes the target sent, never on silence;
- preflight must pass, the path check must not be unusable, and the target
  path must not accept random control ports.

## Scored

### wg-family

| field | value |
|---|---|
| claim | a WireGuard-family responder answered our handshake initiation |
| evidence | UDP reply of exactly 92 B `02 00 00 00` (MessageResponse) or 64 B `03 00 00 00` (cookie reply), optionally behind an S2 junk prefix up to 128 B for AmneziaWG, with the receiver index equal to the sender index we sent |
| false-positive modes | (1) any service returning 92 B that start with `02000000`; closed by the receiver-index check, lab stand K. (2) UDP echo or reflector; closed by the echo check. (3) a deliberate impostor that copies our index; not closable without the server key. (4) a single stray datagram; closed by the repeat rule |
| control | a reply at all proves the path carried our datagram; silence and ICMP give "not applicable", never negative |
| repeats | up to 3 per probe kind, stop at 2 agreeing; silence stops the series after one probe |
| inconclusive when | one matching reply only; matching and non-matching replies on the same port |
| tier and weight | A, 15. A fixed-layout header is exactly what F5 matches on the box. 15 keeps one hit at 69 through the A cap, same as before |
| model | F5 |
| test | stands W and G (synthetic, positive), K (trap, negative), F (real xray WireGuard, not applicable) |
| limits | real WireGuard and AmneziaWG never answer an initiation without a valid mac1 and a known peer key. **On real servers this signal cannot fire**; it only catches layouts that answer unauthenticated packets (synthetic stands W and G). For the owner's own WireGuard node use [wg-keyed](#wg-keyed) |

Former ids `wireguard` and `amnezia` were one piece of evidence counted
twice on the same port; they are merged here and score once per scan.

### wg-keyed

| field | value |
|---|---|
| claim | the node completes a WireGuard handshake initiated with the owner's peer key |
| evidence | a 92 B MessageResponse to our sender index whose mac1 verifies. That mac1 is keyed by our static public key, which travels encrypted to the server key, so only the holder of the server private key can produce it. When the empty AEAD under the derived key also opens, the handshake is complete; when it does not, the server key is still proven and the preshared key differs, reported as such |
| how it is sent | a full initiation (whitepaper 5.4.2): RAND_bytes ephemeral and sender index, TAI64N with the low 24 bits of nanoseconds cleared like wireguard-go and the Linux module, mac2 zero. Byte-identical in form to a real client's first message |
| false-positive modes | (1) a responder that copies our index without the key: mac1 fails, negative (stand WK). (2) unrelated type-2 bytes: index mismatch, negative (stand KK). (3) an echo or reflector: negative. (4) one stray datagram: two agreeing answers required. (5) the scanning machine itself tunnelled to the node: preflight. (6) wrong keys typed by the owner: silence, inconclusive, never a verdict either way (stand FW) |
| control | the reply authenticates itself; silence and ICMP give inconclusive, never negative |
| repeats | up to 3, 1.0 to 1.5 s apart, stop at 2 agreeing. Back to back the second one is lost: wireguard-go drops an initiation within 20 ms of the previous one and the timestamp moves in 2^24 ns steps (first lab run, 1 of 3 unanswered) |
| inconclusive when | no reply; a cookie reply (responder under load); one matching reply only; disagreement |
| tier and weight | A, 15, in group `wg` with wg-family: both say "a WireGuard responder listens on that port" and score once. A proven endpoint means every client handshake to it carries the fixed type 1/2 layout that F5 matches |
| model | F5 |
| test | FK (xray wireguard-go, positive), FS (preshared key the server lacks, positive with that note), FW (peer key the server does not know, inconclusive), WK (synthetic responder copying our index, negative), KK (unrelated type 2, negative); unit vectors RFC 7693, RFC 7748 and the Noise initial chaining key and hash |
| limits | needs keys only the owner has, so it adds no ability against other people's nodes. Measures this path at this moment. The node moves that peer's endpoint to the scanning machine until its own client sends again: use a spare peer. Says nothing about AmneziaWG with junk or custom headers, which drops a plain initiation (inconclusive, not "hidden"). Keys are read from files at use time, wiped after, never printed and never in JSON; JSON carries `wg_self_check.requested`, `ran` and `port` only |

### socks5

| field | value |
|---|---|
| claim | the port negotiates SOCKS5 methods |
| evidence | a 2-byte reply `05 00`, `05 02` or `05 FF` to the greeting `05 02 00 02` (RFC 1928 section 3) |
| false-positive modes | (1) a service that answers any input with `05 xx`; improbable, closed by repeats. (2) middlebox injection; closed by repeats and the ack-all control. (3) a local proxy on the scanning machine answering for every address; closed by preflight |
| control | the reply itself; non-SOCKS bytes give negative, silence or FIN or RST give inconclusive |
| repeats | up to 3 greetings, stop at 2 agreeing |
| inconclusive when | no bytes; disagreement |
| tier and weight | A, 20. SOCKS5 answers unauthenticated clients by design, F6 and F11 both apply |
| model | F6, F11 |
| test | stand S (xray SOCKS5, positive), I (ack-all, inconclusive) |

### sstp

| field | value |
|---|---|
| claim | the TLS service on 443 accepts an SSTP setup request |
| evidence | HTTP/1.1 200 with `Content-Length: 18446744073709551615` and no Transfer-Encoding in reply to `SSTP_DUPLEX_POST /sra_{BA195980-...}/` (MS-SSTP 3.2.4.1) |
| false-positive modes | (1) a catch-all backend echoing the request length; not seen, closed by repeats. (2) our own malformed request drawing an odd answer: the request used an IP literal as SNI and an all-zero correlation id, neither of which a real client sends; now the SNI is the host name or absent and the GUID is random. (3) a TLS-terminating proxy in front of a real RRAS; true positive for the purpose |
| control | a valid HTTP answer that is not the SSTP one gives negative; a TLS failure or no HTTP gives inconclusive |
| repeats | up to 3, stop at 2 agreeing |
| tier and weight | A, 18. Plaintext method name inside TLS; F6 only if the box terminates TLS, F11 for an active prober |
| model | F6, F11 |
| test | stand X (synthetic, positive), A (nginx-like 405, negative) |

## Client side (own exit code, never in the server verdict)

These describe the path from the machine running the tool to one host at
one moment. They never enter `evaluate_report()` and never move the scan
score; every result prints and serialises the scope sentence.

### volume-freeze

| field | value |
|---|---|
| claim | on this path, a TLS download from the node stops delivering bytes on an open connection before 64 KB, while a control host carries 64 KB or more |
| evidence | per transfer: an HTTP status line from the node, then no byte for 8 s with the connection still open. The offset is counted in socket bytes, TLS handshake included, as the field reports count it |
| how it is sent | TLS with the shared client context, `GET <path>` with the same header set as the HTTPS probe (Host, Accept, Connection: close). Nothing new for the node to see, nothing visible to the path inside TLS |
| false-positive modes | (1) a bad link: the control runs before and after and must carry 64 KB both times (lab VC). (2) random loss: two stalls must agree within 4 KB or 25% (unit). (3) a server that pauses: 8 s stall timeout, lab VY pauses 3 s at 16 KB and passes. (4) a server that closes early: FIN or RST is not a freeze (lab VT). (5) a resource smaller than the window: not applicable (lab VA). (6) no control: inconclusive (lab VN). (7) server think time before any answer: needs a status line first |
| control | a second host given with `--control`, measured with the same reader; no control, no claim |
| repeats | targets until two agree, at most three, 0.5 s apart |
| inconclusive when | control failed or stalled; stalls at different offsets; stall and pass mixed; one stall only; closed or reset; handshake failed; a drip over 45 s |
| outcome and exit | positive 2, negative 0, inconclusive or not applicable 4. The text says whether the offset falls inside the 16-20 KB band the field reports describe; it does not change the outcome |
| model | F7 |
| test | VZ (emulated freeze after 14000 B of body, positive), VV and VY (negative), VT, VC, VN (inconclusive), VA (not applicable); test_volume.cpp |
| limits | a loopback stand can emulate the node's side of a freeze, not the operator. No real F7 freeze has been measured with this code yet. The result holds for this client, this operator, this moment; a pass today says nothing about another subscriber or tomorrow |

### sni-address (`dpi --sni NAME --real IP|auto`)

| field | value |
|---|---|
| claim | on this path the node's name fails to the node and passes to the address it really lives on: a rule ties the name to its address (F10) |
| evidence | per round three ClientHellos with the same builder as `dpi`: the name to the node, a benign name to the node, the name to the real address. Positive round: node + name reset or silent, node + benign replies, real + name replies |
| false-positive modes | (1) the node is down or filtered: node + benign must reply (lab SD). (2) the real address unreachable: real + name must reply (lab SR). (3) the name blocked everywhere on the path: reported as blocked, not as the address rule (lab SB). (4) one flaky round: two agreeing rounds out of at most three. (5) a node that ignores the name itself (Reality with another serverName): looks the same as the rule; run it with the serverName the node really serves |
| control | node + benign and real + name in every round |
| repeats | until two rounds agree, at most three, 0.7 s apart |
| inconclusive when | rounds disagree, a control fails, or the name fails to both addresses (then `name_blocked` is set and the exit code is 2) |
| outcome and exit | positive 2, negative 0, inconclusive 4; name blocked everywhere 2 with that reason |
| model | F10, F3 |
| test | SM (positive), SP (negative), SB (blocked everywhere), SD and SR (inconclusive); test_volume.cpp |
| limits | the lab emulates a box that drops one name; a real F10 rule has not been measured with this code yet. One path, one moment |

### sni-path (`dpi`, existing)

Now reports the shared outcomes: positive for an SNI-specific reset or
silent drop next to a working benign SNI, negative for a TLS reply to the
target SNI, inconclusive otherwise, not applicable through a fake-IP
tunnel. Exit codes unchanged; `--json` added; the scope sentence is printed.

### inner-handshake (`pcap <file> --node IP`)

| field | value |
|---|---|
| claim | in the owner's own capture, flows to one server carry the sizes of a TLS handshake inside the outer TLS: the tunnel forwards the inner handshake record for record (F12) |
| evidence | per TCP flow after the outer handshake, in plaintext bytes (record length minus the outer AEAD overhead: 17 for TLS 1.3, 24 for TLS 1.2 GCM, 16 for ChaCha20): the first client flight 280 B or more (an inner ClientHello plus a proxy header), the server's answer 600 B or more (an inner server flight with a certificate), then a client record of exactly 58, 64, 74 or 80 B: an inner TLS 1.3 Finished, alone or after a ChangeCipherSpec, SHA-256 or SHA-384 |
| how it is measured | offline on a pcap or pcapng file: TCP rebuilt per direction (first 64 KB), TLS records walked from the stream start, flights ordered by capture time. Nothing is sent |
| false-positive modes | (1) plain HTTPS with keep-alive puts the next request where the Finished would be; lab PH sends browser-sized requests (first flight 492 B, answer 12.5 KB) and stays negative because the next request is 492 B. (2) an HTTP client whose next message is exactly 58, 64, 74 or 80 B after a large request and a large answer: not closable by sizes; two matching flows to the same server are required, which a client repeating one request byte for byte would also produce. (3) tickets and server-first bytes: server records before the first client data are skipped. (4) TLS 1.3 client certificates: the outer Finished is not where expected, the flow is not checked. (5) TLS 1.2 CBC suites: overhead unknown, not checked |
| control | flows without the pattern print their sizes; a negative needs two checked flows |
| repeats | per server: positive at two matching flows, negative at two checked flows and none matching, one match is inconclusive. Each flow is an observation; a flow without the pattern does not contradict one with it, they carry different content |
| inconclusive when | fewer than two checked flows; one match only |
| outcome and exit | `pcap` exits 2 when inner-handshake, dns-clear or outside-node is positive, 0 otherwise, 64 on a file it cannot read |
| model | F12 |
| test | PV (VLESS over TLS, 4 of 4), PT (Trojan over TLS, 4 of 4) positive; PX (VLESS with Vision, 0 of 4) and PH (plain HTTPS, 0 of 4) negative; real xray 26.7.28 through a recording relay; test_pcap.cpp |
| limits | sizes only, no timing model. A client that sends its first request in the same burst as its Finished hides the pattern from this rule, not from a box that models timing. Inner TLS 1.2 and resumed inner sessions without a certificate flight are not modelled. Vision pads exactly the records this rule reads; a box with a better model may still separate it |

### dns-clear (`pcap`)

| field | value |
|---|---|
| claim | the capture holds DNS queries in the clear |
| evidence | a message to port 53, UDP or TCP, with QR 0, opcode 0, one to four questions and a name that parses |
| false-positive modes | (1) a capture taken inside the tunnel shows the tunnel's own resolver (fake-ip 198.18.0.0/15 is flagged in the text); capture on the physical interface. (2) mDNS and LLMNR are not port 53 and are ignored. (3) queries to the router for LAN names: still in the clear on that link, marked lan |
| repeats | positive at two queries, one is inconclusive, none among 20 or more packets is negative |
| model | F13; F3 for the names a DoH ClientHello carries |
| test | test_pcap.cpp, test_offline_cli.py; row pcap-dns-clear (negative on all four tunnel captures) |
| limits | DoH, DoT and DoQ hide the names, not the resolver: DoT shows as a peer on 853, DoH to well-known resolver names is marked from the SNI |

### outside-node (`pcap --node IP`)

| field | value |
|---|---|
| claim | the capture holds public traffic to addresses other than the node |
| evidence | two or more packets, TCP or UDP, IPv4 or IPv6, to addresses that are not the node and not private, loopback, link-local or multicast |
| false-positive modes | (1) split tunnelling set up on purpose: true but intended; the list shows where it goes. (2) the tunnel client's own bootstrap traffic (resolving the node name, time sync): real traffic beside the node. (3) a capture taken inside the tunnel: the node never appears, the result is inconclusive, not positive |
| control | the node must appear in the capture |
| repeats | positive at two packets, one is inconclusive, none with the node present is negative |
| model | F1 and F3 apply to every flow beside the tunnel as to any other |
| test | test_pcap.cpp, test_offline_cli.py; row pcap-outside-node (negative on all four tunnel captures) |
| limits | CGNAT 100.64.0.0/10 counts as public |

### ipv6-leak (`local`)

| field | value |
|---|---|
| claim | with a tunnel adapter up, connections to public IPv6 addresses leave through another adapter |
| evidence | a global (2000::/3) address on a non-tunnel adapter, then a TCP connect to `[2606:4700:4700::1111]:443` and `[2001:4860:4860::8888]:443` whose local address belongs to that adapter |
| how it is sent | a plain connect the system makes for any app, closed at once, no payload. No packet at all when there is no global IPv6 beside the tunnel |
| false-positive modes | (1) a kill switch blocking IPv6 beside the tunnel: the connect fails or times out, never positive. (2) the tunnel carries IPv6 itself: the local address is the tunnel's, negative. (3) IPv6 left direct on purpose: true but intended. (4) a tunnel adapter with a name the tool does not know looks like an outside one; the adapter list shows the [VPN] tags |
| repeats | two targets, two agreeing results (`combine_observations`) |
| inconclusive when | a connect times out; the targets disagree |
| outcome and exit | `local` exits 2 when ipv6-leak or dns-leak is positive, 0 otherwise |
| model | F1 and F3 on the flows beside the tunnel |
| test | test_leaks.cpp; one machine with a TUN client and no global IPv6 beside it: negative without packets |
| limits | Windows only. The system's choice for two addresses at this moment; an app that binds to an interface itself can differ |

### dns-leak (`local`)

| field | value |
|---|---|
| claim | with a tunnel adapter up, the system resolver would ask a resolver beside the tunnel, and that resolver answers there |
| evidence | resolvers from the adapter settings; Windows asks every adapter's resolvers in parallel unless the DisableSmartNameResolution policy is 1, otherwise the lowest metric first. Resolvers routed into the tunnel are skipped. Up to three are asked twice for `example.com` A with a random id; an answer with the same id and QR set counts |
| false-positive modes | (1) a kill switch dropping port 53 beside the tunnel: silence (inconclusive) or a refused send (negative), never positive. (2) Windows DoH set for that resolver: the system's own queries are encrypted while ours gets an answer; check with `pcap`. (3) a tunnel client that answers port 53 on every interface: the answer is the client's, not the resolver's; check with `pcap` on the physical interface |
| control | the system setting says whether the resolver would be used; the answer says the path is open |
| repeats | two queries per resolver, positive at two answers |
| inconclusive when | silence; one answer |
| model | F13 |
| test | test_leaks.cpp; one machine with a TUN client: the LAN resolver stays silent, inconclusive |
| limits | Windows only. Two benign queries per resolver leave beside the tunnel by design, that is the measurement. Apps with their own resolver (browser DoH) are not seen |

## Reference only (never scored)

### geoip-tags

Author heuristic. Was geo-vpn -18, geo-proxy -12, geo-tor -25; now a note.
Reasons, in order of weight:

1. the box acts on its own address lists (F1); commercial VPN tags are a
   different list with unknown overlap;
2. the five providers are not independent evidence: several resell or
   merge the same upstream feeds, so "two providers agree" was one
   observation counted twice (rule 6);
3. tags describe the address history, including previous tenants of a
   reused VPS address.

Measured 2026-09-30 with `byebyevpn geoip` on six clean sites hosted at
AWS, Fastly, Hetzner, OVH and Akamai: 0 VPN or proxy tags from any
provider, one HOSTING flag (iplocate.io). The claim that ipapi.is tags any
hosting address as VPN did not reproduce. Not measured: VPS ranges that VPN
operators favour, which is where these tags would actually bite.

### junk-probes

Author heuristic borrowed from GFW active probing, no TSPU rule behind it.
Each probe now ends in one of: reply, closed by peer, reset, no reply held
open, no connect. Before, all four non-replies printed as "SILENT (dropped)"
and six of them produced "silent-on-junk (TLS-only / Reality-hidden)" on a
plain nginx-like origin (lab stand A). Control: a well-formed TLS or HTTP
exchange on the same port; without it the counts are declared meaningless.
On a lossy path (path check loss >= 20%) silence is declared not evidence.

### tcp-stack

Handshake timing, peer window and MSS, closed-port reply. The closed-port
probe used to read "drop" on every closed port because Windows retries SYN
after RST for ~2 s and `--tcp-to 800` gave up first (tcp.cpp now sets
`SIO_TCP_INITIAL_RTO` with no SYN retransmission; 2030 ms became 1 ms).
The OS guess was removed: 0 of 9 Windows stands were named Windows.

### ja4s-family

Seed table re-observed in wire order on 2026-09-30 (`sh_order.py`). The
old seeds were sorted hashes; the TLS 1.2 one could never match. Cloudflare
sends key_share before supported_versions, so the "universal" TLS 1.3 hash
is two hashes. Names no stack; the box is not known to act on server hellos.

### cert-brand

A certificate naming a large brand on an address outside that brand is the
Reality-with-brand-target pattern (F10, lab stand D). Whether the box acts
on it is open question 1 in the model; until then it is a note. The ASN
side needs GeoIP, which is itself reference output.

### quic-endpoint

A reply to the protected QUIC v1 Initial (or the reserved-version probe)
that passes `quic_response_valid()`: a complete long header whose DCID is
the SCID we chose, version 1 or version negotiation with whole 32-bit
entries. Proves a QUIC stack, not a tunnel: HTTP/3 sites answer the same
way (F4 acts on the client's Initial, not on the server's reply). Lab: Q
(xray Hysteria2) positive, U negative. Stand U found that the printed line
under the hex dump called any QUIC-shaped datagram "QUIC Initial packet"
even when the ids were someone else's, and that the version-negotiation
probe went to the first port that sent any bytes; both now require the
same validation as the note.

### client-hello (`pcap`)

What the owner's client sends before any key: SNI, JA4 (`t` over TCP, `q`
from a decrypted QUIC Initial), GREASE, the encrypted_client_hello
extension, a post-quantum hybrid group (X25519MLKEM768 and relatives) and
ALPN. Facts, not a verdict. No GREASE means not Chromium or Safari (Firefox,
Go, OpenSSL send none). `ech-ext yes` can be GREASE ECH: Chromium sends the
extension with the real name in the clear when it has no ECH config, so the
box still reads the SNI. On the lab captures the xray client shows uTLS
Chrome (`t13d1516h2_8daaf6152771_d8a2da3f94cd`, GREASE, ECH extension,
X25519MLKEM768) and the plain Python client OpenSSL 3.5
(`t13d1712h1_ab0a1bf427ad_8e6e362c5eac`, no GREASE). Model F3, F4.

### ct-names (`names <domain> --ct`)

Every host name under a domain that certificate transparency logs publish,
from crt.sh or a saved crt.sh JSON (`--ct-file`), run through the hostname
markers. Facts, not guesses: the names are public and anyone can list them.
The markers stay heuristics with no score. `--resolve` (DNS from this
machine, at most 64 names) shows which names share an address and marks
the node given with `--node`; behind a CDN that grouping means nothing and
the output says so. Mail addresses from S/MIME certificates, IP literals
and names under other domains are dropped. A failed lookup exits 4 and is
never read as "no names". Tests: test_ct_names.cpp and the `--ct-file`
cases in test_names_cli.py, including look-alikes (`subway.`,
`notexample.com`, `example.com.evil.net`).

### snitch RTT

Observations only. Every former conclusion ("GeoIP lies", "tunnel queue
overhead", "extra hops") is now a stated observation with "cause
unverified". Without a country there is no band comparison.

## Removed from any verdict path

- port hints naming Reality, XTLS or "possible VPN" on 443, 4433, 4443,
  8443, 6443 and 10800-10820
- "open but silent on connect (... Shadowsocks / Trojan / Reality wrapper)"
- "accepts random bytes but never replies (... Reality hidden-mode ...)"
- "This does not confirm Xray, REALITY or Vision" on every TLS host
