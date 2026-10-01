# AmneziaWG traffic analysis

Implemented command:

```powershell
byebyevpn awg-entropy connection.pcap
byebyevpn awg-entropy connection.pcapng --json
```

Analyze the **outer UDP traffic of a real connection**, captured on the client
or server uplink. A capture inside the VPN/TUN sees plaintext inner traffic and
cannot provide the required observations. No network requests, private keys,
Npcap dependency or administrator rights are required for this offline command.
Use full-packet captures and include both directions and multiple connection
starts/re-handshakes. An idle UDP server scan cannot reveal the client's junk
train. Scanning with random probes does not substitute for a real capture.

## Source research (2026-09-12)

The upstream repository was cloned alongside this project as `../awg-go-source`.
These are reproducible source references, not a claim that entropy identifies a
release number:

| Protocol generation | Source revision | Relevant behavior |
| --- | --- | --- |
| 2.x | [`v0.2.19`, `1cc94272`](https://github.com/amnezia-vpn/amneziawg-go/tree/1cc94272ca8e9e223a5fe76382f5880f09d3c12d) | I-chain, random J packets, S1-S4 prefixes, header ranges |
| 3.0 | [`v3.0.0`, `457d920a`](https://github.com/amnezia-vpn/amneziawg-go/tree/457d920a1a7d103fc7354e0ca3979e493a681d5e) | Header protection, content padding and configurable timing ranges |
| 3.1, latest examined | [`v3.1.20260828`, `b5928efb`](https://github.com/amnezia-vpn/amneziawg-go/tree/b5928efb6ca19f0153958460c3d141f04abc5c2e) | Random trailers and cookie-related changes in addition to the above |

[`SendHandshakeInitiation`](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/send.go)
appends configured I-packets, `JunkPackets()`, then the authenticated initiation.
[`JunkPackets`](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/noise-protocol.go)
uses the configured count and size bounds, with random contents. Junk is not
necessarily numerous and can be disabled. I-packets can contain structured or
ASCII data, so not every pre-handshake packet has high entropy.

The current sender can encrypt the handshake/header using ChaCha20 header
protection; it also has random content padding and trailers. Consequently this
detector does **not** depend on visible H1-H4, exact 148/92-byte handshake sizes,
a fixed S1, a 16-byte length residue, or a fixed 120-second period. The
[`receive` path](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/receive.go)
checks MAC1 and drops invalid initiations. Random datagrams cannot be used to
make a server reveal a genuine client's junk pattern.

See also the [official protocol documentation](https://docs.amnezia.org/documentation/amnezia-wg/).

## What the detector measures

For each UDP conversation, separately for each capture section/interface:

1. Compute Shannon byte entropy (0-8 bits) and nibble entropy (0-4 bits) per
   payload. Raw byte entropy is biased downward on short packets; it is reported
   descriptively, not compared with a universal 7.9-bit threshold.
2. A payload of at least 64 bytes is `random_like` when nibble entropy is at
   least 3.85 bits and fewer than 8% of bytes are zero. This is an encrypted/
   random-like feature, not a randomness test or protocol signature.
3. Find a capture start or >=1 second of flow inactivity, followed by 4-64
   same-direction packets within 250 ms, at least three different sizes, >=512
   total payload bytes, and >=75% random-like packets. Require a reverse packet
   within 1 second of the train's last packet, then >=3 packets each way and >=6
   random-like packets within 5 seconds of that response.
4. Require at least two such events, >=12 entropy-sampled packets, and >=70%
   random-like payloads overall for `AWG_COMPATIBLE_HEURISTIC`.
5. Repeated plausible WireGuard, QUIC long-header, DTLS, STUN or DNS framing in
   both directions (>=3 matching packets) suppresses the AWG candidate. A single
   QUIC-looking CPS packet does not. These are competing-protocol **hints**, not
   complete cryptographic protocol validators.

These thresholds are an initial, explicitly documented heuristic. They are not
learned or calibrated on a labeled production corpus. Other encrypted/custom
UDP protocols can produce the same pattern. AWG with Jc=0, constant junk sizes,
high latency, packet loss, shaping, short captures or missing directions can
fail to match. More advanced mimicry can also suppress detection.

## Results and limits

- `AWG_COMPATIBLE_HEURISTIC`: repeated compatible behavior; **not proof of AWG**.
- `ENCRYPTED_UDP_INCONCLUSIVE`: entropy evidence, insufficient sequence evidence.
- `OTHER_PROTOCOL_HINT`: competing bidirectional framing.
- `INSUFFICIENT_DATA`: too few usable packets or missing reverse direction.
- `NO_MATCH`: the implemented pattern was not found; does not exclude AWG.

The output always reports `protocol_confirmed: false` and `awg_version: unknown`.
There is no probability or automatic TSPU verdict. No live scanner score is
changed by this command. Exit 0 means analysis completed, **not** that the
traffic is safe or clean; 64 means an input/read error.

Input support: classic PCAP (little/big endian, micro/nanosecond timestamps),
PCAPNG Enhanced Packet Blocks (per-interface timestamp resolution/offset and
multiple sections); Ethernet with VLAN, raw IPv4/IPv6, Linux SLL/SLL2, loopback.
IPv6 hop/routing/destination/AH extensions are walked with bounded lengths.
IP fragments, truncated UDP datagrams, non-UDP and timestamp-less/obsolete
PCAPNG packet blocks are skipped and counted. No fragment reassembly. Unsupported
classic PCAP link types are errors; unsupported PCAPNG interfaces are counted
as skipped. Limits: 64 MiB per file, 200000 UDP packets, 4096 conversations and
1024 interfaces per section. Exceeding limits is an error, not a partial verdict.

## Validation

`tests/test_awg_entropy.cpp` covers entropy sample limits, repeated synthetic
3.x-style variable-size trains, constant-size and one-direction negatives,
ordinary random UDP, competing framing, flow isolation, capture formats,
timestamp units/endianness, truncation and malformed length fields. Synthetic
tests establish implementation behavior, not field detection accuracy.

Real labeled 2.x/3.x captures and negative HTTP/3/DTLS/media traffic are still
needed to measure false-positive/false-negative rates before treating results
as operational protocol identification.

The core tests are included in `make test` and `make test-asan`. After building
the scanner, run the offline end-to-end checks with:

```powershell
python tests/test_awg_cli.py ./byebyevpn.exe
```

These checks generate temporary synthetic captures, invoke the actual CLI,
parse its JSON and verify text output, negative traffic and file errors.
