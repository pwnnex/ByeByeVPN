# Security policy

## Reporting a vulnerability

If you've found a security issue in ByeByeVPN — a way the tool leaks
information it shouldn't, a fingerprint that enumerates scanner users,
a memory-safety bug in protocol parsing, a supply-chain concern, or
anything else — please report it **before** publicly disclosing.

### Preferred channels

1. **GitHub Security Advisory** — https://github.com/pwnnex/ByeByeVPN/security/advisories/new
   — Private, auditable, integrates with the CVE process if needed.

2. **ntc.party thread** — mention `@pwnnex` in the
   [ByeByeVPN topic NOT AVAILABLE RIGHT NOW](https://ntc.party/) if the issue is minor and you
   prefer open discussion. Anything sensitive should go via the
   GitHub advisory path above, not the public thread.

### What counts as "security-sensitive"

* **Fingerprinting** — any byte the tool emits that identifies it and
  could be used to enumerate scanner users from external log sources.
  This is the primary threat model (see
  [README §On-the-wire posture](README.md#on-the-wire-posture-anti-fingerprinting-v25)).
* **Memory safety** — buffer overflows / OOB reads in the HTTP response
  parser, TLS parser, UDP probe reply decoder, or JSON parser (the tool
  consumes attacker-controlled bytes from every target and every
  IP-intel service).
* **Information leaks** — paths where the target IP, the user's own IP,
  or local system state is sent anywhere unexpected.
* **Supply-chain** — compromised build artefacts, tampered release
  zips, backdoored dependencies.

### What we'd like in the report

* Version (`byebyevpn --help` prints the version line).
* Reproduction steps — exact command line or the probe sequence.
* Packet capture (tcpdump/wireshark) if network-level.
* The specific source line / commit / hex bytes if code-level.
* Your suggested fix if you have one.

### Response expectations

This is a single-maintainer project. No SLAs. Realistic turnaround:

* **Acknowledgement** — within ~72h (often faster).
* **Fix in `main`** — as soon as root cause is understood; typically
  hours to a couple of days for anything in the fingerprint class,
  which is treated as urgent.
* **Release** — pushed to `main` + tagged + release zip uploaded on the
  same day as the fix lands.

I'll credit you in the release notes and the CHANGELOG unless you ask
me not to.

## Scope

**In scope** — anything in `src/byebyevpn.cpp`, `Makefile`, build
configuration, release artefacts (exe + zip), documented threat model.

**Out of scope**

* Vulnerabilities in third-party IP-intel services the tool queries
  (ipify, 2ip.me, ipinfo.io, sypexgeo, ip-api, ipapi.is, crt.sh). Report
  those to the services directly.
* General Windows, OpenSSL, or msys2 CVEs unless they have a specific
  exploitable path via this tool.
* "You shouldn't scan servers you don't own" — that's an ethics /
  legal concern, not a security bug in the tool.
* Cosmetic issues (typos in help text, incorrect emoji rendering).

## Known open threats / limitations

These are **known** and **not** new findings. No need to report them —
they're on the roadmap.

| Threat                                   | Status  | Planned fix                                                    |
|------------------------------------------|---------|----------------------------------------------------------------|
| TLS JA3 ≠ Chrome even with Chrome UA     | open    | uTLS-Chrome ClientHello port (large rewrite, not imminent)     |
| Behavioral burst (N IP-intel APIs at once) | open  | Configurable, fewer default calls, opt-in `--deep`             |
| Not byte-reproducible build              | open    | `Dockerfile.build` + strip PE timestamps + build ID            |
| No Authenticode code signing             | open    | Requires EV cert (~$300/yr); will sign if project gets funded  |
| Unsigned git commits / tags              | open    | GPG-signing keys to be published in a future release           |
| OpenSSL CVE requires rebuild             | inherent| Static linking trade-off — documented, re-release on CVE drop  |
| Single-maintainer / bus factor           | inherent| Contributors welcome (see `README` contrib section)            |

## Coordinated disclosure

For issues in the **fingerprinting** class specifically — where public
disclosure before a fix could actively harm existing scanner users —
please wait for the fixed release before publishing details. I'll work
with you on the timeline, typically 1-3 days.

For all other issues, standard 90-day disclosure is fine; I'll
usually move faster than that.

## Out-of-band verification

If you ever need to confirm a message claiming to be from the
maintainer (for example, to verify a signed release), the authoritative
channels are:

* GitHub: https://github.com/pwnnex
* The commit history of this repo (anything not signed by the
  maintainer's pushes is not official)

Thank you for making the tool safer.
