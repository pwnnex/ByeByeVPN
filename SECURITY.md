# Security policy

## Reporting

Found a way the tool leaks something it shouldn't (fingerprint that
enumerates scanner users, memory-safety bug in a parser, supply-chain
concern, etc.)? Report before disclosing publicly.

**Channels:**

- [GitHub Security Advisory](https://github.com/pwnnex/ByeByeVPN/security/advisories/new)
  - private, integrates with the CVE process
- [GitHub Issues](https://github.com/pwnnex/ByeByeVPN/issues) - for
  anything that's fine to discuss in public
- [ntc.party/t/byebyevpn/24325](https://ntc.party/t/byebyevpn/24325) -
  the public thread where most of the current audit discussion happens

## In scope

- the modular source tree under `src/` and everything in the repo
- Release artifacts (exe + zip SHA256 on the release page)
- Anything in the documented threat model below

## Out of scope

- Bugs in third-party services the tool queries (ipapi.is, iplocate.io,
  freeipapi.com, ipwho.is, ipinfo.io, crt.sh, dns.google,
  cloudflare-dns.com). Report those upstream.
- General OpenSSL / Windows / msys2 CVEs, unless there's a specific
  exploitable path via this tool.
- "Don't scan servers you don't own" - ethics/legal, not a security
  bug.

## Threat model

The primary class is **fingerprinting**: any byte the tool emits
that identifies it and could be used to enumerate scanner users
from external log sources (a censor on the wire, a third-party
service operator, or a log aggregator).

Secondary: memory safety in parsers that consume attacker-controlled
bytes (HTTP response parser, TLS parser, UDP reply decoder, JSON
scanner).

## Owner key material (`--wg-pubkey`, `--wg-key`, `--wg-psk`)

The WireGuard self-check reads the peer private key and the preshared key
from files only, so they never appear in argv or shell history; the server
public key may be text or a file. Keys are parsed at use time, held in
fixed arrays, wiped with `OPENSSL_cleanse` after the probe series, and
never printed, saved or serialised: error messages name the path, JSON
carries `wg_self_check.requested`, `ran` and `port`. The lab checks the
saved results for every key string (0 hits on the 2026-10-01 runs). A handshake
made with a peer key moves that peer's endpoint to the scanning machine on
the server until the peer's own client sends again; `--help` and README
say to use a spare peer.

## Known open threats

These are known and tracked here; no need to report them.

| Threat                                               | Status  | Plan                                                            |
|------------------------------------------------------|---------|-----------------------------------------------------------------|
| Synthetic hello is not a current Chrome (fixed order, no ML-KEM, no ECH GREASE); `tls_probe` is OpenSSL default | open | Documented as its own fingerprint in README |
| Behavioural burst: 5 IP-intel APIs hit in ~2s        | partial | Closed by `--stealth` / `--no-geoip`; still default-on          |
| Build not byte-reproducible across envs              | partial | CI workflow pins msys2; strip PE timestamp + build-id TODO      |
| No Authenticode code signing                         | open    | EV cert needed (~$300/yr)                                       |
| Unsigned git commits/tags                            | open    | GPG keys pending                                                |
| OpenSSL CVE requires rebuild                         | inherent| Static-link trade-off; re-release on CVE drop                   |
| Single-source-IP repeat-scan correlation             | inherent| Can't be fixed at the tool layer; use a fresh upstream each run |

## Recently closed

- **`http_get()` sent `Accept-Encoding: gzip, deflate`** while the docs
  said GET + Host only. The WinHTTP decompression option was the
  source; it is gone. Captured on loopback the request is now
  `GET`, `Connection: Keep-Alive` (added by WinHTTP) and `Host`, plus
  `Accept: application/dns-json` on the Cloudflare DoH fallback only.
- **ICMP traceroute sent 33 bytes** (`sizeof` counted the string
  terminator) while claiming the 32-byte `ping.exe` payload. Now 32,
  guarded by a `static_assert`.
- **J3 invalid-SNI ClientHello was malformed**: 76 extension bytes
  under a 65-byte header, so every TLS server answered decode_error.
  The hello is now built with computed lengths and unit-tested.
- **`dpi` treated a silent drop as a pass**: a dropped ClientHello next
  to a working benign SNI printed "got a TLS reply" and exited 0.
- **Chrome-131 header block was itself a fingerprint**
  ([#5](https://github.com/pwnnex/ByeByeVPN/issues/5)).
  `http_get()` sends no tool-specific headers. The WinHTTP session
  agent is empty and `WINHTTP_OPTION_USER_AGENT` is force-overridden
  to empty. `https_probe()` uses a minimal
  `Host`+`Accept: */*`+`Connection: close` triple.
- **2ip.io HTML-scraping path triggered anti-bot**
  ([#5](https://github.com/pwnnex/ByeByeVPN/issues/5)). The provider
  now uses `api.2ip.me/geo.json` directly - a plain JSON endpoint.
- **BUILD.md SHA256 didn't match shipped archives**
  ([#4](https://github.com/pwnnex/ByeByeVPN/issues/4)). `build-win/`
  now contains the real msys2 static archives and the SHA256s in
  BUILD.md are the actual msys2 pkg values. OpenSSL upgraded from
  the stale `3.6.1-3` to the current upstream `3.6.2-2`; the
  package hash, libssl.a hash, and libcrypto.a hash in BUILD.md
  are reproducible from `pacman -S` or from the msys2 repo mirror
  directly.
- **Release binary provenance**. Releases are now produced by the
  [CI workflow](.github/workflows/release.yml) from the exact same
  msys2 image, with exe + zip SHA256 printed in each release's
  notes.
- **`fp_socks5` read beyond the received byte count when the server
  replied with exactly one byte (uninitialized stack read)**. Now
  guarded by `n >= 2`.
- **`WSACleanup` skipped on several CLI error paths**. All paths
  now fall through to `WSACleanup` via `goto done`.
- **CLI accepted negative `--threads`, `--tcp-to`, `--udp-to`
  values** (would wrap SO_TIMEO to ~49 days). Clamped to 1+.
- **Scan-progress printer read `open.size()` outside the mutex**
  (formal data race). Snapshot taken under lock.

## Coordinated disclosure

For fingerprint-class issues where public disclosure before a fix
could harm existing users, please wait for the patched release. For
everything else, 90-day disclosure is fine.

## Verifying a build

```
sha256sum byebyevpn.exe                                # compare with release notes
sha256sum byebyevpn-v2.5.4-win64.zip                   # same
sha256sum build-win/libssl.a build-win/libcrypto.a     # compare with BUILD.md
```

SHA mismatch on a release zip = a CDN or middlebox altered it, don't
run it.
