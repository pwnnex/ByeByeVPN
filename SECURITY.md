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

- `src/byebyevpn.cpp` and everything in the repo
- Release artifacts (exe + zip SHA256 on the release page)
- Anything in the documented threat model below

## Out of scope

- Bugs in third-party IP-intel services (ipapi.is, iplocate.io,
  ip-api.com, ipwho.is, ipinfo.io, freeipapi.com, 2ip.me,
  sypexgeo.net, crt.sh). Report those upstream.
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

## Known open threats

These are known and tracked here; no need to report them.

| Threat                                               | Status  | Plan                                                            |
|------------------------------------------------------|---------|-----------------------------------------------------------------|
| TLS JA3 != Chrome                                    | open    | Needs a uTLS-Chrome ClientHello port in C++ (large rewrite)     |
| Behavioural burst: 9 IP-intel APIs hit in ~2s        | partial | Closed by `--stealth` / `--no-geoip`; still default-on          |
| Build not byte-reproducible across envs              | partial | CI workflow pins msys2; strip PE timestamp + build-id TODO      |
| No Authenticode code signing                         | open    | EV cert needed (~$300/yr)                                       |
| Unsigned git commits/tags                            | open    | GPG keys pending                                                |
| OpenSSL CVE requires rebuild                         | inherent| Static-link trade-off; re-release on CVE drop                   |
| Single-source-IP repeat-scan correlation             | inherent| Can't be fixed at the tool layer; use a fresh upstream each run |

## Recently closed

- **Chrome-131 header block was itself a fingerprint**
  ([#5](https://github.com/pwnnex/ByeByeVPN/issues/5)).
  `http_get()` now sends **zero** tool-specific headers - no
  `User-Agent`, no `Accept`, no `Accept-Language`, no
  `Accept-Encoding`, no `Sec-Fetch-*`, no
  `Upgrade-Insecure-Requests`. The WinHTTP session agent is empty
  and `WINHTTP_OPTION_USER_AGENT` is force-overridden to empty to
  cover WinHTTP defaults. `https_probe()` uses a minimal
  `Host`+`Accept: */*`+`Connection: close` triple. IP-intel
  endpoints all accept bare GETs (same as `curl -sS` without flags).
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
