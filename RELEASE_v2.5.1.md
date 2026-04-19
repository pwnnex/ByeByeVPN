# ByeByeVPN v2.5.1 — audit-cleanup follow-up

**Tag:** `v2.5.1`
**Target branch:** `main`
**Date:** 2026-04-20
**Previous release:** [v2.5](https://github.com/pwnnex/ByeByeVPN/releases/tag/v2.5) (the anti-fingerprinting pass — required reading for context)

This is a follow-up cleanup release on top of v2.5, addressing three
audit-grade observations made after v2.5 shipped. No new features, no
behavioural changes to scanning logic or the verdict engine. The
binary changed; the output it produces did not.

## What changed

### 1. `rand()` → `RAND_bytes()` for outbound payload bytes

Two probes were still using `rand()` (Windows linear-congruential PRNG)
to fill payload bytes that get sent to the target:

| Location | What it does | Before | After |
|---|---|---|---|
| `src/byebyevpn.cpp` ~L995 | Shadowsocks probe — 64 bytes of garbage to test silent-on-junk pattern | `rand()` 64× | `RAND_bytes(rnd, 64)` |
| `src/byebyevpn.cpp` ~L1813 | J3 probe #5 — 512 random bytes | `rand()` 512× | `RAND_bytes(buf, 512)` |

Why this matters: `rand()` was seeded with `time(nullptr)` (one-second
granularity ≈ 17 bits of real entropy). An observer who knows the
approximate scan time could brute-force the exact bytes the tool
emitted — that's a uniqueness fingerprint by construction, regardless
of the v2.5 markers cleanup. The unused `srand((unsigned)time(nullptr))`
in `main()` is also removed.

Both call sites now use OpenSSL's `RAND_bytes()` — same CSPRNG that
the rest of the codebase already uses for protocol-layer random fields.

### 2. `BUILD.md` — OpenSSL provenance + reproduce-the-build

New top-level [`BUILD.md`](./BUILD.md) closes a recurring audit
question: *"how do I know the OpenSSL static archives in `build-win/`
aren't a backdoored blob?"*

Documented:

- Exact build environment for the v2.5.1 release exe (compiler version,
  OpenSSL version, host OS, target flags).
- SHA256 of the static `libssl.a` / `libcrypto.a` actually used.
- Three reproduction paths:
  - msys2 (recommended) — signed packages, mirrored sources.
  - Build OpenSSL from source — for the "I trust nothing pre-built" path.
  - Linux cross-compile via mingw-w64 — for CI / Docker.
- Why static linking was chosen and the trade-offs.
- Known caveats around byte-reproducibility.

The `build-win/*.a` files were already gitignored (never tracked in
the repo); the Makefile comment falsely claimed they were "shipped" —
fixed to point at `BUILD.md`.

### 3. `SECURITY.md` — disclosure policy + known-threats table

New top-level [`SECURITY.md`](./SECURITY.md) lists how to report a
vulnerability and explicitly enumerates **known open threats** that
v2.5.1 does NOT close:

- TLS JA3 ≠ Chrome (even with Chrome UA — needs uTLS port to fix).
- Behavioral burst pattern (multiple IP-intel APIs queried in parallel
  from the same source — inherent to cross-validation design).
- Build is not byte-reproducible (PE timestamps, build IDs).
- No Authenticode code signing (needs EV cert).
- Commits / tags not GPG-signed (key publication pending).
- Static OpenSSL means CVEs require a rebuild.

Listing them publicly removes them from the "potential audit gotcha"
category — they're now documented limitations on a roadmap, not hidden
surprises.

## Downloads

**`byebyevpn-v2.5.1-win64.zip`** — single self-contained static
`byebyevpn.exe` + LICENSE + README + CHANGELOG + BUILD.md + SECURITY.md.
No DLLs required.

### SHA256

```
byebyevpn.exe                ff9e0f65778f9335be6219227876dbb82d7aabdc476b05dfacbcc8d945267661
byebyevpn-v2.5.1-win64.zip   6aae6b359954a78f8f1ab418b7a5b01f3deb8cffaf8a1e2fcc678674239c84da
```

Verify with:

```powershell
# Windows
Get-FileHash byebyevpn-v2.5.1-win64.zip -Algorithm SHA256
```

```bash
# Linux / macOS
sha256sum byebyevpn-v2.5.1-win64.zip
```

### Reproducible build

```bash
git clone https://github.com/pwnnex/ByeByeVPN.git
cd ByeByeVPN
git checkout v2.5.1
# Follow BUILD.md to obtain OpenSSL static libs into build-win/
make windows-static
sha256sum byebyevpn.exe
```

Note: the SHA256 of your locally-built `byebyevpn.exe` will probably
**not** match the release exe byte-for-byte (PE timestamps,
linker build ID). What matches is the **functional behaviour**. See
`BUILD.md §Reproducibility caveats` for what would be needed for true
byte-for-byte reproducibility.

## Upgrade path

Drop-in replacement for v2.5 — same CLI, same output, just better
randomness in two probe payloads. If you're running v2.5 happily,
upgrading to v2.5.1 changes nothing user-visible.

## Full changelog

[CHANGELOG.md `## v2.5.1 — 2026-04-20`](./CHANGELOG.md) for the full
file-by-file diff.

---

**Previous release:** [v2.5](https://github.com/pwnnex/ByeByeVPN/releases/tag/v2.5)
