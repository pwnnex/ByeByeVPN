# Build guide

This document explains how to reproduce the release `byebyevpn.exe` from
source, with verified OpenSSL provenance. The static OpenSSL archives
(`libssl.a`, `libcrypto.a`) are **not shipped** in the repository — they
are `.gitignore`d. You obtain them yourself from a trusted source, so
the audit chain "does the repo ship a backdoored crypto blob?" has an
answer: it doesn't ship one at all.

## v2.5 release build environment

The official `byebyevpn-v2.5-win64.zip` exe was built with:

| Component       | Version                                                 | Source                                    |
|-----------------|---------------------------------------------------------|-------------------------------------------|
| Compiler        | g++ 15.2.0 (MinGW-w64 UCRT posix-seh, WinLibs r7)       | https://winlibs.com/                      |
| C++ standard    | `-std=c++20`                                            | compiler built-in                         |
| OpenSSL         | 3.6.1 (27 Jan 2026)                                     | msys2 package `mingw-w64-ucrt-x86_64-openssl-3.6.1-3` |
| Host OS         | Windows 11 Pro 10.0.26200                               | —                                         |
| Target          | x86_64-w64-mingw32, `_WIN32_WINNT=0x0A00` (Win10+)      | compile flag                              |

Static libraries used (from `build-win/` at build time):

```
libssl.a     475 768 bytes   SHA256: 069b8c7c92872a5a4336aeea492a58d3be137afc69bd49d4cc4f153d347a65be
libcrypto.a  4 607 000 bytes SHA256: 0aa09e4841847b6aee0d77449c576944b0fe08e9baa457cebb0d2560d7abe371
```

These are static archives built from OpenSSL 3.6.1 source. Any reader
can rebuild from the same source and verify the byte contents.

## How to reproduce the build yourself

### Option A — via msys2 (recommended)

msys2 packages are signed and the package sources are mirrored. This is
the cleanest audit path.

1. Install msys2 from https://www.msys2.org/ (installer is signed and
   has a published checksum on the download page).

2. From an msys2 UCRT shell, install the toolchain and OpenSSL:

   ```bash
   pacman -S --needed mingw-w64-ucrt-x86_64-gcc \
                       mingw-w64-ucrt-x86_64-openssl \
                       mingw-w64-ucrt-x86_64-make \
                       git
   ```

3. Clone the repo and produce the static libs:

   ```bash
   git clone https://github.com/pwnnex/ByeByeVPN.git
   cd ByeByeVPN
   mkdir -p build-win
   # Copy the msys2-installed static archives into build-win/:
   cp /ucrt64/lib/libssl.a      build-win/libssl.a
   cp /ucrt64/lib/libcrypto.a   build-win/libcrypto.a
   ```

4. Build:

   ```bash
   git checkout v2.5
   make windows-static
   sha256sum byebyevpn.exe
   ```

   Note: byte-for-byte reproducibility is **not** guaranteed across
   different msys2 installations (PE timestamp, build IDs, compiler
   revision will vary). A sha256 that matches the release is a lucky
   bonus, not an expected outcome. What's guaranteed reproducible is
   the **functional** behaviour — same source + same OpenSSL version =
   semantically identical binary.

### Option B — build OpenSSL from source

If you don't trust msys2's packaging either, build OpenSSL yourself:

```bash
# Download OpenSSL 3.6.1 source from openssl.org (signed tarball)
wget https://www.openssl.org/source/openssl-3.6.1.tar.gz
wget https://www.openssl.org/source/openssl-3.6.1.tar.gz.sha256

# Verify the tarball matches the published SHA256
sha256sum -c openssl-3.6.1.tar.gz.sha256

tar xzf openssl-3.6.1.tar.gz
cd openssl-3.6.1
./Configure mingw64 no-shared no-dso \
            --prefix=$PWD/install \
            --cross-compile-prefix=x86_64-w64-mingw32-
make -j$(nproc)
make install_sw

# Copy libs to byebyevpn build-win/
cp install/lib64/libssl.a     ../ByeByeVPN/build-win/libssl.a
cp install/lib64/libcrypto.a  ../ByeByeVPN/build-win/libcrypto.a

cd ../ByeByeVPN
make windows-static
```

### Option C — Linux cross-compile (no Windows host needed)

```bash
# Debian/Ubuntu
sudo apt install -y mingw-w64 wine64

# Build static OpenSSL under mingw-w64 per Option B above, OR install
# a distro-packaged static OpenSSL for mingw if available:
#   Arch:   mingw-w64-openssl
#   Fedora: mingw64-openssl-static

x86_64-w64-mingw32-g++ -O2 -std=c++20 -D_WIN32_WINNT=0x0A00 \
    -static -static-libgcc -static-libstdc++ \
    src/byebyevpn.cpp -o byebyevpn.exe \
    build-win/libssl.a build-win/libcrypto.a \
    -lws2_32 -liphlpapi -lwinhttp -lcrypt32 -lbcrypt -ldnsapi -luser32 -ladvapi32

wine byebyevpn.exe help    # smoke test
```

## Why static linking?

The release exe statically links OpenSSL so end-users don't have to
juggle two DLLs (`libssl-3-x64.dll`, `libcrypto-3-x64.dll`) that often
collide with unrelated OpenSSL installations on the user's `PATH`.

Trade-offs of this choice:

| Aspect                | Static (what we ship)                       | Dynamic (alternative)           |
|-----------------------|---------------------------------------------|---------------------------------|
| User experience       | 1 file, no DLL hell                         | 3 files, DLL version conflicts  |
| CVE patching          | needs new binary on every OpenSSL CVE       | user updates DLLs independently |
| Audit surface         | OpenSSL source + build procedure documented | same + DLL trust chain          |
| Distribution size     | ≈1.1 MB exe                                 | ≈200 KB exe + ≈5 MB DLLs        |

The dynamic-build target exists too (`make windows`) if a packager
prefers DLL distribution.

## Reproducibility caveats

The tool build is **not** byte-reproducible across different
environments — PE timestamps, linker build IDs, and compiler revisions
differ even when the source and OpenSSL version match. If you need
byte-for-byte reproducibility for supply-chain attestation, the path
is:

1. Use an exact, pinned build container (TODO: ship `Dockerfile.build`
   in a future release).
2. Use `objcopy --remove-section=.buildid` to strip the linker build ID
   after link.
3. Strip PE timestamps with `objcopy --set-section-flags` or a
   post-link helper.

Pull requests to wire this up are welcome.

## Release artifact verification

```
byebyevpn-v2.5-win64.zip   a74e1c41ae69f9048ae53e317119ff3b7b4f729181305c95e02dc826598180f9
byebyevpn.exe              d608cc75801644e84906c4d314b320fe08ae46a83d0a64c7b8e8a7c4a7f1ad3d
```

Verify with:

```powershell
# Windows
Get-FileHash byebyevpn-v2.5-win64.zip -Algorithm SHA256
```

```bash
# Linux / macOS
sha256sum byebyevpn-v2.5-win64.zip
```

If your hash matches, the zip you received is byte-identical to what
was uploaded. A different hash means a middlebox / CDN altered the
file — do not use it.
