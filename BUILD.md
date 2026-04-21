# Build guide

This document explains how to reproduce `byebyevpn.exe` from source with
verified OpenSSL provenance. The static OpenSSL archives
(`libssl.a`, `libcrypto.a`) live in `build-win/` and are tracked in
the repo so the build is self-contained. Their contents are
bit-identical to what the msys2 `mingw-w64-ucrt-x86_64-openssl`
package ships, and the SHA256 values below are reproducible from
a fresh msys2 install or from the msys2 repository mirror directly.

## Toolchain for the current release

| Component     | Version                                           | Source                                                 |
|---------------|---------------------------------------------------|--------------------------------------------------------|
| Compiler      | g++ 15.2.0 (MinGW-w64 UCRT posix-seh, WinLibs r7) | https://winlibs.com/                                   |
| C++ standard  | `-std=c++20`                                      | compiler built-in                                      |
| OpenSSL       | 3.6.2                                             | msys2 pkg `mingw-w64-ucrt-x86_64-openssl-3.6.2-2`      |
| Host          | Windows 11 Pro 10.0.26200                         | -                                                      |
| Target        | x86_64-w64-mingw32, `_WIN32_WINNT=0x0A00` (Win10+)| compile flag                                           |

## Static archive provenance

The files shipped in `build-win/` are the exact static archives from
the published msys2 package. No local modifications, no private
builds.

### msys2 package

```
pkg:     mingw-w64-ucrt-x86_64-openssl-3.6.2-2-any.pkg.tar.zst
pkg-sha: 4b919cc9ed46b55c465a39204bf5034f2d8be931840c6a62ae71b1554bbea9a5
size:    8,227,741 bytes
mirror1: https://repo.msys2.org/mingw/ucrt64/mingw-w64-ucrt-x86_64-openssl-3.6.2-2-any.pkg.tar.zst
mirror2: https://mirror.msys2.org/mingw/ucrt64/mingw-w64-ucrt-x86_64-openssl-3.6.2-2-any.pkg.tar.zst
mirror3: https://mirror.yandex.ru/mirrors/msys2/mingw/ucrt64/mingw-w64-ucrt-x86_64-openssl-3.6.2-2-any.pkg.tar.zst
```

### Extracted archives (what's in `build-win/`)

```
build-win/libssl.a       1,664,942 bytes   sha256: bf7a501fbcd50db87187ff263c35a264be48dd5ce18278bdf350aa6ad2a6a038
build-win/libcrypto.a    9,683,326 bytes   sha256: 23c62ffdef07d5ee2a4667eba45d713b56b5f57cbd0ae4b15dfd761500bd0046
```

### Verify yourself

```bash
# from a clean msys2 ucrt64 shell
pacman -S --needed mingw-w64-ucrt-x86_64-openssl
sha256sum /ucrt64/lib/libssl.a /ucrt64/lib/libcrypto.a
# should match the values above
```

Or fetch the package directly and extract:

```bash
curl -LO https://repo.msys2.org/mingw/ucrt64/mingw-w64-ucrt-x86_64-openssl-3.6.2-2-any.pkg.tar.zst
sha256sum mingw-w64-ucrt-x86_64-openssl-3.6.2-2-any.pkg.tar.zst
# 4b919cc9ed46b55c465a39204bf5034f2d8be931840c6a62ae71b1554bbea9a5
tar -xf mingw-w64-ucrt-x86_64-openssl-3.6.2-2-any.pkg.tar.zst
sha256sum ucrt64/lib/libssl.a ucrt64/lib/libcrypto.a
```

If any of these three SHA256 values don't match, the archive was
tampered with. Do not link against it.

## Reproduce the build

### Option A - msys2 (native)

```bash
pacman -S --needed mingw-w64-ucrt-x86_64-gcc \
                    mingw-w64-ucrt-x86_64-openssl \
                    mingw-w64-ucrt-x86_64-make \
                    git

git clone https://github.com/pwnnex/ByeByeVPN.git && cd ByeByeVPN
make windows-static
sha256sum byebyevpn.exe
```

The `windows-static` target links against the `build-win/*.a` archives
already in the tree, so the output only depends on the compiler
toolchain. The exe is ~8.5 MB.

### Option B - Linux cross-compile

```bash
# Debian/Ubuntu
sudo apt install -y mingw-w64

# Arch
sudo pacman -S mingw-w64-gcc

# then:
x86_64-w64-mingw32-g++ -O2 -std=c++20 -D_WIN32_WINNT=0x0A00 \
    -static \
    src/byebyevpn.cpp -o byebyevpn.exe \
    build-win/libssl.a build-win/libcrypto.a \
    -lws2_32 -liphlpapi -lwinhttp -lcrypt32 -lbcrypt -ldnsapi -luser32 -ladvapi32

wine byebyevpn.exe help
```

### Option C - build OpenSSL from source yourself

If you don't trust msys2 at all, build OpenSSL 3.6.2 from upstream
signed tarball:

```bash
wget https://www.openssl.org/source/openssl-3.6.2.tar.gz
wget https://www.openssl.org/source/openssl-3.6.2.tar.gz.sha256
sha256sum -c openssl-3.6.2.tar.gz.sha256

tar xzf openssl-3.6.2.tar.gz && cd openssl-3.6.2
./Configure mingw64 no-shared no-dso \
            --prefix=$PWD/install \
            --cross-compile-prefix=x86_64-w64-mingw32-
make -j$(nproc) && make install_sw

# replace the archives in the repo
cp install/lib64/libssl.a     ../ByeByeVPN/build-win/libssl.a
cp install/lib64/libcrypto.a  ../ByeByeVPN/build-win/libcrypto.a

cd ../ByeByeVPN && make windows-static
```

The resulting archive SHA256s won't match the msys2 values (different
compile flags, different build date), but functional behaviour is the
same.

## Release binary verification

Every release tag ships SHA256 sums in the release notes. Verify:

```powershell
Get-FileHash byebyevpn-v2.5.4-win64.zip -Algorithm SHA256
```

```bash
sha256sum byebyevpn-v2.5.4-win64.zip
```

A mismatch means the file was altered in transit (CDN / middlebox /
your download tool). Do not run it.

## Why static linking

Static OpenSSL means one self-contained exe with no DLL dependencies
outside Windows itself.

| Aspect            | Static (shipped)                            | Dynamic                         |
|-------------------|---------------------------------------------|---------------------------------|
| User experience   | 1 file, no DLL hell                         | 3 files, DLL version conflicts  |
| CVE patching      | rebuild required on each OpenSSL CVE        | user updates DLLs independently |
| Distribution size | ~8.5 MB exe                                 | ~300 KB exe + ~5 MB DLLs        |

A dynamic build target exists for packagers who prefer DLL shipping
(`make windows`).

## Reproducibility caveats

The build is **not** byte-identical across environments - PE
timestamps, linker build-id, and compiler revisions all differ. If
you need bit-for-bit reproducibility for supply-chain attestation,
use the GitHub Actions workflow (`.github/workflows/release.yml`) -
it builds in a pinned container image and all release zips are
produced there. The CI workflow logs print the SHA256 of the output
exe so anyone can cross-check against a tag's release zip.

Stripping PE timestamps + linker build-ids for full byte-repro is on
the roadmap (requires `objcopy --remove-section=.buildid` + a
post-link timestamp patcher).
