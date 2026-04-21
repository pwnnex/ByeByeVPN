CXX      ?= g++
CXXFLAGS ?= -O2 -std=c++20 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function
LDFLAGS  ?=
LIBS     = -lssl -lcrypto -lpthread

WIN_SYS_LIBS = -lws2_32 -liphlpapi -lwinhttp -lcrypt32 -lbcrypt -ldnsapi -luser32 -ladvapi32

SRC = src/byebyevpn.cpp
BIN = byebyevpn

# Path to prebuilt OpenSSL static archives. These are NOT shipped in the
# repo (gitignored) — see BUILD.md for how to obtain them with verified
# provenance (msys2 pacman package + SHA256 check).
WIN_OSSL_DIR ?= build-win

all: $(BIN)

$(BIN): $(SRC)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $< -o $@ $(LIBS)

# -----------------------------------------------------------------
# Dynamic Windows build (requires libssl-3/libcrypto-3 DLLs next to exe)
# -----------------------------------------------------------------
windows: $(SRC)
	$(CXX) $(CXXFLAGS) -D_WIN32_WINNT=0x0A00 $(LDFLAGS) $< -o $(BIN).exe \
	    -lssl -lcrypto $(WIN_SYS_LIBS)

# -----------------------------------------------------------------
# Truly static Windows build — produces ONE self-contained byebyevpn.exe
# with no MinGW runtime DLLs and no OpenSSL DLLs required.
#
# Prereqs:
#   * MinGW-w64 g++ (UCRT or MSVCRT toolchain)
#   * Static OpenSSL archives (libssl.a + libcrypto.a) in $(WIN_OSSL_DIR)/
#     (this repo ships them in build-win/)
# -----------------------------------------------------------------
windows-static: $(SRC)
	$(CXX) $(CXXFLAGS) -D_WIN32_WINNT=0x0A00 \
	    -static \
	    $< -o $(BIN).exe \
	    $(WIN_OSSL_DIR)/libssl.a $(WIN_OSSL_DIR)/libcrypto.a \
	    $(WIN_SYS_LIBS)
	@echo "=> $(BIN).exe  (OpenSSL + libwinpthread + libstdc++ baked in;"
	@echo "    on Win10 1803+ runs as-is, on Win7/8 install UCRT redist:"
	@echo "    https://www.microsoft.com/en-us/download/details.aspx?id=49093)"

# -----------------------------------------------------------------
# Linux static (glibc static is nasty; we do partial static: pthread + SSL)
# -----------------------------------------------------------------
static: $(SRC)
	$(CXX) $(CXXFLAGS) -static $< -o $(BIN)-static \
	    -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic -lpthread -ldl

# -----------------------------------------------------------------
# Release zip: single static .exe + LICENSE + README.md + CHANGELOG.md
# Output: byebyevpn-<VERSION>-win64.zip containing ONE runnable exe.
# Override with:  make release-zip VERSION=v2.3
# -----------------------------------------------------------------
VERSION ?= v2.5.5
ZIP_NAME = $(BIN)-$(VERSION)-win64.zip

release-zip: windows-static
	@rm -rf dist-release && mkdir -p dist-release
	@cp $(BIN).exe dist-release/
	@cp LICENSE README.md CHANGELOG.md dist-release/
	@cd dist-release && \
	  (command -v zip >/dev/null && zip -9 ../$(ZIP_NAME) *) || \
	  powershell -Command "Compress-Archive -Path dist-release\\* -DestinationPath $(ZIP_NAME) -Force"
	@ls -la $(ZIP_NAME)

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)/usr/local/bin/$(BIN)

clean:
	rm -f $(BIN) $(BIN)-static $(BIN).exe $(BIN)-*-win64.zip $(BIN)-win64.zip
	rm -rf dist-release

.PHONY: all windows windows-static static release-zip install clean
