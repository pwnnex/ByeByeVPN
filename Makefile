CXX      ?= g++
CXXFLAGS ?= -O2 -std=c++20 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function
LDFLAGS  ?=
LIBS     = -lssl -lcrypto -lpthread

WIN_SYS_LIBS = -lws2_32 -liphlpapi -lwinhttp -lcrypt32 -lbcrypt -ldnsapi -luser32 -ladvapi32

# all source files in the modular tree
SRC := \
    src/main.cpp \
    src/common/config.cpp \
    src/common/console.cpp \
    src/common/util.cpp \
    src/common/tspu.cpp \
    src/net/dns.cpp \
    src/net/tcp.cpp \
    src/net/udp.cpp \
    src/net/http.cpp \
    src/net/icmp.cpp \
    src/geoip/geoip.cpp \
    src/scan/ports.cpp \
    src/scan/tcp_scan.cpp \
    src/scan/udp_probes.cpp \
    src/scan/fingerprint.cpp \
    src/scan/tls_ctx.cpp \
    src/scan/tls.cpp \
    src/scan/https_probe.cpp \
    src/scan/sni.cpp \
    src/scan/brand.cpp \
    src/scan/j3.cpp \
    src/scan/snitch.cpp \
    src/scan/ct.cpp \
    src/local/local.cpp \
    src/app/target.cpp \
    src/app/orchestrator.cpp \
    src/app/cli.cpp

OBJ := $(SRC:.cpp=.o)

BIN = byebyevpn

# path to prebuilt OpenSSL static archives (gitignored, see BUILD.md)
WIN_OSSL_DIR ?= build-win

all: $(BIN)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BIN): $(OBJ)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(OBJ) -o $@ $(LIBS)

# -----------------------------------------------------------------
# dynamic windows build (requires libssl-3 / libcrypto-3 DLLs)
# -----------------------------------------------------------------
WIN_OBJ := $(SRC:.cpp=.win.o)

%.win.o: %.cpp
	$(CXX) $(CXXFLAGS) -D_WIN32_WINNT=0x0A00 -c $< -o $@

windows: $(WIN_OBJ)
	$(CXX) $(CXXFLAGS) -D_WIN32_WINNT=0x0A00 $(LDFLAGS) $(WIN_OBJ) -o $(BIN).exe \
	    -lssl -lcrypto $(WIN_SYS_LIBS)

# -----------------------------------------------------------------
# truly static windows build — single self-contained byebyevpn.exe
# -----------------------------------------------------------------
windows-static: $(WIN_OBJ)
	$(CXX) $(CXXFLAGS) -D_WIN32_WINNT=0x0A00 \
	    -static \
	    $(WIN_OBJ) -o $(BIN).exe \
	    $(WIN_OSSL_DIR)/libssl.a $(WIN_OSSL_DIR)/libcrypto.a \
	    $(WIN_SYS_LIBS)
	@echo "=> $(BIN).exe  (OpenSSL + libwinpthread + libstdc++ baked in)"

static: $(OBJ)
	$(CXX) $(CXXFLAGS) -static $(OBJ) -o $(BIN)-static \
	    -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic -lpthread -ldl

# -----------------------------------------------------------------
# release zip
# -----------------------------------------------------------------
VERSION ?= v2.5.8
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
	rm -f $(OBJ) $(WIN_OBJ) $(BIN) $(BIN)-static $(BIN).exe $(BIN)-*-win64.zip $(BIN)-win64.zip
	rm -rf dist-release

.PHONY: all windows windows-static static release-zip install clean
