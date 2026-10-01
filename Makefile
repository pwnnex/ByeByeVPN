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
    src/common/json.cpp \
    src/common/outcome.cpp \
    src/net/dns.cpp \
    src/net/tcp.cpp \
    src/net/udp.cpp \
    src/net/http.cpp \
    src/net/icmp.cpp \
    src/geoip/geoip.cpp \
    src/scan/ports.cpp \
    src/scan/tcp_scan.cpp \
    src/scan/udp_probes.cpp \
    src/scan/udp_validate.cpp \
    src/scan/wg_handshake.cpp \
    src/scan/fingerprint.cpp \
    src/scan/tls_ctx.cpp \
    src/scan/tls.cpp \
    src/scan/https_probe.cpp \
    src/scan/sni.cpp \
    src/scan/brand.cpp \
    src/scan/hostname_marks.cpp \
    src/scan/certificate_info.cpp \
    src/scan/https_response.cpp \
    src/scan/j3_analysis.cpp \
    src/scan/ct_response.cpp \
    src/scan/protocol_response.cpp \
    src/scan/sni_analysis.cpp \
    src/scan/h2_response.cpp \
    src/app/verdict.cpp \
    src/app/signals.cpp \
    src/app/preflight_core.cpp \
    src/app/preflight.cpp \
    src/scan/hostname_input.cpp \
    src/scan/hostname_json.cpp \
    src/scan/public_suffix.cpp \
    src/scan/j3.cpp \
    src/scan/snitch.cpp \
    src/scan/ct.cpp \
    src/scan/ja4.cpp \
    src/scan/chrome_ch.cpp \
    src/scan/utls_compare.cpp \
    src/scan/utls.cpp \
    src/scan/tcpfp.cpp \
    src/scan/ja4s_db.cpp \
    src/scan/amnezia_probe.cpp \
    src/scan/awg_entropy.cpp \
    src/scan/awg_capture.cpp \
    src/scan/capture.cpp \
    src/scan/pcap_analysis.cpp \
    src/scan/quic.cpp \
    src/scan/grpc.cpp \
    src/scan/transport_probe.cpp \
    src/scan/dpi_probe.cpp \
    src/scan/volume_probe.cpp \
    src/scan/volume_analysis.cpp \
    src/scan/sni_mismatch.cpp \
    src/scan/ct_names.cpp \
    src/scan/ech.cpp \
    src/scan/ech_query.cpp \
    src/local/local.cpp \
    src/local/leaks.cpp \
    src/app/target.cpp \
    src/app/orchestrator.cpp \
    src/app/verdict_print.cpp \
    src/app/json_report.cpp \
    src/app/config_audit.cpp \
    src/app/sweep_core.cpp \
    src/app/sweep.cpp \
    src/app/cli.cpp \
    src/app/commands.cpp \
    src/app/tui.cpp \
    src/app/tui_layout.cpp \
    src/app/hostname_analysis.cpp \
    src/app/awg_analysis.cpp \
    src/app/pcap_cli.cpp \
    src/app/report_diff.cpp \
    src/app/batch.cpp

OBJ := $(SRC:.cpp=.o)

BIN = byebyevpn

# path to prebuilt openssl static archives (gitignored, see build.md)
WIN_OSSL_DIR ?= build-win

all: $(BIN)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(BIN): $(OBJ)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(OBJ) -o $@ $(LIBS)

#
# dynamic windows build (requires libssl-3 / libcrypto-3 dlls)
#
WIN_OBJ := $(SRC:.cpp=.win.o)

%.win.o: %.cpp
	$(CXX) $(CXXFLAGS) -MMD -MP -D_WIN32_WINNT=0x0A00 -c $< -o $@

windows: $(WIN_OBJ)
	$(CXX) $(CXXFLAGS) -D_WIN32_WINNT=0x0A00 $(LDFLAGS) $(WIN_OBJ) -o $(BIN).exe \
	    -lssl -lcrypto $(WIN_SYS_LIBS)

#
# truly static windows build - single self-contained byebyevpn.exe
#
windows-static: $(WIN_OBJ)
	$(CXX) $(CXXFLAGS) -D_WIN32_WINNT=0x0A00 \
	    -static \
	    $(WIN_OBJ) -o $(BIN).exe \
	    $(WIN_OSSL_DIR)/libssl.a $(WIN_OSSL_DIR)/libcrypto.a \
	    $(WIN_SYS_LIBS)
	@echo "=> $(BIN).exe  (OpenSSL + libwinpthread + libstdc++ baked in)"

web-probe-tests.exe: tests/web_probe_harness.cpp $(WIN_OBJ)
	$(CXX) $(CXXFLAGS) -D_WIN32_WINNT=0x0A00 -static \
	    tests/web_probe_harness.cpp $(filter-out src/main.win.o,$(WIN_OBJ)) -o $@ \
	    $(WIN_OSSL_DIR)/libssl.a $(WIN_OSSL_DIR)/libcrypto.a $(WIN_SYS_LIBS)

static: $(OBJ)
	$(CXX) $(CXXFLAGS) -static $(OBJ) -o $(BIN)-static \
	    -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic -lpthread -ldl

#
# release zip
#
# must match SCANNER_VERSION in src/common/config.h - that macro is what the
# banner, the --json report and the --save header actually print.
VERSION ?= v3.2.0
ZIP_NAME = $(BIN)-$(VERSION)-win64.zip

release-zip: windows-static
	@rm -rf dist-release && mkdir -p dist-release
	@cp $(BIN).exe dist-release/
	@cp LICENSE NOTICE README.md CHANGELOG.md dist-release/
	@mkdir -p dist-release/third_party/psl
	@cp third_party/psl/LICENSE dist-release/third_party/psl/
	@cd dist-release && \
	  (command -v zip >/dev/null && zip -9 -r ../$(ZIP_NAME) *) || \
	  powershell -Command "Compress-Archive -Path dist-release\\* -DestinationPath $(ZIP_NAME) -Force"
	@ls -la $(ZIP_NAME)

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)/usr/local/bin/$(BIN)

#
# unit tests (doctest, single-header, no extra deps). builds the pure
# platform-agnostic logic modules + the test driver and runs them.
#
TEST_SRC := \
    tests/test_main.cpp \
    tests/test_util.cpp \
    tests/test_ja4.cpp \
    tests/test_tspu.cpp \
    tests/test_ports.cpp \
    tests/test_brand.cpp \
    tests/test_hostname_marks.cpp \
    tests/test_web_observations.cpp \
    tests/test_protocol_observations.cpp \
    tests/test_verdict_engine.cpp \
    tests/test_tui.cpp \
    src/app/tui_layout.cpp \
    tests/test_json.cpp \
    tests/test_config_audit.cpp \
    tests/test_utls.cpp \
    src/scan/utls_compare.cpp \
    tests/test_quic.cpp \
    tests/test_sweep.cpp \
    tests/test_ech.cpp \
    tests/test_awg_entropy.cpp \
    tests/test_udp_validate.cpp \
    tests/test_wg_handshake.cpp \
    src/scan/wg_handshake.cpp \
    tests/test_volume.cpp \
    src/scan/volume_analysis.cpp \
    src/scan/sni_mismatch.cpp \
    tests/test_ct_names.cpp \
    src/scan/ct_names.cpp \
    src/scan/awg_entropy.cpp \
    src/scan/awg_capture.cpp \
    src/scan/capture.cpp \
    tests/test_pcap.cpp \
    tests/test_leaks.cpp \
    tests/test_report_diff.cpp \
    src/app/report_diff.cpp \
    src/local/leaks.cpp \
    src/scan/pcap_analysis.cpp \
    src/scan/udp_validate.cpp \
    src/common/util.cpp \
    src/common/tspu.cpp \
    src/common/json.cpp \
    src/scan/ja4.cpp \
    src/scan/chrome_ch.cpp \
    src/scan/ja4s_db.cpp \
    src/scan/brand.cpp \
    src/scan/hostname_marks.cpp \
    src/scan/certificate_info.cpp \
    src/scan/https_response.cpp \
    src/scan/j3_analysis.cpp \
    src/scan/ct_response.cpp \
    src/scan/protocol_response.cpp \
    src/scan/sni_analysis.cpp \
    src/scan/h2_response.cpp \
    src/app/verdict.cpp \
    src/app/signals.cpp \
    src/app/preflight_core.cpp \
    src/common/outcome.cpp \
    src/scan/hostname_input.cpp \
    src/scan/hostname_json.cpp \
    src/scan/public_suffix.cpp \
    src/scan/ports.cpp \
    src/scan/quic.cpp \
    src/scan/ech.cpp \
    src/app/config_audit.cpp \
    src/app/sweep_core.cpp \
    src/common/config.cpp

# headers and embedded data must also invalidate the single-command test build.
TEST_HEADERS := $(wildcard src/common/*.h src/scan/*.h src/app/*.h tests/*.h) src/scan/public_suffix_data.inc

test: $(TEST_SRC) $(TEST_HEADERS)
	$(CXX) -std=c++20 -O1 -g -Wall -Wextra -Itests $(TEST_SRC) -lcrypto -o byebyevpn-tests
	./byebyevpn-tests

# run the suite with asan and ubsan; only executed paths are checked
test-asan: $(TEST_SRC) $(TEST_HEADERS)
	$(CXX) -std=c++20 -O1 -g -Wall -Wextra -Itests \
	    -fsanitize=address,undefined -fno-sanitize-recover=all \
	    $(TEST_SRC) -lcrypto -o byebyevpn-tests-asan
	./byebyevpn-tests-asan

#
# libfuzzer harness for the ja4 byte parsers (clang only).
#
FUZZ_CXX ?= clang++
FUZZ_PCAP_SRC = src/scan/pcap_analysis.cpp src/scan/capture.cpp src/scan/ja4.cpp src/scan/quic.cpp \
    src/common/json.cpp src/common/outcome.cpp

fuzz: fuzz/fuzz_ja4.cpp fuzz/fuzz_pcap.cpp src/scan/ja4.cpp $(FUZZ_PCAP_SRC)
	$(FUZZ_CXX) -std=c++20 -g -O1 -fsanitize=fuzzer,address,undefined \
	    fuzz/fuzz_ja4.cpp src/scan/ja4.cpp -lcrypto -o fuzz_ja4
	$(FUZZ_CXX) -std=c++20 -g -O1 -fsanitize=fuzzer,address,undefined \
	    fuzz/fuzz_pcap.cpp $(FUZZ_PCAP_SRC) -lcrypto -o fuzz_pcap

clean:
	rm -f $(OBJ) $(WIN_OBJ) $(BIN) $(BIN)-static $(BIN).exe $(BIN)-*-win64.zip $(BIN)-win64.zip
	rm -f $(OBJ:.o=.d) $(WIN_OBJ:.o=.d)
	rm -f byebyevpn-tests byebyevpn-tests-asan udp-probe-tests.exe web-probe-tests.exe fuzz_ja4 fuzz_pcap byebyevpn-sbom.json
	rm -rf dist-release

.PHONY: all windows windows-static static release-zip install clean test test-asan fuzz

-include $(OBJ:.o=.d) $(WIN_OBJ:.o=.d)
