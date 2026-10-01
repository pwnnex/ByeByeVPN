cmake_minimum_required(VERSION 3.15)
project(byebyevpn CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(MSVC)
    add_compile_options(/W3 /O2 /utf-8)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -DNOMINMAX -DWIN32_LEAN_AND_MEAN)
else()
    add_compile_options(-O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function)
endif()

find_package(OpenSSL REQUIRED)

set(BBVPN_SOURCES
    src/main.cpp

    src/common/config.cpp
    src/common/console.cpp
    src/common/util.cpp
    src/common/tspu.cpp
    src/common/json.cpp
    src/common/outcome.cpp

    src/net/dns.cpp
    src/net/tcp.cpp
    src/net/udp.cpp
    src/net/http.cpp
    src/net/icmp.cpp

    src/geoip/geoip.cpp

    src/scan/ports.cpp
    src/scan/tcp_scan.cpp
    src/scan/udp_probes.cpp
    src/scan/udp_validate.cpp
    src/scan/wg_handshake.cpp
    src/scan/fingerprint.cpp
    src/scan/tls_ctx.cpp
    src/scan/tls.cpp
    src/scan/https_probe.cpp
    src/scan/sni.cpp
    src/scan/brand.cpp
    src/scan/hostname_marks.cpp
    src/scan/certificate_info.cpp
    src/scan/https_response.cpp
    src/scan/j3_analysis.cpp
    src/scan/ct_response.cpp
    src/scan/protocol_response.cpp
    src/scan/sni_analysis.cpp
    src/scan/h2_response.cpp
    src/app/verdict.cpp
    src/app/signals.cpp
    src/app/preflight_core.cpp
    src/app/preflight.cpp
    src/scan/hostname_input.cpp
    src/scan/hostname_json.cpp
    src/scan/public_suffix.cpp
    src/scan/j3.cpp
    src/scan/snitch.cpp
    src/scan/ct.cpp
    src/scan/ja4.cpp
    src/scan/chrome_ch.cpp
    src/scan/utls_compare.cpp
    src/scan/utls.cpp
    src/scan/tcpfp.cpp
    src/scan/ja4s_db.cpp
    src/scan/amnezia_probe.cpp
    src/scan/awg_entropy.cpp
    src/scan/awg_capture.cpp
    src/scan/quic.cpp
    src/scan/grpc.cpp
    src/scan/transport_probe.cpp
    src/scan/dpi_probe.cpp
    src/scan/volume_probe.cpp
    src/scan/volume_analysis.cpp
    src/scan/ech.cpp
    src/scan/ech_query.cpp

    src/local/local.cpp

    src/app/target.cpp
    src/app/orchestrator.cpp
    src/app/verdict_print.cpp
    src/app/json_report.cpp
    src/app/config_audit.cpp
    src/app/sweep_core.cpp
    src/app/sweep.cpp
    src/app/cli.cpp
    src/app/commands.cpp
    src/app/tui.cpp
    src/app/tui_layout.cpp
    src/app/hostname_analysis.cpp
    src/app/awg_analysis.cpp
)

add_executable(byebyevpn ${BBVPN_SOURCES})
target_link_libraries(byebyevpn PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(WIN32)
    target_link_libraries(byebyevpn PRIVATE ws2_32 iphlpapi winhttp crypt32 bcrypt dnsapi user32 advapi32)
    target_compile_definitions(byebyevpn PRIVATE _WIN32_WINNT=0x0A00)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(byebyevpn PRIVATE Threads::Threads)
endif()

install(TARGETS byebyevpn RUNTIME DESTINATION bin)
install(FILES third_party/psl/LICENSE DESTINATION share/byebyevpn/licenses/psl)
