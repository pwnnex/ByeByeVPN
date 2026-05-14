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

    src/net/dns.cpp
    src/net/tcp.cpp
    src/net/udp.cpp
    src/net/http.cpp
    src/net/icmp.cpp

    src/geoip/geoip.cpp

    src/scan/ports.cpp
    src/scan/tcp_scan.cpp
    src/scan/udp_probes.cpp
    src/scan/fingerprint.cpp
    src/scan/tls_ctx.cpp
    src/scan/tls.cpp
    src/scan/https_probe.cpp
    src/scan/sni.cpp
    src/scan/brand.cpp
    src/scan/j3.cpp
    src/scan/snitch.cpp
    src/scan/ct.cpp
    src/scan/ja4.cpp
    src/scan/utls.cpp
    src/scan/tcpfp.cpp
    src/scan/ja4s_db.cpp
    src/scan/amnezia_probe.cpp

    src/local/local.cpp

    src/app/target.cpp
    src/app/orchestrator.cpp
    src/app/json_report.cpp
    src/app/cli.cpp
)

add_executable(byebyevpn ${BBVPN_SOURCES})
target_link_libraries(byebyevpn PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(WIN32)
    target_link_libraries(byebyevpn PRIVATE ws2_32 iphlpapi winhttp crypt32 bcrypt dnsapi)
    target_compile_definitions(byebyevpn PRIVATE _WIN32_WINNT=0x0A00)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(byebyevpn PRIVATE Threads::Threads)
endif()

install(TARGETS byebyevpn RUNTIME DESTINATION bin)
