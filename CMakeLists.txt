cmake_minimum_required(VERSION 3.10)
project(ByeByeVPN)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(OpenSSL REQUIRED)

file(GLOB_RECURSE SRC_FILES
    "src/core/*.cpp"
    "src/network/*.cpp"
    "src/analysis/*.cpp"
    "src/cli/*.cpp"
    "src/main.cpp"
)

add_executable(byebyevpn ${SRC_FILES})

target_include_directories(byebyevpn PRIVATE ${OPENSSL_INCLUDE_DIR})

target_link_libraries(byebyevpn PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(WIN32)
    target_link_libraries(byebyevpn PRIVATE ws2_32 iphlpapi)
    add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS)

    if(MSVC)
        add_compile_options(/W3)
    elseif(MINGW)
        add_compile_options(-Wall -Wextra)
    endif()
else()
    target_link_libraries(byebyevpn PRIVATE pthread)
    
    # Flags for valgrind memory leak detection
    target_compile_options(byebyevpn PRIVATE
        $<$<CONFIG:Debug>:-g;-O0;-fno-omit-frame-pointer>
    )
endif()
