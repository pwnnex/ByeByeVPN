cmake_minimum_required(VERSION 3.15)
project(ByeByeVPN)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

set(OPENSSL_USE_STATIC_LIBS TRUE)
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
    target_link_libraries(byebyevpn PRIVATE ws2_32 iphlpapi crypt32)
    add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS)

    if(MSVC)
        add_compile_options(/W3)
    elseif(MINGW)
        add_compile_options(-Wall -Wextra)
        target_link_options(byebyevpn PRIVATE -static -static-libgcc -static-libstdc++)
    endif()
else()
    target_link_libraries(byebyevpn PRIVATE pthread dl)

    target_link_options(byebyevpn PRIVATE -static-libgcc -static-libstdc++)

    target_compile_options(byebyevpn PRIVATE
        $<$<CONFIG:Debug>:-g;-O0;-fno-omit-frame-pointer>
    )
endif()
