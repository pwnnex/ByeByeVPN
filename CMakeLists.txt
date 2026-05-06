cmake_minimum_required(VERSION 3.10)
project(ByeByeVPN)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Collect source files
file(GLOB_RECURSE SRC_FILES
    "core/*.cpp"
    "network/*.cpp"
    "analysis/*.cpp"
    "cli/*.cpp"
    "main.cpp"
)

add_executable(byebyevpn ${SRC_FILES})

# Include directories
target_include_directories(byebyevpn PRIVATE ${OPENSSL_INCLUDE_DIR})

# Link OpenSSL
target_link_libraries(byebyevpn PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Platform specific libraries
if(WIN32)
    target_link_libraries(byebyevpn PRIVATE ws2_32 iphlpapi)
    
    if(MSVC)
        # MSVC specific flags if needed
        add_compile_options(/W3)
    elseif(MINGW)
        # MinGW specific flags if needed
        add_compile_options(-Wall -Wextra)
    endif()
else()
    target_link_libraries(byebyevpn PRIVATE pthread)
endif()
