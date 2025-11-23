cmake_minimum_required(VERSION 3.16)
project(dns_proxy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(dns_proxy
    src/main.cpp
    src/config.cpp
    src/rules.cpp
    src/dns_message.cpp
    src/server.cpp
    src/dns_configurator.cpp
)

target_include_directories(dns_proxy PRIVATE include)

if (WIN32)
    target_link_libraries(dns_proxy PRIVATE ws2_32 iphlpapi)
endif()
