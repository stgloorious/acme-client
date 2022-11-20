project(acme-client C)
cmake_minimum_required(VERSION 3.23)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

file(GLOB sources src/*.c)

add_executable(acme-client ${sources})
target_link_libraries(acme-client OpenSSL::SSL)
target_link_libraries(acme-client OpenSSL::Crypto)
target_link_libraries(acme-client cjson CURL::libcurl)

if (OPENSSL_VERSION VERSION_LESS "3.0.0")
        message(FATAL_ERROR "OpenSSL version must be greater than 3.0.0")
endif()

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -g -Og -ggdb")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -pedantic")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCONFIG_PRINT_ARGS")

