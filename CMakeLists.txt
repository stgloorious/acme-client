project(acme-client C)
cmake_minimum_required(VERSION 3.23)

find_package(OpenSSL 3 REQUIRED)
find_package(CURL REQUIRED)

file(GLOB sources src/*.c)

add_executable(acme-client ${sources})
target_link_libraries(acme-client OpenSSL::SSL)
target_link_libraries(acme-client OpenSSL::Crypto)
target_link_libraries(acme-client cjson CURL::libcurl)

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -g -Og -ggdb")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCONFIG_PRINT_ARGS")

