project(acme-client C)
cmake_minimum_required(VERSION 3.23)

# Can't use find_package because my system uses OpenSSL 1.1.1q 
# and version 3 is manually installed. To avoid conflicts,
# I explicitly specify the shared object files.

#find_package(OpenSSL 3 REQUIRED)
find_library(OPENSSL_LIB libcrypto.so.3 libssl.so.3)
find_package(CURL REQUIRED)

file(GLOB sources src/*.c)

add_executable(acme-client ${sources})
target_link_libraries(acme-client libssl.so.3)
target_link_libraries(acme-client libcrypto.so.3)
target_link_libraries(acme-client cjson CURL::libcurl)

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -g -Og -ggdb")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -pedantic")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCONFIG_PRINT_ARGS")

