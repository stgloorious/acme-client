find_package(OpenSSL 3 REQUIRED)
find_package(CURL REQUIRED)

file(GLOB sources *.c)

# Executable binary
add_executable(acme-client ${sources})

target_link_libraries(acme-client OpenSSL::SSL)
target_link_libraries(acme-client OpenSSL::Crypto)
target_link_libraries(acme-client cjson CURL::libcurl)

set (CMAKE_C_FLAGS "-Wall -Wextra -Werror")
set (CMAKE_C_FLAGS_RELEASE "-O2")
set (CMAKE_C_FLAGS_DEBUG "-Og -ggdb --coverage -fprofile-arcs -ftest-coverage \
-DCONFIG_PRINT_ARGS")

