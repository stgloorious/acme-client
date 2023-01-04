find_package(OpenSSL 3 REQUIRED)
find_package(CURL REQUIRED)
find_package(cJSON REQUIRED)
find_program(pebble NAMES pebble_linux-amd64 pebble REQUIRED)

file(GLOB sources ../src/*.c)

set (CMAKE_C_FLAGS "-Wall -Wextra -Werror")
set (CMAKE_C_FLAGS_RELEASE "-O2")
set (CMAKE_C_FLAGS_DEBUG "-Og -g3 -ggdb --coverage -fprofile-arcs \
-ftest-coverage -DCONFIG_PRINT_ARGS")

# Build a library for testing
add_library(acme ${sources})
target_link_libraries(acme OpenSSL::SSL)
target_link_libraries(acme OpenSSL::Crypto)
target_link_libraries(acme cjson CURL::libcurl)

add_executable(b64 src/test_b64.c)
add_executable(string src/test_string.c)
add_executable(chal src/test_chal.c)
add_executable(id src/test_id.c)
target_link_libraries(b64 acme)
target_link_libraries(string acme)
target_link_libraries(chal acme)
target_link_libraries(id acme)
find_program(BASH_PROGRAM bash)

add_test(NAME base64-encoder COMMAND ${BASH_PROGRAM}
        ${CMAKE_SOURCE_DIR}/test/valgrind_b64.sh)
add_test(NAME string-list COMMAND ${BASH_PROGRAM}
        ${CMAKE_SOURCE_DIR}/test/string_list.sh)
add_test(NAME valgrind-string-list COMMAND ${BASH_PROGRAM}
        ${CMAKE_SOURCE_DIR}/test/valgrind_string_list.sh)
add_test(NAME valgrind-chal-list COMMAND ${BASH_PROGRAM}
        ${CMAKE_SOURCE_DIR}/test/valgrind_chal_list.sh)
add_test(NAME valgrind-id-list COMMAND ${BASH_PROGRAM}
        ${CMAKE_SOURCE_DIR}/test/valgrind_id_list.sh)
add_test(NAME http-single-1 COMMAND ${BASH_PROGRAM} 
        ${CMAKE_SOURCE_DIR}/test/http_single.sh)
add_test(NAME http-single-2 COMMAND ${BASH_PROGRAM} 
        ${CMAKE_SOURCE_DIR}/test/http_single.sh)
add_test(NAME valgrind-no-args COMMAND ${BASH_PROGRAM}
        ${CMAKE_SOURCE_DIR}/test/valgrind_no_args.sh)
add_test(NAME valgrind-help COMMAND ${BASH_PROGRAM}
        ${CMAKE_SOURCE_DIR}/test/valgrind_help.sh)
add_test(NAME valgrind-http-single-new-account COMMAND ${BASH_PROGRAM}
        ${CMAKE_SOURCE_DIR}/test/valgrind_http_single_new_account.sh)
add_test(NAME valgrind-http-single-1 COMMAND ${BASH_PROGRAM}
        ${CMAKE_SOURCE_DIR}/test/valgrind_http_single.sh)
add_test(NAME valgrind-http-single-2 COMMAND ${BASH_PROGRAM}
        ${CMAKE_SOURCE_DIR}/test/valgrind_http_single.sh)
add_test(NAME valgrind-http-single-3 COMMAND ${BASH_PROGRAM}
        ${CMAKE_SOURCE_DIR}/test/valgrind_http_single.sh)
add_test(NAME valgrind-http-multi-1 COMMAND ${BASH_PROGRAM}
        ${CMAKE_SOURCE_DIR}/test/valgrind_http_multi.sh)

set_tests_properties(
        base64-encoder
        string-list
        valgrind-string-list
        valgrind-chal-list
        valgrind-id-list
        http-single-1
        http-single-2
        valgrind-no-args
        valgrind-help
        valgrind-http-single-new-account
        valgrind-http-single-1
        valgrind-http-single-2
        valgrind-http-single-3
        valgrind-http-multi-1
PROPERTIES
TIMEOUT 180
SKIP_RETURN_CODE 127
ENVIRONMENT
"TEST_DIR=${CMAKE_SOURCE_DIR}/test;\
ACME_BIN=${CMAKE_SOURCE_DIR}/build/acme-client;\
PEBBLE_HOSTNAME=pebble;\
PEBBLE_LISTEN_PORT=14000;\
PEBBLE_MGMT_PORT=15000;\
PEBBLE_HTTP_PORT=8080;\
PEBBLE_TLS_PORT=443;\
PEBBLE_ROOT_CERT=${CMAKE_SOURCE_DIR}/test/pebble/root.pem;\
ACME_OUT_DIR=${CMAKE_SOURCE_DIR}/build/test;\
SKIP_CODE=127"
)

set_property(TEST http-single-1 APPEND PROPERTY ENVIRONMENT
        "DOMAIN=example.com")
set_property(TEST http-single-2 APPEND PROPERTY ENVIRONMENT
        "DOMAIN=foobar.domain.com")
set_property(TEST valgrind-http-single-new-account APPEND PROPERTY ENVIRONMENT
        "DOMAIN=example.com")
set_property(TEST valgrind-http-single-1 APPEND PROPERTY ENVIRONMENT
        "DOMAIN=example.com")
set_property(TEST valgrind-http-single-2 APPEND PROPERTY ENVIRONMENT
        "DOMAIN=foobar.domain.com")
set_property(TEST valgrind-http-single-3 APPEND PROPERTY ENVIRONMENT
        "DOMAIN=admin.test.server.certificate.foobar.domain.com")
set_property(TEST valgrind-http-multi-1 APPEND PROPERTY ENVIRONMENT
        "DOMAIN_A=admin.test.server.certificate.foobar.domain.com;DOMAIN_B=example.com;DOMAIN_C=foobar.domain.com")

