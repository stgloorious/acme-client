find_package(OpenSSL 3 REQUIRED)
find_package(CURL REQUIRED)

file(GLOB sources ../src/*.c)
        
# Build a library for testing
add_library(acme ${sources})
target_link_libraries(acme OpenSSL::SSL)
target_link_libraries(acme OpenSSL::Crypto)
target_link_libraries(acme cjson CURL::libcurl)

add_executable(b64 b64.c)
add_executable(string string.c)
add_executable(chal chal.c)
add_executable(id id.c)
target_link_libraries(b64 acme)
target_link_libraries(string acme)
target_link_libraries(chal acme)
target_link_libraries(id acme)
find_program(BASH_PROGRAM bash)
add_test(NAME base64_encoder COMMAND ${BASH_PROGRAM}
        ../../test/valgrind_b64.sh)
add_test(NAME string_list COMMAND ${BASH_PROGRAM}
        ../../test/string_list.sh)
add_test(NAME valgrind_string_list COMMAND ${BASH_PROGRAM}
        ../../test/valgrind_string_list.sh)
add_test(NAME chal_list COMMAND ${BASH_PROGRAM}
        ../../test/valgrind_chal_list.sh)
add_test(NAME id_list COMMAND ${BASH_PROGRAM}
        ../../test/valgrind_id_list.sh)
add_test(NAME http-single-1 COMMAND ${BASH_PROGRAM} ../../test/http_single-1.sh)
add_test(NAME http-single-2 COMMAND ${BASH_PROGRAM} ../../test/http_single-2.sh)
add_test(NAME valgrind-no-args COMMAND ${BASH_PROGRAM} ../../test/valgrind_no_args.sh)
add_test(NAME valgrind-help COMMAND ${BASH_PROGRAM} ../../test/valgrind_help.sh)
add_test(NAME valgrind-http-single-1 COMMAND ${BASH_PROGRAM} ../../test/valgrind_http_single-1.sh)
