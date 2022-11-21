find_package(OpenSSL 3 REQUIRED)
find_package(CURL REQUIRED)

file(GLOB sources ../src/*.c)

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -g -Og -ggdb")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCONFIG_PRINT_ARGS")
        
# Build a library for testing
add_library(acme ${sources})
target_link_libraries(acme OpenSSL::SSL)
target_link_libraries(acme OpenSSL::Crypto)
target_link_libraries(acme cjson CURL::libcurl)

add_executable(b64 b64.c)
add_executable(string string.c)
target_link_libraries(b64 acme)
target_link_libraries(string acme)
find_program(BASH_PROGRAM bash)
add_test(NAME base64_encoder COMMAND ${BASH_PROGRAM} ../../test/b64.sh)
add_test(NAME string_list COMMAND ${BASH_PROGRAM} ../../test/string.sh)

