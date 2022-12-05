project(acme-client C)
cmake_minimum_required(VERSION 3.23)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)

add_subdirectory(src)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        message("***************************")
        message("*** Debug configuration ***")
        message("***************************")
        set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build/test)
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build/test)
        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build/test)

        enable_testing()
        add_subdirectory(test)
endif()

