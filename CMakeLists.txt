project(acme-client C)
cmake_minimum_required(VERSION 3.23)

add_subdirectory(src)

enable_testing()
add_subdirectory(test)

