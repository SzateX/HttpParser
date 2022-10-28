cmake_minimum_required(VERSION 3.23)
project(HttpParser C)

set(CMAKE_C_STANDARD 23)

set(httpparser-include dependencies/pcre2/src include)

include_directories(${httpparser-include})

file (GLOB_RECURSE httpparser-src CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/*.c")

add_subdirectory(dependencies/pcre2)

#add_executable(HttpParser main.c ${httpparser-src})
add_library(HttpParser STATIC ${httpparser-src})
target_compile_definitions(HttpParser PUBLIC PCRE2_STATIC PCRE2_CODE_UNIT_WIDTH=8)
target_link_libraries(HttpParser pcre2-8-static)