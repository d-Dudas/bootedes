cmake_minimum_required(VERSION 3.10)

project(thades VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_compile_options(
            -Wall
            -Wextra
            -Wpedantic
            -g
            -O0
            -Werror
            -Wno-unused-parameter
            -Wno-unused-variable
            -Wno-unused-function
            -Wno-unused-but-set-variable
        )

include_directories(includes)

add_subdirectory(source)
