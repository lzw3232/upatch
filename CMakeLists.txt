# SPDX-License-Identifier: MulanPSL-2.0

cmake_minimum_required(VERSION 3.14)
find_package(Git QUIET)

project(upatch)

add_compile_options(-g -Wall -O2)

# Build syscare
add_custom_target(syscare ALL
    COMMENT "Compiling upatch-build..."
    COMMAND cargo build --release --target-dir ${CMAKE_CURRENT_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_subdirectory(upatch-diff)
add_subdirectory(upatch-compile)
add_subdirectory(upatch-manage)
