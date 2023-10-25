# SPDX-License-Identifier: GPL-2.0

add_subdirectory(ko)
# add_subdirectory(ebpf)

add_executable(compiler-hijacker gnu-compiler-hijacker.c)
add_executable(as-hijacker gnu-as-hijacker.c)


# Copy compiler hijacker
add_custom_target(Copy_hijacker ALL
    COMMENT "Copying compiler hijacker..."
    COMMAND cp -a compiler-hijacker gcc-hijacker
    COMMAND cp -a compiler-hijacker g++-hijacker
    COMMAND cp -a compiler-hijacker cc-hijacker
    COMMAND cp -a compiler-hijacker c++-hijacker
    DEPENDS compiler-hijacker
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)