# SPDX-License-Identifier: GPL-2.0

set(UPATCH_MANAGE "upatch-manage")

EXECUTE_PROCESS(COMMAND uname -m
                OUTPUT_VARIABLE ARCH
                OUTPUT_STRIP_TRAILING_WHITESPACE)

set(ARCH_PATH arch/${ARCH})

include_directories(
    arch/${ARCH}/
    ./
)

file(GLOB HOST_SRC_FILES
    arch/${ARCH}/*.c
    *.c
)

add_compile_options(-g -Wall)
add_executable(${UPATCH_MANAGE} ${HOST_SRC_FILES})
target_link_libraries(${UPATCH_MANAGE} elf)

install(
    TARGETS
        ${UPATCH_MANAGE}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_READ WORLD_EXECUTE
    DESTINATION
        ${SYSCARE_LIBEXEC_DIR}
)