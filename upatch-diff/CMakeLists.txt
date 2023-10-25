# SPDX-License-Identifier: GPL-2.0

include_directories(
    ./
    ./insn/
)

file(GLOB HOST_SRC_FILES
    insn/*.c
    *.c
)

add_executable(upatch-diff ${HOST_SRC_FILES})
target_link_libraries(upatch-diff elf)

install(
    TARGETS
        upatch-diff
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_READ WORLD_EXECUTE
    DESTINATION
        ${SYSCARE_LIBEXEC_DIR}
)
