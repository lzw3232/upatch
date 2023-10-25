#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "upatch-env.h"

/*
 * ATTENTION: written by ebpf directly.
 * 
 * The whole part:
 * 1. the compiler path + other inode number(before execve) -> the hijacker
 * 2. the hijacker inode number + the hijacker path -> the compiler path(after execve)
 * 
 * Pid keeps the same.
 */
static char original_path[PATH_MAX] = {0xff};

static const int append_args_len = 4;
static const char *compiler_append_args[] = {
    "-gdwarf", /* obatain debug information */
    "-ffunction-sections",
    "-fdata-sections",
    "-frecord-gcc-switches",
    NULL,
};

int main(int argc, char *argv[], char *envp[])
{
    int tmp = 0, new_index = 1, old_index = 1;
    const char **__argv = (const char **)argv;
    char *upatch_env = NULL;

    upatch_env = getenv(UPATCH_HIJACKER_ENV);
    if (!upatch_env)
        goto out;

    /* append NULL at the end of argv */
    __argv = calloc(sizeof(char *), argc + append_args_len + 1);
    if (!__argv)
        return -ENOMEM;

    __argv[0] = argv[0];
    for (tmp = 0; tmp < append_args_len; tmp ++)
        __argv[new_index ++] = compiler_append_args[tmp];
    while (old_index < argc)
        __argv[new_index ++] = argv[old_index ++];
    __argv[new_index] = NULL;
out:
    tmp = readlink("/proc/self/exe", (char *)&original_path, PATH_MAX);
    original_path[tmp] = '\0';
    printf("[hacked] original path is %s \n", (char *)&original_path);
    return execve((const char *)&original_path, (void *)__argv, envp);
}