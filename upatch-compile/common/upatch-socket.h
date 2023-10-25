// SPDX-License-Identifier: GPL-2.0
/*
 * Authors:
 *   Longjun Luo <luolongjuna@gmail.com>
 */

#ifndef _UPATCH_SOCKET_H
#define _UPATCH_SOCKET_H

#include "upatch-entry.h"

/* This struct must be packed */
struct upatch_socket_msg {
    unsigned long magic;
    unsigned long prey_ino;
    unsigned long hijacker_ino;
    char prey_name[UPATCH_ENTRY_MAX_LEN];
    char hijacker_name[UPATCH_ENTRY_MAX_LEN];
};

#define UPATCH_SOCKET_MAGIC 0xEEE55EE5
#define UPATCH_SOCKET_PATH "/var/run/upatch-hijacker"

#endif /* _UPATCH_SOCKET_H */
