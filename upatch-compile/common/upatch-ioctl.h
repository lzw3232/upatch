// SPDX-License-Identifier: GPL-2.0
/*
 * Authors:
 *   Longjun Luo <luolongjuna@gmail.com>
 */

#ifndef _UPATCH_IOCTL_H
#define _UPATCH_IOCTL_H

/* ATTENTION: This head file is exported to userspace */
#include <linux/ioctl.h>
#include <linux/types.h>

/* This struct must be packed */
struct upatch_hijack_msg {
    unsigned long prey_ino;
    unsigned long hijacker_ino;
    const char *prey_name;
    const char *hijacker_name;
};

#define UPATCH_HIJACKER_DEV_NAME   "upatch-hijacker"

#define UPATCH_HIJACKER_DEV_PATH "/dev/upatch-hijacker"

#define UPATCH_HIJACKER_MAGIC 0xE5

/* used for upatch-build */
#define UPATCH_HIJACKER_REGISTER _IOW(UPATCH_HIJACKER_MAGIC, 0x1, const struct upatch_hijack_msg *)

#define UPATCH_HIJACKER_UNREGISTER _IOW(UPATCH_HIJACKER_MAGIC, 0x2, const struct upatch_hijack_msg *)

#endif /* _UPATCH_IOCTL_H */
