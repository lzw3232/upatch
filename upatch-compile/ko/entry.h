// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 HUAWEI, Inc.
 *
 * Authors:
 *   Longjun Luo <luolongjuna@gmail.com>
 *
 */

#ifndef _KMOD_ENTRY_H
#define _KMOD_ENTRY_H

#include "upatch-entry.h"

int entries_enabled(void);
int entries_lookup(const char *search, struct upatch_entry_des *value);
int entry_get(const char *search, struct upatch_entry_des *value);
int entry_put(const char *search);

#endif /* _KMOD_ENTRY_H */
