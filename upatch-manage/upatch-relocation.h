// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 HUAWEI, Inc.
 *
 * Authors:
 *   Zongwu Li <lzw32321226@gmail.com>
 *
 */

#ifndef __UPATCH_RELOCATION__
#define __UPATCH_RELOCATION__

#include <gelf.h>

#include "log.h"
#include "upatch-common.h"
#include "upatch-elf.h"

// TODO: change define
#define s64 int64_t
#define u64 uint64_t
#define u32 uint32_t
#define s32 int32_t
#define u16 uint16_t
#define s16 int16_t

int apply_relocate_add(struct upatch_elf *, unsigned int, unsigned int);

int apply_relocations(struct upatch_elf *);

#endif