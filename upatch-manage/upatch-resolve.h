// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 HUAWEI, Inc.
 *
 * Authors:
 *   Zongwu Li <lzw32321226@gmail.com>
 *
 */

#ifndef __UPATCH_RESOLVE__
#define __UPATCH_RESOLVE__

#include "upatch-elf.h"
#include "upatch-process.h"

#define SHN_LIVEPATCH 0xff20

/* jmp table, solve limit for the jmp instruction, Used for both PLT/GOT */
struct upatch_jmp_table_entry;

unsigned int get_jmp_table_entry();

unsigned long insert_plt_table(struct upatch_elf *, struct object_file *,
			       unsigned long, unsigned long);
unsigned long insert_got_table(struct upatch_elf *, struct object_file *,
			       unsigned long, unsigned long);

unsigned long search_insert_plt_table(struct upatch_elf *, unsigned long,
				      unsigned long);

int simplify_symbols(struct upatch_elf *, struct object_file *);

#endif