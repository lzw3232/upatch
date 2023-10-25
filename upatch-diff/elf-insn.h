/*
 * elf-insn.h
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2013-2014 Josh Poimboeuf <jpoimboe@redhat.com>
 * Copyright (C) 2022 Longjun Luo <luolongjun@huawei.com>
 * Copyright (C) 2022 Zongwu Li <lzw32321226@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA,
 * 02110-1301, USA.
 */

#ifndef __UPATCH_INSN_H_
#define __UPATCH_INSN_H_

#include "asm/insn.h"
#include "upatch-elf.h"

#define ARM64_INSTR_LEN 4

void rela_insn(const struct section *sec, const struct rela *rela, struct insn *insn);

/*
 * For S + A: addend is the section offset
 * For L/S + A - P: addend is the symbol_offset - relocation_len
 * More info, check https://anatasluo.github.io/eaaed1ffd135/
 */

long rela_target_offset(struct upatch_elf *, struct section *, struct rela *);

unsigned int insn_length(struct upatch_elf *, void *);

bool insn_is_load_immediate(struct upatch_elf *, void *);

#endif /* __UPATCH_INSN_H_ */