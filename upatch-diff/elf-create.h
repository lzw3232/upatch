/*
 * elf-create.h
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

#ifndef __UPATCH_CREATE_H_
#define __UPATCH_CREATE_H_

#include "upatch-elf.h"

void upatch_create_strings_elements(struct upatch_elf *);

void upatch_create_patches_sections(struct upatch_elf *, struct running_elf *);

void upatch_create_intermediate_sections(struct upatch_elf *, struct running_elf *);

static inline void create_kpatch_arch_section(struct upatch_elf *uelf) {}

void upatch_build_strings_section_data(struct upatch_elf *);

void upatch_reorder_symbols(struct  upatch_elf *);

void upatch_strip_unneeded_syms(struct upatch_elf *);

void upatch_reindex_elements(struct upatch_elf *);

void upatch_rebuild_relocations(struct upatch_elf *);

void upatch_check_relocations(struct upatch_elf *);

void upatch_create_shstrtab(struct upatch_elf *);

void upatch_create_strtab(struct upatch_elf *);

void upatch_create_symtab(struct upatch_elf *);

void upatch_write_output_elf(struct upatch_elf *, Elf *, char *, mode_t);

#endif /* __UPATCH_CREATE_H_ */