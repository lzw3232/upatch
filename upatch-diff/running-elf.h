/*
 * running-elf.h
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

#ifndef __RUNNING_ELF_H_
#define __RUNNING_ELF_H_

#include <stdbool.h>
#include <errno.h>
#include <gelf.h>

#include "upatch-elf.h"

struct symbol;

struct lookup_result {
    struct object_symbol *symbol;
	unsigned long sympos;
	bool global;
};

struct object_symbol {
    char *name;
    unsigned char type, bind;
    unsigned int shndx;
    unsigned long addr;
    unsigned long size;
};

struct running_elf {
    int obj_nr;
    struct object_symbol *obj_syms;
    int fd;
    Elf *elf;
    bool is_exec;
};

void relf_init(char *, struct running_elf *);

int relf_destroy(struct running_elf *);

bool lookup_relf(struct running_elf *, struct symbol *, struct lookup_result *);

#endif