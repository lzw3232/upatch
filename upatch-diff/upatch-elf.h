/*
 * upatch-elf.h
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

#ifndef __UPATCH_ELF_H_
#define __UPATCH_ELF_H_

#include <gelf.h>
#include <stdbool.h>

#include "list.h"
#include "running-elf.h"

extern char *upatch_elf_name;

// these data structs contain each other
struct section;
struct rela;
struct symbol;

enum status {
	NEW,
	CHANGED,
	SAME
};

enum symbol_strip {
	SYMBOL_DEFAULT,
	SYMBOL_USED,
	SYMBOL_STRIP,
};

struct string {
	struct list_head list;
	char *name;
};

struct section {
	struct list_head list;
	struct section *twin;
	char *name;
	Elf_Data *data;
	GElf_Shdr sh;
	int ignore;
	int include;
	int grouped;
	unsigned int index;
	enum status status;
	union {
        // section with relocation information
		struct {
			struct section *base;
			struct list_head relas;
		};
        // other function or data section
		struct {
			struct section *rela;
			struct symbol *sym;
			struct symbol *secsym;
		};
	};
};

struct rela {
	struct list_head list;
	GElf_Rela rela;
	struct symbol *sym;
	unsigned int type;
	unsigned int offset;
	long addend;
	char *string;
	bool need_dynrela;
};

struct symbol {
	struct list_head list;
	struct symbol *twin;
	struct symbol *parent;
	struct list_head children;
	struct list_head subfunction_node;
	struct section *sec;
	GElf_Sym sym;
	char *name;
	struct object_symbol *lookup_running_file_sym;
	unsigned int index;
	unsigned char bind;
	unsigned char type;
	enum status status;
	union {
		int include; /* used in the patched elf */
		enum symbol_strip strip; /* used in the output elf */
	};
};

enum architecture {
	X86_64 = 0x1 << 0,
	AARCH64 = 0x1 << 1,
};

struct upatch_elf {
	Elf *elf;
	enum architecture arch;
	struct list_head sections;
	struct list_head symbols;
	struct list_head strings;
	Elf_Data *symtab_shndx;
	int fd;
};

// init a upatch_elf from a path
void upatch_elf_open(struct upatch_elf *, const char *);

// Destory upatch_elf struct
void upatch_elf_teardown(struct upatch_elf *);

void upatch_elf_free(struct upatch_elf *);

#endif
