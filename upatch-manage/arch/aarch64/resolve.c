// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 HUAWEI, Inc.
 *
 * Authors:
 *   Zongwu Li <lzw32321226@gmail.com>
 *
 */

#include <gelf.h>

#include "log.h"
#include "upatch-ptrace.h"
#include "upatch-resolve.h"

/*
 * ldr x16, #24
 * ldr x17, #12
 * br x17
 * undefined
 */
#define AARCH64_JUMP_TABLE_JMP1 0x58000071580000d0
#define AARCH64_JUMP_TABLE_JMP2 0xffffffffd61f0220

struct upatch_jmp_table_entry {
	unsigned long inst[2];
	unsigned long addr[2];
};

unsigned int get_jmp_table_entry()
{
	return sizeof(struct upatch_jmp_table_entry);
}

static unsigned long setup_jmp_table(struct upatch_elf *uelf,
				     unsigned long jmp_addr,
				     unsigned long origin_addr)
{
	struct upatch_jmp_table_entry *table =
		uelf->core_layout.kbase + uelf->jmp_offs;
	unsigned int index = uelf->jmp_cur_entry;
	if (index >= uelf->jmp_max_entry) {
		log_error("jmp table overflow \n");
		return 0;
	}

	table[index].inst[0] = AARCH64_JUMP_TABLE_JMP1;
	table[index].inst[1] = AARCH64_JUMP_TABLE_JMP2;
	table[index].addr[0] = jmp_addr;
	table[index].addr[1] = origin_addr;
	uelf->jmp_cur_entry++;
	return (unsigned long)(uelf->core_layout.base + uelf->jmp_offs +
			       index * sizeof(struct upatch_jmp_table_entry));
}

static unsigned long setup_got_table(struct upatch_elf *uelf,
				     unsigned long jmp_addr,
				     unsigned long tls_addr)
{
	struct upatch_jmp_table_entry *table =
		uelf->core_layout.kbase + uelf->jmp_offs;
	unsigned int index = uelf->jmp_cur_entry;

	if (index >= uelf->jmp_max_entry) {
		log_error("got table overflow \n");
		return 0;
	}

	table[index].inst[0] = jmp_addr;
	table[index].inst[1] = tls_addr;
	table[index].addr[0] = 0xffffffff;
	table[index].addr[1] = 0xffffffff;
	uelf->jmp_cur_entry++;
	return (unsigned long)(uelf->core_layout.base + uelf->jmp_offs +
			       index * sizeof(struct upatch_jmp_table_entry));
}

unsigned long insert_plt_table(struct upatch_elf *uelf, struct object_file *obj,
			       unsigned long r_type, unsigned long addr)
{
	unsigned long jmp_addr = 0xffffffff;
	unsigned long tls_addr = 0xffffffff;
	unsigned long elf_addr = 0;

	if (upatch_process_mem_read(obj->proc, addr, &jmp_addr,
				    sizeof(jmp_addr))) {
		log_error("copy address failed \n");
		goto out;
	}

	if (r_type == R_AARCH64_TLSDESC &&
	    upatch_process_mem_read(obj->proc, addr + sizeof(unsigned long),
				    &tls_addr, sizeof(tls_addr))) {
		log_error("copy address failed \n");
		goto out;
	}

	if (r_type == R_AARCH64_TLSDESC)
		elf_addr = setup_got_table(uelf, jmp_addr, tls_addr);
	else
		elf_addr = setup_jmp_table(uelf, jmp_addr, (unsigned long)addr);

	log_debug("0x%lx: jmp_addr=0x%lx, tls_addr=0x%lx \n", elf_addr,
		  jmp_addr, tls_addr);

out:
	return elf_addr;
}

unsigned long insert_got_table(struct upatch_elf *uelf, struct object_file *obj,
			       unsigned long r_type, unsigned long addr)
{
	unsigned long jmp_addr = 0xffffffff;
	unsigned long tls_addr = 0xffffffff;
	unsigned long elf_addr = 0;

	if (upatch_process_mem_read(obj->proc, addr, &jmp_addr,
				    sizeof(jmp_addr))) {
		log_error("copy address failed \n");
		goto out;
	}

	if (r_type == R_AARCH64_TLSDESC &&
	    upatch_process_mem_read(obj->proc, addr + sizeof(unsigned long),
				    &tls_addr, sizeof(tls_addr))) {
		log_error("copy address failed \n");
		goto out;
	}

	elf_addr = setup_got_table(uelf, jmp_addr, tls_addr);

	log_debug("0x%lx: jmp_addr=0x%lx, tls_addr=0x%lx \n", elf_addr,
		  jmp_addr, tls_addr);

out:
	return elf_addr;
}

unsigned long search_insert_plt_table(struct upatch_elf *uelf,
				      unsigned long jmp_addr,
				      unsigned long origin_addr)
{
	struct upatch_jmp_table_entry *table =
		uelf->core_layout.kbase + uelf->jmp_offs;
	unsigned int i = 0;

	for (i = 0; i < uelf->jmp_cur_entry; ++i) {
		if (table[i].addr[0] != jmp_addr)
			continue;
		return (unsigned long)(uelf->core_layout.base + uelf->jmp_offs +
				       i * sizeof(struct upatch_jmp_table_entry));
	}

	return setup_jmp_table(uelf, jmp_addr, origin_addr);
}