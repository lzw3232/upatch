// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 HUAWEI, Inc.
 *
 * Authors:
 *   Longjun Luo <luolongjuna@gmail.com>
 *   Zongwu Li <lzw32321226@gmail.com>
 *
 */

#include <errno.h>
#include <gelf.h>
#include <string.h>

#include "upatch-relocation.h"

int apply_relocate_add(struct upatch_elf *uelf, unsigned int symindex,
		       unsigned int relsec)
{
	unsigned int i;
	GElf_Sym *sym;
	void *loc, *real_loc;
	u64 val;
	const char *sym_name;
	GElf_Xword tls_size;
	GElf_Shdr *shdrs = (void *)uelf->info.shdrs;
	GElf_Rela *rel = (void *)shdrs[relsec].sh_addr;

	log_debug("Applying relocate section %u to %u\n", relsec,
		  shdrs[relsec].sh_info);

	for (i = 0; i < shdrs[relsec].sh_size / sizeof(*rel); i++) {
		/* This is where to make the change, calculate it from kernel address */
		loc = (void *)shdrs[shdrs[relsec].sh_info].sh_addr +
		      rel[i].r_offset;

		real_loc = (void *)shdrs[shdrs[relsec].sh_info].sh_addralign +
			   rel[i].r_offset;

		/* This is the symbol it is referring to.  Note that all
		   undefined symbols have been resolved. */
		sym = (GElf_Sym *)shdrs[symindex].sh_addr +
		      GELF_R_SYM(rel[i].r_info);

		if (GELF_ST_TYPE(sym[i].st_info) == STT_SECTION &&
		    sym->st_shndx < uelf->info.hdr->e_shnum)
			sym_name = uelf->info.shstrtab +
				   shdrs[sym->st_shndx].sh_name;
		else
			sym_name = uelf->strtab + sym->st_name;

		log_debug("type %d st_value %lx r_addend %lx loc %lx\n",
			  (int)GELF_R_TYPE(rel[i].r_info), sym->st_value,
			  rel[i].r_addend, (u64)loc);

		val = sym->st_value + rel[i].r_addend;
		switch (GELF_R_TYPE(rel[i].r_info)) {
		case R_X86_64_NONE:
			break;
		case R_X86_64_64:
			if (*(u64 *)loc != 0)
				goto invalid_relocation;
			memcpy(loc, &val, 8);
			break;
		case R_X86_64_32:
			if (*(u32 *)loc != 0)
				goto invalid_relocation;
			memcpy(loc, &val, 4);
			if (val != *(u32 *)loc &&
			    (GELF_ST_TYPE(sym->st_info) != STT_SECTION))
				goto overflow;
			break;
		case R_X86_64_32S:
			if (*(s32 *)loc != 0)
				goto invalid_relocation;
			memcpy(loc, &val, 4);
			if ((s64)val != *(s32 *)loc &&
			    (GELF_ST_TYPE(sym->st_info) != STT_SECTION))
				goto overflow;
			break;
		case R_X86_64_TLSGD:
		case R_X86_64_GOTTPOFF:
		case R_X86_64_GOTPCRELX:
		case R_X86_64_REX_GOTPCRELX:
			if (sym->st_value == 0)
				goto overflow;
			/* G + GOT + A*/
			val = sym->st_value + rel[i].r_addend;
		case R_X86_64_PC32:
		case R_X86_64_PLT32:
			if (*(u32 *)loc != 0)
				goto invalid_relocation;
			val -= (u64)real_loc;
			memcpy(loc, &val, 4);
			break;
		case R_X86_64_PC64:
			if (*(u64 *)loc != 0)
				goto invalid_relocation;
			val -= (u64)real_loc;
			memcpy(loc, &val, 8);
			break;
		case R_X86_64_TPOFF32:
			tls_size = ALIGN(uelf->relf->tls_size,
					 uelf->relf->tls_align);
			// %fs + val - tls_size
			if (val >= tls_size)
				goto overflow;
			val -= (u64)tls_size;
			memcpy(loc, &val, 4);
			break;
		default:
			log_error("Unknown rela relocation: %lu\n",
				  GELF_R_TYPE(rel[i].r_info));
			return -ENOEXEC;
		}
	}
	return 0;

invalid_relocation:
	log_error("upatch: Skipping invalid relocation target, \
        existing value is nonzero for type %d, loc %p, name %s\n",
		  (int)GELF_R_TYPE(rel[i].r_info), loc, sym_name);
	return -ENOEXEC;

overflow:
	log_error("upatch: overflow in relocation type %d name %s\n",
		  (int)GELF_R_TYPE(rel[i].r_info), sym_name);
	return -ENOEXEC;
}
