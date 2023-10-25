// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 HUAWEI, Inc.
 *
 * Authors:
 *   Zongwu Li <lzw32321226@gmail.com>
 *
 */

#include <errno.h>
#include <string.h>

#include "log.h"
#include "upatch-common.h"
#include "upatch-elf.h"
#include "upatch-resolve.h"

static unsigned long resolve_symbol(struct upatch_elf *uelf,
				    struct object_file *obj, const char *name,
				    GElf_Sym patch_sym)
{
	unsigned int i;
	unsigned long elf_addr = 0;
	char *sym_name = NULL, *tmp;
	GElf_Shdr *sechdr;
	GElf_Sym *sym;
	GElf_Rela *rela;
	struct running_elf *relf = uelf->relf;

	if (GELF_ST_TYPE(patch_sym.st_info) == STT_GNU_IFUNC &&
	    (relf->info.hdr->e_ident[EI_OSABI] == ELFOSABI_GNU ||
	     relf->info.hdr->e_ident[EI_OSABI] == ELFOSABI_FREEBSD))
		goto out_plt;

	/*
	 * In a shared library with position-independent code (PIC) (no pie),
	 * Such code accesses all constant addresses through a global offset table
	 * (GOT).
	 * TODO: consider check PIE
	 */
	if (relf->info.hdr->e_type == ET_DYN &&
	    GELF_ST_BIND(patch_sym.st_info) == STB_GLOBAL &&
	    (GELF_ST_TYPE(patch_sym.st_info) == STT_OBJECT ||
	     GELF_ST_TYPE(patch_sym.st_info) == STT_FUNC))
		goto out_plt;

	/* handle symbol table first, in most cases, symbol table does not exist */
	sechdr = &relf->info.shdrs[relf->index.sym];
	sym = (void *)relf->info.hdr + sechdr->sh_offset;
	for (i = 0; i < sechdr->sh_size / sizeof(GElf_Sym); i++) {
		sym_name = relf->strtab + sym[i].st_name;
		/* FIXME: handle version for external function */
		tmp = strchr(sym_name, '@');
		if (tmp != NULL)
			*tmp = '\0';
		if (streql(sym_name, name) && sym[i].st_shndx != SHN_UNDEF) {
			log_debug(
				"found resolved undefined symbol %s at 0x%lx \n",
				name, sym[i].st_value);
			elf_addr = relf->load_bias + sym[i].st_value;
			goto out;
		}
	}

	/*
	 * Handle external symbol, several possible solutions here:
	 * 1. use symbol address from .dynsym, but most of its address is still
	 * undefined
	 * 2. use address from PLT/GOT, problems are:
	 *    1) range limit(use jmp table?)
	 *    2) only support existed symbols
	 * 3. read symbol from library, combined with load_bias, calculate it
	 * directly and then worked with jmp table.
	 *
	 * Currently, we will try approach 1 and approach 2.
	 * Approach 3 is more general, but difficulty to implement.
	 */
out_plt:
	if (!relf->index.dynsym)
		goto out;

	sechdr = &relf->info.shdrs[relf->index.dynsym];
	sym = (void *)relf->info.hdr + sechdr->sh_offset;

	/* handle external function */
	if (!relf->index.rela_plt)
		goto out_got;

	sechdr = &relf->info.shdrs[relf->index.rela_plt];
	rela = (void *)relf->info.hdr + sechdr->sh_offset;
	for (i = 0; i < sechdr->sh_size / sizeof(GElf_Rela); i++) {
		unsigned long r_sym = GELF_R_SYM(rela[i].r_info);
		/* for executable file, r_offset is virtual address of PLT table */
		unsigned long tmp_addr = relf->load_bias + rela[i].r_offset;

		/* some rela don't have the symbol index, use the symbol's value and
		 * rela's addend to find the symbol. for example, R_X86_64_IRELATIVE.
		 */
		if (r_sym == 0) {
			if (rela[i].r_addend != patch_sym.st_value)
				continue;
			sprintf(sym_name, "%lx", rela[i].r_addend);
		} else {
			/* ATTENTION: should we consider the relocation type ? */
			sym_name = relf->dynstrtab + sym[r_sym].st_name;
			/* FIXME: consider version of the library */
			tmp = strchr(sym_name, '@');
			if (tmp != NULL)
				*tmp = '\0';

			if (!(streql(sym_name, name) &&
			      (GELF_ST_TYPE(sym[r_sym].st_info) == STT_FUNC ||
			       GELF_ST_TYPE(sym[r_sym].st_info) == STT_TLS)))
				continue;
		}

		elf_addr = insert_plt_table(
			uelf, obj, GELF_R_TYPE(rela[i].r_info), tmp_addr);
		log_debug("found unresolved plt.rela %s at 0x%lx -> 0x%lx\n",
			  sym_name, rela[i].r_offset, elf_addr);
		goto out;
	}

out_got:
	/* handle external object, we need get it's address, used for
	 * R_X86_64_REX_GOTPCRELX */
	if (!relf->index.rela_dyn)
		goto out;

	sechdr = &relf->info.shdrs[relf->index.rela_dyn];
	rela = (void *)relf->info.hdr + sechdr->sh_offset;
	for (i = 0; i < sechdr->sh_size / sizeof(GElf_Rela); i++) {
		unsigned long r_sym = GELF_R_SYM(rela[i].r_info);
		/* for executable file, r_offset is virtual address of GOT table */
		unsigned long tmp_addr = relf->load_bias + rela[i].r_offset;

		if (r_sym == 0) {
			if (rela[i].r_addend != patch_sym.st_value)
				continue;
			sprintf(sym_name, "%lx", rela[i].r_addend);
		} else {
			sym_name = relf->dynstrtab + sym[r_sym].st_name;
			/* TODO: don't care about its version here */
			tmp = strchr(sym_name, '@');
			if (tmp != NULL)
				*tmp = '\0';

			/* function could also be part of the GOT with the type
			 * R_X86_64_GLOB_DAT */
			if (!streql(sym_name, name))
				continue;
		}

		elf_addr = insert_got_table(
			uelf, obj, GELF_R_TYPE(rela[i].r_info), tmp_addr);
		log_debug("found unresolved .got %s at 0x%lx \n", sym_name,
			  elf_addr);
		goto out;
	}

	// get symbol address from .dynsym
	sechdr = &relf->info.shdrs[relf->index.dynsym];
	sym = (void *)relf->info.hdr + sechdr->sh_offset;
	for (i = 0; i < sechdr->sh_size / sizeof(GElf_Sym); i++) {
		unsigned long tmp_addr;

		/* only need the st_value that is not 0 */
		if (sym[i].st_value == 0)
			continue;

		sym_name = relf->dynstrtab + sym[i].st_name;
		/* TODO: don't care about its version here */
		tmp = strchr(sym_name, '@');
		if (tmp != NULL)
			*tmp = '\0';

		/* function could also be part of the GOT with the type
		 * R_X86_64_GLOB_DAT */
		if (!streql(sym_name, name))
			continue;

		tmp_addr = relf->load_bias + sym[i].st_value;
		elf_addr = insert_got_table(uelf, obj, 0, tmp_addr);
		log_debug("found unresolved .got %s at 0x%lx \n", sym_name,
			  elf_addr);
		goto out;
	}

out:
	if (!elf_addr) {
		log_error("unable to found valid symbol %s \n", name);
	}
	return elf_addr;
}

int simplify_symbols(struct upatch_elf *uelf, struct object_file *obj)
{
	GElf_Sym *sym = (void *)uelf->info.shdrs[uelf->index.sym].sh_addr;
	unsigned long secbase;
	unsigned int i;
	int ret = 0;
	unsigned long elf_addr;

	for (i = 1; i < uelf->num_syms; i++) {
		const char *name;

		if (GELF_ST_TYPE(sym[i].st_info) == STT_SECTION &&
		    sym[i].st_shndx < uelf->info.hdr->e_shnum)
			name = uelf->info.shstrtab +
			       uelf->info.shdrs[sym[i].st_shndx].sh_name;
		else
			name = uelf->strtab + sym[i].st_name;

		switch (sym[i].st_shndx) {
		case SHN_COMMON:
			log_debug("unsupported Common symbol: %s\n", name);
			ret = -ENOEXEC;
			break;
		case SHN_ABS:
			break;
		case SHN_UNDEF:
			elf_addr = resolve_symbol(uelf, obj, name, sym[i]);
			if (!elf_addr)
				ret = -ENOEXEC;
			sym[i].st_value = elf_addr;
			log_debug("resolved symbol %s at 0x%lx \n", name,
				  (unsigned long)sym[i].st_value);
			break;
		case SHN_LIVEPATCH:
			sym[i].st_value += uelf->relf->load_bias;
			log_debug("resolved livepatch symbol %s at 0x%lx \n",
				  name, (unsigned long)sym[i].st_value);
			break;
		default:
			/* use real address to calculate secbase */
			secbase =
				uelf->info.shdrs[sym[i].st_shndx].sh_addralign;
			sym[i].st_value += secbase;
			log_debug("normal symbol %s at 0x%lx \n", name,
				  (unsigned long)sym[i].st_value);
			break;
		}
	}

	return ret;
}