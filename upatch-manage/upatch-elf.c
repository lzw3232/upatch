// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 HUAWEI, Inc.
 *
 * Authors:
 *   Zongwu Li <lzw32321226@gmail.com>
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "log.h"
#include "upatch-common.h"
#include "upatch-elf.h"
#include "upatch-ptrace.h"

static int read_from_offset(int fd, void **buf, int len, off_t offset)
{
	int ret = -1;
	size_t size;

	*buf = malloc(len);
	if (*buf == NULL) {
		printf("malloc failed \n");
		goto out;
	}

	size = pread(fd, *buf, len, offset);
	if (size == -1) {
		ret = -errno;
		printf("read file failed - %d \n", -ret);
		goto out;
	}

	ret = 0;
out:
	return ret;
}

static int open_elf(struct elf_info *einfo, const char *name)
{
	int ret = 0, fd = -1, i;
	char *sec_name;
	struct stat st;

	// TODO: check ELF
	fd = open(name, O_RDONLY);
	if (fd == -1)
		ERROR("open %s failed with errno %d \n", name, errno);

	ret = stat(name, &st);
	if (ret)
		ERROR("get %s stat failed with errno %d \n", name, errno);

	ret = read_from_offset(fd, (void **)&einfo->patch_buff, st.st_size, 0);
	if (ret)
		goto out;

	einfo->name = name;
	einfo->inode = st.st_ino;
	einfo->patch_size = st.st_size;
	einfo->hdr = (void *)einfo->patch_buff;
	einfo->shdrs = (void *)einfo->hdr + einfo->hdr->e_shoff;
	einfo->shstrtab = (void *)einfo->hdr +
			  einfo->shdrs[einfo->hdr->e_shstrndx].sh_offset;

	for (i = 0; i < einfo->hdr->e_shnum; ++i) {
		sec_name = einfo->shstrtab + einfo->shdrs[i].sh_name;
		if (streql(sec_name, BUILD_ID_NAME) &&
		    einfo->shdrs[i].sh_type == SHT_NOTE) {
			einfo->num_build_id = i;
			break;
		}
	}

	if (einfo->num_build_id == 0) {
		ret = -EINVAL;
		log_error("no %s found \n", BUILD_ID_NAME);
		goto out;
	}

	log_error("no %ld found \n", einfo->inode);

	ret = 0;
out:
	if (fd != -1)
		close(fd);
	return ret;
}

int upatch_init(struct upatch_elf *uelf, const char *name)
{
	int ret = 0, i;
	char *sec_name;

	memset(uelf, 0, sizeof(struct upatch_elf));

	ret = open_elf(&uelf->info, name);
	if (ret)
		goto out;

	for (i = 1; i < uelf->info.hdr->e_shnum; ++i) {
		sec_name = uelf->info.shstrtab + uelf->info.shdrs[i].sh_name;
		if (uelf->info.shdrs[i].sh_type == SHT_SYMTAB) {
			uelf->num_syms =
				uelf->info.shdrs[i].sh_size / sizeof(GElf_Sym);
			uelf->index.sym = i;
			uelf->index.str = uelf->info.shdrs[i].sh_link;
			uelf->strtab =
				(char *)uelf->info.hdr +
				uelf->info.shdrs[uelf->info.shdrs[i].sh_link]
					.sh_offset;
		} else if (streql(sec_name, UPATCH_FUNC_NAME)) {
			uelf->index.upatch_funcs = i;
		}
	}

	ret = 0;

out:
	return ret;
}

int binary_init(struct running_elf *relf, const char *name)
{
	int ret = 0, i;
	char *sec_name;

	memset(relf, 0, sizeof(struct running_elf));

	ret = open_elf(&relf->info, name);
	if (ret)
		goto out;

	relf->phdrs = (void *)relf->info.hdr + relf->info.hdr->e_phoff;

	for (i = 1; i < relf->info.hdr->e_shnum; i++) {
		sec_name = relf->info.shstrtab + relf->info.shdrs[i].sh_name;
		if (relf->info.shdrs[i].sh_type == SHT_SYMTAB) {
			relf->num_syms =
				relf->info.shdrs[i].sh_size / sizeof(GElf_Sym);
			relf->index.sym = i;
			relf->index.str = relf->info.shdrs[i].sh_link;
			relf->strtab =
				(char *)relf->info.hdr +
				relf->info.shdrs[relf->info.shdrs[i].sh_link]
					.sh_offset;
		} else if (relf->info.shdrs[i].sh_type == SHT_DYNSYM) {
			relf->index.dynsym = i;
			relf->index.dynstr = relf->info.shdrs[i].sh_link;
			relf->dynstrtab =
				(char *)relf->info.hdr +
				relf->info.shdrs[relf->info.shdrs[i].sh_link]
					.sh_offset;
			log_debug("found dynsym with %d \n", i);
		} else if (relf->info.shdrs[i].sh_type == SHT_DYNAMIC) {
			/* Currently, we don't utilize it */
		} else if (streql(sec_name, PLT_RELA_NAME) &&
			   relf->info.shdrs[i].sh_type == SHT_RELA) {
			relf->index.rela_plt = i;
			log_debug("found %s with %d \n", PLT_RELA_NAME, i);
		} else if (streql(sec_name, GOT_RELA_NAME) &&
			   relf->info.shdrs[i].sh_type == SHT_RELA) {
			relf->index.rela_dyn = i;
			log_debug("found %s with %d \n", GOT_RELA_NAME, i);
		}
	}

	for (i = 0; i < relf->info.hdr->e_phnum; i++) {
		if (relf->phdrs[i].p_type == PT_TLS) {
			relf->tls_size = relf->phdrs[i].p_memsz;
			relf->tls_align = relf->phdrs[i].p_align;
			log_debug("found TLS size = %ld, memsz = %ld \n",
				  relf->tls_size, relf->tls_align);
			break;
		}
	}

	ret = 0;

out:
	return ret;
}

bool check_build_id(struct elf_info *uelf, struct elf_info *relf)
{
	return uelf->shdrs[uelf->num_build_id].sh_size ==
		       relf->shdrs[relf->num_build_id].sh_size &&
	       !memcmp(uelf->hdr + uelf->shdrs[uelf->num_build_id].sh_offset,
		       relf->hdr + relf->shdrs[relf->num_build_id].sh_offset,
		       uelf->shdrs[uelf->num_build_id].sh_size);
}

void binary_close(struct running_elf *relf)
{
	// TODO: free relf
	if (relf->info.patch_buff)
		free(relf->info.patch_buff);
}

void upatch_close(struct upatch_elf *uelf)
{
	// TODO: free uelf
	if (uelf->info.patch_buff)
		free(uelf->info.patch_buff);

	if (uelf->core_layout.kbase)
		free(uelf->core_layout.kbase);
}

bool is_upatch_section(const char *name)
{
	return !strncmp(name, ".upatch.", strlen(".upatch."));
}

bool is_note_section(GElf_Word type)
{
	return type == SHT_NOTE;
}
