// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 HUAWEI, Inc.
 *
 * Authors:
 *   Zongwu Li <lzw32321226@gmail.com>
 *
 */

#include "upatch-relocation.h"
#include <errno.h>

#include "log.h"

int apply_relocations(struct upatch_elf *uelf)
{
	unsigned int i;
	int err = 0;

	/* Now do relocations. */
	for (i = 1; i < uelf->info.hdr->e_shnum; i++) {
		unsigned int infosec = uelf->info.shdrs[i].sh_info;
		const char *name =
			uelf->info.shstrtab + uelf->info.shdrs[i].sh_name;

		/* Not a valid relocation section? */
		if (infosec >= uelf->info.hdr->e_shnum)
			continue;

		/* Don't bother with non-allocated sections */
		if (!(uelf->info.shdrs[infosec].sh_flags & SHF_ALLOC))
			continue;

		if (uelf->info.shdrs[i].sh_type == SHT_REL) {
			log_error("do rel relocations for %s \n", name);
			return -EPERM;
		} else if (uelf->info.shdrs[i].sh_type == SHT_RELA) {
			log_debug("do rela relocations for %s \n", name);
			err = apply_relocate_add(uelf, uelf->index.sym, i);
		}

		if (err < 0)
			break;
	}
	return err;
}