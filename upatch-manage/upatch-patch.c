// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 HUAWEI, Inc.
 *
 * Authors:
 *   Zongwu Li <lzw32321226@gmail.com>
 *
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/time.h>

#include "log.h"
#include "upatch-common.h"
#include "upatch-patch.h"
#include "upatch-ptrace.h"
#include "upatch-relocation.h"
#include "upatch-resolve.h"

#define GET_MICROSECONDS(a, b) \
	((a.tv_sec - b.tv_sec) * 1000000 + (a.tv_usec - b.tv_usec))

#ifndef ARCH_SHF_SMALL
#define ARCH_SHF_SMALL 0
#endif
#ifndef SHF_RO_AFTER_INIT
#define SHF_RO_AFTER_INIT 0x00200000
#endif

/* If this is set, the section belongs in the init part of the module */
#define BITS_PER_LONG sizeof(unsigned long) * 8

static GElf_Off calculate_load_address(struct running_elf *relf,
				       bool check_code)
{
	int i;
	GElf_Off min_addr = -1;

	/* TODO: for ET_DYN, consider check PIE */
	if (relf->info.hdr->e_type != ET_EXEC &&
	    relf->info.hdr->e_type != ET_DYN) {
		log_error("invalid elf type, it should be ET_EXEC or ET_DYN\n");
		goto out;
	}

	for (i = 0; i < relf->info.hdr->e_phnum; ++i) {
		if (relf->phdrs[i].p_type != PT_LOAD)
			continue;
		if (!check_code ||
		    (check_code && (relf->phdrs[i].p_flags & PF_X)))
			min_addr = (min_addr > relf->phdrs[i].p_vaddr) ?
					   relf->phdrs[i].p_vaddr :
					   min_addr;
		// min_addr = min(min_addr, relf->phdrs[i].p_vaddr);
	}

out:
	return min_addr;
}

static unsigned long calculate_mem_load(struct object_file *obj)
{
	struct obj_vm_area *ovma;
	unsigned long load_addr = -1;

	list_for_each_entry(ovma, &obj->vma, list) {
		if (ovma->inmem.prot & PROT_EXEC) {
			load_addr = (load_addr > ovma->inmem.start) ?
					    ovma->inmem.start :
					    load_addr;
		}
	}

	return load_addr;
}

static int rewrite_section_headers(struct upatch_elf *uelf)
{
	unsigned int i;

	/* Handle SHF_ALLOC in this part */

	/* This should always be true, but let's be sure. */
	uelf->info.shdrs[0].sh_addr = 0;
	uelf->info.shdrs[0].sh_addralign = 0;

	for (i = 1; i < uelf->info.hdr->e_shnum; i++) {
		GElf_Shdr *shdr = &uelf->info.shdrs[i];
		if (shdr->sh_type != SHT_NOBITS &&
		    uelf->info.patch_size < shdr->sh_offset + shdr->sh_size) {
			log_error("upatch len %lu truncated\n",
				  uelf->info.patch_size);
			return -ENOEXEC;
		}

		/* Mark all sections sh_addr with their address in the
		   temporary image. */
		shdr->sh_addr = (size_t)uelf->info.hdr + shdr->sh_offset;
		log_debug("section %s at 0x%lx \n",
			  uelf->info.shstrtab + shdr->sh_name, shdr->sh_addr);
	}

	return 0;
}

/* Additional bytes needed by arch in front of individual sections */
unsigned int arch_mod_section_prepend(struct upatch_elf *uelf,
				      unsigned int section)
{
	/* default implementation just returns zero */
	return 0;
}

static long get_offset(struct upatch_elf *uelf, unsigned int *size,
		       GElf_Shdr *sechdr, unsigned int section)
{
	long ret;

	*size += arch_mod_section_prepend(uelf, section);
	ret = ALIGN(*size, sechdr->sh_addralign ?: 1);
	*size = ret + sechdr->sh_size;
	return ret;
}

static void layout_upatch_info(struct upatch_elf *uelf)
{
	GElf_Shdr *upatch_func = uelf->info.shdrs + uelf->index.upatch_funcs;
	int num = upatch_func->sh_size / sizeof(struct upatch_patch_func);

	uelf->core_layout.info_size = uelf->core_layout.size;
	uelf->core_layout.size += sizeof(struct upatch_info) +
				  num * sizeof(struct upatch_info_func);
	uelf->core_layout.size = PAGE_ALIGN(uelf->core_layout.size);
}

static void layout_jmptable(struct upatch_elf *uelf)
{
	uelf->jmp_cur_entry = 0;
	uelf->jmp_max_entry = JMP_TABLE_MAX_ENTRY;
	uelf->jmp_offs = ALIGN(uelf->core_layout.size, sizeof(unsigned long));
	uelf->core_layout.size =
		uelf->jmp_offs + uelf->jmp_max_entry * get_jmp_table_entry();
	uelf->core_layout.text_size = uelf->core_layout.size;
}

static void layout_sections(struct upatch_elf *uelf)
{
	static unsigned long const masks[][2] = {
		/* NOTE: all executable code must be the last section
		 * in this array; otherwise modify the text_size
		 * finder in the two loops below */
		{ SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_SMALL },
		{ SHF_ALLOC, SHF_WRITE | ARCH_SHF_SMALL },
		{ SHF_RO_AFTER_INIT | SHF_ALLOC, ARCH_SHF_SMALL },
		{ SHF_WRITE | SHF_ALLOC, ARCH_SHF_SMALL },
		{ ARCH_SHF_SMALL | SHF_ALLOC, 0 }
	};
	unsigned int m, i;

	for (i = 0; i < uelf->info.hdr->e_shnum; i++)
		uelf->info.shdrs[i].sh_entsize = ~0UL;

	log_debug("upatch section allocation order: \n");
	for (m = 0; m < ARRAY_SIZE(masks); ++m) {
		for (i = 0; i < uelf->info.hdr->e_shnum; ++i) {
			GElf_Shdr *s = &uelf->info.shdrs[i];
			const char *sname = uelf->info.shstrtab + s->sh_name;

			if ((s->sh_flags & masks[m][0]) != masks[m][0] ||
			    (s->sh_flags & masks[m][1]) ||
			    s->sh_entsize != ~0UL)
				continue;

			s->sh_entsize =
				get_offset(uelf, &uelf->core_layout.size, s, i);
			log_debug("\tm = %d; %s: sh_entsize: 0x%lx\n", m, sname,
				  s->sh_entsize);
		}
		switch (m) {
		case 0: /* executable */
			uelf->core_layout.size =
				PAGE_ALIGN(uelf->core_layout.size);
			uelf->core_layout.text_size = uelf->core_layout.size;
			break;
		case 1: /* RO: text and ro-data */
			uelf->core_layout.size =
				PAGE_ALIGN(uelf->core_layout.size);
			uelf->core_layout.ro_size = uelf->core_layout.size;
			break;
		case 2: /* RO after init */
			uelf->core_layout.size =
				PAGE_ALIGN(uelf->core_layout.size);
			uelf->core_layout.ro_after_init_size =
				uelf->core_layout.size;
			break;
		case 3: /* whole core */
			uelf->core_layout.size =
				PAGE_ALIGN(uelf->core_layout.size);
			break;
		}
	}
}

/* TODO: only included used symbol */
static bool is_upatch_symbol(const GElf_Sym *src, const GElf_Shdr *sechdrs,
			     unsigned int shnum)
{
	return true;
}
/*
 * We only allocate and copy the strings needed by the parts of symtab
 * we keep.  This is simple, but has the effect of making multiple
 * copies of duplicates.  We could be more sophisticated, see
 * linux-kernel thread starting with
 * <73defb5e4bca04a6431392cc341112b1@localhost>.
 */
static void layout_symtab(struct upatch_elf *uelf)
{
	GElf_Shdr *symsect = uelf->info.shdrs + uelf->index.sym;
	GElf_Shdr *strsect = uelf->info.shdrs + uelf->index.str;
	/* TODO: only support same arch as kernel now */
	const GElf_Sym *src;
	unsigned int i, nsrc, ndst, strtab_size = 0;

	/* Put symbol section at end of init part of module. */
	symsect->sh_flags |= SHF_ALLOC;
	symsect->sh_entsize = get_offset(uelf, &uelf->core_layout.size, symsect,
					 uelf->index.sym);
	log_debug("\t%s\n", uelf->info.shstrtab + symsect->sh_name);

	src = (void *)uelf->info.hdr + symsect->sh_offset;
	nsrc = symsect->sh_size / sizeof(*src);

	/* Compute total space required for the symbols' strtab. */
	for (ndst = i = 0; i < nsrc; i++) {
		if (i == 0 || is_upatch_symbol(src + i, uelf->info.shdrs,
					       uelf->info.hdr->e_shnum)) {
			strtab_size +=
				strlen(&uelf->strtab[src[i].st_name]) + 1;
			ndst++;
		}
	}

	/* Append room for core symbols at end of core part. */
	uelf->symoffs =
		ALIGN(uelf->core_layout.size, symsect->sh_addralign ?: 1);
	uelf->stroffs = uelf->core_layout.size =
		uelf->symoffs + ndst * sizeof(GElf_Sym);
	uelf->core_layout.size += strtab_size;
	uelf->core_typeoffs = uelf->core_layout.size;
	uelf->core_layout.size += ndst * sizeof(char);
	uelf->core_layout.size = PAGE_ALIGN(uelf->core_layout.size);

	/* Put string table section at end of init part of module. */
	strsect->sh_flags |= SHF_ALLOC;
	strsect->sh_entsize = get_offset(uelf, &uelf->core_layout.size, strsect,
					 uelf->index.str);
	uelf->core_layout.size = PAGE_ALIGN(uelf->core_layout.size);
	log_debug("\t%s\n", uelf->info.shstrtab + strsect->sh_name);
}

static void *upatch_alloc(struct object_file *obj, size_t sz)
{
	int ret;
	unsigned long addr;
	struct vm_hole *hole = NULL;

	addr = object_find_patch_region(obj, sz, &hole);
	if (!addr)
		return NULL;

	addr = upatch_mmap_remote(proc2pctx(obj->proc), addr, sz,
				  PROT_READ | PROT_WRITE | PROT_EXEC,
				  MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1,
				  0);
	if (addr == 0) {
		log_error("remote alloc memory for patch failed\n");
		return NULL;
	}

	log_debug("allocated 0x%lx bytes at 0x%lx for '%s' patch\n", sz, addr,
		  obj->name);

	// log_debug("Marking this space as busy\n");
	ret = vm_hole_split(hole, addr, addr + sz);
	if (ret) {
		// TODO: clear
		log_error("vm_hole_split failed\n");
		return NULL;
	}

	return (void *)addr;
}

static void __upatch_memfree(struct object_file *obj, void *base,
			     unsigned int size)
{
	log_debug("munmap upatch memory at: %p\n", base);
	if (upatch_munmap_remote(proc2pctx(obj->proc), (unsigned long)base,
				 size)) {
		log_error("Failed to munmap upatch memory at: %p\n", base);
	}
}

static int __alloc_memory(struct object_file *obj_file,
			  struct upatch_layout *layout)
{
	/* Do the allocs. */
	layout->base = upatch_alloc(obj_file, layout->size);
	if (!layout->base) {
		log_error("alloc upatch core_layout memory failed: %p \n",
			  layout->base);
		return -ENOMEM;
	}

	layout->kbase = malloc(layout->size);
	if (!layout->kbase) {
		__upatch_memfree(obj_file, layout->base, layout->size);
		return -ENOMEM;
	}

	memset(layout->kbase, 0, layout->size);

	return 0;
}

static int alloc_memory(struct upatch_elf *uelf, struct object_file *obj)
{
	int i, ret;

	/* Do the allocs. */
	ret = __alloc_memory(obj, &uelf->core_layout);
	if (ret) {
		log_error("alloc upatch module memory failed: %d \n", ret);
		return ret;
	}

	/* Transfer each section which specifies SHF_ALLOC */
	log_debug("final section addresses:\n");
	for (i = 0; i < uelf->info.hdr->e_shnum; i++) {
		void *kdest;
		void *dest;
		GElf_Shdr *shdr = &uelf->info.shdrs[i];

		if (!(shdr->sh_flags & SHF_ALLOC))
			continue;

		kdest = uelf->core_layout.kbase + shdr->sh_entsize;
		dest = uelf->core_layout.base + shdr->sh_entsize;

		if (shdr->sh_type != SHT_NOBITS)
			memcpy(kdest, (void *)shdr->sh_addr, shdr->sh_size);
		shdr->sh_addr = (unsigned long)kdest;
		/* overuse this attr to record user address */
		shdr->sh_addralign = (unsigned long)dest;
		log_debug("\t0x%lx %s <- 0x%lx\n", (long)kdest,
			  uelf->info.shstrtab + shdr->sh_name, (long)dest);
	}

	return 0;
}

static int post_memory(struct upatch_elf *uelf, struct object_file *obj)
{
	int ret = 0;

	log_debug("post kbase %lx(%x) to base %lx\n",
		  (unsigned long)uelf->core_layout.kbase,
		  uelf->core_layout.size,
		  (unsigned long)uelf->core_layout.base);
	ret = upatch_process_mem_write(obj->proc, uelf->core_layout.kbase,
				       (unsigned long)uelf->core_layout.base,
				       uelf->core_layout.size);
	if (ret) {
		log_error("can't move kbase to base - %d\n", ret);
		goto out;
	}

out:
	return ret;
}

static int complete_info(struct upatch_elf *uelf, struct object_file *obj)
{
	int ret = 0, i;
	struct upatch_info *uinfo =
		(void *)uelf->core_layout.kbase + uelf->core_layout.info_size;
	struct upatch_patch_func *upatch_funcs_addr =
		(void *)uelf->info.shdrs[uelf->index.upatch_funcs].sh_addr;

	// TODO: uinfo->id
	memcpy(uinfo, UPATCH_HEADER, strlen(UPATCH_HEADER));
	uinfo->size = uelf->core_layout.size - uelf->core_layout.info_size;
	uinfo->start = (unsigned long)uelf->core_layout.base;
	uinfo->end =
		(unsigned long)uelf->core_layout.base + uelf->core_layout.size;
	uinfo->changed_func_num =
		uelf->info.shdrs[uelf->index.upatch_funcs].sh_size /
		sizeof(struct upatch_patch_func);

	log_debug("change insn:\n");
	for (i = 0; i < uinfo->changed_func_num; ++i) {
		struct upatch_info_func *upatch_func =
			(void *)uelf->core_layout.kbase +
			uelf->core_layout.info_size +
			sizeof(struct upatch_info) +
			i * sizeof(struct upatch_info_func);

		upatch_func->old_addr =
			upatch_funcs_addr[i].old_addr + uelf->relf->load_bias;
		upatch_func->new_addr = upatch_funcs_addr[i].new_addr;
		ret = upatch_process_mem_read(obj->proc, upatch_func->old_addr,
					      &upatch_func->old_insn,
					      get_origin_insn_len());
		if (ret) {
			log_error("can't read origin insn at 0x%lx - %d\n",
				  upatch_func->old_addr, ret);
			goto out;
		}

		upatch_func->new_insn = get_new_insn(obj, upatch_func->old_addr,
						     upatch_func->new_addr);

		log_debug("\t0x%lx(0x%lx -> 0x%lx)\n", upatch_func->old_addr,
			  upatch_func->old_insn, upatch_func->new_insn);
	}

out:
	return ret;
}

static int unapply_patch(struct object_file *obj,
			 struct upatch_info_func *funcs,
			 unsigned int changed_func_num)
{
	int ret = 0, i;

	log_debug("change insn:\n");
	for (i = 0; i < changed_func_num; ++i) {
		log_debug("\t0x%lx(0x%lx -> 0x%lx)\n", funcs[i].old_addr,
			  funcs[i].new_insn, funcs[i].old_insn);

		ret = upatch_process_mem_write(obj->proc, &funcs[i].old_insn,
					       (unsigned long)funcs[i].old_addr,
					       get_origin_insn_len());

		if (ret) {
			log_error("can't write old insn at 0x%lx - %d\n",
				  funcs[i].old_addr, ret);
			goto out;
		}
	}

out:
	return ret;
}

static int apply_patch(struct upatch_elf *uelf, struct object_file *obj)
{
	int ret = 0, i;
	struct upatch_info *uinfo =
		(void *)uelf->core_layout.kbase + uelf->core_layout.info_size;

	for (i = 0; i < uinfo->changed_func_num; ++i) {
		struct upatch_info_func *upatch_func =
			(void *)uelf->core_layout.kbase +
			uelf->core_layout.info_size +
			sizeof(struct upatch_info) +
			i * sizeof(struct upatch_info_func);

		ret = upatch_process_mem_write(
			obj->proc, &upatch_func->new_insn,
			(unsigned long)upatch_func->old_addr,
			get_origin_insn_len());
		if (ret) {
			log_error(
				"can't ptrace upatch func at 0x%lx(0x%lx) - %d\n",
				upatch_func->old_addr, upatch_func->new_insn,
				ret);
			goto out;
		}
	}

out:
	if (ret) {
		unapply_patch(obj,
			      (void *)uelf->core_layout.kbase +
				      uelf->core_layout.info_size +
				      sizeof(struct upatch_info),
			      i);
	}
	return ret;
}

static int upatch_mprotect(struct upatch_elf *uelf, struct object_file *obj)
{
	int ret;

	if (uelf->core_layout.text_size > 0) {
		ret = upatch_mprotect_remote(
			proc2pctx(obj->proc),
			(unsigned long)uelf->core_layout.base,
			uelf->core_layout.text_size, PROT_READ | PROT_EXEC);
		if (ret < 0) {
			log_error(
				"Failed to change upatch text protection to r-x");
			return ret;
		}
	}

	if (uelf->core_layout.ro_size > uelf->core_layout.text_size) {
		ret = upatch_mprotect_remote(
			proc2pctx(obj->proc),
			(unsigned long)uelf->core_layout.base +
				uelf->core_layout.text_size,
			uelf->core_layout.ro_size - uelf->core_layout.text_size,
			PROT_READ);
		if (ret < 0) {
			log_error(
				"Failed to change upatch ro protection to r--");
			return ret;
		}
	}

	if (uelf->core_layout.ro_after_init_size > uelf->core_layout.ro_size) {
		ret = upatch_mprotect_remote(
			proc2pctx(obj->proc),
			(unsigned long)uelf->core_layout.base +
				uelf->core_layout.ro_size,
			uelf->core_layout.ro_after_init_size -
				uelf->core_layout.ro_size,
			PROT_READ);
		if (ret < 0) {
			log_error(
				"Failed to change upatch ro init protection to r--");
			return ret;
		}
	}

	if (uelf->core_layout.info_size >
	    uelf->core_layout.ro_after_init_size) {
		ret = upatch_mprotect_remote(
			proc2pctx(obj->proc),
			(unsigned long)uelf->core_layout.base +
				uelf->core_layout.ro_after_init_size,
			uelf->core_layout.info_size -
				uelf->core_layout.ro_after_init_size,
			PROT_READ | PROT_WRITE);
		if (ret < 0) {
			log_error(
				"Failed to change upatch rw protection to rw-");
			return ret;
		}
	}

	if (uelf->core_layout.size > uelf->core_layout.info_size) {
		ret = upatch_mprotect_remote(
			proc2pctx(obj->proc),
			(unsigned long)uelf->core_layout.base +
				uelf->core_layout.info_size,
			uelf->core_layout.size - uelf->core_layout.info_size,
			PROT_READ);
		if (ret < 0) {
			log_error(
				"Failed to change upatch info protection to r--");
			return ret;
		}
	}

	return 0;
}

static int upatch_apply_patches(struct upatch_process *proc,
				struct upatch_elf *uelf)
{
	int ret = 0;
	struct object_file *obj = NULL;
	GElf_Off min_addr;
	bool found = false;

	list_for_each_entry(obj, &proc->objs, list) {
		if (obj->inode == uelf->relf->info.inode) {
			found = true;
			break;
		}
	}

	if (!found) {
		ret = -1;
		log_debug("can't found inode %lu in pid %d\n",
			  uelf->relf->info.inode, proc->pid);
		goto out;
	}

	min_addr = calculate_load_address(uelf->relf, true);
	uelf->relf->load_start = calculate_mem_load(obj);
	uelf->relf->load_bias = uelf->relf->load_start - min_addr;
	log_debug("load_bias = %lx\n", uelf->relf->load_bias);

	ret = rewrite_section_headers(uelf);
	if (ret)
		goto free;

	// Caculate upatch mem size
	layout_jmptable(uelf);
	layout_sections(uelf);
	layout_symtab(uelf);
	layout_upatch_info(uelf);

	log_debug("calculate core_layout = %x \n", uelf->core_layout.size);
	log_debug(
		"core_layout: text_size = %x, ro_size = %x, ro_after_init_size = "
		"%x, info = %x, size = %x\n",
		uelf->core_layout.text_size, uelf->core_layout.ro_size,
		uelf->core_layout.ro_after_init_size,
		uelf->core_layout.info_size, uelf->core_layout.size);

	/*
	 * Map patch as close to the original code as possible.
	 * Otherwise we can't use 32-bit jumps.
	 */
	ret = alloc_memory(uelf, obj);
	if (ret)
		goto free;

	ret = upatch_mprotect(uelf, obj);
	if (ret)
		goto free;

	/* Fix up syms, so that st_value is a pointer to location. */
	ret = simplify_symbols(uelf, obj);
	if (ret)
		goto free;

	/* upatch new address will be updated */
	ret = apply_relocations(uelf);
	if (ret)
		goto free;

	/* upatch upatch info */
	ret = complete_info(uelf, obj);
	if (ret)
		goto free;

	ret = post_memory(uelf, obj);
	if (ret)
		goto free;

	ret = apply_patch(uelf, obj);
	if (ret)
		goto free;

	ret = 0;
	goto out;

// TODO: clear
free:
	__upatch_memfree(obj, uelf->core_layout.base, uelf->core_layout.size);
out:
	return ret;
}

int process_patch(int pid, struct upatch_elf *uelf, struct running_elf *relf)
{
	int ret;
	bool is_calc_time = false;
	struct timeval start_tv, end_tv;
	unsigned long frozen_time;
	struct upatch_process proc;

	// 查看process的信息，pid: maps, mem, cmdline, exe
	ret = upatch_process_init(&proc, pid);
	if (ret < 0) {
		log_error("cannot init process %d\n", pid);
		goto out;
	}

	upatch_process_print_short(&proc);

	ret = upatch_process_mem_open(&proc, MEM_READ);
	if (ret < 0)
		goto out_free;

	// use uprobe to hack function. the program has been executed to the entry
	// point

	/*
	 * For each object file that we want to patch (either binary itself or
	 * shared library) we need its ELF structure to perform relocations.
	 * Because we know uniq BuildID of the object the section addresses
	 * stored in the patch are valid for the original object.
	 */
	// 解析process的mem-maps，获得各个块的内存映射以及phdr
	ret = upatch_process_map_object_files(&proc, NULL);
	if (ret < 0)
		goto out_free;

	is_calc_time = true;
	gettimeofday(&start_tv, NULL);

	/* Finally, attach to process */
	ret = upatch_process_attach(&proc);
	if (ret < 0)
		goto out_free;

	// TODO: 栈解析
	// 应用
	ret = upatch_apply_patches(&proc, uelf);
	if (ret < 0)
		goto out_free;

	ret = 0;

out_free:
	upatch_process_memfree(&proc);
out:
	if (is_calc_time) {
		gettimeofday(&end_tv, NULL);
		frozen_time = GET_MICROSECONDS(end_tv, start_tv);
		log_normal(
			"PID '%d' process patch frozen_time is %ld microsecond\n",
			pid, frozen_time);
	}
	return ret;
}

static int upatch_unapply_patches(struct upatch_process *proc)
{
	int ret = 0;
	struct object_file *obj = NULL;
	struct object_patch *patch = NULL;
	bool found = false;

	list_for_each_entry(obj, &proc->objs, list) {
		if (obj->is_patch) {
			found = true;
			break;
		}
	}

	if (!found) {
		ret = -1;
		log_debug("can't found patch info memory\n");
		goto out;
	}

	found = false;
	list_for_each_entry(patch, &obj->applied_patch, list) {
		// TODO: check upatch_info id
		found = true;
		break;
	}

	if (!found) {
		ret = -1;
		log_debug("can't found patch info memory\n");
		goto out;
	}

	ret = unapply_patch(obj, patch->funcs, patch->uinfo->changed_func_num);
	if (ret)
		goto out;

	log_debug("munmap upatch layout core:\n");
	__upatch_memfree(obj, (void *)patch->uinfo->start,
			 patch->uinfo->end - patch->uinfo->start);
out:
	return ret;
}

int process_unpatch(int pid)
{
	int ret;
	bool is_calc_time = false;
	struct timeval start_tv, end_tv;
	unsigned long frozen_time;
	struct upatch_process proc;

	// TODO: check build id
	// TODO: 栈解析
	// 查看process的信息，pid: maps, mem, cmdline, exe
	ret = upatch_process_init(&proc, pid);
	if (ret < 0) {
		log_error("cannot init process %d\n", pid);
		goto out;
	}

	upatch_process_print_short(&proc);

	ret = upatch_process_mem_open(&proc, MEM_READ);
	if (ret < 0)
		goto out_free;

	// use uprobe to hack function. the program has been executed to the entry
	// point

	/*
	 * For each object file that we want to patch (either binary itself or
	 * shared library) we need its ELF structure to perform relocations.
	 * Because we know uniq BuildID of the object the section addresses
	 * stored in the patch are valid for the original object.
	 */
	// 解析process的mem-maps，获得各个块的内存映射以及phdr
	ret = upatch_process_map_object_files(&proc, NULL);
	if (ret < 0)
		goto out_free;

	is_calc_time = true;
	gettimeofday(&start_tv, NULL);

	/* Finally, attach to process */
	ret = upatch_process_attach(&proc);
	if (ret < 0)
		goto out_free;

	// 应用
	ret = upatch_unapply_patches(&proc);
	if (ret < 0)
		goto out_free;

	ret = 0;

out_free:
	upatch_process_memfree(&proc);
out:
	if (is_calc_time) {
		gettimeofday(&end_tv, NULL);
		frozen_time = GET_MICROSECONDS(end_tv, start_tv);
		log_normal(
			"PID '%d' process patch frozen_time is %ld microsecond\n",
			pid, frozen_time);
	}
	return ret;
}

static int upatch_info(struct upatch_process *proc)
{
	struct object_file *obj = NULL;
	struct object_patch *patch = NULL;
	bool found = false;

	list_for_each_entry(obj, &proc->objs, list) {
		if (obj->is_patch) {
			found = true;
			break;
		}
	}

	if (!found)
		return found;

	found = false;
	list_for_each_entry(patch, &obj->applied_patch, list) {
		// TODO: check upatch_info id
		found = true;
		break;
	}

	return found;
}

int process_info(int pid)
{
	int ret;
	struct upatch_process proc;
	char *status = "error";

	// TODO: check build id
	// TODO: 栈解析
	// 查看process的信息，pid: maps, mem, cmdline, exe
	ret = upatch_process_init(&proc, pid);
	if (ret < 0) {
		log_error("cannot init process %d\n", pid);
		goto out;
	}

	ret = upatch_process_mem_open(&proc, MEM_READ);
	if (ret < 0)
		goto out_free;

	ret = upatch_process_map_object_files(&proc, NULL);
	if (ret < 0)
		goto out_free;

	// 应用
	ret = upatch_info(&proc);
	if (ret)
		status = "active";
	else
		status = "removed";

	ret = 0;

out_free:
	upatch_process_memfree(&proc);
out:
	log_normal("%s\n", status);
	return ret;
}
