/*
 * elf-compare.c
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

#include <libgen.h>

#include "log.h"
#include "elf-common.h"
#include "elf-compare.h"
#include "elf-insn.h"

static void compare_correlated_symbol(struct symbol *sym, struct symbol *symtwin)
{
    // compare bind and type info
    if (sym->sym.st_info != symtwin->sym.st_info ||
	    (sym->sec && !symtwin->sec) ||
	    (symtwin->sec && !sym->sec))
		DIFF_FATAL("symbol info mismatch: %s", sym->name);

    // check if correlated symbols have correlated sections
    if (sym->sec && symtwin->sec && sym->sec->twin != symtwin->sec)
		DIFF_FATAL("symbol changed sections: %s", sym->name);

    // data object can't change size
    if (sym->type == STT_OBJECT && sym->sym.st_size != symtwin->sym.st_size)
		DIFF_FATAL("object size mismatch: %s", sym->name);

	if (sym->sym.st_shndx == SHN_UNDEF || 
        sym->sym.st_shndx == SHN_ABS)
		sym->status = SAME;

    /*
     * For local symbols, we handle them based on their matching sections.
     */
}

void upatch_compare_symbols(struct upatch_elf *uelf)
{
	struct symbol *sym;

	list_for_each_entry(sym, &uelf->symbols, list) {
		if (sym->twin)
			compare_correlated_symbol(sym, sym->twin);
		else
			sym->status = NEW;

		log_debug("symbol %s is %s\n", sym->name, status_str(sym->status));
	}
}

static bool rela_equal(struct rela *rela1, struct rela *rela2)
{
    if (rela1->type != rela2->type ||
        rela1->offset != rela2->offset)
        return false;

    /* TODO: handle altinstr_aux */

    /* TODO: handle rela for toc section */

	if (rela1->string)
		return rela2->string && !strcmp(rela1->string, rela2->string);

	if (rela1->addend != rela2->addend) {
        log_debug("relocation addend has changed from %ld to %ld", rela1->addend, rela2->addend);
		return false;
    }

    return !mangled_strcmp(rela1->sym->name, rela2->sym->name);
}

static void compare_correlated_rela_section(struct section *relasec, struct section *relasec_twin)
{
	struct rela *rela1, *rela2 = NULL;

    /* check relocation item one by one, order matters */
	rela2 = list_entry(relasec_twin->relas.next, struct rela, list);
	list_for_each_entry(rela1, &relasec->relas, list) {
		if (rela_equal(rela1, rela2)) {
			rela2 = list_entry(rela2->list.next, struct rela, list);
			continue;
		}
		relasec->status = CHANGED;
		return;
	}

	relasec->status = SAME;
}

static void compare_correlated_nonrela_section(struct section *sec, struct section *sectwin)
{
	if (sec->sh.sh_type != SHT_NOBITS &&
        (sec->data->d_size != sectwin->data->d_size ||
	    memcmp(sec->data->d_buf, sectwin->data->d_buf, sec->data->d_size)))
		sec->status = CHANGED;
	else
		sec->status = SAME;
}

// we may change status of sec, they are not same
static int compare_correlated_section(struct section *sec, struct section *sectwin)
{
    /* TODO: addr align of rodata has changed. after strlen(str) >= 30, align 8 exists */
    /* compare section headers */
	if (sec->sh.sh_type != sectwin->sh.sh_type ||
	    sec->sh.sh_flags != sectwin->sh.sh_flags ||
	    sec->sh.sh_entsize != sectwin->sh.sh_entsize ||
	    (sec->sh.sh_addralign != sectwin->sh.sh_addralign &&
	    !is_text_section(sec) && !is_string_section(sec))) {
		    DIFF_FATAL("%s section header details differ from %s", sec->name, sectwin->name);
            return -1;
        }

	if (is_note_section(sec)) {
		sec->status = SAME;
		goto out;
	}

	/* As above but for aarch64 */
	if (!strcmp(sec->name, ".rela__patchable_function_entries") ||
	    !strcmp(sec->name, "__patchable_function_entries")) {
		sec->status = SAME;
		goto out;
	}

    /* compare file size and data size(memory size) */
	if (sec->sh.sh_size != sectwin->sh.sh_size ||
	    sec->data->d_size != sectwin->data->d_size ||
        (sec->rela && !sectwin->rela) || (!sec->rela && sectwin->rela)) {
		sec->status = CHANGED;
		goto out;
	}

    if (is_rela_section(sec))
        compare_correlated_rela_section(sec, sectwin);
    else
        compare_correlated_nonrela_section(sec, sectwin);

out:
    if(sec->status == CHANGED)
		log_debug("section %s has changed\n", sec->name);

    return 0;
}

bool upatch_handle_redis_line(const char *symname)
{
	if (!strncmp(symname, "_serverPanic", 12) ||
		!strncmp(symname, "_serverAssert", 13) ||
		!strncmp(symname, "_serverAssertWithInfo", 21) ||
        !strncmp(symname, "rdbReportError", 14) ||
        !strncmp(symname, "RedisModule__Assert", 19))
		return true;
	return false;
}

/* TODO: let user support this list or generate by the compiler ? */
bool check_line_func(struct upatch_elf *uelf, const char *symname)
{
	if (!strncmp(basename(upatch_elf_name), "redis-server", 12))
		return upatch_handle_redis_line(symname);

	return false;
}

/* Determine if a section has changed only due to a __LINE__ bumber change.
 * For example, a WARN() or might_sleep() macro's embedding of the line number into an
 * instruction operand.
 */
static bool _line_macro_change_only(struct upatch_elf *uelf, struct section *sec)
{
    unsigned long offset, insn1_len, insn2_len;
    void *data1, *data2, *insn1, *insn2;
    struct rela *rela;
    bool found, found_any = false;

	if (sec->status != CHANGED ||
		is_rela_section(sec) ||
		!is_text_section(sec) ||
		sec->sh.sh_size != sec->twin->sh.sh_size ||
		!sec->rela ||
		sec->rela->status != SAME)
		return false;

	data1 = sec->twin->data->d_buf;
	data2 = sec->data->d_buf;
	for (offset = 0; offset < sec->sh.sh_size; offset += insn1_len) {
		insn1 = data1 + offset;
		insn2 = data2 + offset;

		insn1_len = insn_length(uelf, insn1);
		insn2_len = insn_length(uelf, insn2);

		if (!insn1_len || !insn2_len)
			ERROR("decode instruction in section %s at offset 0x%lx failed",
				sec->name, offset);

		if (insn1_len != insn2_len)
			return false;

		/* if insn are same, continue*/
		if (!memcmp(insn1, insn2, insn1_len))
			continue;

		log_debug("check list for %s at 0x%lx \n", sec->name, offset);

		/*
		 * Here we found a differece between two instructions of the
		 * same length. Only ignore the change if:
		 *
		 * 1) the instruction match a known pattern of a '__LINE__'
		 * 	  macro immediate value which was embedded in the instruction.
		 *
		 * 2) the instructions are followed by certain expected relocations.
		 *    (white-list)
		 */
		if (!insn_is_load_immediate(uelf, insn1) ||
			!insn_is_load_immediate(uelf, insn2))
			return false;

		found = false;
		list_for_each_entry(rela, &sec->rela->relas, list) {
			if (rela->offset < offset + insn1_len)
				continue;

			if (rela->string)
				continue;

			/* TODO: we may need black list ? */
			if (check_line_func(uelf, rela->sym->name)) {
				found = true;
				break;
			}

			return false;
		}
		if (!found)
			return false;

		found_any = true;
	}

	if (!found_any)
		ERROR("no instruction changes detected for changed section %s",
			sec->name);

    return true;
}

static bool _line_macro_change_only_aarch64(struct upatch_elf *uelf, struct section *sec)
{

	unsigned long start1, start2, size, offset;
	struct rela *rela;
	bool found_any = false, found;
	unsigned int mov_imm_mask = ((1<<16) - 1)<<5;
	unsigned long insn_len = insn_length(uelf, NULL);

	if (sec->status != CHANGED ||
	    is_rela_section(sec) ||
	    !is_text_section(sec) ||
	    sec->sh.sh_size != sec->twin->sh.sh_size ||
	    !sec->rela ||
	    sec->rela->status != SAME)
		return false;

	start1 = (unsigned long)sec->twin->data->d_buf;
	start2 = (unsigned long)sec->data->d_buf;
	size = sec->sh.sh_size;
	for (offset = 0; offset < size; offset += insn_len) {
		if (!memcmp((void *)start1 + offset, (void *)start2 + offset, insn_len))
			continue;

		/* verify it's a mov immediate to w1 */
		if ((*(int *)(start1 + offset) & ~mov_imm_mask) !=
				(*(int *)(start2 + offset) & ~mov_imm_mask))
			return false;

		found = false;
		list_for_each_entry(rela, &sec->rela->relas, list) {
			if (rela->offset < offset + insn_len)
				continue;
			if (rela->string)
				continue;

			/* TODO: we may need black list ? */
			if (check_line_func(uelf, rela->sym->name)) {
				found = true;
				break;
			}
			return false;
		}
		if (!found)
			return false;

		found_any = true;
	}

	if (!found_any)
		ERROR("no instruction changes detected for changed section %s",
		      sec->name);

	return true;
}

static bool line_macro_change_only(struct upatch_elf *uelf, struct section *sec)
{
	switch(uelf->arch) {
	case AARCH64:
		return _line_macro_change_only_aarch64(uelf, sec);
	case X86_64:
		return _line_macro_change_only(uelf, sec);
	default:
		ERROR("unsupported arch");
	}
	return false;
}

void upatch_compare_sections(struct upatch_elf *uelf)
{
	struct section *sec;
	struct list_head *seclist = &uelf->sections;

	/* compare all sections */
	list_for_each_entry(sec, seclist, list) {
		if (sec->twin)
			compare_correlated_section(sec, sec->twin);
		else
			sec->status = NEW;
	}

	/* exclude WARN-only, might_sleep changes */
	list_for_each_entry(sec, seclist, list) {
		if (line_macro_change_only(uelf, sec)) {
			log_debug("reverting macro / line number section %s status to SAME\n", sec->name);
			sec->status = SAME;
		}
	}

	/* sync symbol status */
	list_for_each_entry(sec, seclist, list) {
		if (is_rela_section(sec)) {
            /* sync bundleable symbol for relocation section */
			if (sec->base->sym && sec->base->sym->status != CHANGED)
				sec->base->sym->status = sec->status;
		} else {
			struct symbol *sym = sec->sym;
			if (sym && sym->status != CHANGED)
				sym->status = sec->status;
                /* TODO: handle child func */
		}
	}
}