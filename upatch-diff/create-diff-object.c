/*
 * create-diff-object.c
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

/*
 * This file contains the heart of the ELF object differencing engine.
 *
 * The tool takes two ELF objects from two versions of the same source
 * file; a "orig" object and a "patched" object.  These object need to have
 * been compiled with the -ffunction-sections and -fdata-sections GCC options.
 *
 * The tool compares the objects at a section level to determine what
 * sections have changed.  Once a list of changed sections has been generated,
 * various rules are applied to determine any object local sections that
 * are dependencies of the changed section and also need to be included in
 * the output object.
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <libgen.h>
#include <argp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "log.h"
#include "elf-debug.h"
#include "elf-common.h"
#include "elf-insn.h"
#include "elf-compare.h"
#include "elf-correlate.h"
#include "elf-resolve.h"
#include "elf-create.h"
#include "running-elf.h"
#include "upatch-patch.h"

#ifndef UPATCH_VERSION
#define UPATCH_VERSION "dev"
#endif

enum loglevel loglevel = NORMAL;
char *logprefix;
char *upatch_elf_name;

struct arguments {
    char *source_obj;
    char *patched_obj;
    char *running_elf;
    char *output_obj;
    bool debug;
};

static struct argp_option options[] = {
    {"debug", 'd', NULL, 0, "Show debug output"},
    {"source", 's', "source", 0, "Source object"},
    {"patched", 'p', "patched", 0, "Patched object"},
    {"running", 'r', "running", 0, "Running binary file"},
    {"output", 'o', "output", 0, "Output object"},
    {NULL}
};

static char program_doc[] =
    "upatch-build -- generate a patch object based on the source object";

static char args_doc[] = "-s source_obj -p patched_obj -r elf_file -o output_obj";

const char *argp_program_version = UPATCH_VERSION;

static error_t check_opt(struct argp_state *state)
{
    struct arguments *arguments = state->input;

    if (arguments->source_obj == NULL ||
        arguments->patched_obj == NULL ||
        arguments->running_elf == NULL ||
        arguments->output_obj == NULL) {
            argp_usage(state);
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;

    switch (key)
    {
        case 'd':
            arguments->debug = true;
            break;
        case 's':
            arguments->source_obj = arg;
            break;
        case 'p':
            arguments->patched_obj = arg;
            break;
        case 'r':
            arguments->running_elf = arg;
            break;
        case 'o':
            arguments->output_obj = arg;
            break;
        case ARGP_KEY_ARG:
            break;
        case ARGP_KEY_END:
            return check_opt(state);
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, program_doc};

/*
 * Key point for chreate-diff-object:
 * 1. find changed func/data for each object
 * 2. link all these objects into a relocatable file
 * 3. add sections for management (hash/init/patch info etc.)
 * 4. locate old symbols for the relocatable file
 */

/* Format of output file is the only export API */
static void show_program_info(struct arguments *arguments)
{
    log_debug("source object: %s\n", arguments->source_obj);
    log_debug("patched object: %s\n", arguments->patched_obj);
    log_debug("running binary: %s\n", arguments->running_elf);
    log_debug("output object: %s\n", arguments->output_obj);
}

static void compare_elf_headers(struct upatch_elf *uelf_source, struct upatch_elf *uelf_patched)
{
    GElf_Ehdr ehdr_source, ehdr_patched;

    if (!gelf_getehdr(uelf_source->elf, &ehdr_source))
        ERROR("gelf_getehdr source failed for %s.", elf_errmsg(0));

    if (!gelf_getehdr(uelf_patched->elf, &ehdr_patched))
        ERROR("gelf_getehdr patched failed for %s.", elf_errmsg(0));

    if (memcmp(ehdr_source.e_ident, ehdr_patched.e_ident, EI_NIDENT) ||
        ehdr_source.e_type != ehdr_patched.e_type ||
        ehdr_source.e_machine != ehdr_patched.e_machine ||
        ehdr_source.e_version != ehdr_patched.e_version ||
        ehdr_source.e_entry != ehdr_patched.e_entry ||
        ehdr_source.e_phoff != ehdr_patched.e_phoff ||
        ehdr_source.e_flags != ehdr_patched.e_flags ||
        ehdr_source.e_ehsize != ehdr_patched.e_ehsize ||
        ehdr_source.e_phentsize != ehdr_patched.e_phentsize ||
        ehdr_source.e_shentsize != ehdr_patched.e_shentsize) {
            ERROR("compare_elf_headers failed.");
        }
}

/* we can sure we only handle relocatable file, this is unnecessary */
static void check_program_headers(struct upatch_elf *uelf)
{
    size_t ph_nr;
    if (elf_getphdrnum(uelf->elf, &ph_nr))
        ERROR("elf_getphdrnum with error %s.", elf_errmsg(0));

    if (ph_nr != 0)
        ERROR("ELF contains program header.");
}

static char *strarrcmp(char *name, char **prefix)
{
    size_t len;

    if (name == NULL)
        return NULL;

    while (*prefix != NULL) {
        len = strlen(*prefix);
        if (!strncmp(name, *prefix, len))
            return name + len;
        prefix++;
    }

    return NULL;
}

static bool is_bundleable(struct symbol *sym)
{
    char *name = NULL;
    size_t text_name_len = 0;
    /* handle .text.unlikely. and then .text. */
    char *func_prefix[] = {
        ".text.unlikely.",
        ".text.startup.", /* used for cold startup main function */
        ".text.hot.",
        ".text.",
        NULL,
    };

    char *obj_prefix[] = {
        ".data.rel.ro.",
        ".data.rel.",
        ".data.",
        ".rodata.",
        ".bss.",
        NULL,
    };

    if (sym == NULL || sym->sec == NULL)
        return false;

    if (sym->type == STT_FUNC)
        name = strarrcmp(sym->sec->name, func_prefix);
    else if (sym->type == STT_OBJECT)
        name = strarrcmp(sym->sec->name, obj_prefix);

    /* no prefix found or invalid type */
    if (name == NULL)
        return false;

    if (!strcmp(name, sym->name))
        return true;

    /* special case for cold func */
    text_name_len = strlen(".text.unlikely.");
    if (sym->type == STT_FUNC && !strncmp(sym->sec->name, ".text.unlikely.", text_name_len) &&
        strstr(sym->name, ".cold") &&
        !strncmp(sym->sec->name + text_name_len, sym->name, strlen(sym->sec->name) - text_name_len))
        return true;

    return false;
}

/*
 * When compiled with -ffunction-sections and -fdata-sections, almost each
 * symbol gets its own dedicated section. We call such symbols "bundled"
 * symbols. It can be checked by "sym->sec->sym == sym"
 */
static void bundle_symbols(struct upatch_elf *uelf)
{
    struct symbol *sym;

    list_for_each_entry(sym, &uelf->symbols, list) {
        if (is_bundleable(sym)) {
            if (sym->sym.st_value != 0 &&
                is_gcc6_localentry_bundled_sym(uelf, sym)) {
                ERROR("symbol %s at offset %lu within section %s, expected 0.",
                    sym->name, sym->sym.st_value, sym->sec->name);
            }
            sym->sec->sym = sym;
        /* except handler is also a kind of bundle symbol */
        } else if (sym->type == STT_SECTION && is_except_section(sym->sec)) {
            sym->sec->sym = sym;
        }
    }
}

/*
 * During optimization, gcc may move unlikely execution branches into *.cold
 * subfunctions. Some functions can also be split into mutiple *.part funtions.
 * detect_child_functions detects such subfunctions and crossreferences
 * them with their parent functions through parent/child pointers.
 */
static void detect_child_functions(struct upatch_elf *uelf)
{
    struct symbol *sym;
    char *childstr;
    char *pname;

    list_for_each_entry(sym, &uelf->symbols, list) {
        if (sym->type != STT_FUNC)
            continue;

        /* search twice and check if found. */
        childstr = strstr(sym->name, ".cold");
        if (!childstr)
            childstr = strstr(sym->name, ".cold");

        if (!childstr)
            continue;

        pname =strndup(sym->name, childstr - sym->name);
        if (!pname)
            ERROR("detect_child_functions strndup failed.");

        sym->parent = find_symbol_by_name(&uelf->symbols, pname);
        if (sym->parent)
            list_add_tail(&sym->subfunction_node, &sym->parent->children);
        free(pname);
    }
}

static bool discarded_sym(struct running_elf *relf, struct symbol *sym)
{
	if (!sym || !sym->sec || !sym->sec->name)
		return false;

    /*
     * ".gnu.warning." section is to prevent some symbols in the dynamic library being used by external programs.
     * in the exec program, these sections are discarded in linker. so we discard these symbols.
     */
	if (relf->is_exec && !strncmp(sym->sec->name, ".gnu.warning.", strlen(".gnu.warning.")))
		return true;

	return false;
}

enum LOCAL_MATCH {
    FOUND,
    NOT_FOUND,
    EMPTY,
};

static enum LOCAL_MATCH locals_match(struct running_elf *relf, int idx,
    struct symbol *file_sym, struct list_head *sym_list)
{
    struct symbol *sym;
    struct object_symbol *running_sym;
    int i;
    enum LOCAL_MATCH found = EMPTY;

    for (i = idx + 1; i < relf->obj_nr; ++i) {
        running_sym = &relf->obj_syms[i];
        if (running_sym->type == STT_FILE)
            break;
        if (running_sym->bind != STB_LOCAL)
            continue;
        if (running_sym->type != STT_FUNC && running_sym->type != STT_OBJECT)
            continue;

        found = NOT_FOUND;
        sym = file_sym;
        list_for_each_entry_continue(sym, sym_list, list) {
            if (sym->type == STT_FILE)
                break;
            if(sym->bind != STB_LOCAL)
                continue;

            if (sym->type == running_sym->type &&
                !strcmp(sym->name, running_sym->name)) {
                    found = FOUND;
                    break;
            }
        }

        if (found == NOT_FOUND){
            log_debug("can't find %s - in running_sym \n", running_sym->name);
            return NOT_FOUND;
        }
    }

    sym = file_sym;
    list_for_each_entry_continue(sym, sym_list, list) {
        if (sym->type == STT_FILE)
            break;
        if(sym->bind != STB_LOCAL)
            continue;
        if (sym->type != STT_FUNC && sym->type != STT_OBJECT)
            continue;
        if (discarded_sym(relf, sym))
            continue;

        found = NOT_FOUND;
        for (i = idx + 1; i < relf->obj_nr; ++i) {
            running_sym = &relf->obj_syms[i];
            if (running_sym->type == STT_FILE)
                break;
            if (running_sym->bind != STB_LOCAL)
                continue;

            if (sym->type == running_sym->type &&
                !strcmp(sym->name, running_sym->name)) {
                    found = FOUND;
                    break;
            }
        }

        if (found == NOT_FOUND){
            log_debug("can't find %s - in sym \n", sym->name);
            return NOT_FOUND;
        }
    }

    return found;
}

static void find_local_syms(struct running_elf *relf, struct symbol *file_sym,
    struct list_head *sym_list)
{
    struct object_symbol *running_sym;
    struct object_symbol *lookup_running_file_sym = NULL;
    int i;
    enum LOCAL_MATCH found;

    for (i = 0; i < relf->obj_nr; ++i) {
        running_sym = &relf->obj_syms[i];
        if (running_sym->type != STT_FILE)
            continue;
        if (strcmp(file_sym->name, running_sym->name))
            continue;
        found = locals_match(relf, i, file_sym, sym_list);
        if (found == NOT_FOUND) {
            continue;
        } else if (found == EMPTY) {
            lookup_running_file_sym = running_sym;
            break;
        } else {
            if (lookup_running_file_sym)
                ERROR("found duplicate matches for %s local symbols in running elf.", file_sym->name);

            lookup_running_file_sym = running_sym;
        }
    }

    if (!lookup_running_file_sym)
        ERROR("could't find matching %s local symbols in running elf.", file_sym->name);

    list_for_each_entry_continue(file_sym, sym_list, list) {
        if (file_sym->type == STT_FILE)
            break;
        file_sym->lookup_running_file_sym = lookup_running_file_sym;
    }
}

/*
 * Because there can be duplicate symbols in elf, we need correlate each symbol from
 * source elf to it's corresponding symbol in running elf.
 * Both the source elf and the running elf can be split on STT_FILE
 * symbols into blocks of symbols originating from a single source file.
 * We then compare local symbol lists from both blocks and store the pointer
 * to STT_FILE symbol in running elf for later using.
 */
static void find_file_symbol(struct upatch_elf *uelf, struct running_elf *relf)
{
    struct symbol *sym;

    list_for_each_entry(sym, &uelf->symbols, list) {
        if (sym->type == STT_FILE)
            find_local_syms(relf, sym, &uelf->symbols);
    }
}

static void mark_grouped_sections(struct upatch_elf *uelf)
{
    struct section *groupsec, *sec;
	unsigned int *data, *end;

    list_for_each_entry(groupsec, &uelf->sections, list) {
        if (groupsec->sh.sh_type != SHT_GROUP)
            continue;
		data = groupsec->data->d_buf;
		end = groupsec->data->d_buf + groupsec->data->d_size;
		data++; /* skip first flag word (e.g. GRP_COMDAT) */
		while (data < end) {
			sec = find_section_by_index(&uelf->sections, *data);
			if (!sec)
				ERROR("group section not found");
			sec->grouped = 1;
			log_debug("marking section %s (%d) as grouped\n",
			          sec->name, sec->index);
			data++;
		}
    }
}

/*
 * There are two kinds of relocation. One is based on the variable symbol.
 * And the other one is based on the section symbol. The second type is often
 * used for static objects. Here, we replace the second type with the first ons.
 * So we can compare them with each other directly.
 */
static void replace_section_syms(struct upatch_elf *uelf)
{
    struct section *relasec;
    struct rela *rela;
    struct symbol *sym;
    long target_off;
    bool found = false;

    list_for_each_entry(relasec, &uelf->sections, list) {
        if (!is_rela_section(relasec) || is_debug_section(relasec) || is_note_section(relasec))
            continue;

        list_for_each_entry(rela, &relasec->relas, list) {
            if (!rela->sym || !rela->sym->sec || rela->sym->type != STT_SECTION)
                continue;

            log_debug("found replace symbol for section %s \n", rela->sym->name);

            /*
             * for section symbol, rela->sym->sec is the section itself.
             * rela->sym->sec->sym is the bundleable symbol which is a function or object.
             */
            if (rela->sym->sec->sym) {
                log_debug("act: replace it with %s <- %s \n", rela->sym->sec->sym->name, rela->sym->sec->name);
                rela->sym = rela->sym->sec->sym;

                if (rela->sym->sym.st_value != 0)
                    ERROR("symbol offset is not zero.");

                continue;
            }

            target_off = rela_target_offset(uelf, relasec, rela);
            list_for_each_entry(sym, &uelf->symbols, list) {
                long start, end;

                /* find object which belongs to this section, it could be .data .rodata etc */
                if (sym->type == STT_SECTION || sym->sec != rela->sym->sec)
                    continue;

                start = sym->sym.st_value;
                end = sym->sym.st_value + sym->sym.st_size;

                /* text section refer other sections */
                if (is_text_section(relasec->base) &&
                    !is_text_section(sym->sec) &&
                    (rela->type == R_X86_64_32S || rela->type == R_X86_64_32 || rela->type == R_AARCH64_ABS64) &&
                    rela->addend == (long)sym->sec->sh.sh_size &&
                    end == (long)sym->sec->sh.sh_size)
                    ERROR("relocation refer end of data sections.");
                else if (target_off == start && target_off == end){
                    if(is_mapping_symbol(uelf, sym))
                        continue;
                    log_debug("find relocation reference for empty symbol.\n");
                }
                else if (target_off < start || target_off >= end)
                    continue;

                log_debug("%s: replacing %s+%ld reference with %s+%ld\n",
                    relasec->name, rela->sym->name, rela->addend,
                    sym->name, rela->addend - start);
                found = true;
                rela->sym = sym;
                rela->addend -= start;
                break;
            }

            /* only rodata and data based is allowed
             * if we compile with fPIC and the function's local char* array is too large,
             * (we test the array's size > 32),
             * gcc will generate the relocation rodata.str1.1 about the array in .data section.
             * this .data symbol's type is STT_SECTION. and this function has the .data
             * symbol's relocation. just like:
             *
             * code:
             * int glo_func(void)
             * {
             * char *help[]={"test1", "test2",.....,"test33"};
             * return 0;
             * }
             *
             * elf:
             * Relocation section '.rela.data' at offset 0xc30 contains 33 entries:
             * Offset          Info           Type           Sym. Value    Sym. Name + Addend
             * 000000000000  000300000001 R_X86_64_64       0000000000000000 .rodata.str1.1 + 0
             * 000000000008  000300000001 R_X86_64_64       0000000000000000 .rodata.str1.1 + 6
             * ....
             *
             * Relocation section '.rela.text.glo_func' at offset 0x738 contains 3 entries:
             * Offset          Info           Type           Sym. Value    Sym. Name + Addend
             * 000000000015  000200000002 R_X86_64_PC32     0000000000000000 .data - 4
             *
             * but if we change the other function which has nothing to do with this .data
             * section and the glo_function. the glo_function will still error because of
             * the glo_function's .data relocation.
             *
             * we do not allow .data section is "include" in verify_patchability. so we
             * don't worry about the .data section will produce unexpected behavior later on.
             */
            if (!found && !is_string_literal_section(rela->sym->sec) &&
                strncmp(rela->sym->name, ".rodata", strlen(".rodata")) &&
                strncmp(rela->sym->name, ".data", strlen(".data"))) {
                ERROR("%s+0x%x: can't find replacement symbol for %s+%ld reference.",
                relasec->base->name, rela->offset, rela->sym->name, rela->addend);
            }
        }
    }
}

static void mark_ignored_sections(struct upatch_elf *uelf)
{
    /* Ignore any discarded sections */
    struct section *sec;

    list_for_each_entry(sec, &uelf->sections, list) {
        if (!strncmp(sec->name, ".discard", strlen(".discard")) ||
            !strncmp(sec->name, ".rela.discard", strlen(".rela.discard"))) {
                log_debug("found discard section %s\n", sec->name);
                sec->ignore = 1;
            }
    }

    /* TODO: handle ignore information from sections or settings */
}

/*  TODO: we do not handle it now */
static void mark_ignored_functions_same(struct upatch_elf *uelf) {}
static void mark_ignored_sections_same(struct upatch_elf *uelf) {}

/*
* For a local symbol referenced in the rela list of a changing function,
* if it has no section, it will link error in arm.
* So we create a empty section for link purpose.
* We use st_other to mark these symbols.
*/
static void include_special_local_section(struct upatch_elf *uelf) {
    struct symbol *sym, *sym_changed;
    struct rela *rela;

    list_for_each_entry(sym_changed, &uelf->symbols, list) {
        if (!(sym_changed->status == CHANGED && sym_changed->type == STT_FUNC))
            continue;

        if (!sym_changed->sec || !sym_changed->sec->rela)
            continue;

        list_for_each_entry(rela, &sym_changed->sec->rela->relas, list) {
            sym = rela->sym;
            if (sym->sec && sym->status == SAME && sym->bind == STB_LOCAL && !sym->sec->include) {
                sym->sym.st_other |= SYM_OTHER;
                sym->sec->include = 1;
                sym->sec->data->d_buf = NULL;
                sym->sec->data->d_size = 0;
                // arm error: (.debug_info+0x...) undefined reference to `no symbol'
                if (sym->sec->secsym)
                    sym->sec->secsym->include = 1;
            }
        }
    }
}

static void include_section(struct section *sec);
static void include_symbol(struct symbol *sym)
{
    if (sym->include)
        return;

    /*
     * The symbol gets included even if its section isn't needed, as it
     * might be needed: either permanently for a rela, or temporarily for
     * the later creation of a dynrela.
     */
    sym->include = 1;

    /*
     * For a function/object symbol, if it has a section, we only need to
     * include the section if it has changed. Otherwise the symbol will be
     * used by relas/dynrelas to link to the real symbol externally.
     *
     * For section symbols, we always include the section because
     * references to them can't otherwise be resolved externally.
     */
    if (sym->sec && (sym->type == STT_SECTION || sym->status != SAME))
        include_section(sym->sec);
}

static void include_section(struct section *sec)
{
    struct rela *rela;

    if (sec->include)
        return;

    sec->include = 1;
    if (sec->secsym)
        sec->secsym->include = 1;

    if (!sec->rela)
        return;

    sec->rela->include = 1;
    list_for_each_entry(rela, &sec->rela->relas, list)
        include_symbol(rela->sym);
}

static void include_standard_elements(struct upatch_elf *uelf)
{
    struct section *sec;
    struct symbol *sym;

    list_for_each_entry(sec, &uelf->sections, list) {
        if (!strcmp(sec->name, ".shstrtab") ||
            !strcmp(sec->name, ".strtab") ||
            !strcmp(sec->name, ".symtab") ||
            !strcmp(sec->name, ".rodata") ||
            is_string_literal_section(sec))
            include_section(sec);
    }

    list_for_each_entry(sym, &uelf->symbols, list)
        if (sym->sec && is_string_literal_section(sym->sec))
            sym->include = 1;

    /* include the NULL symbol */
    list_entry(uelf->symbols.next, struct symbol, list)->include = 1;
}

static int include_changed_functions(struct upatch_elf *uelf)
{
    struct symbol *sym;
    int changed_nr = 0;

    list_for_each_entry(sym, &uelf->symbols, list) {
        if (sym->status == CHANGED &&
            sym->type == STT_FUNC) {
            changed_nr++;
            include_symbol(sym);
        }

        /* exception handler is a special function */
        if (sym->status == CHANGED &&
            sym->type == STT_SECTION &&
            sym->sec && is_except_section(sym->sec)) {
            log_warn("found changed exeception section %s \n", sym->sec->name);
            changed_nr++;
            include_symbol(sym);
        }

        if (sym->type == STT_FILE)
            sym->include = 1;
    }

    return changed_nr;
}

static int include_new_globals(struct upatch_elf *uelf)
{
    struct symbol *sym;
    int nr = 0;

    list_for_each_entry(sym, &uelf->symbols, list) {
        if (sym->bind == STB_GLOBAL && sym->sec &&
            sym->status == NEW) {
            include_symbol(sym);
            nr++;
        }
    }

    return nr;
}

static void include_debug_sections(struct upatch_elf *uelf)
{
    struct rela *rela, *saferela;
    struct section *sec = NULL, *eh_sec = NULL;

    /* include all .debug_* sections */
    list_for_each_entry(sec, &uelf->sections, list) {
        if (is_debug_section(sec)) {
            sec->include = 1;

            if (!is_rela_section(sec) && sec->secsym)
                sec->secsym->include = 1;

            if (!is_rela_section(sec) && is_eh_frame(sec))
                eh_sec = sec;
        }
    }

    /*
     * modify relocation entry here
     * remove unincluded symbol in debug relocation section
     * for eh_frame section, sync the FDE at the same time
     */
    list_for_each_entry(sec, &uelf->sections, list) {
        if (!is_rela_section(sec) || !is_debug_section(sec))
            continue;

        list_for_each_entry_safe(rela, saferela, &sec->relas, list)
            // The shndex of symbol is SHN_COMMON, there is no related section
            if (rela->sym && !rela->sym->include)
                list_del(&rela->list);
    }

    if (eh_sec)
        upatch_rebuild_eh_frame(eh_sec);
}

/* currently, there si no special section need to be handled */
static void process_special_sections(struct upatch_elf *uelf) {}

static void verify_patchability(struct upatch_elf *uelf)
{
    struct section *sec;
    int errs = 0;

    list_for_each_entry(sec, &uelf->sections, list) {
        if (sec->status == CHANGED && !sec->include) {
            log_normal("changed section %s not selected for inclusion\n", sec->name);
            errs++;
        }

        if (sec->status != SAME && sec->grouped) {
            log_normal("changed section %s is part of a section group\n", sec->name);
            errs++;
        }

        if (sec->sh.sh_type == SHT_GROUP && sec->status == NEW) {
            log_normal("new/changed group sections are not supported\n");
            errs++;
        }

        if (sec->include && sec->status != NEW &&
            (!strncmp(sec->name, ".data", 5) || !strncmp(sec->name, ".bss", 4)) &&
            (strcmp(sec->name, ".data.unlikely") && strcmp(sec->name, ".data.once"))) {
            log_normal("data section %s selected for inclusion\n", sec->name);
            errs++;
        }
    }

    if (errs)
        DIFF_FATAL("%d unsupported section changes", errs);
}

static void migrate_included_elements(struct upatch_elf *uelf_patched, struct upatch_elf *uelf_out)
{
    struct section *sec, *safesec;
    struct symbol *sym, *safesym;

    memset(uelf_out, 0, sizeof(struct upatch_elf));
    uelf_out->arch = uelf_patched->arch;

    INIT_LIST_HEAD(&uelf_out->sections);
    INIT_LIST_HEAD(&uelf_out->symbols);
    INIT_LIST_HEAD(&uelf_out->strings);

    /* migrate included sections from uelf_patched to uelf_out */
    list_for_each_entry_safe(sec, safesec, &uelf_patched->sections, list) {
        if (!sec->include)
            continue;

        list_del(&sec->list);
        list_add_tail(&sec->list, &uelf_out->sections);
        sec->index = 0;
        if (!is_rela_section(sec) && sec->secsym && !sec->secsym->include)
            sec->secsym = NULL; // break link to non-included section symbol
    }

    /* migrate included symbols from kelf to out */
    list_for_each_entry_safe(sym, safesym, &uelf_patched->symbols, list) {
        if (!sym->include)
            continue;

        list_del(&sym->list);
        list_add_tail(&sym->list, &uelf_out->symbols);
        sym->index = 0;
        sym->strip = SYMBOL_DEFAULT;
        if (sym->sec && !sym->sec->include)
            sym->sec = NULL; // break link to non-included section
    }
}

int main(int argc, char*argv[])
{
    struct arguments arguments;
    struct upatch_elf uelf_source, uelf_patched, uelf_out;
    struct running_elf relf;

    int num_changed, new_globals_exist;

    memset(&arguments, 0, sizeof(arguments));
    argp_parse(&argp, argc, argv, 0, NULL, &arguments);

    if (arguments.debug)
        loglevel = DEBUG;
    logprefix = basename(arguments.source_obj);
    show_program_info(&arguments);

    if (elf_version(EV_CURRENT) ==  EV_NONE)
        ERROR("ELF library initialization failed");

    /* TODO: with debug info, this may changed */
    upatch_elf_name = arguments.running_elf;

    /* check error in log, since errno may be from libelf */
    upatch_elf_open(&uelf_source, arguments.source_obj);
    upatch_elf_open(&uelf_patched, arguments.patched_obj);

    relf_init(arguments.running_elf, &relf);

    compare_elf_headers(&uelf_source, &uelf_patched);
    check_program_headers(&uelf_source);
    check_program_headers(&uelf_patched);

    bundle_symbols(&uelf_source);
    bundle_symbols(&uelf_patched);

    detect_child_functions(&uelf_source);
    detect_child_functions(&uelf_patched);

    find_file_symbol(&uelf_source, &relf);

    mark_grouped_sections(&uelf_patched);

    replace_section_syms(&uelf_source);
    replace_section_syms(&uelf_patched);

    upatch_correlate_elf(&uelf_source, &uelf_patched);
    upatch_correlate_static_local_variables(&uelf_source, &uelf_patched);

    /* Now, we can only check uelf_patched, all we need is in the twin part */
    /* Also, we choose part of uelf_patched and output new object */
    mark_ignored_sections(&uelf_patched);

    upatch_compare_correlated_elements(&uelf_patched);

    mark_ignored_functions_same(&uelf_patched);
    mark_ignored_sections_same(&uelf_patched);

    upatch_elf_teardown(&uelf_source);
    upatch_elf_free(&uelf_source);

    include_standard_elements(&uelf_patched);

    num_changed = include_changed_functions(&uelf_patched);
    new_globals_exist = include_new_globals(&uelf_patched);

    include_debug_sections(&uelf_patched);

    process_special_sections(&uelf_patched);

    upatch_print_changes(&uelf_patched);

    upatch_dump_kelf(&uelf_patched);

    verify_patchability(&uelf_patched);

    include_special_local_section(&uelf_patched);

    if (!num_changed && !new_globals_exist) {
        log_normal("no changed functions were found\n");
        return 0;
    }

    migrate_included_elements(&uelf_patched, &uelf_out);

    /* since out elf still point to it, we only destroy it, not free it */
    upatch_elf_teardown(&uelf_patched);

    upatch_create_strings_elements(&uelf_out);

    upatch_create_patches_sections(&uelf_out, &relf);

    upatch_create_intermediate_sections(&uelf_out, &relf);

    create_kpatch_arch_section(&uelf_out);

    upatch_build_strings_section_data(&uelf_out);

    /*
     * At this point, the set of output sections and symbols is finalized.
     * Reorder eth symbols into link-compliant order and index all the symbols
     * and sections. After the indexes have beed established, update index data
     * throughout the structure.
     */
    upatch_reorder_symbols(&uelf_out);

    upatch_strip_unneeded_syms(&uelf_out);

    upatch_reindex_elements(&uelf_out);

    upatch_rebuild_relocations(&uelf_out);

    upatch_check_relocations(&uelf_out);

    upatch_create_shstrtab(&uelf_out);

    upatch_create_strtab(&uelf_out);

    upatch_partly_resolve(&uelf_out, &relf);

    upatch_create_symtab(&uelf_out);

    upatch_dump_kelf(&uelf_out);

    upatch_write_output_elf(&uelf_out, uelf_patched.elf, arguments.output_obj, 0664);

    relf_destroy(&relf);
    upatch_elf_free(&uelf_patched);
    upatch_elf_teardown(&uelf_out);
    upatch_elf_free(&uelf_out);

    log_normal("upatch-build executes successful.\n");
    return 0;
}