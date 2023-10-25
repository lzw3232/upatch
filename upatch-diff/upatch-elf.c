/*
 * upatch-elf.c
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

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include <gelf.h>

#include "elf-common.h"
#include "elf-insn.h"
#include "upatch-elf.h"
#include "list.h"
#include "log.h"

static void create_section_list(struct upatch_elf *uelf)
{
    size_t shstrndx, sections_nr;

    struct section *sec;
    Elf_Scn *scn = NULL;

    if (elf_getshdrnum(uelf->elf, &sections_nr))
        ERROR("elf_getshdrnum with error %s", elf_errmsg(0));

    sections_nr --;

    if (elf_getshdrstrndx(uelf->elf, &shstrndx))
        ERROR("elf_getshdrstrndx with error %s", elf_errmsg(0));

    log_debug("=== section list (%zu) === \n", sections_nr);
    while (sections_nr --) {
        ALLOC_LINK(sec, &uelf->sections);

        scn = elf_nextscn(uelf->elf, scn);
        if (!scn)
            ERROR("elf_nextscn with error %s", elf_errmsg(0));

        if (!gelf_getshdr(scn, &sec->sh))
            ERROR("gelf_getshdr with error %s", elf_errmsg(0));
        
        sec->name = elf_strptr(uelf->elf, shstrndx, sec->sh.sh_name);
        if (!sec->name)
            ERROR("elf_strptr with error %s", elf_errmsg(0));
        
        sec->data = elf_getdata(scn, NULL);
        if (!sec->data)
            ERROR("elf_getdata with error %s", elf_errmsg(0));

        sec->index = (unsigned int)elf_ndxscn(scn);
        /* found extended section header */
        if (sec->sh.sh_type == SHT_SYMTAB_SHNDX)
            uelf->symtab_shndx = sec->data; /* correct ? */

        log_debug("ndx %02d, data %p, size %zu, name %s\n",
            sec->index, sec->data->d_buf, sec->data->d_size, sec->name);
    }

    if (elf_nextscn(uelf->elf, scn))
        ERROR("elf_nextscn with error %s", elf_errmsg(0));
}

static void create_symbol_list(struct upatch_elf *uelf)
{
    struct section *symtab;
    unsigned int symbols_nr;
    Elf32_Word shndx;
    struct symbol *sym;
    unsigned int index = 0;

    /* consider type first */
    symtab = find_section_by_name(&uelf->sections, ".symtab");
    if (!symtab)
        ERROR("can't find symbol table");

    symbols_nr = (unsigned int)(symtab->sh.sh_size / symtab->sh.sh_entsize);

    log_debug("\n=== symbol list (%d entries) ===\n", symbols_nr);
    while (symbols_nr --) {
        ALLOC_LINK(sym, &uelf->symbols);
        INIT_LIST_HEAD(&sym->children);

        sym->index = index;
        if (!gelf_getsym(symtab->data, index, &sym->sym))
            ERROR("gelf_getsym with error %s", elf_errmsg(0));

        index ++;

        sym->name = elf_strptr(uelf->elf, symtab->sh.sh_link, sym->sym.st_name);
        if (!sym->name)
            ERROR("elf_strptr with error %s", elf_errmsg(0));
        
        sym->type = GELF_ST_TYPE(sym->sym.st_info);
        sym->bind = GELF_ST_BIND(sym->sym.st_info);

        shndx = sym->sym.st_shndx;
        /* releated section located in extended header */
        if (shndx == SHN_XINDEX &&
            !gelf_getsymshndx(symtab->data, uelf->symtab_shndx,
                sym->index, &sym->sym, &shndx))
            ERROR("gelf_getsymshndx with error %s", elf_errmsg(0));

        if ((sym->sym.st_shndx > SHN_UNDEF && sym->sym.st_shndx < SHN_LORESERVE) ||
            sym->sym.st_shndx == SHN_XINDEX) {
            
            sym->sec = find_section_by_index(&uelf->sections, shndx);
            if (!sym->sec)
                ERROR("no releated section found for symbol %s \n", sym->name);
            
            /* this symbol is releated with a section */
            if (sym->type == STT_SECTION) {
                /* secsym must be the bundleable symbol */
                sym->sec->secsym = sym;

                /* use section name as symbol name */
                sym->name = sym->sec->name;
            }
        }
        log_debug("sym %02d, type %d, bind %d, ndx %02d, name %s",
            sym->index, sym->type, sym->bind, sym->sym.st_shndx,
            sym->name);
        if (sym->sec)
            log_debug(" -> %s", sym->sec->name);
        log_debug("\n");
    }
}

static void create_rela_list(struct upatch_elf *uelf, struct section *relasec)
{
    unsigned long rela_nr;
    unsigned int symndx;
    struct rela *rela;
    int index = 0, skip = 0;

    /* for relocation sections, sh_info is the index which these informations apply */
    relasec->base = find_section_by_index(&uelf->sections, relasec->sh.sh_info);
    if (!relasec->base)
        ERROR("no base section found for relocation section %s", relasec->name);

    relasec->base->rela = relasec;
    rela_nr = relasec->sh.sh_size / relasec->sh.sh_entsize;

    log_debug("\n=== rela list for %s (%ld entries) === \n",
        relasec->base->name, rela_nr);

    if (is_debug_section(relasec)) {
        log_debug("skipping rela listing for .debug_* section \n");
        skip = 1;
    }

    if (is_note_section(relasec)) {
        log_debug("skipping rela listing for .note_* section \n");
        skip = 1;
    }

    while (rela_nr --) {
        ALLOC_LINK(rela, &relasec->relas);

        /* use index because we need to keep the order of rela */
        if (!gelf_getrela(relasec->data, index, &rela->rela))
            ERROR("gelf_getrela with error %s", elf_errmsg(0));
        index++;
        
        rela->type = GELF_R_TYPE(rela->rela.r_info);
        rela->addend = rela->rela.r_addend;
        rela->offset = (unsigned int)rela->rela.r_offset;
        symndx = (unsigned int)GELF_R_SYM(rela->rela.r_info);
        rela->sym = find_symbol_by_index(&uelf->symbols, symndx);
        if (!rela->sym)
            ERROR("no rela entry symbol found \n");
        
        if (rela->sym->sec && is_string_section(rela->sym->sec)) {
            rela->string = rela->sym->sec->data->d_buf +
                rela->sym->sym.st_value +
                rela_target_offset(uelf, relasec, rela);
            if (!rela->string)
                ERROR("could not lookup rela string for %s+%ld",
                    rela->sym->name, rela->addend);
        }

        if (skip)
            continue;
        
        log_debug("offset %d, type %d, %s %s %ld \n", rela->offset,
            rela->type, rela->sym->name,
            (rela->addend < 0) ? "-" : "+", labs(rela->addend));
        if (rela->string)  // rela->string is not utf8
            log_debug(" string = %s", rela->string);
        log_debug("\n");
    }
}

void upatch_elf_open(struct upatch_elf *uelf, const char *name)
{
    GElf_Ehdr ehdr;
    struct section *relasec;
    Elf *elf = NULL;
    int fd = 1;

    fd = open(name, O_RDONLY);
    if (fd == -1)
        ERROR("open %s failed with errno %d \n", name, errno);

    elf = elf_begin(fd, ELF_C_RDWR, NULL);
    if (!elf)
        ERROR("open elf %s failed with error %s \n", name, elf_errmsg(0));

    memset(uelf, 0, sizeof(*uelf));
    INIT_LIST_HEAD(&uelf->sections);
    INIT_LIST_HEAD(&uelf->symbols);
    INIT_LIST_HEAD(&uelf->strings);

    uelf->elf = elf;
    uelf->fd = fd;

    if (!gelf_getehdr(uelf->elf, &ehdr))
        ERROR("get file %s elf header failed with error %s \n",
            name, elf_errmsg(0));

    /* TODO: check ELF type here, we only handle object file */
    if (ehdr.e_type != ET_REL)
        ERROR("only handles relocatable files \n");

    /*
     * Main problem here is stack check, for kernel, only x86 is support
     * Not sure how to handle userspace, but let us handle x86 first here
     */
    switch (ehdr.e_machine) {
    case EM_AARCH64:
        uelf->arch = AARCH64;
        break;
    case EM_X86_64:
        uelf->arch = X86_64;
        break;
    default:
        ERROR("unsupported architecture here");
    }

    create_section_list(uelf);
    create_symbol_list(uelf);

    list_for_each_entry(relasec, &uelf->sections, list) {
        if (!is_rela_section(relasec))
            continue;
        INIT_LIST_HEAD(&relasec->relas);

        create_rela_list(uelf, relasec);
    }
}

void upatch_elf_teardown(struct upatch_elf *uelf)
{
    struct section *sec, *safesec;
    struct symbol *sym, *safesym;
    struct rela *rela, *saferela;

    list_for_each_entry_safe(sec, safesec, &uelf->sections, list) {
        if (sec->twin)
            sec->twin->twin = NULL;
        if (is_rela_section(sec)) {
            list_for_each_entry_safe(rela, saferela, &sec->relas, list) {
                memset(rela, 0, sizeof(*rela));
                free(rela);
            }
        }
        memset(sec, 0, sizeof(*sec));
        free(sec);
    }

    list_for_each_entry_safe(sym, safesym, &uelf->symbols, list) {
        if (sym->twin)
            sym->twin->twin = NULL;
        memset(sym, 0, sizeof(*sym));
        free(sym);
    }

    INIT_LIST_HEAD(&uelf->sections);
    INIT_LIST_HEAD(&uelf->symbols);
}

void upatch_elf_free(struct upatch_elf *uelf)
{
    elf_end(uelf->elf);
    close(uelf->fd);
    memset(uelf, 0, sizeof(*uelf));
}














