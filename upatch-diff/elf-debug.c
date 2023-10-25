/*
 * elf-debug.c
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2013-2014 Josh Poimboeuf <jpoimboe@redhat.com>
 * Copyright (C) 2022 Longjun Luo <luolongjun@huawei.com>
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

#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "list.h"
#include "elf-common.h"
#include "elf-debug.h"
#include "upatch-elf.h"

void upatch_print_changes(struct upatch_elf *uelf)
{
    struct symbol *sym;

    list_for_each_entry(sym, &uelf->symbols, list) {
        if (!sym->include || !sym->sec || sym->type != STT_FUNC || sym->parent)
            continue;
        if (sym->status == NEW)
            log_normal("new function: %s\n", sym->name);
        else if (sym->status == CHANGED)
            log_normal("changed function: %s\n", sym->name);
    }
}

void upatch_dump_kelf(struct upatch_elf *uelf)
{
    struct section *sec;
    struct symbol *sym;
    struct rela *rela;

    log_debug("\n=== Sections ===\n");
    list_for_each_entry(sec, &uelf->sections, list) {
        log_debug("%02d %s (%s)", sec->index, sec->name, status_str(sec->status));
        if (is_rela_section(sec)) {
            log_debug(", base-> %s\n", sec->base->name);
            if (is_debug_section(sec) || is_note_section(sec))
                goto next;
            log_debug("rela section expansion\n");
            list_for_each_entry(rela, &sec->relas, list) {
                log_debug("sym %d, offset %d, type %d, %s %s %ld \n",
                    rela->sym->index, rela->offset,
                    rela->type, rela->sym->name,
                    (rela->addend < 0) ? "-" : "+",
                    labs(rela->addend));
            }
        } else {
            if (sec->sym)
                log_debug(", sym-> %s", sec->sym->name);
            if (sec->secsym)
                log_debug(", secsym-> %s", sec->secsym->name);
            if (sec->rela)
                log_debug(", rela-> %s", sec->rela->name);
        }
next:
        log_debug("\n");
    }

    log_debug("\n=== Symbols ===\n");
    list_for_each_entry(sym, &uelf->symbols, list) {
        log_debug("sym %02d, type %d, bind %d, ndx %02d, name %s (%s)",
            sym->index, sym->type, sym->bind, sym->sym.st_shndx,
            sym->name, status_str(sym->status));
        if (sym->sec && (sym->type == STT_FUNC || sym->type == STT_OBJECT))
            log_debug(" -> %s", sym->sec->name);
        log_debug("\n");
    }
}

/* debuginfo releated */
static inline bool skip_bytes(unsigned char **iter, unsigned char *end, unsigned int len)
{
    if ((unsigned int)(end - *iter) < len) {
        *iter = end;
        return false;
    }
    *iter += len;
    return true;
}

void upatch_rebuild_eh_frame(struct section *sec)
{
    void *eh_frame;
    unsigned long long frame_size;
    struct rela *rela;
    unsigned char *data, *data_end;
    unsigned int hdr_length, hdr_id;
    unsigned int current_offset;
    unsigned int count = 0;

    /* sanity check */
    if (!is_eh_frame(sec) || is_rela_section(sec) || !sec->rela)
        return;

    list_for_each_entry(rela, &sec->rela->relas, list)
        count ++;

    /* currently, only delete is possible */
    if (sec->rela->sh.sh_entsize != 0 &&
        count == sec->rela->sh.sh_size / sec->rela->sh.sh_entsize)
        return;

    log_debug("sync modification for eh_frame \n");

    data = sec->data->d_buf;
    data_end = sec->data->d_buf + sec->data->d_size;

    /* in this time, some relcation entries may have been deleted */
    frame_size = 0;
    eh_frame = malloc(sec->data->d_size);
    if (!eh_frame)
        ERROR("malloc eh_frame failed \n");

    /* 8 is the offset of PC begin */
    current_offset = 8;
    list_for_each_entry(rela, &sec->rela->relas, list) {
        unsigned int offset = rela->offset;
        bool found_rela = false;
        log_debug("handle relocaton offset at 0x%x \n", offset);
        while (data != data_end) {
            void *__src = data;

            log_debug("current handle offset is 0x%x \n", current_offset);

            REQUIRE(skip_bytes(&data, data_end, 4), "no length to be read");
            hdr_length = *(unsigned int *)(data - 4);

            REQUIRE(hdr_length != 0xffffffff, "64 bit .eh_frame is not supported");
            /* if it is 0, we reach the end. */
            if (hdr_length == 0)
                break;

            REQUIRE(skip_bytes(&data, data_end, 4), "no length to be read");
            hdr_id = *(unsigned int *)(data - 4);

            REQUIRE(skip_bytes(&data, data_end, hdr_length - 4), "no length to be read");

            if (current_offset == offset)
                found_rela = true;

            /* CIE or relocation releated FDE */
            if (hdr_id == 0 || found_rela) {
                memcpy(eh_frame + frame_size, __src, hdr_length + 4);
                /* update rela offset to point to new offset, and also hdr_id */
                if (found_rela) {
                    /* 4 is the offset of hdr_id and 8 is the offset of PC begin */
                    *(unsigned int *)(eh_frame + frame_size + 4) = frame_size + 4;
                    rela->offset = frame_size + 8;
                }

                frame_size += (hdr_length + 4);
            } else {
                log_debug("remove FDE at 0x%x \n", current_offset);
            }

            /* hdr_length(value) + hdr_length(body) */
            current_offset += (4 + hdr_length);

            if (found_rela)
                break;
        }
        if (!found_rela)
            ERROR("No FDE found for relocation at 0x%x \n", offset);
    }

    /*
     * FIXME: data may not reach the data_end, since we have found
     *        all FDE for relocation entries, the only problem here is
     *        we may miss the CIE, but CIE is always in the beginning ?
     */

    sec->data->d_buf = eh_frame;
    sec->data->d_size = frame_size;
    sec->sh.sh_size = frame_size;
}
