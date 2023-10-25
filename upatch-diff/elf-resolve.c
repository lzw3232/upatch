/*
 * upatch-resolve.c
 *
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


#include <gelf.h>

#include "running-elf.h"
#include "upatch-patch.h"

/* To avoid mutiple definiation, only handle local symbols */
void upatch_partly_resolve(struct upatch_elf *uelf, struct running_elf *relf)
{
    struct symbol *sym;
    struct lookup_result symbol;

    list_for_each_entry(sym, &uelf->symbols, list) {
        if (sym->sym.st_other & SYM_OTHER) {
            if (!lookup_relf(relf, sym, &symbol))
                continue;
            /* keep it undefined for link purpose */
            sym->sym.st_value = symbol.symbol->addr;
            sym->sym.st_size = symbol.symbol->size;
        }
    }
}