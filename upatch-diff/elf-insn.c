/*
 * elf-insn.c
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

#include <string.h>

#include "elf-common.h"
#include "elf-insn.h"

void rela_insn(const struct section *sec, const struct rela *rela, struct insn *insn)
{
    unsigned long insn_addr, start, end, rela_addr;

    start = (unsigned long)sec->data->d_buf;
    end = start + sec->sh.sh_size;

    if (end <= start)
        ERROR("bad section size");

    rela_addr = start + rela->offset;
    for (insn_addr = start; insn_addr < end; insn_addr += insn->length) {
        insn_init(insn, (void *)insn_addr, 1);
        insn_get_length(insn);
        if (!insn->length)
            ERROR("can't decode instruction in section %s at offset 0x%lx",
                sec->name, insn_addr);
        if (rela_addr >= insn_addr &&
            rela_addr < insn_addr + insn->length)
            return;
    }

    ERROR("can't find instruction for rela at %s+0x%x",
        sec->name, rela->offset);
}

long rela_target_offset(struct upatch_elf *uelf, struct section *relasec, struct rela *rela)
{
    long add_off;
    struct section *sec = relasec->base;

    switch(uelf->arch) {
    case AARCH64:
        add_off = 0;
        break;
    case X86_64:
        if (!is_text_section(sec) ||
            rela->type == R_X86_64_64 ||
            rela->type == R_X86_64_32 ||
            rela->type == R_X86_64_32S)
            add_off = 0;
        else if (rela->type == R_X86_64_PC32 ||
                rela->type == R_X86_64_PLT32) {
            struct insn insn;
            rela_insn(sec, rela, &insn);
            add_off = (long)insn.next_byte -
                        (long)sec->data->d_buf -
                        rela->offset;
        } else {
            ERROR("unable to handle rela type %d \n", rela->type);
        }
        break;
    default:
        ERROR("unsupported arch \n");
        break;
    }

    return rela->addend + add_off;
}

unsigned int insn_length(struct upatch_elf *uelf, void *addr)
{
    struct insn decoded_insn;
    
    switch(uelf->arch) {
    case AARCH64:
        return ARM64_INSTR_LEN;
    case X86_64:
        insn_init(&decoded_insn, addr, 1);
        insn_get_length(&decoded_insn);
        return decoded_insn.length;
    default:
        ERROR("unsupported arch");
    }

    return 0;
}

/* check: http://ref.x86asm.net/coder64.html */
bool insn_is_load_immediate(struct upatch_elf *uelf, void *addr)
{
    unsigned char *insn = addr;

    switch(uelf->arch) {
    case X86_64:
        /* arg2: mov $imm, %esi */
        if (insn[0] == 0xbe)
            return true;

        /* arg3: mov $imm, %edx */
        if (insn[0] == 0xba)
            return true;

        /* 0x41 is the prefix extend - REX.B */
        if (insn[0] == 0x41 && insn[1] == 0xb8)
            return true;

        break;
    default:
        ERROR("unsupported arch");
    }
    return false;
}