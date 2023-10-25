/*
 * upatch-dynrela.h
 *
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

#ifndef __UPATCH_DYN_RELA_H_
#define __UPATCH_DYN_RELA_H_

struct upatch_symbol {
    unsigned long src;
    unsigned long sympos;
    unsigned char bind, type;
    char *name;
};

struct upatch_relocation {
    unsigned long dst;
    unsigned long type;
    long addend;
    struct upatch_symbol *sym;
};

#endif /* __UPATCH_DYN_RELA_H_ */