/*
 * elf-common.c
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

#include "elf-common.h"

int mangled_strcmp(char *str1, char *str2)
{
    /*
    * ELF string sections aren't mangled, though they look that way. 
    */
	if (strstr(str1, ".str1."))
		return strcmp(str1, str2);

	while (*str1 == *str2) {
		if (!*str2)
			return 0;

        // format like ".[0-9]"
		if (*str1 == '.' && isdigit(str1[1])) {
			if (!isdigit(str2[1]))
				return 1;
			while (isdigit(*++str1))
				;
			while (isdigit(*++str2))
				;
		} else {
			str1++;
			str2++;
		}
	}

	if ((!*str1 && has_digit_tail(str2)) ||
	    (!*str2 && has_digit_tail(str1)))
		return 0;

	return 1;
}

bool is_normal_static_local(struct symbol *sym)
{
    // only handle local variable
	if (sym->type != STT_OBJECT || sym->bind != STB_LOCAL)
		return false;

    // TODO: .Local ? need a example here
	if (!strncmp(sym->name, ".L", 2)) {
        ERROR("find no-local variable \n");
		return false;
    }

	if (!strchr(sym->name, '.'))
		return false;

	if (is_special_static(sym))
		return false;

	return true;
}

int offset_of_string(struct list_head *list, char *name)
{
	struct string *string;
	int index = 0;

	list_for_each_entry(string, list, list) {
		if (!strcmp(string->name, name))
			return index;
		index += (int)strlen(string->name) + 1;
	}

	ALLOC_LINK(string, list);
	string->name = name;
	return index;
}

// no need for X86
bool is_gcc6_localentry_bundled_sym(struct upatch_elf *uelf, struct symbol *sym)
{
	switch(uelf->arch) {
	case AARCH64:
		return false;
	case X86_64:
		return false;
	default:
		ERROR("unsupported arch");
	}
	return false;
}

bool is_mapping_symbol(struct upatch_elf *uelf, struct symbol *sym)
{
	if (uelf->arch != AARCH64)
		return false;

	if (sym->name && sym->name[0] == '$'
		&& sym->type == STT_NOTYPE
		&& sym->bind == STB_LOCAL)
		return true;
	return false;
}
