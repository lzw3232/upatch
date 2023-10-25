// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 HUAWEI, Inc.
 *
 * Authors:
 *   Zongwu Li <lzw32321226@gmail.com>
 *
 */

#ifndef __UPATCH_COMMON__
#define __UPATCH_COMMON__

#include <stdbool.h>

#define ALLOC_LINK(_new, _list)                           \
	{                                                 \
		(_new) = calloc(1, sizeof(*(_new)));      \
		if (!(_new))                              \
			ERROR("calloc");                  \
		INIT_LIST_HEAD(&(_new)->list);            \
		if (_list)                                \
			list_add(&(_new)->list, (_list)); \
	}

static inline int page_shift(int n)
{
	int res = -1;

	while (n) {
		res++;
		n >>= 1;
	}

	return res;
}

#ifndef PAGE_SIZE
#define PAGE_SIZE sysconf(_SC_PAGE_SIZE)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PAGE_SHIFT page_shift(PAGE_SIZE)
#endif
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define ALIGN(x, a) (((x) + (a)-1) & (~((a)-1)))
#define PAGE_ALIGN(x) ALIGN((x), PAGE_SIZE)

#define ROUND_DOWN(x, m) ((x) & ~((m)-1))
#define ROUND_UP(x, m) (((x) + (m)-1) & ~((m)-1))

#define BIT(x) (1UL << (x))

bool streql(const char *, const char *);

#endif