// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 HUAWEI, Inc.
 *
 * Authors:
 *   Zongwu Li <lzw32321226@gmail.com>
 *
 */

#include <string.h>

#include "upatch-common.h"

bool streql(const char *a, const char *b)
{
	return strlen(a) == strlen(b) && !strncmp(a, b, strlen(a));
}