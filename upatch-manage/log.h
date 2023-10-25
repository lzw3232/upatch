/*
 * log.h
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

#ifndef __UPATCH_LOG_H_
#define __UPATCH_LOG_H_

#include <error.h>
#include <stdio.h>

/* Files that include log.h must define loglevel and logprefix */
extern enum loglevel loglevel;
extern char *logprefix;

enum exit_status {
	EXIT_STATUS_SUCCESS = 0,
	EXIT_STATUS_ERROR = 1,
	EXIT_STATUS_DIFF_FATAL = 2,
	EXIT_STATUS_NO_CHANGE = 3,
};

/* Since upatch-build is an one-shot program, we do not care about failure
 * handler */
#define ERROR(format, ...)                                                   \
	error(EXIT_STATUS_ERROR, 0, "ERROR: %s: %s: %d: " format, logprefix, \
	      __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define DIFF_FATAL(format, ...)                                        \
	error(EXIT_STATUS_DIFF_FATAL, 0, "ERROR: %s: %s: %d: " format, \
	      logprefix, __FUNCTION__, __LINE__, ##__VA_ARGS__)

/* it is time cost */
#define log_debug(format, ...) log(DEBUG, format, ##__VA_ARGS__)
#define log_normal(format, ...) log(NORMAL, format, ##__VA_ARGS__)
#define log_warn(format, ...) log(WARN, "%s: " format, logprefix, ##__VA_ARGS__)
#define log_error(format, ...) log(ERR, format, ##__VA_ARGS__)

#define log(level, format, ...)                        \
	({                                             \
		if (loglevel <= (level))               \
			printf(format, ##__VA_ARGS__); \
	})

#define REQUIRE(COND, message)          \
	do                              \
		if (!(COND))            \
			ERROR(message); \
	while (0)

enum loglevel {
	DEBUG,
	NORMAL,
	WARN,
	ERR,
};
#endif