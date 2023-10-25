// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 HUAWEI, Inc.
 *
 * Authors:
 *   Zongwu Li <lzw32321226@gmail.com>
 *
 */

#include <argp.h>
#include <dirent.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "upatch-elf.h"
#include "upatch-patch.h"

enum loglevel loglevel = NORMAL;
char *logprefix;

#define COMMAND_SIZE 4
char *command[COMMAND_SIZE] = { "", "patch", "unpatch", "info" };
enum Command {
	DEFAULT,
	PATCH,
	UNPATCH,
	INFO,
};

struct arguments {
	int cmd;
	int pid;
	char *upatch;
	char *binary;
	bool verbose;
};

static struct argp_option options[] = {
	{ "verbose", 'v', NULL, 0, "Show verbose output" },
	{ "pid", 'p', "pid", 0, "the pid of the user-space process" },
	{ "upatch", 'u', "upatch", 0, "the upatch file" },
	{ "binary", 'b', "binary", 0, "the binary file" },
	{ "cmd", 0, "patch", 0, "Apply a upatch file to a user-space process" },
	{ "cmd", 0, "unpatch", 0,
	  "Unapply a upatch file to a user-space process" },
	{ NULL }
};

static char program_doc[] = "Operate a upatch file on the user-space process";

static char args_doc[] =
	"<cmd> --pid <Pid> --upatch <Upatch path> --binary <Binary path>";

const char *argp_program_version = "UPATCH_VERSION";

static error_t check_opt(struct argp_state *state)
{
	struct arguments *arguments = state->input;

	if (arguments->cmd == DEFAULT) {
		argp_usage(state);
		return ARGP_ERR_UNKNOWN;
	}
	switch (arguments->cmd) {
	case PATCH:
	case UNPATCH:
	case INFO:
		if (!arguments->pid || arguments->upatch == NULL ||
		    arguments->binary == NULL) {
			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}
	default:
		break;
	}
	return 0;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;

	switch (key) {
	case 'v':
		arguments->verbose = true;
		break;
	case 'p':
		arguments->pid = atoi(arg);
		break;
	case 'u':
		arguments->upatch = arg;
		break;
	case 'b':
		arguments->binary = arg;
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num >= 1)
			argp_usage(state);
		if (arguments->cmd != DEFAULT)
			argp_usage(state);
		for (int i = 1; i < COMMAND_SIZE; ++i) {
			if (!strcmp(arg, command[i])) {
				arguments->cmd = i;
				break;
			}
		}
		break;
	case ARGP_KEY_END:
		return check_opt(state);
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, program_doc };

static void show_program_info(struct arguments *arguments)
{
	log_debug("pid: %d\n", arguments->pid);
	log_debug("upatch object: %s\n", arguments->upatch);
	log_debug("binary object: %s\n", arguments->binary);
}

int patch_upatch(const char *binary_path, const char *upatch_path, int pid)
{
	int ret;
	struct upatch_elf uelf;
	struct running_elf relf;

	ret = upatch_init(&uelf, upatch_path);
	if (ret) {
		log_error("upatch_init failed %d \n", ret);
		goto out;
	}

	ret = binary_init(&relf, binary_path);
	if (ret) {
		log_error("binary_init failed %d \n", ret);
		goto out;
	}

	uelf.relf = &relf;

	// ret = check_build_id(&uelf.info, &relf.info);
	// if (ret) {
	//     log_error("check build id failed %d \n", ret);
	//     goto out;
	// }

	ret = process_patch(pid, &uelf, &relf);
	if (ret) {
		log_error("process patch failed %d \n", ret);
		goto out;
	}

out:
	upatch_close(&uelf);
	binary_close(&relf);
	if (ret)
		log_normal("FAIL\n");
	else
		log_normal("SUCCESS\n");
	return ret;
}

int unpatch_upatch(const char *binary_path, const char *upatch_path, int pid)
{
	int ret = 0;

	ret = process_unpatch(pid);
	if (ret) {
		log_error("process patch failed %d \n", ret);
		goto out;
	}

out:
	if (ret)
		log_normal("FAIL\n");
	else
		log_normal("SUCCESS\n");
	return ret;
}

int info_upatch(const char *binary_path, const char *upatch_path, int pid)
{
	int ret = 0;

	ret = process_info(pid);
	if (ret) {
		log_error("process patch failed %d \n", ret);
		goto out;
	}

out:
	return ret;
}

int main(int argc, char *argv[])
{
	struct arguments arguments;

	memset(&arguments, 0, sizeof(arguments));
	argp_parse(&argp, argc, argv, 0, NULL, &arguments);
	if (arguments.verbose)
		loglevel = DEBUG;

	logprefix = basename(arguments.upatch);
	show_program_info(&arguments);
	switch (arguments.cmd) {
	case PATCH:
		return patch_upatch(arguments.binary, arguments.upatch,
				    arguments.pid);
	case UNPATCH:
		return unpatch_upatch(arguments.binary, arguments.upatch,
				      arguments.pid);
	case INFO:
		return info_upatch(arguments.binary, arguments.upatch,
				   arguments.pid);
	default:
		ERROR("unknown command");
	}
}