/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023 Longjun Luo. */
#ifndef __UPATCH_ENTRY_H_
#define __UPATCH_ENTRY_H_

#define UPATCH_MAX_HIJACK_ENTRY 16
#define UPATCH_ENTRY_MAX_LEN 128

/* These structs must be packed since we use them in the hashtable */
struct upatch_entry {
	char name[UPATCH_ENTRY_MAX_LEN];
};

struct upatch_entry_des {
	unsigned int ref;
	unsigned int if_hijacker;
	unsigned long self_ino;
	char jumper_path[UPATCH_ENTRY_MAX_LEN];
};

#endif /* __UPATCH_ENTRY_H_ */
