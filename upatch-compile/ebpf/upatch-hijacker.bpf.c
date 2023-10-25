// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 Longjun Luo */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "upatch-entry.h"

#ifndef NULL
#define NULL ((void*)0)
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile unsigned int hijacker_total_ref = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, UPATCH_MAX_HIJACK_ENTRY);
	__type(key, struct upatch_entry);
	__type(value, struct upatch_entry_des);
} hijacker_entries SEC(".maps");

/*
 * >> cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
 */
struct sys_execve_enter_ctx {
    unsigned long long unused;
    int __syscall_nr;
    unsigned int padding;
    const char* filename;
    const char* const* argv;
    const char* const* envp;
};

SEC("tp/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct sys_execve_enter_ctx *ctx)
{
	long ret;
	unsigned long caller_ino;
	struct upatch_entry entry;
	unsigned int jumper_len = UPATCH_ENTRY_MAX_LEN;
	struct upatch_entry_des *entry_des = NULL;
	struct task_struct *tsk = NULL;

	if (hijacker_total_ref == 0)
		goto out;

	tsk = (struct task_struct *)bpf_get_current_task();
	caller_ino = BPF_CORE_READ(tsk, mm, exe_file, f_inode, i_ino);

	/* make sure the size of filename > 2 */
	__builtin_memset(&entry.name, '\x00', UPATCH_ENTRY_MAX_LEN);
	ret = bpf_probe_read_user_str(&entry.name, UPATCH_ENTRY_MAX_LEN, ctx->filename);
	if (ret < 0 || entry.name[1] == '\x00') {
		bpf_printk("read filename failed or filename too short - %d \n", ret);
		goto out;
	}

	entry_des = bpf_map_lookup_elem(&hijacker_entries, &entry);
	if (!entry_des || entry_des->ref == 0)
		goto out;

	if (!entry_des->if_hijacker)
		jumper_len = 2 + 1;

	/*
	 * Two situatiobs will triger the jump action:
	 * 1) filename is hijacker and it starts execute.
	 * 2) filename is not hijacker and someone others starts execute.
	 */
	if ((entry_des->if_hijacker && entry_des->self_ino == caller_ino) ||
		(!entry_des->if_hijacker && entry_des->self_ino != caller_ino))
		ret = bpf_probe_write_user((void*)ctx->filename,
			(const void *)&entry_des->jumper_path, jumper_len);

	if (ret < 0)
		bpf_printk("write jumper path failed - %d \n", ret);
out:
	return 0;
}
