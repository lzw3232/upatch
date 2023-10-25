#ifndef __UPATCH_PTRACE__
#define __UPATCH_PTRACE__

#include "upatch-process.h"
#include <sys/user.h>

#include "list.h"
#include "log.h"

#define MAX_ERRNO 4095

struct upatch_ptrace_ctx {
	int pid;
	int running;
	unsigned long execute_until;
	struct upatch_process *proc;
	struct list_head list;
};

#define proc2pctx(proc) \
	list_first_entry(&(proc)->ptrace.pctxs, struct upatch_ptrace_ctx, list)

int upatch_process_mem_read(struct upatch_process *proc, unsigned long src,
			    void *dst, size_t size);

int upatch_process_mem_write(struct upatch_process *, void *, unsigned long,
			     size_t);

int upatch_ptrace_attach_thread(struct upatch_process *, int);

int upatch_ptrace_detach(struct upatch_ptrace_ctx *);

int wait_for_stop(struct upatch_ptrace_ctx *, const void *);

void copy_regs(struct user_regs_struct *, struct user_regs_struct *);

int upatch_arch_execute_remote_func(struct upatch_ptrace_ctx *pctx,
				    const unsigned char *code, size_t codelen,
				    struct user_regs_struct *pregs,
				    int (*func)(struct upatch_ptrace_ctx *pctx,
						const void *data),
				    const void *data);

int upatch_arch_syscall_remote(struct upatch_ptrace_ctx *, int, unsigned long,
			       unsigned long, unsigned long, unsigned long,
			       unsigned long, unsigned long, unsigned long *);

unsigned long upatch_mmap_remote(struct upatch_ptrace_ctx *, unsigned long,
				 size_t, int, int, int, off_t);

int upatch_mprotect_remote(struct upatch_ptrace_ctx *, unsigned long, size_t,
			   int);

int upatch_munmap_remote(struct upatch_ptrace_ctx *, unsigned long, size_t);

int upatch_execute_remote(struct upatch_ptrace_ctx *, const unsigned char *,
			  size_t, struct user_regs_struct *);

size_t get_origin_insn_len();

unsigned long get_new_insn(struct object_file *, unsigned long, unsigned long);

#endif