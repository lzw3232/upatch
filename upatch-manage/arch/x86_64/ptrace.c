#include <string.h>

#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include "upatch-ptrace.h"

#define ORIGIN_INSN_LEN 5

int upatch_arch_syscall_remote(struct upatch_ptrace_ctx *pctx, int nr,
			       unsigned long arg1, unsigned long arg2,
			       unsigned long arg3, unsigned long arg4,
			       unsigned long arg5, unsigned long arg6,
			       unsigned long *res)
{
	struct user_regs_struct regs;

	unsigned char syscall[] = {
		0x0f, 0x05, /* syscall */
		0xcc, /* int3 */
	};
	int ret;

	memset(&regs, 0, sizeof(struct user_regs_struct));
	log_debug("Executing syscall %d (pid %d)...\n", nr, pctx->pid);
	regs.rax = (unsigned long)nr;
	regs.rdi = arg1;
	regs.rsi = arg2;
	regs.rdx = arg3;
	regs.r10 = arg4;
	regs.r8 = arg5;
	regs.r9 = arg6;

	ret = upatch_execute_remote(pctx, syscall, sizeof(syscall), &regs);
	if (ret == 0)
		*res = regs.rax;

	return ret;
}

int upatch_arch_execute_remote_func(struct upatch_ptrace_ctx *pctx,
				    const unsigned char *code, size_t codelen,
				    struct user_regs_struct *pregs,
				    int (*func)(struct upatch_ptrace_ctx *pctx,
						const void *data),
				    const void *data)
{
	struct user_regs_struct orig_regs, regs;
	unsigned char orig_code[codelen];
	int ret;
	struct upatch_process *proc = pctx->proc;
	unsigned long libc_base = proc->libc_base;

	ret = ptrace(PTRACE_GETREGS, pctx->pid, NULL, &orig_regs);
	if (ret < 0) {
		log_error("can't get regs - %d\n", pctx->pid);
		return -1;
	}
	ret = upatch_process_mem_read(proc, libc_base,
				      (unsigned long *)orig_code, codelen);
	if (ret < 0) {
		log_error("can't peek original code - %d\n", pctx->pid);
		return -1;
	}
	ret = upatch_process_mem_write(proc, (unsigned long *)code, libc_base,
				       codelen);
	if (ret < 0) {
		log_error("can't poke syscall code - %d\n", pctx->pid);
		goto poke_back;
	}

	regs = orig_regs;
	regs.rip = libc_base;

	copy_regs(&regs, pregs);

	ret = ptrace(PTRACE_SETREGS, pctx->pid, NULL, &regs);
	if (ret < 0) {
		log_error("can't set regs - %d\n", pctx->pid);
		goto poke_back;
	}

	ret = func(pctx, data);
	if (ret < 0) {
		log_error("failed call to func\n");
		goto poke_back;
	}

	ret = ptrace(PTRACE_GETREGS, pctx->pid, NULL, &regs);
	if (ret < 0) {
		log_error("can't get updated regs - %d\n", pctx->pid);
		goto poke_back;
	}

	ret = ptrace(PTRACE_SETREGS, pctx->pid, NULL, &orig_regs);
	if (ret < 0) {
		log_error("can't restore regs - %d\n", pctx->pid);
		goto poke_back;
	}

	*pregs = regs;

poke_back:
	upatch_process_mem_write(proc, (unsigned long *)orig_code, libc_base,
				 codelen);
	return ret;
}

void copy_regs(struct user_regs_struct *dst, struct user_regs_struct *src)
{
#define COPY_REG(x) dst->x = src->x
	COPY_REG(r15);
	COPY_REG(r14);
	COPY_REG(r13);
	COPY_REG(r12);
	COPY_REG(rbp);
	COPY_REG(rbx);
	COPY_REG(r11);
	COPY_REG(r10);
	COPY_REG(r9);
	COPY_REG(r8);
	COPY_REG(rax);
	COPY_REG(rcx);
	COPY_REG(rdx);
	COPY_REG(rsi);
	COPY_REG(rdi);
#undef COPY_REG
}

size_t get_origin_insn_len()
{
	return ORIGIN_INSN_LEN;
}

unsigned long get_new_insn(struct object_file *obj, unsigned long old_addr,
			   unsigned long new_addr)
{
	char jmp_insn[] = { 0xe9, 0x00, 0x00, 0x00, 0x00 }; /* jmp IMM */

	*(unsigned int *)(jmp_insn + 1) =
		(unsigned int)(new_addr - old_addr - 5);

	return *(unsigned long *)jmp_insn;
}