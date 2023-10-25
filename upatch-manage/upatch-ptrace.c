#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <asm/unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "upatch-common.h"
#include "upatch-ptrace.h"

/* process's memory access */
int upatch_process_mem_read(struct upatch_process *proc, unsigned long src,
			    void *dst, size_t size)
{
	ssize_t r;

	r = pread(proc->memfd, dst, size, (off_t)src);

	return r != size ? -1 : 0;
}

static int upatch_process_mem_write_ptrace(struct upatch_process *proc,
					   void *src, unsigned long dst,
					   size_t size)
{
	int ret;

	while (ROUND_DOWN(size, sizeof(long)) != 0) {
		ret = ptrace(PTRACE_POKEDATA, proc->pid, dst,
			     *(unsigned long *)src);
		if (ret)
			return -1;

		dst += sizeof(long);
		src += sizeof(long);
		size -= sizeof(long);
	}

	if (size) {
		unsigned long tmp;

		tmp = ptrace(PTRACE_PEEKDATA, proc->pid, dst, NULL);
		if (tmp == (unsigned long)-1 && errno)
			return -1;
		memcpy(&tmp, src, size);

		ret = ptrace(PTRACE_POKEDATA, proc->pid, dst, tmp);
		if (ret)
			return -1;
	}

	return 0;
}

int upatch_process_mem_write(struct upatch_process *proc, void *src,
			     unsigned long dst, size_t size)
{
	static int use_pwrite = 1;
	ssize_t w;

	if (use_pwrite)
		w = pwrite(proc->memfd, src, size, (off_t)dst);
	if (!use_pwrite || (w == -1 && errno == EINVAL)) {
		use_pwrite = 0;
		return upatch_process_mem_write_ptrace(proc, src, dst, size);
	}

	return w != size ? -1 : 0;
}

static struct upatch_ptrace_ctx *
upatch_ptrace_ctx_alloc(struct upatch_process *proc)
{
	struct upatch_ptrace_ctx *p;

	p = malloc(sizeof(*p));
	if (!p)
		return NULL;
	memset(p, 0, sizeof(*p));

	p->execute_until = 0UL;
	p->running = 1;
	p->proc = proc;

	INIT_LIST_HEAD(&p->list);
	list_add(&p->list, &proc->ptrace.pctxs);
	return p;
}

int upatch_ptrace_attach_thread(struct upatch_process *proc, int tid)
{
	long ret;
	int status;
	struct upatch_ptrace_ctx *pctx;

	pctx = upatch_ptrace_ctx_alloc(proc);
	if (pctx == NULL) {
		log_error("Can't alloc upatch_ptrace_ctx");
		return -1;
	}

	pctx->pid = tid;
	log_debug("Attaching to %d...", pctx->pid);

	ret = ptrace(PTRACE_ATTACH, pctx->pid, NULL, NULL);
	if (ret < 0) {
		log_error("can't attach to %d\n", pctx->pid);
		return -1;
	}

	do {
		ret = waitpid(tid, &status, __WALL);
		if (ret < 0) {
			log_error("can't wait for thread\n");
			return -1;
		}

		/* We are expecting SIGSTOP */
		if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
			break;

		/* If we got SIGTRAP because we just got out of execve, wait
		 * for the SIGSTOP
		 */
		if (WIFSTOPPED(status))
			status = (WSTOPSIG(status) == SIGTRAP) ?
					 0 :
					 WSTOPSIG(status);
		else if (WIFSIGNALED(status))
			/* Resend signal */
			status = WTERMSIG(status);

		ret = ptrace(PTRACE_CONT, pctx->pid, NULL,
			     (void *)(uintptr_t)status);
		if (ret < 0) {
			log_error("can't cont tracee\n");
			return -1;
		}
	} while (1);

	pctx->running = 0;

	log_debug("OK\n");
	return 0;
}

int wait_for_stop(struct upatch_ptrace_ctx *pctx, const void *data)
{
	int ret, status = 0, pid = (int)(uintptr_t)data ?: pctx->pid;
	log_debug("wait_for_stop(pctx->pid=%d, pid=%d)\n", pctx->pid, pid);

	while (1) {
		ret = ptrace(PTRACE_CONT, pctx->pid, NULL,
			     (void *)(uintptr_t)status);
		if (ret < 0) {
			log_error("can't start tracee %d\n", pctx->pid);
			return -1;
		}

		ret = waitpid(pid, &status, __WALL);
		if (ret < 0) {
			log_error("can't wait tracee %d\n", pid);
			return -1;
		}

		if (WIFSTOPPED(status)) {
			if (WSTOPSIG(status) == SIGSTOP ||
			    WSTOPSIG(status) == SIGTRAP)
				break;
			status = WSTOPSIG(status);
			continue;
		}

		status = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
	}

	return 0;
}

int upatch_ptrace_detach(struct upatch_ptrace_ctx *pctx)
{
	long ret;

	if (!pctx->pid)
		return 0;
	log_debug("Detaching from %d...\n", pctx->pid);
	ret = ptrace(PTRACE_DETACH, pctx->pid, NULL, NULL);
	if (ret < 0) {
		log_error("can't detach from %d\n", pctx->pid);
		return -errno;
	}

	log_debug("OK\n");

	pctx->running = 1;
	pctx->pid = 0;
	return 0;
}

int upatch_execute_remote(struct upatch_ptrace_ctx *pctx,
			  const unsigned char *code, size_t codelen,
			  struct user_regs_struct *pregs)
{
	return upatch_arch_execute_remote_func(pctx, code, codelen, pregs,
					       wait_for_stop, NULL);
}

unsigned long upatch_mmap_remote(struct upatch_ptrace_ctx *pctx,
				 unsigned long addr, size_t length, int prot,
				 int flags, int fd, off_t offset)
{
	int ret;
	unsigned long res = 0;

	log_debug("mmap_remote: 0x%lx+%lx, %x, %x, %d, %lx\n", addr, length,
		  prot, flags, fd, offset);
	ret = upatch_arch_syscall_remote(pctx, __NR_mmap, (unsigned long)addr,
					 length, prot, flags, fd, offset, &res);
	if (ret < 0)
		return 0;
	if (ret == 0 && res >= (unsigned long)-MAX_ERRNO) {
		errno = -(long)res;
		return 0;
	}
	return res;
}

int upatch_mprotect_remote(struct upatch_ptrace_ctx *pctx, unsigned long addr,
			   size_t length, int prot)
{
	int ret;
	unsigned long res;

	log_debug("mprotect_remote: 0x%lx+%lx\n", addr, length);
	ret = upatch_arch_syscall_remote(pctx, __NR_mprotect,
					 (unsigned long)addr, length, prot, 0,
					 0, 0, &res);
	if (ret < 0)
		return -1;
	if (ret == 0 && res >= (unsigned long)-MAX_ERRNO) {
		errno = -(long)res;
		return -1;
	}

	return 0;
}

int upatch_munmap_remote(struct upatch_ptrace_ctx *pctx, unsigned long addr,
			 size_t length)
{
	int ret;
	unsigned long res;

	log_debug("munmap_remote: 0x%lx+%lx\n", addr, length);
	ret = upatch_arch_syscall_remote(pctx, __NR_munmap, (unsigned long)addr,
					 length, 0, 0, 0, 0, &res);
	if (ret < 0)
		return -1;
	if (ret == 0 && res >= (unsigned long)-MAX_ERRNO) {
		errno = -(long)res;
		return -1;
	}
	return 0;
}
