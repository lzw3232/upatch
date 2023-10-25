#ifndef __UPATCH_PROCESS__
#define __UPATCH_PROCESS__

#include <gelf.h>

#include "list.h"
#include "upatch-patch.h"

#define OBJECT_UNKNOWN 0
#define OBJECT_ELF 1
#define OBJECT_UPATCH 2

#define ELFMAG "\177ELF"
#define SELFMAG 4

enum {
	MEM_READ,
	MEM_WRITE,
};

struct object_file {
	struct list_head list;
	struct upatch_process *proc;

	/* Device the object resides on */
	dev_t dev;
	ino_t inode;

	/* Object name (as seen in /proc/<pid>/maps) */
	char *name;

	/* List of object's VM areas */
	struct list_head vma;

	/* Pointer to the previous hole in the patient's mapping */
	struct vm_hole *previous_hole;

	/* Pointer to the applied patch list, if any */
	struct list_head applied_patch;
	/* The number of applied patch */
	size_t num_applied_patch;

	/* Is that a patch for some object? */
	unsigned int is_patch;

	/* Is it an ELF or a mmap'ed regular file? */
	unsigned int is_elf;
};

struct vm_area {
	unsigned long start;
	unsigned long end;
	unsigned long offset;
	unsigned int prot;
};

struct vm_hole {
	unsigned long start;
	unsigned long end;
	struct list_head list;
};

struct obj_vm_area {
	struct list_head list;
	struct vm_area inmem;
};

struct object_patch {
	struct list_head list;
	struct upatch_info *uinfo;
	struct upatch_info_func *funcs;
};

struct upatch_process {
	/* Pid of target process */
	int pid;

	/* memory fd of /proc/<pid>/mem */
	int memfd;

	/* /proc/<pid>/maps FD, also works as lock */
	int fdmaps;

	/* Process name */
	char comm[16];

	/* List of process objects */
	struct list_head objs;
	int num_objs;

	/* List ptrace contexts (one per each thread) */
	struct {
		struct list_head pctxs;
	} ptrace;

	struct {
		struct list_head coros;
	} coro;

	/* List of free VMA areas */
	struct list_head vmaholes;

	// TODO: other base?
	/* libc's base address to use as a worksheet */
	unsigned long libc_base;
};

int upatch_process_init(struct upatch_process *, int);

void upatch_process_print_short(struct upatch_process *);

int upatch_process_mem_open(struct upatch_process *, int);

int upatch_process_map_object_files(struct upatch_process *, const char *);

int upatch_process_attach(struct upatch_process *);

int vm_hole_split(struct vm_hole *, unsigned long, unsigned long);

unsigned long object_find_patch_region(struct object_file *, size_t,
				       struct vm_hole **);

void upatch_process_memfree(struct upatch_process *);

#endif