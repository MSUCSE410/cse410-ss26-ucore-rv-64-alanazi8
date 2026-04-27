#ifndef PROC_H
#define PROC_H

#include "riscv.h"
#include "types.h"

#define NPROC (512)
#define FD_BUFFER_SIZE (16)

struct file;

// Saved registers for kernel context switches.
struct context {
	uint64 ra;
	uint64 sp;

	// callee-saved
	uint64 s0;
	uint64 s1;
	uint64 s2;
	uint64 s3;
	uint64 s4;
	uint64 s5;
	uint64 s6;
	uint64 s7;
	uint64 s8;
	uint64 s9;
	uint64 s10;
	uint64 s11;
};

enum procstate { UNUSED, USED, SLEEPING, RUNNABLE, RUNNING, ZOMBIE };

// Per-process state
struct proc {
	enum procstate state; // Process state
	int pid; // Process ID
	pagetable_t pagetable; // User page table
	uint64 ustack; // Virtual address of kernel stack
	uint64 kstack; // Virtual address of kernel stack
	struct trapframe *trapframe; // data page for trampoline.S
	struct context context; // swtch() here to run process
	uint64 max_page;
	struct proc *parent; // Parent process
	uint64 exit_code;
	struct file *files[FD_BUFFER_SIZE]; // File descriptor table
	unsigned int syscall_times[500]; // per-syscall call count, for sys_task_info
	uint64 start_time;               // cycle count when process first ran, for elapsed time
	uint64 stride;                   // stride scheduling: accumulated pass value, starts at 0
	uint64 priority;                 // stride scheduling: process priority (>=2), default 16
};

// BIG_STRIDE / priority = how much stride increases per scheduled timeslice.
// 65536 chosen so integer division error is small and powers-of-2 priorities divide evenly.
#define BIG_STRIDE 65536ULL

#define MAX_SYSCALL_NUM 500

typedef enum { UnInit, Ready, Running, Exited } TaskStatus;

struct TaskInfo {
    TaskStatus status;
    unsigned int syscall_times[MAX_SYSCALL_NUM];
    int time;
};

int cpuid();
struct proc *curr_proc();
void exit(int);
void proc_init();
void scheduler() __attribute__((noreturn));
void sched();
void yield();
int fork();
int spawn(char *);  // create child process by loading ELF directly, no memory copy
int exec(char *, char **);
int wait(int, int *);
void add_task(struct proc *);
struct proc *pop_task();
struct proc *allocproc();
int fdalloc(struct file *);
int init_stdio(struct proc *);
int push_argv(struct proc *, char **);
// swtch.S
void swtch(struct context *, struct context *);

#endif // PROC_H