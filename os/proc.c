#include "proc.h"
#include "defs.h"
#include "loader.h"
#include "trap.h"
#include "vm.h"
#include "queue.h"
#include "timer.h"  // needed for get_cycle() in start_time and sys_task_info

struct proc pool[NPROC];
__attribute__((aligned(16))) char kstack[NPROC][PAGE_SIZE];
__attribute__((aligned(4096))) char trapframe[NPROC][TRAP_PAGE_SIZE];

extern char boot_stack_top[];
struct proc *current_proc;
struct proc idle;
struct queue task_queue;

int threadid()
{
	return curr_proc()->pid;
}

int cpuid()
{
	return 0;
}

struct proc *curr_proc()
{
	return current_proc;
}

// initialize the proc table at boot time.
void proc_init()
{
	struct proc *p;
	for (p = pool; p < &pool[NPROC]; p++) {
		p->state = UNUSED;
		p->kstack = (uint64)kstack[p - pool];
		p->trapframe = (struct trapframe *)trapframe[p - pool];
		memset(p->syscall_times, 0, sizeof(p->syscall_times));
		p->start_time = 0;
	}
	idle.kstack = (uint64)boot_stack_top;
	idle.pid = IDLE_PID;
	current_proc = &idle;
	init_queue(&task_queue);
}

int allocpid()
{
	static int PID = 1;
	return PID++;
}

// Stride scheduler: pool scan for the RUNNABLE proc with the smallest stride.
// Increment winner's stride before returning so it moves back in the ordering.
// The FIFO queue is abandoned — keeping push_queue here would overflow it over
// time because we never drain it via pop_queue anymore.
struct proc *fetch_task()
{
	struct proc *p, *best = NULL;
	for (p = pool; p < &pool[NPROC]; p++) {
		if (p->state == RUNNABLE)
			if (best == NULL || p->stride < best->stride)
				best = p;
	}
	if (best != NULL)
		best->stride += BIG_STRIDE / best->priority;
	return best;
}

// No-op: stride scheduler discovers RUNNABLE procs via pool scan in fetch_task.
void add_task(struct proc *p) { (void)p; }

// Look in the process table for an UNUSED proc.
// If found, initialize state required to run in the kernel.
// If there are no free procs, or a memory allocation fails, return 0.
struct proc *allocproc()
{
	struct proc *p;
	for (p = pool; p < &pool[NPROC]; p++) {
		if (p->state == UNUSED) {
			goto found;
		}
	}
	return 0;

found:
	// init proc
	p->pid = allocpid();
	p->state = USED;
	p->ustack = 0;
	p->max_page = 0;
	p->parent = NULL;
	p->exit_code = 0;
	p->pagetable = uvmcreate((uint64)p->trapframe);
	memset(&p->context, 0, sizeof(p->context));
	memset((void *)p->kstack, 0, KSTACK_SIZE);
	memset((void *)p->trapframe, 0, TRAP_PAGE_SIZE);
	memset((void *)p->files, 0, sizeof(struct file *) * FD_BUFFER_SIZE);
	p->context.ra = (uint64)usertrapret;
	p->context.sp = p->kstack + KSTACK_SIZE;
	p->stride = 0;     // all new procs start equal; stride scheduler picks whichever is lowest
	p->priority = 16;  // default priority per spec
	return p;
}

int init_stdio(struct proc *p)
{
	for (int i = 0; i < 3; i++) {
		if (p->files[i] != NULL) {
			return -1;
		}
		p->files[i] = stdio_init(i);
	}
	return 0;
}

// Scheduler never returns.
void scheduler()
{
	struct proc *p;
	for (;;) {
		p = fetch_task();
		if (p == NULL) {
			panic("all app are over!\n");
		}
		tracef("swtich to proc %d", p - pool);
		// Record first-run time so sys_task_info can report elapsed ms correctly
		if (p->start_time == 0)
			p->start_time = get_cycle();
		p->state = RUNNING;
		current_proc = p;
		swtch(&idle.context, &p->context);
	}
}

void sched()
{
	struct proc *p = curr_proc();
	if (p->state == RUNNING)
		panic("sched running");
	swtch(&p->context, &idle.context);
}

// Give up the CPU for one scheduling round.
void yield()
{
	current_proc->state = RUNNABLE;
	add_task(current_proc);
	sched();
}

// Free a process's page table, and free the physical memory it refers to.
void freepagetable(pagetable_t pagetable, uint64 max_page)
{
	uvmunmap(pagetable, TRAMPOLINE, 1, 0);
	uvmunmap(pagetable, TRAPFRAME, 1, 0);
	uvmfree(pagetable, max_page);
}

void freeproc(struct proc *p)
{
	if (p->pagetable)
		freepagetable(p->pagetable, p->max_page);
	p->pagetable = 0;
	for (int i = 0; i > FD_BUFFER_SIZE; i++) {
		if (p->files[i] != NULL) {
			fileclose(p->files[i]);
		}
	}
	p->state = UNUSED;
}

int fork()
{
	struct proc *np;
	struct proc *p = curr_proc();
	int i;
	// Allocate process.
	if ((np = allocproc()) == 0) {
		panic("allocproc\n");
	}
	// Copy user memory from parent to child.
	if (uvmcopy(p->pagetable, np->pagetable, p->max_page) < 0) {
		panic("uvmcopy\n");
	}
	np->max_page = p->max_page;
	// Copy file table to new proc
	for (i = 0; i < FD_BUFFER_SIZE; i++) {
		if (p->files[i] != NULL) {
			p->files[i]->ref++;
			np->files[i] = p->files[i];
		}
	}
	// copy saved user registers.
	*(np->trapframe) = *(p->trapframe);
	// Cause fork to return 0 in the child.
	np->trapframe->a0 = 0;
	np->parent = p;
	np->state = RUNNABLE;
	add_task(np);
	return np->pid;
}

int push_argv(struct proc *p, char **argv)
{
	uint64 argc, ustack[MAX_ARG_NUM + 1];
	uint64 sp = p->ustack + USTACK_SIZE, spb = p->ustack;
	for (argc = 0; argv[argc]; argc++) {
		if (argc >= MAX_ARG_NUM)
			panic("...");
		sp -= strlen(argv[argc]) + 1;
		sp -= sp % 16;
		if (sp < spb) {
			panic("...");
		}
		if (copyout(p->pagetable, sp, argv[argc],
			    strlen(argv[argc]) + 1) < 0) {
			panic("...");
		}
		ustack[argc] = sp;
	}
	ustack[argc] = 0;
	sp -= (argc + 1) * sizeof(uint64);
	sp -= sp % 16;
	if (sp < spb) {
		panic("...");
	}
	if (copyout(p->pagetable, sp, (char *)ustack,
		    (argc + 1) * sizeof(uint64)) < 0) {
		panic("...");
	}
	p->trapframe->a1 = sp;
	p->trapframe->sp = sp;
	return argc;
}

int exec(char *path, char **argv)
{
	infof("exec : %s\n", path);
	struct inode *ip;
	struct proc *p = curr_proc();
	if ((ip = namei(path)) == 0) {
		errorf("invalid file name %s\n", path);
		return -1;
	}
	uvmunmap(p->pagetable, 0, p->max_page, 1);
	bin_loader(ip, p);
	iput(ip);
	return push_argv(p, argv);
}

// spawn: creates a child process and loads the named executable from the filesystem.
// Uses namei() + bin_loader() — ch6 filesystem API replaces the old get_id_by_name/loader.
// Inherits parent's file descriptors so stdin/stdout/stderr carry over to the child.
int spawn(char *name)
{
	struct inode *ip = namei(name);
	if (ip == 0) return -1;

	struct proc *np = allocproc();
	if (np == NULL) { iput(ip); return -1; }

	np->parent = curr_proc();

	// Copy parent's file descriptor table so the child has stdin/stdout/stderr
	struct proc *p = curr_proc();
	for (int i = 0; i < FD_BUFFER_SIZE; i++) {
		if (p->files[i] != NULL) {
			p->files[i]->ref++;
			np->files[i] = p->files[i];
		}
	}

	bin_loader(ip, np);
	iput(ip);   // release inode reference now that loading is done
	return np->pid;
}

int wait(int pid, int *code)
{
	struct proc *np;
	int havekids;
	struct proc *p = curr_proc();

	for (;;) {
		havekids = 0;
		for (np = pool; np < &pool[NPROC]; np++) {
			if (np->state != UNUSED && np->parent == p &&
			    (pid <= 0 || np->pid == pid)) {
				havekids = 1;
				if (np->state == ZOMBIE) {
					np->state = UNUSED;
					pid = np->pid;
					*code = np->exit_code;
					return pid;
				}
			}
		}
		if (!havekids) {
			return -1;
		}
		p->state = RUNNABLE;
		add_task(p);
		sched();
	}
}

// Exit the current process.
void exit(int code)
{
	struct proc *p = curr_proc();
	p->exit_code = code;
	debugf("proc %d exit with %d", p->pid, code);
	freeproc(p);
	if (p->parent != NULL) {
		p->state = ZOMBIE;
	}
	struct proc *np;
	for (np = pool; np < &pool[NPROC]; np++) {
		if (np->parent == p) {
			np->parent = NULL;
		}
	}
	sched();
}

int fdalloc(struct file *f)
{
	debugf("debugf f = %p, type = %d", f, f->type);
	struct proc *p = curr_proc();
	for (int i = 0; i < FD_BUFFER_SIZE; ++i) {
		if (p->files[i] == NULL) {
			p->files[i] = f;
			debugf("debugf fd = %d, f = %p", i, p->files[i]);
			return i;
		}
	}
	return -1;
}