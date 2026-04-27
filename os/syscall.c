#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"

uint64 console_write(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	tracef("write size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return len;
}

uint64 console_read(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	tracef("read size = %d", len);
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
}

uint64 sys_write(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}
	switch (f->type) {
	case FD_STDIO:
		return console_write(va, len);
	case FD_INODE:
		return inodewrite(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
}

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}
	switch (f->type) {
	case FD_STDIO:
		return console_read(va, len);
	case FD_INODE:
		return inoderead(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

uint64 sys_gettimeofday(uint64 val, int _tz)
{
	struct proc *p = curr_proc();
	uint64 cycle = get_cycle();
	TimeVal t;
	t.sec = cycle / CPU_FREQ;
	t.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	copyout(p->pagetable, val, (char *)&t, sizeof(TimeVal));
	return 0;
}

uint64 sys_getpid()
{
	return curr_proc()->pid;
}

uint64 sys_getppid()
{
	struct proc *p = curr_proc();
	return p->parent == NULL ? IDLE_PID : p->parent->pid;
}

uint64 sys_clone()
{
	debugf("fork!");
	return fork();
}

static inline uint64 fetchaddr(pagetable_t pagetable, uint64 va)
{
	uint64 *addr = (uint64 *)useraddr(pagetable, va);
	return *addr;
}

uint64 sys_exec(uint64 path, uint64 uargv)
{
	struct proc *p = curr_proc();
	char name[MAX_STR_LEN];
	copyinstr(p->pagetable, name, path, MAX_STR_LEN);
	uint64 arg;
	static char strpool[MAX_ARG_NUM][MAX_STR_LEN];
	char *argv[MAX_ARG_NUM];
	int i;
	for (i = 0; uargv && (arg = fetchaddr(p->pagetable, uargv));
	     uargv += sizeof(char *), i++) {
		copyinstr(p->pagetable, (char *)strpool[i], arg, MAX_STR_LEN);
		argv[i] = (char *)strpool[i];
	}
	argv[i] = NULL;
	return exec(name, (char **)argv);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = (int *)useraddr(p->pagetable, va);
	return wait(pid, code);
}

// Copies filename from user VA, delegates to spawn() in proc.c (no memory copy).
uint64 sys_spawn(uint64 va)
{
	struct proc *p = curr_proc();
	char name[200];
	copyinstr(p->pagetable, name, va, 200);
	return spawn(name);
}

// Sets priority of calling process. Valid range [2, LLONG_MAX] per spec.
uint64 sys_set_priority(long long prio)
{
	if (prio < 2) return -1;
	curr_proc()->priority = (uint64)prio;
	return prio;
}

// Returns status, syscall counts, and elapsed time for the current process.
// Uses copyout because TaskInfo is ~2KB — too large to use useraddr safely.
int sys_task_info(struct TaskInfo *ti)
{
	struct proc *p = curr_proc();
	struct TaskInfo kti;
	kti.status = Running;
	kti.time = (get_cycle() - p->start_time) / (CPU_FREQ / 1000);
	memmove(kti.syscall_times, p->syscall_times, sizeof(p->syscall_times));
	if (copyout(p->pagetable, (uint64)ti, (char *)&kti, sizeof(kti)) < 0)
		return -1;
	return 0;
}

// Maps anonymous memory at start with permissions from port.
// port bits: 0=R, 1=W, 2=X. start must be page-aligned. Max 1GiB per call.
uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd)
{
	if (!PGALIGNED(start)) return -1;
	if (len == 0) return 0;
	if ((port & ~0x7) != 0) return -1;
	if ((port & 0x7) == 0) return -1;
	len = PGROUNDUP(len);
	if (len > (1ULL << 30)) return -1;
	struct proc *p = curr_proc();
	int perm = ((port & 0x7) << 1) | PTE_U | PTE_V;
	for (uint64 va = start; va < start + len; va += PGSIZE)
		if (walkaddr(p->pagetable, va) != 0) return -1;
	for (uint64 va = start; va < start + len; va += PGSIZE) {
		void *pa = kalloc();
		if (pa == 0) return -1;
		memset(pa, 0, PGSIZE);
		if (mappages(p->pagetable, va, PGSIZE, (uint64)pa, perm) != 0) {
			kfree(pa);
			return -1;
		}
	}
	return 0;
}

// Unmaps len bytes at start, freeing physical pages.
uint64 sys_munmap(uint64 start, uint64 len)
{
	if (!PGALIGNED(start)) return -1;
	if (len == 0) return 0;
	len = PGROUNDUP(len);
	struct proc *p = curr_proc();
	for (uint64 va = start; va < start + len; va += PGSIZE)
		if (walkaddr(p->pagetable, va) == 0) return -1;
	uvmunmap(p->pagetable, start, len / PGSIZE, 1);
	return 0;
}

uint64 sys_openat(uint64 va, uint64 omode, uint64 _flags)
{
	struct proc *p = curr_proc();
	char path[200];
	copyinstr(p->pagetable, path, va, 200);
	return fileopen(path, omode);
}

uint64 sys_close(int fd)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d", fd);
		return -1;
	}
	fileclose(f);
	p->files[fd] = 0;
	return 0;
}

// Stat struct — must match user/lib definition exactly.
#define STAT_DIR  0x040000
#define STAT_FILE 0x100000

typedef struct {
	uint64 dev;
	uint64 ino;
	uint32 mode;
	uint32 nlink;
	uint64 pad[7];
} Stat;

// Returns inode metadata for an open file.
int sys_fstat(int fd, uint64 stat)
{
	struct proc *p = curr_proc();
	if (fd < 0 || fd >= FD_BUFFER_SIZE) return -1;
	struct file *f = p->files[fd];
	if (f == NULL || f->type != FD_INODE) return -1;
	struct inode *ip = f->ip;
	ivalid(ip);
	Stat st;
	st.dev   = 0;
	st.ino   = ip->inum;
	st.mode  = (ip->type == T_DIR) ? STAT_DIR : STAT_FILE;
	st.nlink = ip->nlink;
	memset(st.pad, 0, sizeof(st.pad));
	if (copyout(p->pagetable, stat, (char *)&st, sizeof(st)) < 0) return -1;
	return 0;
}

// Creates a new directory entry newpath pointing to the same inode as oldpath.
// olddirfd/newdirfd/flags are ignored (always AT_FDCWD/0 per spec).
int sys_linkat(int olddirfd, uint64 oldpath, int newdirfd, uint64 newpath, uint64 flags)
{
	struct proc *p = curr_proc();
	char old[200], newp[200];
	copyinstr(p->pagetable, old,  oldpath, 200);
	copyinstr(p->pagetable, newp, newpath, 200);
	struct inode *ip = namei(old);
	if (ip == 0) return -1;
	ivalid(ip);
	// linking to same name is an error per spec
	if (strncmp(old, newp, DIRSIZ) == 0) { iput(ip); return -1; }
	ip->nlink++;
	iupdate(ip);
	struct inode *dp = root_dir();
	if (dirlink(dp, newp, ip->inum) < 0) {
		ip->nlink--;
		iupdate(ip);
		iput(dp); iput(ip);
		return -1;
	}
	iput(dp);
	iput(ip);
	return 0;
}

// Removes the named directory entry. If nlink hits 0, iput() frees the inode+data.
// dirfd/flags are ignored (always AT_FDCWD/0 per spec).
int sys_unlinkat(int dirfd, uint64 name, uint64 flags)
{
	struct proc *p = curr_proc();
	char path[200];
	copyinstr(p->pagetable, path, name, 200);
	struct inode *ip = namei(path);
	if (ip == 0) return -1;
	ivalid(ip);
	struct inode *dp = root_dir();
	if (dirunlink(dp, path) < 0) { iput(dp); iput(ip); return -1; }
	iput(dp);
	ip->nlink--;
	iupdate(ip);
	iput(ip);
	return 0;
}

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	// Track per-syscall call counts for sys_task_info
	if (id >= 0 && id < 500)
		curr_proc()->syscall_times[id]++;
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_read:
		ret = sys_read(args[0], args[1], args[2]);
		break;
	case SYS_openat:
		ret = sys_openat(args[0], args[1], args[2]);
		break;
	case SYS_close:
		ret = sys_close(args[0]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday(args[0], args[1]);
		break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
	case SYS_getppid:
		ret = sys_getppid();
		break;
	case SYS_clone:
		ret = sys_clone();
		break;
	case SYS_execve:
		ret = sys_exec(args[0], args[1]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
	case SYS_spawn:
		ret = sys_spawn(args[0]);
		break;
	case SYS_setpriority:
		ret = sys_set_priority(args[0]);
		break;
	case SYS_task_info:
		ret = sys_task_info((struct TaskInfo *)args[0]);
		break;
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;
	case SYS_fstat:
		ret = sys_fstat(args[0], args[1]);
		break;
	case SYS_linkat:
		ret = sys_linkat(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_unlinkat:
		ret = sys_unlinkat(args[0], args[1], args[2]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}