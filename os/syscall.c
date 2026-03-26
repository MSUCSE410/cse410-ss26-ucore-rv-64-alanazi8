#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
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

uint64 sys_gettimeofday(TimeVal *val, int _tz)
{
	struct proc *p = curr_proc();
	TimeVal *kval = (TimeVal *)useraddr(p->pagetable, (uint64)val);
	if (kval == 0)
		return -1;
	uint64 cycle = get_cycle();
	kval->sec = cycle / CPU_FREQ;
	kval->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	return 0;
}

// TODO: add support for mmap and munmap syscall.
// hint: read through docstrings in vm.c. Watching CH4 video may also help.
// Note the return value and PTE flags (especially U,X,W,R)

uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd)
{
	if (!PGALIGNED(start))
		return -1;
	if (len == 0)
		return 0;
	if ((port & ~0x7) != 0)
		return -1;
	if ((port & 0x7) == 0)
		return -1;
	len = PGROUNDUP(len);
	if (len > (1ULL << 30))
		return -1;
	struct proc *p = curr_proc();
	// Convert port bits to PTE flags: port bit 0=R, 1=W, 2=X -> PTE bit 1=R, 2=W, 3=X
	int perm = ((port & 0x7) << 1) | PTE_U | PTE_V;
	// Check that no page in range is already mapped
	for (uint64 va = start; va < start + len; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) != 0)
			return -1;
	}
	// Map page by page since kalloc gives non-contiguous pages
	for (uint64 va = start; va < start + len; va += PGSIZE) {
		void *pa = kalloc();
		if (pa == 0)
			return -1;
		memset(pa, 0, PGSIZE);
		if (mappages(p->pagetable, va, PGSIZE, (uint64)pa, perm) != 0) {
			kfree(pa);
			return -1;
		}
	}
	return 0;
}

uint64 sys_munmap(uint64 start, uint64 len)
{
	if (!PGALIGNED(start))
		return -1;
	if (len == 0)
		return 0;
	len = PGROUNDUP(len);
	struct proc *p = curr_proc();
	// Check all pages in range are mapped
	for (uint64 va = start; va < start + len; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) == 0)
			return -1;
	}
	uvmunmap(p->pagetable, start, len / PGSIZE, 1);
	return 0;
}
/*
* LAB1: you may need to define sys_task_info here
*/
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

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	/*
	* LAB1: you may need to update syscall counter for task info here
	*/
	if (id >= 0 && id < MAX_SYSCALL_NUM) {


		curr_proc()->syscall_times[id]++;


	}
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
	/*
	* LAB1: you may need to add SYS_taskinfo case here
	*/
	case SYS_task_info:


		ret = sys_task_info((struct TaskInfo *)args[0]);


		break;
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}