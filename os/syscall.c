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

/*
 * TASK 1: Fix sys_gettimeofday for virtual memory
 *
 * In ch3, user and kernel shared the same physical address space,
 * so we could write directly to the user's pointer: val->sec = ...
 *
 * In ch4, each process has its own page table. The pointer "val"
 * is a VIRTUAL address in the user's address space. If the kernel
 * dereferences it directly, it would access the WRONG physical
 * memory (or crash), because the kernel uses a different page table.
 *
 * Solution: use useraddr() to walk the user's page table and
 * translate the virtual address into the real physical address
 * that the kernel can safely write to.
 */
uint64 sys_gettimeofday(TimeVal *val, int _tz)
{
	/* Get the current process so we can access its page table */
	struct proc *p = curr_proc();

	/* Translate user virtual address -> physical address using the
	 * user's page table. useraddr() calls walkaddr() internally to
	 * get the physical page, then ORs in the 12-bit page offset
	 * from the original virtual address to get the exact byte address. */
	TimeVal *kval = (TimeVal *)useraddr(p->pagetable, (uint64)val);

	/* If translation failed (page not mapped), return error */
	if (kval == 0)
		return -1;

	/* Now kval points to the actual physical memory — safe to write.
	 * Same logic as ch3: read hardware cycle counter, convert to sec/usec */
	uint64 cycle = get_cycle();
	kval->sec = cycle / CPU_FREQ;
	kval->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	return 0;
}

/*
 * TASK 2: Implement mmap — anonymous memory mapping
 *
 * syscall ID: 222
 * Allows user programs to request new virtual memory pages.
 * The user specifies a starting virtual address, length, and
 * permission bits (read/write/execute).
 *
 * We allocate physical pages one at a time with kalloc() because
 * kalloc only returns single 4KB pages (not contiguous blocks),
 * then create page table entries linking each virtual page to
 * its allocated physical page using mappages().
 */
uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd)
{
	/* start must be page-aligned (multiple of 4096) */
	if (!PGALIGNED(start))
		return -1;

	/* len == 0 means nothing to map, return success immediately */
	if (len == 0)
		return 0;

	/* Validate port: bits 3+ must be zero (only bits 0,1,2 are valid).
	 * port & ~0x7 isolates everything above bit 2 — must all be 0 */
	if ((port & ~0x7) != 0)
		return -1;

	/* At least one of R/W/X must be set — mapping memory with
	 * no permissions at all is meaningless */
	if ((port & 0x7) == 0)
		return -1;

	/* Round len up to the next page boundary so we map full pages */
	len = PGROUNDUP(len);

	/* Spec says len must not exceed 1 GiB */
	if (len > (1ULL << 30))
		return -1;

	struct proc *p = curr_proc();

	/* Convert user permission bits to RISC-V page table entry (PTE) flags.
	 *
	 * User port bits:   bit 0 = Read,  bit 1 = Write,  bit 2 = Execute
	 * RISC-V PTE bits:  bit 1 = PTE_R, bit 2 = PTE_W,  bit 3 = PTE_X
	 *
	 * So we shift left by 1 to align them.
	 * We also add PTE_U (user-accessible) and PTE_V (valid).
	 * Without PTE_U, the CPU would fault when user-mode code touches these pages. */
	int perm = ((port & 0x7) << 1) | PTE_U | PTE_V;

	/* First pass: check that NO page in [start, start+len) is already mapped.
	 * walkaddr returns non-zero if a valid user mapping exists.
	 * If any page is already mapped, it's an error — we can't double-map. */
	for (uint64 va = start; va < start + len; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) != 0)
			return -1;
	}

	/* Second pass: allocate and map each page one at a time.
	 * kalloc() returns one 4KB physical page from the free list.
	 * We can't get contiguous physical memory, so we do it page by page.
	 * mappages() creates the page table entry linking this virtual
	 * address to the allocated physical page. */
	for (uint64 va = start; va < start + len; va += PGSIZE) {
		void *pa = kalloc();
		/* If out of physical memory, return error */
		if (pa == 0)
			return -1;
		/* Zero out the page so user gets clean memory */
		memset(pa, 0, PGSIZE);
		/* Create the page table entry. If this fails, free the page */
		if (mappages(p->pagetable, va, PGSIZE, (uint64)pa, perm) != 0) {
			kfree(pa);
			return -1;
		}
	}
	return 0;
}

/*
 * TASK 2: Implement munmap — unmap virtual memory
 *
 * syscall ID: 215
 * The reverse of mmap: removes page table entries and frees
 * the underlying physical memory back to the free list.
 */
uint64 sys_munmap(uint64 start, uint64 len)
{
	/* start must be page-aligned */
	if (!PGALIGNED(start))
		return -1;

	/* Nothing to unmap */
	if (len == 0)
		return 0;

	/* Round up to full pages */
	len = PGROUNDUP(len);

	struct proc *p = curr_proc();

	/* Verify every page in the range IS mapped. If any page
	 * has no mapping (walkaddr returns 0), it's an error —
	 * the spec says unmapping non-existent memory is invalid. */
	for (uint64 va = start; va < start + len; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) == 0)
			return -1;
	}

	/* uvmunmap removes the page table entries.
	 * Arguments: page table, starting VA, number of pages, do_free flag.
	 * do_free = 1 means also call kfree() on each physical page
	 * to return it to the free list for future kalloc() calls. */
	uvmunmap(p->pagetable, start, len / PGSIZE, 1);
	return 0;
}

/*
 * TASK 1: Fix sys_task_info for virtual memory
 *
 * Same virtual memory problem as gettimeofday, but TaskInfo is ~2KB
 * (because of the 500-element syscall_times array). That's large
 * enough to SPAN across two physical pages. If we used useraddr(),
 * we'd only get the physical address of the first page, and writing
 * past the page boundary would corrupt random kernel memory.
 *
 * Solution: build the entire TaskInfo in a LOCAL kernel variable (on
 * the kernel stack), then use copyout() to transfer it to the user.
 * copyout() handles page boundaries automatically — it translates
 * page by page and copies the correct number of bytes into each
 * physical page.
 */
int sys_task_info(struct TaskInfo *ti)
{
	struct proc *p = curr_proc();

	/* Build TaskInfo entirely in kernel space first */
	struct TaskInfo kti;

	/* The current task is obviously Running — you can only call
	 * sys_task_info if you're the task that's currently executing */
	kti.status = Running;

	/* Elapsed wall-clock time in milliseconds since first scheduled.
	 * get_cycle() reads the hardware mtime counter.
	 * CPU_FREQ / 1000 = 12500 = cycles per millisecond. */
	kti.time = (get_cycle() - p->start_time) / (CPU_FREQ / 1000);

	/* Copy the per-process syscall counter array */
	memmove(kti.syscall_times, p->syscall_times, sizeof(p->syscall_times));

	/* copyout: copy from kernel buffer -> user virtual address.
	 * It walks the user's page table internally, handles page
	 * boundaries, and writes to the correct physical pages.
	 * "ti" here is still the user's virtual address from args[0]. */
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

	/* Count every syscall BEFORE dispatching it. This way,
	 * sys_task_info's own invocation is included in the count.
	 * Bounds check ensures we don't write outside the array. */
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
	case SYS_task_info:
		ret = sys_task_info((struct TaskInfo *)args[0]);
		break;
	/* NEW in ch4: mmap and munmap for anonymous memory mapping */
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