# Linux Project 3


## 目標
1. 取得程式 context switch 的次數
1. 取得程式進入 waiting queue 的次數

> https://staff.csie.ncu.edu.tw/hsufh/COURSES/FALL2021/linux_project_3.html
## 先備知識

https://blog.csdn.net/gatieme/article/details/51569932

### `fork()`
完全複製父行程的資源，子行程獨立於父行程， 但是二者之間的通訊需要通過專門的通訊機制如：pipe，popen&pclose、協同進程、fifo，System V IPC（消息隊列、信號量和共享內存）機制等。
Linux中採取了copy-on-write技術減少無用複製。
https://blog.xuite.net/ian11832/blogg/23967641

### copy_on_write


## Code Trace
![](https://i.imgur.com/4wwZqxh.png)

### `task_struct`
修改 task_struct的code，新增用來計數的變數。
```clike=
struct task_struct {
#ifdef CONFIG_THREAD_INFO_IN_TASK
	/*
	 * For reasons of header soup (see current_thread_info()), this
	 * must be the first element of task_struct.
	 */
	struct thread_info		thread_info;
#endif
	/* -1 unrunnable, 0 runnable, >0 stopped: */
	volatile long			state;
/*
 ...
 中間程式碼太多先省略
 ...
*/
    
#ifdef CONFIG_X86_MCE
	u64				mce_addr;
	__u64				mce_ripv : 1,
					mce_whole_page : 1,
					__mce_reserved : 62;
	struct callback_head		mce_kill_me;
#endif
        unsigned int cs_count; /*自己增加記錄context switch 次數的變數*/
        unsigned int wq_count; /*自己增加記錄進入waiting queue 次數的變數*/
    
	/*
	 * New fields for task_struct should be added above here, so that
	 * they are included in the randomized portion of task_struct.
	 */
	randomized_struct_fields_end

	/* CPU-specific state of this task: */
	struct thread_struct		thread;

	/*
	 * WARNING: on x86, 'thread_struct' contains a variable-sized
	 * structure.  It *MUST* be at the end of 'task_struct'.
	 *
	 * Do not put anything below here!
	 */
};

```


### `do_fork()` 
```clike=
long do_fork(unsigned long clone_flags,
	      unsigned long stack_start,
	      unsigned long stack_size,
	      int __user *parent_tidptr,
	      int __user *child_tidptr)
{
	struct kernel_clone_args args = {
		.flags		= (lower_32_bits(clone_flags) & ~CSIGNAL),
		.pidfd		= parent_tidptr,
		.child_tid	= child_tidptr,
		.parent_tid	= parent_tidptr,
		.exit_signal	= (lower_32_bits(clone_flags) & CSIGNAL),
		.stack		= stack_start,
		.stack_size	= stack_size,
	};

	if (!legacy_clone_args_valid(&args))
		return -EINVAL;

	return _do_fork(&args);
}
```

### `_do_fork()`
```clike=
long _do_fork(struct kernel_clone_args *args)
{
	u64 clone_flags = args->flags;
	struct completion vfork;
	struct pid *pid;
	struct task_struct *p;
	int trace = 0;
	long nr;

	/*
	 * Determine whether and which event to report to ptracer.  When
	 * called from kernel_thread or CLONE_UNTRACED is explicitly
	 * requested, no event is reported; otherwise, report if the event
	 * for the type of forking is enabled.
	 */
	if (!(clone_flags & CLONE_UNTRACED)) {
		if (clone_flags & CLONE_VFORK)
			trace = PTRACE_EVENT_VFORK;
		else if (args->exit_signal != SIGCHLD)
			trace = PTRACE_EVENT_CLONE;
		else
			trace = PTRACE_EVENT_FORK;

		if (likely(!ptrace_event_enabled(current, trace)))
			trace = 0;
	}
        
	p = copy_process(NULL, trace, NUMA_NO_NODE, args);
	add_latent_entropy();

	if (IS_ERR(p))
		return PTR_ERR(p);

	/*
	 * Do this prior waking up the new thread - the thread pointer
	 * might get invalid after that point, if the thread exits quickly.
	 */
	trace_sched_process_fork(current, p);

	pid = get_task_pid(p, PIDTYPE_PID);
	nr = pid_vnr(pid);

	if (clone_flags & CLONE_PARENT_SETTID)
		put_user(nr, args->parent_tid);

	if (clone_flags & CLONE_VFORK) {
		p->vfork_done = &vfork;
		init_completion(&vfork);
		get_task_struct(p);
	}

	wake_up_new_task(p);

	/* forking complete and child started to run, tell ptracer */
	if (unlikely(trace))
		ptrace_event_pid(trace, pid);

	if (clone_flags & CLONE_VFORK) {
		if (!wait_for_vfork_done(p, &vfork))
			ptrace_event_pid(PTRACE_EVENT_VFORK_DONE, pid);
	}

	put_pid(pid);
	return nr;
}
```


### `copy_process()`
Here is a brief overview of how copy_process() works:
1. It first allocates memory for the new struct task_struct structure and sets up the basic fields of the structure.
1. It then ==copies the memory and other resources of the existing process to the new process.== This includes copying the program code, data, and stack of the process, as well as any open file descriptors and other resources.
1. It sets up the new process's execution context, including the program counter, stack pointer, and other registers.
1. It adds the new process to the system's list of processes and assigns it a unique process ID. 
1. It ==returns a pointer to the new struct task_struct structure, which can be used== to control and manipulate the new process.
```clike=
static __latent_entropy struct task_struct *copy_process(
					struct pid *pid,
					int trace,
					int node,
					struct kernel_clone_args *args)
{
	int pidfd = -1, retval;
	struct task_struct *p;
	struct multiprocess_signals delayed;
	struct file *pidfile = NULL;
	u64 clone_flags = args->flags;
	struct nsproxy *nsp = current->nsproxy;
    
    
        /*
        ...
         中間程式碼太多先省略
        ...
        */
        trace_task_newtask(p, clone_flags);
        uprobe_copy_process(p, clone_flags);
        /*將這兩個新增的變數初始化*/
        p->cs_count = 0; 
        p->wq_count = 0; 
    
        return p;
        /*下面省略*/
}

```

### `schedule()`
The Linux kernel's scheduling function, called schedule(), is responsible for deciding which process should be executed next by the CPU. 

決定要跑哪個process，
例如：wait系列的function會呼叫其把cpu的控制權交出去


https://zhuanlan.zhihu.com/p/363791563

主要重要步驟在`__schedule()`中
```clike=
asmlinkage __visible void __sched schedule(void)
{
	struct task_struct *tsk = current;

	sched_submit_work(tsk);
	do {
		preempt_disable();
		__schedule(false);
		sched_preempt_enable_no_resched();
	} while (need_resched());
	sched_update_worker(tsk);
}
```

### `__schedule(false)`
__schedule() is responsible for selecting the next process to run and switching to that process's execution context. It does this by examining the list of runnable processes in the system and selecting the one with the highest priority. It then saves the current process's execution context and restores the execution context of the selected process.

裡面又再呼叫到`context_switch()`

```clike=
static void __sched notrace __schedule(bool preempt)
{
	struct task_struct *prev, *next;
	unsigned long *switch_count;
	unsigned long prev_state;
	struct rq_flags rf;
	struct rq *rq;
	int cpu;

	cpu = smp_processor_id();
	rq = cpu_rq(cpu);
	prev = rq->curr;

	schedule_debug(prev, preempt);

	if (sched_feat(HRTICK))
		hrtick_clear(rq);

	local_irq_disable();
	rcu_note_context_switch(preempt);

	/*
	 * Make sure that signal_pending_state()->signal_pending() below
	 * can't be reordered with __set_current_state(TASK_INTERRUPTIBLE)
	 * done by the caller to avoid the race with signal_wake_up():
	 *
	 * __set_current_state(@state)		signal_wake_up()
	 * schedule()				  set_tsk_thread_flag(p, TIF_SIGPENDING)
	 *					  wake_up_state(p, state)
	 *   LOCK rq->lock			    LOCK p->pi_state
	 *   smp_mb__after_spinlock()		    smp_mb__after_spinlock()
	 *     if (signal_pending_state())	    if (p->state & @state)
	 *
	 * Also, the membarrier system call requires a full memory barrier
	 * after coming from user-space, before storing to rq->curr.
	 */
	rq_lock(rq, &rf);
	smp_mb__after_spinlock();

	/* Promote REQ to ACT */
	rq->clock_update_flags <<= 1;
	update_rq_clock(rq);

	switch_count = &prev->nivcsw;

	/*
	 * We must load prev->state once (task_struct::state is volatile), such
	 * that:
	 *
	 *  - we form a control dependency vs deactivate_task() below.
	 *  - ptrace_{,un}freeze_traced() can change ->state underneath us.
	 */
	prev_state = prev->state;
	if (!preempt && prev_state) {
		if (signal_pending_state(prev_state, prev)) {
			prev->state = TASK_RUNNING;
		} else {
			prev->sched_contributes_to_load =
				(prev_state & TASK_UNINTERRUPTIBLE) &&
				!(prev_state & TASK_NOLOAD) &&
				!(prev->flags & PF_FROZEN);

			if (prev->sched_contributes_to_load)
				rq->nr_uninterruptible++;

			/*
			 * __schedule()			ttwu()
			 *   prev_state = prev->state;    if (p->on_rq && ...)
			 *   if (prev_state)		    goto out;
			 *     p->on_rq = 0;		  smp_acquire__after_ctrl_dep();
			 *				  p->state = TASK_WAKING
			 *
			 * Where __schedule() and ttwu() have matching control dependencies.
			 *
			 * After this, schedule() must not care about p->state any more.
			 */
			deactivate_task(rq, prev, DEQUEUE_SLEEP | DEQUEUE_NOCLOCK);

			if (prev->in_iowait) {
				atomic_inc(&rq->nr_iowait);
				delayacct_blkio_start();
			}
		}
		switch_count = &prev->nvcsw;
	}

	next = pick_next_task(rq, prev, &rf);
	clear_tsk_need_resched(prev);
	clear_preempt_need_resched();

	if (likely(prev != next)) {
		rq->nr_switches++;
		/*
		 * RCU users of rcu_dereference(rq->curr) may not see
		 * changes to task_struct made by pick_next_task().
		 */
		RCU_INIT_POINTER(rq->curr, next);
		/*
		 * The membarrier system call requires each architecture
		 * to have a full memory barrier after updating
		 * rq->curr, before returning to user-space.
		 *
		 * Here are the schemes providing that barrier on the
		 * various architectures:
		 * - mm ? switch_mm() : mmdrop() for x86, s390, sparc, PowerPC.
		 *   switch_mm() rely on membarrier_arch_switch_mm() on PowerPC.
		 * - finish_lock_switch() for weakly-ordered
		 *   architectures where spin_unlock is a full barrier,
		 * - switch_to() for arm64 (weakly-ordered, spin_unlock
		 *   is a RELEASE barrier),
		 */
		++*switch_count;

		psi_sched_switch(prev, next, !task_on_rq_queued(prev));

		trace_sched_switch(preempt, prev, next);

		/* Also unlocks the rq: */
		rq = context_switch(rq, prev, next, &rf);
	} else {
		rq->clock_update_flags &= ~(RQCF_ACT_SKIP|RQCF_REQ_SKIP);
		rq_unlock_irq(rq, &rf);
	}

	balance_callback(rq);
}

```

### `context_switch()`

A context switch is the process by which the kernel switches the execution of a process from one CPU to another. There are two types of context switches: voluntary and involuntary.

A **voluntary context switch** occurs when a process voluntarily yields the CPU, such as when it calls the sched_yield() system call or when it blocks waiting for a resource. In this case, the **nvcsw** field is incremented.

An **involuntary context** switch occurs when the kernel forces a process to yield the CPU, such as ==when a higher-priority process becomes runnable or when a timer interrupt occurs.== In this case, the **nivcsw** field is incremented.

kernel process don't have own `mm_struct` because they do not use virtual memory in the same way as user processes.

因為 kernel process 的mm沒有指向 `mm_struct` 所以
會需要考慮以下幾種情況
 
>  /*
>     * kernel -> kernel   lazy + transfer active
>     *   user -> kernel   lazy + mmgrab() active
>     *
>     * kernel ->   user   switch + mmdrop() active
>     *   user ->   user   switch
>     */

```clike=
/*
 * context_switch - switch to the new MM and the new thread's register state.
 */
static __always_inline struct rq *
context_switch(struct rq *rq, struct task_struct *prev,
	       struct task_struct *next, struct rq_flags *rf)
{
	prepare_task_switch(rq, prev, next);

	/*
	 * For paravirt, this is coupled with an exit in switch_to to
	 * combine the page table reload and the switch backend into
	 * one hypercall.
	 */
	arch_start_context_switch(prev);

	/*
	 * kernel -> kernel   lazy + transfer active
	 *   user -> kernel   lazy + mmgrab() active
	 *
	 * kernel ->   user   switch + mmdrop() active
	 *   user ->   user   switch
	 */
	if (!next->mm) {                                // to kernel
		enter_lazy_tlb(prev->active_mm, next);

		next->active_mm = prev->active_mm;
		if (prev->mm)                           // from user
			mmgrab(prev->active_mm);
		else
			prev->active_mm = NULL;
	} else {                                        // to user
		membarrier_switch_mm(rq, prev->active_mm, next->mm);
		/*
		 * sys_membarrier() requires an smp_mb() between setting
		 * rq->curr / membarrier_switch_mm() and returning to userspace.
		 *
		 * The below provides this either through switch_mm(), or in
		 * case 'prev->active_mm == next->mm' through
		 * finish_task_switch()'s mmdrop().
		 */
		switch_mm_irqs_off(prev->active_mm, next->mm, next);

		if (!prev->mm) {                        // from kernel
			/* will mmdrop() in finish_task_switch(). */
			rq->prev_mm = prev->active_mm;
			prev->active_mm = NULL;
		}
	}

	rq->clock_update_flags &= ~(RQCF_ACT_SKIP|RQCF_REQ_SKIP);

	prepare_lock_switch(rq, next, rf);

	/* Here we just switch the register state and the stack. */
	switch_to(prev, next, prev);
	barrier();

	return finish_task_switch(prev);
}
```


### `switch_to`

```clike=
#define switch_to(prev, next, last)					\
do {									\
	((last) = __switch_to_asm((prev), (next)));			\
} while (0)
```

### `__switch_to_asm`

```x86=
/*
 * %eax: prev task
 * %edx: next task
 */
.pushsection .text, "ax"
SYM_CODE_START(__switch_to_asm)
	/*
	 * Save callee-saved registers
	 * This must match the order in struct inactive_task_frame
	 */
	pushl	%ebp
	pushl	%ebx
	pushl	%edi
	pushl	%esi
	/*
	 * Flags are saved to prevent AC leakage. This could go
	 * away if objtool would have 32bit support to verify
	 * the STAC/CLAC correctness.
	 */
	pushfl

	/* switch stack */
	movl	%esp, TASK_threadsp(%eax)
	movl	TASK_threadsp(%edx), %esp

#ifdef CONFIG_STACKPROTECTOR
	movl	TASK_stack_canary(%edx), %ebx
	movl	%ebx, PER_CPU_VAR(stack_canary)+stack_canary_offset
#endif

#ifdef CONFIG_RETPOLINE
	/*
	 * When switching from a shallower to a deeper call stack
	 * the RSB may either underflow or use entries populated
	 * with userspace addresses. On CPUs where those concerns
	 * exist, overwrite the RSB with entries which capture
	 * speculative execution to prevent attack.
	 */
	FILL_RETURN_BUFFER %ebx, RSB_CLEAR_LOOPS, X86_FEATURE_RSB_CTXSW
#endif

	/* Restore flags or the incoming task to restore AC state. */
	popfl
	/* restore callee-saved registers */
	popl	%esi
	popl	%edi
	popl	%ebx
	popl	%ebp

	jmp	__switch_to
SYM_CODE_END(__switch_to_asm)
```
### `wait_event`

讓process進到wait queue休眠

### `__wait_event`
### `___wait_event`


### `__wait_up_common`
參數說明
- wq_head：wq的頭
- mode：process的狀態模式
- nr_exclusive：是 number exclusive??
- wake_flags  : 是同步唤醒sync，还是异步唤醒 async??
- key : 一般为NULL

https://blog.51cto.com/weiguozhihui/1566980
 
```clike=
static int __wake_up_common(struct wait_queue_head *wq_head, unsigned int mode,
			int nr_exclusive, int wake_flags, void *key,
			wait_queue_entry_t *bookmark)
{
	wait_queue_entry_t *curr, *next;
	int cnt = 0;

	lockdep_assert_held(&wq_head->lock);

	if (bookmark && (bookmark->flags & WQ_FLAG_BOOKMARK)) {
		curr = list_next_entry(bookmark, entry);

		list_del(&bookmark->entry);
		bookmark->flags = 0;
	} else
		curr = list_first_entry(&wq_head->head, wait_queue_entry_t, entry);

	if (&curr->entry == &wq_head->head)
		return nr_exclusive;

	list_for_each_entry_safe_from(curr, next, &wq_head->head, entry) {
		unsigned flags = curr->flags;
		int ret;

		if (flags & WQ_FLAG_BOOKMARK)
			continue;
        
		ret = curr->func(curr, mode, wake_flags, key); /*呼叫 喚醒wait queue裡面process的實現函式*/
		if (ret < 0)
			break;
		if (ret && (flags & WQ_FLAG_EXCLUSIVE) && !--nr_exclusive)
			break;

		if (bookmark && (++cnt > WAITQUEUE_WALK_BREAK_CNT) &&
				(&next->entry != &wq_head->head)) {
			bookmark->flags = WQ_FLAG_BOOKMARK;
			list_add_tail(&bookmark->entry, &next->entry);
			break;
		}
	}

	return nr_exclusive;
}
```


### `default_wake_function`
預設用來喚醒wait queue中process的實現函式，
```clike=
int default_wake_function(wait_queue_entry_t *curr, unsigned mode, int wake_flags,
			  void *key)
{
	WARN_ON_ONCE(IS_ENABLED(CONFIG_SCHED_DEBUG) && wake_flags & ~WF_SYNC);
	return try_to_wake_up(curr->private, mode, wake_flags);
}
```
### `try_to_wake_up`

呼叫`ttwu_queue()` 這個 funtion 然後 ttwu_queue() -> `ttwu_do_activate()` -> `ttwu_do_wakeup()`

### `ttwu_do_wakeup`

由於每個進入waiting queue的process ，在等待完I/O後會就會出來，所以我們在叫醒process的這段code進行計數。

```clike=
/*
 * Mark the task runnable and perform wakeup-preemption.
 */
static void ttwu_do_wakeup(struct rq * rq, struct task_struct * p, int wake_flags,
    struct rq_flags * rf) {
    check_preempt_curr(rq, p, wake_flags);
    p -> state = TASK_RUNNING;
    p -> wq_count++; /*計數器加一*/
    trace_sched_wakeup(p);

    #ifdef CONFIG_SMP
    if (p -> sched_class -> task_woken) {
        /*
         * Our task @p is fully woken up and running; so its safe to
         * drop the rq->lock, hereafter rq is only used for statistics.
         */
        rq_unpin_lock(rq, rf);
        p -> sched_class -> task_woken(rq, p);
        rq_repin_lock(rq, rf);
    }

    if (rq -> idle_stamp) {
        u64 delta = rq_clock(rq) - rq -> idle_stamp;
        u64 max = 2 * rq -> max_idle_balance_cost;

        update_avg( & rq -> avg_idle, delta);

        if (rq -> avg_idle > max)
            rq -> avg_idle = max;

        rq -> idle_stamp = 0;
    }
    #endif
}
```


## 實驗

### 第一題
顯示context switch次數
#### 程式碼
```clike=
/*get_number_of_context_switches*/
#include<linux/kernel.h>
#include<linux/syscalls.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/init_task.h>

SYSCALL_DEFINE1(get_number_of_context_switches, unsigned int*, count) {

    unsigned int answer = current->cs_count;
    printk("pid = %d ; cs_count = %u ; nvcsw = %lu ; nivcsw = %lu\n",
           current->pid, answer, current->nvcsw, current->nivcsw);
    return -copy_to_user(count, &(answer), sizeof(unsigned int));
}
```


```clike=
/*q1.c*/
#include<stdio.h>
#include<syscall.h>
#include<unistd.h>

#define NUMBER_OF_ITERATIONS 99999999
#define __NR_get_number_of_context_switches 440

int main(){

    int i, t=2, u=3, v;
    unsigned int w;
    for(i=0; i<NUMBER_OF_ITERATIONS; i++)
                v = (++t)*(u++);

    long syscallResult = syscall(__NR_get_number_of_context_switches, &w);

    if(syscallResult)
        printf("Error!\n");
    else
        printf("This process encounters %u times context switches.\n",w);


    printf("w = %u\tsystem call result = %ld\n", w, syscallResult);
    printf("pid=%d\n", getpid());

    return 0;
}
```
#### 執行結果
![](https://i.imgur.com/iwplkMe.png)

![](https://i.imgur.com/66uKmhU.png)

1. `nvcsw` : 自願切換數
2. `nivcsw` : 非自願切換數
3. `cs_count` : 從下圖可看出，此值為 $(nvcsw+nivcsw)*2+1$，其中因為 cs_count 因為來回都有做計算，所以會是 $(nvcsw+nivcsw)$ 的兩倍，而 $+1$ 是因為我們在 `print cs_count` 時，執行權在 `pid 2980`，所以會 $+1$。

#### 用strace 分析
```bash=
strace -o strace_q1.out ./q1
```
![](https://i.imgur.com/WUdMCBC.png)

### 第二題

顯示進入waiting queue的次數

#### 程式碼
```clike=
/*get_number_of_entering_a_wait_queue.c*/

#include<linux/kernel.h>
#include<linux/syscalls.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/init_task.h>

SYSCALL_DEFINE1(get_number_of_entering_a_wait_queue, unsigned int*, count) {

        unsigned int answer = current->wq_count;
    printk("pid = %d ; wq_count = %u", current->pid, answer);
    return -copy_to_user(count, &(answer), sizeof(unsigned int));
}

```

```clike=
/*q2.c*/

#include <stdio.h>
#include <unistd.h>
#include <syscall.h>
#define NUMBER_OF_IO_ITERATIONS 6
#define NUMBER_OF_ITERATIONS 99999999
#define __NR_get_number_of_context_switches 440
#define __NR_get_number_of_entering_a_wait_queue 441

int main ()
{
        char         c;
        int          i,t=2,u=3,v;
        unsigned int w;

        for(i=0; i<NUMBER_OF_IO_ITERATIONS; i++)
        {
                v=1;
                c = getchar();
        }

        for(i=0; i<NUMBER_OF_ITERATIONS; i++)
                v=(++t)*(u++);


        long syscall_result_get_cs_n = syscall(__NR_get_number_of_context_switches, &w);

        if(syscall_result_get_cs_n)
                printf("Error (1)!\n");
        else
                printf("This process encounters %u times context switches.\n", w);

        long syscall_result_get_wq_n = syscall(__NR_get_number_of_entering_a_wait_queue, &w);

        if(syscall_result_get_wq_n)
                printf("Error (2)!\n");
        else
                printf("This process enters a wait queue %u times.\n", w);


        for(i=0; i<NUMBER_OF_IO_ITERATIONS; i++)
        {
                v=1;
                printf("I love my home.\n");
        }


        if(get_number_of_entering_a_wait_queue(&w)!=0)
                printf("Error (3)!\n");
        else
                printf("This process enters a wait queue %u times.\n", w);

        return 0;
}
```

![](https://i.imgur.com/eK6bCPi.png)

#### 用strace 分析
```bash=
strace -o strace_q2.out ./q2
```
![](https://i.imgur.com/K4xUj8Y.png)
