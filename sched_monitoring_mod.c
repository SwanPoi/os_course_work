
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/sched/types.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/seq_file.h>
#include <linux/fs_struct.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vladimir Lebedev");
MODULE_DESCRIPTION("LKM for intercepting CFS scheduler actions (Kernel 6.9.5)");

// Target process PID
static int target_pid = 0;
module_param(target_pid, int, 0644);
MODULE_PARM_DESC(target_pid, "PID of the target process");

#define MAX_FUNC_NAME_LENGTH 1024
#define MAX_SCHED_CLASS_LENGTH 3

#define RT_SCHED_CLASS 0
#define DL_SCHED_CLASS 1
#define CFS_SCHED_CLASS 2
#define IDLE_SCHED_CLASS 3

struct my_uclamp_bucket {
	unsigned long value : bits_per(SCHED_CAPACITY_SCALE);
	unsigned long tasks : BITS_PER_LONG - bits_per(SCHED_CAPACITY_SCALE);
};

struct my_uclamp_rq {
	unsigned int value;
	struct my_uclamp_bucket bucket[UCLAMP_BUCKETS];
};

/*
 * stop_cpu[s]() is simplistic per-cpu maximum priority cpu
 * monopolization mechanism.  The caller can specify a non-sleeping
 * function to be executed on a single or multiple cpus preempting all
 * other processes and monopolizing those cpus until it finishes.
 *
 * Resources for this mechanism are preallocated when a cpu is brought
 * up and requests are guaranteed to be served as long as the target
 * cpus are online.
 */
typedef int (*my_cpu_stop_fn_t)(void *arg);

struct my_cpu_stop_work {
	struct list_head	list;		/* cpu_stopper->works */
	my_cpu_stop_fn_t		fn;
	unsigned long		caller;
	void			*arg;
	struct cpu_stop_done	*done;
};

/* CFS-related fields in a runqueue */
struct my_cfs_rq {
	struct load_weight	load;
	unsigned int		nr_running;
	unsigned int		h_nr_running;      /* SCHED_{NORMAL,BATCH,IDLE} */
	unsigned int		idle_nr_running;   /* SCHED_IDLE */
	unsigned int		idle_h_nr_running; /* SCHED_IDLE */

	s64			avg_vruntime;
	u64			avg_load;

	u64			exec_clock;
	u64			min_vruntime;
#ifdef CONFIG_SCHED_CORE
	unsigned int		forceidle_seq;
	u64			min_vruntime_fi;
#endif

#ifndef CONFIG_64BIT
	u64			min_vruntime_copy;
#endif

	struct rb_root_cached	tasks_timeline;

	/*
	 * 'curr' points to currently running entity on this cfs_rq.
	 * It is set to NULL otherwise (i.e when none are currently running).
	 */
	struct sched_entity	*curr;
	struct sched_entity	*next;

#ifdef	CONFIG_SCHED_DEBUG
	unsigned int		nr_spread_over;
#endif

#ifdef CONFIG_SMP
	/*
	 * CFS load tracking
	 */
	struct sched_avg	avg;
#ifndef CONFIG_64BIT
	u64			last_update_time_copy;
#endif
	struct {
		raw_spinlock_t	lock ____cacheline_aligned;
		int		nr;
		unsigned long	load_avg;
		unsigned long	util_avg;
		unsigned long	runnable_avg;
	} removed;

#ifdef CONFIG_FAIR_GROUP_SCHED
	u64			last_update_tg_load_avg;
	unsigned long		tg_load_avg_contrib;
	long			propagate;
	long			prop_runnable_sum;

	/*
	 *   h_load = weight * f(tg)
	 *
	 * Where f(tg) is the recursive weight fraction assigned to
	 * this group.
	 */
	unsigned long		h_load;
	u64			last_h_load_update;
	struct sched_entity	*h_load_next;
#endif /* CONFIG_FAIR_GROUP_SCHED */
#endif /* CONFIG_SMP */

#ifdef CONFIG_FAIR_GROUP_SCHED
	struct rq		*rq;	/* CPU runqueue to which this cfs_rq is attached */

	/*
	 * leaf cfs_rqs are those that hold tasks (lowest schedulable entity in
	 * a hierarchy). Non-leaf lrqs hold other higher schedulable entities
	 * (like users, containers etc.)
	 *
	 * leaf_cfs_rq_list ties together list of leaf cfs_rq's in a CPU.
	 * This list is used during load balance.
	 */
	int			on_list;
	struct list_head	leaf_cfs_rq_list;
	struct task_group	*tg;	/* group that "owns" this runqueue */

	/* Locally cached copy of our task_group's idle value */
	int			idle;

#ifdef CONFIG_CFS_BANDWIDTH
	int			runtime_enabled;
	s64			runtime_remaining;

	u64			throttled_pelt_idle;
#ifndef CONFIG_64BIT
	u64                     throttled_pelt_idle_copy;
#endif
	u64			throttled_clock;
	u64			throttled_clock_pelt;
	u64			throttled_clock_pelt_time;
	u64			throttled_clock_self;
	u64			throttled_clock_self_time;
	int			throttled;
	int			throttle_count;
	struct list_head	throttled_list;
	struct list_head	throttled_csd_list;
#endif /* CONFIG_CFS_BANDWIDTH */
#endif /* CONFIG_FAIR_GROUP_SCHED */
};

/*
 * This is the priority-queue data structure of the RT scheduling class:
 */
struct my_rt_prio_array {
	DECLARE_BITMAP(bitmap, MAX_RT_PRIO+1); /* include 1 bit for delimiter */
	struct list_head queue[MAX_RT_PRIO];
};

/* Real-Time classes' related field in a runqueue: */
struct my_rt_rq {
	struct my_rt_prio_array	active;
	unsigned int		rt_nr_running;
	unsigned int		rr_nr_running;
#if defined CONFIG_SMP || defined CONFIG_RT_GROUP_SCHED
	struct {
		int		curr; /* highest queued rt task prio */
#ifdef CONFIG_SMP
		int		next; /* next highest */
#endif
	} highest_prio;
#endif
#ifdef CONFIG_SMP
	int			overloaded;
	struct plist_head	pushable_tasks;

#endif /* CONFIG_SMP */
	int			rt_queued;

	int			rt_throttled;
	u64			rt_time;
	u64			rt_runtime;
	/* Nests inside the rq lock: */
	raw_spinlock_t		rt_runtime_lock;

#ifdef CONFIG_RT_GROUP_SCHED
	unsigned int		rt_nr_boosted;

	struct rq		*rq;
	struct task_group	*tg;
#endif
};

struct my_dl_rq {
	/* runqueue is an rbtree, ordered by deadline */
	struct rb_root_cached	root;

	unsigned int		dl_nr_running;

#ifdef CONFIG_SMP
	/*
	 * Deadline values of the currently executing and the
	 * earliest ready task on this rq. Caching these facilitates
	 * the decision whether or not a ready but not running task
	 * should migrate somewhere else.
	 */
	struct {
		u64		curr;
		u64		next;
	} earliest_dl;

	int			overloaded;

	/*
	 * Tasks on this rq that can be pushed away. They are kept in
	 * an rb-tree, ordered by tasks' deadlines, with caching
	 * of the leftmost (earliest deadline) element.
	 */
	struct rb_root_cached	pushable_dl_tasks_root;
#else
	struct dl_bw		dl_bw;
#endif
	/*
	 * "Active utilization" for this runqueue: increased when a
	 * task wakes up (becomes TASK_RUNNING) and decreased when a
	 * task blocks
	 */
	u64			running_bw;

	/*
	 * Utilization of the tasks "assigned" to this runqueue (including
	 * the tasks that are in runqueue and the tasks that executed on this
	 * CPU and blocked). Increased when a task moves to this runqueue, and
	 * decreased when the task moves away (migrates, changes scheduling
	 * policy, or terminates).
	 * This is needed to compute the "inactive utilization" for the
	 * runqueue (inactive utilization = this_bw - running_bw).
	 */
	u64			this_bw;
	u64			extra_bw;

	/*
	 * Maximum available bandwidth for reclaiming by SCHED_FLAG_RECLAIM
	 * tasks of this rq. Used in calculation of reclaimable bandwidth(GRUB).
	 */
	u64			max_bw;

	/*
	 * Inverse of the fraction of CPU utilization that can be reclaimed
	 * by the GRUB algorithm.
	 */
	u64			bw_ratio;
};

/*
 * This is the main, per-CPU runqueue data structure.
 *
 * Locking rule: those places that want to lock multiple runqueues
 * (such as the load balancing or the thread migration code), lock
 * acquire operations must be ordered by ascending &runqueue.
 */
struct my_rq {
	/* runqueue lock: */
	raw_spinlock_t		__lock;

	unsigned int		nr_running;
#ifdef CONFIG_NUMA_BALANCING
	unsigned int		nr_numa_running;
	unsigned int		nr_preferred_running;
	unsigned int		numa_migrate_on;
#endif
#ifdef CONFIG_NO_HZ_COMMON
#ifdef CONFIG_SMP
	unsigned long		last_blocked_load_update_tick;
	unsigned int		has_blocked_load;
	call_single_data_t	nohz_csd;
#endif /* CONFIG_SMP */
	unsigned int		nohz_tick_stopped;
	atomic_t		nohz_flags;
#endif /* CONFIG_NO_HZ_COMMON */

#ifdef CONFIG_SMP
	unsigned int		ttwu_pending;
#endif
	u64			nr_switches;

#ifdef CONFIG_UCLAMP_TASK
	/* Utilization clamp values based on CPU's RUNNABLE tasks */
	struct my_uclamp_rq	uclamp[UCLAMP_CNT] ____cacheline_aligned;
	unsigned int		uclamp_flags;
#define UCLAMP_FLAG_IDLE 0x01
#endif

	struct my_cfs_rq		cfs;
	struct my_rt_rq		rt;
	struct my_dl_rq		dl;

#ifdef CONFIG_FAIR_GROUP_SCHED
	/* list of leaf cfs_rq on this CPU: */
	struct list_head	leaf_cfs_rq_list;
	struct list_head	*tmp_alone_branch;
#endif /* CONFIG_FAIR_GROUP_SCHED */

	/*
	 * This is part of a global counter where only the total sum
	 * over all CPUs matters. A task can increase this counter on
	 * one CPU and if it got migrated afterwards it may decrease
	 * it on another CPU. Always updated under the runqueue lock:
	 */
	unsigned int		nr_uninterruptible;

	struct task_struct __rcu	*curr;
	struct task_struct	*idle;
	struct task_struct	*stop;
	unsigned long		next_balance;
	struct mm_struct	*prev_mm;

	unsigned int		clock_update_flags;
	u64			clock;
	/* Ensure that all clocks are in the same cache line */
	u64			clock_task ____cacheline_aligned;
	u64			clock_pelt;
	unsigned long		lost_idle_time;
	u64			clock_pelt_idle;
	u64			clock_idle;
#ifndef CONFIG_64BIT
	u64			clock_pelt_idle_copy;
	u64			clock_idle_copy;
#endif

	atomic_t		nr_iowait;

#ifdef CONFIG_SCHED_DEBUG
	u64 last_seen_need_resched_ns;
	int ticks_without_resched;
#endif

#ifdef CONFIG_MEMBARRIER
	int membarrier_state;
#endif

#ifdef CONFIG_SMP
	struct root_domain		*rd;
	struct sched_domain __rcu	*sd;

	unsigned long		cpu_capacity;

	struct balance_callback *balance_callback;

	unsigned char		nohz_idle_balance;
	unsigned char		idle_balance;

	unsigned long		misfit_task_load;

	/* For active balancing */
	int			active_balance;
	int			push_cpu;
	struct my_cpu_stop_work	active_balance_work;

	/* CPU of this runqueue: */
	int			cpu;
	int			online;

	struct list_head cfs_tasks;

	struct sched_avg	avg_rt;
	struct sched_avg	avg_dl;
#ifdef CONFIG_HAVE_SCHED_AVG_IRQ
	struct sched_avg	avg_irq;
#endif
#ifdef CONFIG_SCHED_THERMAL_PRESSURE
	struct sched_avg	avg_thermal;
#endif
	u64			idle_stamp;
	u64			avg_idle;

	/* This is used to determine avg_idle's max value */
	u64			max_idle_balance_cost;

#ifdef CONFIG_HOTPLUG_CPU
	struct rcuwait		hotplug_wait;
#endif
#endif /* CONFIG_SMP */

#ifdef CONFIG_IRQ_TIME_ACCOUNTING
	u64			prev_irq_time;
#endif
#ifdef CONFIG_PARAVIRT
	u64			prev_steal_time;
#endif
#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
	u64			prev_steal_time_rq;
#endif

	/* calc_load related fields */
	unsigned long		calc_load_update;
	long			calc_load_active;

#ifdef CONFIG_SCHED_HRTICK
#ifdef CONFIG_SMP
	call_single_data_t	hrtick_csd;
#endif
	struct hrtimer		hrtick_timer;
	ktime_t 		hrtick_time;
#endif

#ifdef CONFIG_SCHEDSTATS
	/* latency stats */
	struct sched_info	rq_sched_info;
	unsigned long long	rq_cpu_time;
	/* could above be rq->cfs_rq.exec_clock + rq->rt_rq.rt_runtime ? */

	/* sys_sched_yield() stats */
	unsigned int		yld_count;

	/* schedule() stats */
	unsigned int		sched_count;
	unsigned int		sched_goidle;

	/* try_to_wake_up() stats */
	unsigned int		ttwu_count;
	unsigned int		ttwu_local;
#endif

#ifdef CONFIG_CPU_IDLE
	/* Must be inspected within a rcu lock section */
	struct cpuidle_state	*idle_state;
#endif

#ifdef CONFIG_SMP
	unsigned int		nr_pinned;
#endif
	unsigned int		push_busy;
	struct my_cpu_stop_work	push_work;

#ifdef CONFIG_SCHED_CORE
	/* per rq */
	struct rq		*core;
	struct task_struct	*core_pick;
	unsigned int		core_enabled;
	unsigned int		core_sched_seq;
	struct rb_root		core_tree;

	/* shared state -- careful with sched_core_cpu_deactivate() */
	unsigned int		core_task_seq;
	unsigned int		core_pick_seq;
	unsigned long		core_cookie;
	unsigned int		core_forceidle_count;
	unsigned int		core_forceidle_seq;
	unsigned int		core_forceidle_occupation;
	u64			core_forceidle_start;
#endif

	/* Scratch cpumask to be temporarily used under rq_lock */
	cpumask_var_t		scratch_mask;

#if defined(CONFIG_CFS_BANDWIDTH) && defined(CONFIG_SMP)
	call_single_data_t	cfsb_csd;
	struct list_head	cfsb_csd_list;
#endif
};

struct rt_sched_data {
	unsigned long			timeout;
	unsigned int			time_slice;
};

struct dl_sched_data {
	u64	dl_runtime;	/* Maximum runtime for each instance	*/
	u64	dl_deadline;	/* Relative deadline of each instance	*/
	u64	dl_period;	/* Separation of two instances (period) */
	s64	runtime;	/* Remaining runtime for this instance	*/
	u64	deadline;	/* Absolute deadline for this instance	*/
};

struct process_sched_data {
	/* priorities from struct task_struct */
	int prio; 	// priority which include nice value (0-139)
	int static_prio;
	int normal_prio;
	unsigned int rt_priority; // real-time scheduler priority (0-99)

	/* Scheduling policy from struct task_struct */
	unsigned int policy; // scheduling policy
	/* weight from task->se.load.weight */
	unsigned long weight;
	/* task->se.vruntime */
	u64 vruntime; // to account for how long a process has run and thus how much longer it ought to run

	struct dl_sched_data *dl_data;
	struct rt_sched_data *rt_data;
	struct sched_info sched_info;
	struct sched_statistics stats;
	struct sched_entity se;
	char func_name[MAX_FUNC_NAME_LENGTH];
	int sched_class;

	struct process_sched_data *next;
};

struct sched_data_list {
	struct process_sched_data *head;
	struct process_sched_data *tail;
};

struct sched_data_list sched_data_list;

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

void print_task_info(struct task_struct *task);
int fh_install_hook(struct ftrace_hook *hook);
void fh_remove_hook(struct ftrace_hook *hook);
int fh_install_hooks(struct ftrace_hook *hooks, size_t count);
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count);
int install_hooks(void);
void remove_hooks(void);

/* Process_sched_data list functions */
struct process_sched_data * create_process_sched_data(struct task_struct *p, char *func_name, int sched_class);
int push_data(struct process_sched_data *data);
int add_sched_data(struct task_struct *p, char *func_name, int sched_class);
void pop_data(void);
void free_process_sched_data_list(void);
void free_process_sched_data(struct process_sched_data *data);
void init_process_sched_data_list(void);

unsigned long p_regs_get_first_arg(struct pt_regs* regs);
unsigned long p_regs_get_second_arg(struct pt_regs* regs);
unsigned long p_regs_get_third_arg(struct pt_regs* regs);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (!hook->address) {
		printk(KERN_INFO "-> unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;
	err = fh_resolve_hook_address(hook);
	if (err)
		return err;
	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		printk(KERN_INFO "-> ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}
	err = register_ftrace_function(&hook->ops);
	if (err) {
		printk(KERN_INFO "-> register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}
	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;
	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		printk(KERN_INFO "-> unregister_ftrace_function() failed: %d\n", err);
	}
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		printk(KERN_INFO "-> ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;
	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}
	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}
	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

unsigned long p_regs_get_first_arg(struct pt_regs* regs)
{
	return regs->di;
}

unsigned long p_regs_get_second_arg(struct pt_regs* regs)
{
	return regs->si;
}

unsigned long p_regs_get_third_arg(struct pt_regs* regs)
{
	return regs->dx;
}

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

/*
 * x86_64 kernels have a special naming convention for syscall entry points in newer kernels.
 * That's what you end up with if an architecture has 3 (three) ABIs for system calls.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define task_of(_se)	container_of(_se, struct task_struct, se)

static struct sched_statistics *
__my_schedstats_from_se(struct sched_entity *se)
{
	return &task_of(se)->stats; // или другой вариант, который работает без FAIR_GROUP_SCHED
}

struct process_sched_data * create_process_sched_data(struct task_struct *p, char *func_name, int sched_class) 
{
	struct process_sched_data *data = (struct process_sched_data *) kmalloc(sizeof(struct process_sched_data), GFP_KERNEL);
	if (!data) 
		return NULL;
	data->rt_data = NULL;
	data->dl_data = NULL;
	data->rt_data = (struct rt_sched_data *) kmalloc(sizeof(struct rt_sched_data), GFP_KERNEL);
	if (!data->rt_data)
	{
		kfree(data);
		return NULL;
	}
	data->rt_data->timeout = p->rt.timeout;
	data->rt_data->time_slice = p->rt.time_slice;
	data->dl_data = (struct dl_sched_data *) kmalloc(sizeof(struct dl_sched_data), GFP_KERNEL);
	if (!data->dl_data)
	{
		kfree(data->rt_data);
		kfree(data);
		return NULL;
	}
	data->dl_data->dl_runtime = p->dl.dl_runtime;
	data->dl_data->dl_deadline = p->dl.dl_deadline;
	data->dl_data->dl_period = p->dl.dl_period;
	data->dl_data->runtime = p->dl.runtime;
	data->dl_data->deadline = p->dl.deadline;
	data->next = NULL;
	data->prio = p->prio;
	data->static_prio = p->static_prio;
	data->normal_prio = p->normal_prio;
	data->rt_priority = p->rt_priority;
	data->policy = p->policy;
	data->sched_class = sched_class;
	struct sched_statistics *stat = __my_schedstats_from_se(&p->se);
	data->stats =  p->stats;
	data->sched_info = p->sched_info;
	data->se = p->se;
	int read_len = snprintf(data->func_name, MAX_FUNC_NAME_LENGTH, "%s", &func_name[0]);
	return data;
}

void init_process_sched_data_list(void) 
{
	sched_data_list.head = NULL;
	sched_data_list.tail = NULL;
}

int push_data(struct process_sched_data *data) 
{
	if (!data) 
		return -1;
	if (!sched_data_list.head) 
	{
		sched_data_list.head = data;
		sched_data_list.tail = data;
		return 0;
	}

	sched_data_list.tail->next = data;
	sched_data_list.tail = data;

	return 0;
}

int add_sched_data(struct task_struct *p, char *func_name, int sched_class) 
{
	struct process_sched_data *node = create_process_sched_data(p, func_name, sched_class);
	if (!node) 
	{
		return -1;
	}
	return push_data(node);
}

void pop_data(void) 
{
	if (!sched_data_list.head) 
	{
		return;
	}
	struct process_sched_data *prev = sched_data_list.head;

	while (prev->next != sched_data_list.tail) 
	{
		prev = prev->next;
	}
	free_process_sched_data(sched_data_list.tail);
	if (prev != sched_data_list.head)
	{
		prev->next = NULL;
		sched_data_list.tail = prev;
	} 
	else 
	{
		sched_data_list.head = NULL;
		sched_data_list.tail = NULL;
	}
}

void free_process_sched_data_list(void) 
{
	while (sched_data_list.head) 
	{
		pop_data();
	}
}

void free_process_sched_data(struct process_sched_data *data) 
{
	if (!data)
		return;
	kfree(data->dl_data);
	kfree(data->rt_data);
	kfree(data);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
  #define HAVE_PROC_OPS
#endif

#define FILENAME "single_seq_file"

static struct proc_dir_entry *seq_file;

static char *get_policy(int policy)
{
	switch (policy)
	{
		case SCHED_NORMAL:
			return "SCHED_NORMAL";
		case SCHED_FIFO:
			return "SCHED_FIFO";
		case SCHED_RR:
			return "SCHED_RR";
		case SCHED_BATCH:
			return "SCHED_BATCH";
		case SCHED_IDLE:
			return "SCHED_IDLE";
		case SCHED_DEADLINE:
			return "SCHED_DEADLINE";
		default:
			return "UNKNOWN";
			break;
	}
}

u64 get_avg(u64 sum, u64 count) 
{
	if (count == 0)
		return 0;
	return sum / count;
}

static int seq_show(struct seq_file *m, void *v)
{
	printk(KERN_INFO "+seq: show\n");
	seq_printf(m, "|             function              |     policy     |  prio | static_prio | normal_prio | rt_priority | load_weight |    vruntime    "
	   "|      vlag      |     slice      | rt_timeout | rt_time_slice | dl dl_runtime | dl dl_deadline | dl dl_period | dl runtime | dl deadline |"
	    "    p_count    |   run_delay   |   last_arrival   |  last_queued  |    wait_max    |    wait_avg    |   iowait_avg   "
	   "|    sleep_max   |    sleep_sum   |    block_max   |    block_sum   |     exec_max   |    slice_max   |\n");
	seq_printf(m, "----------------------------------------------------------------------------------------------------------------"
	"--------------------------------------------------------------------------------------------------------------------------------"
	"---------------------------------------------------------------------------------------------------------------------------------"
	"----------------------------------------------------------------------------------------------------------------------------\n");
	if (!sched_data_list.head) 
		return 0;
	struct process_sched_data *curr = sched_data_list.head;
	while (curr)
	{
		seq_printf(m, "| %33s | %14s | %5d | %11d | %11d | %11u | %11ld | %14lld | %14lld | %14lld | %10ld | %13u | %13lld | %14lld | %12lld | %10lld | %11lld | %13ld | %13lld | %16lld | %13lld | %14lld | %14lld | %14lld | %14lld | %14lld | %14lld | %14lld | %14lld | %14lld |\n", 
					curr->func_name, get_policy(curr->policy), curr->prio, curr->static_prio, curr->normal_prio, curr->rt_priority,
					curr->se.load.weight, curr->se.vruntime, curr->se.vlag, curr->se.slice, curr->rt_data->timeout, curr->rt_data->time_slice, 
					curr->dl_data->dl_runtime, curr->dl_data->dl_deadline, curr->dl_data->dl_period, curr->dl_data->runtime, curr->dl_data->deadline,
					curr->sched_info.pcount, curr->sched_info.run_delay, curr->sched_info.last_arrival, 
					curr->sched_info.last_queued, curr->stats.wait_max, get_avg(curr->stats.wait_sum, curr->stats.wait_count),
					get_avg(curr->stats.iowait_sum, curr->stats.iowait_count), curr->stats.sleep_max, curr->stats.sum_sleep_runtime, 
					curr->stats.block_max, curr->stats.sum_block_runtime, curr->stats.exec_max, curr->stats.slice_max
		);
		curr = curr->next;
	}
	
	return 0;
}

static int seq_file_open(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "+seq: open\n");
  return single_open(file, seq_show, NULL);
}

static ssize_t seq_file_write(struct file *file, const char __user *buf, size_t len, loff_t *fpos) 
{
  return len;
}

#ifdef HAVE_PROC_OPS
  static const struct proc_ops fops = 
  {
    .proc_open = seq_file_open,
    .proc_release = single_release,
    .proc_write = seq_file_write,
    .proc_read = seq_read
  };
#else
  static const struct file_operations fops = 
  {
    .open = seq_file_open,
    .release = single_release,
    .write = seq_file_write,
    .read = seq_read
  };
#endif

#ifdef PTREGS_SYSCALL_STUBS
static bool (*real_yield_to_task_fair)(struct pt_regs *regs);

static bool fh_yield_to_task_fair(struct pt_regs *regs)
{
	bool ret = false;
	struct task_struct *p = NULL;
	p = (struct task_struct *) p_regs_get_second_arg(regs);
	ret = real_yield_to_task_fair(regs);
	if (ret && p && p->pid == target_pid)
	{
		printk(KERN_INFO "yield_to_task_fair stub() %d", p->pid);
		add_sched_data(p, "yield_to_task_fair", CFS_SCHED_CLASS);
	}
	return ret;
}

static struct task_struct * (*real_pick_next_task_fair)(struct pt_regs *regs);
static struct task_struct * (*real_pick_next_task_rt)(struct pt_regs *regs);
static struct task_struct * (*real_pick_next_task_idle)(struct pt_regs *regs);
static struct task_struct * (*real_pick_next_task_dl)(struct pt_regs *regs);

static struct task_struct * fh_pick_next_task_fair(struct pt_regs *regs)
{
	struct task_struct *p = NULL;
	p = (struct task_struct *) real_pick_next_task_fair(regs);
	if (p && p->pid == target_pid) 
	{
		add_sched_data(p, "pick_next_task_fair", CFS_SCHED_CLASS);
	}
	return p;
}

static struct task_struct * fh_pick_next_task_rt(struct pt_regs *regs)
{
	struct task_struct *p = NULL;
	p = (struct task_struct *) real_pick_next_task_rt(regs);
	if (p && p->pid == target_pid) 
	{
		add_sched_data(p, "pick_next_task_rt", RT_SCHED_CLASS);
	}
	return p;
}

static struct task_struct * fh_pick_next_task_dl(struct pt_regs *regs)
{
	struct task_struct *p = NULL;
	p = (struct task_struct *) real_pick_next_task_dl(regs);
	if (p && p->pid == target_pid) 
	{
		add_sched_data(p, "pick_next_task_dl", DL_SCHED_CLASS);
	}
	return p;
}

static struct task_struct * fh_pick_next_task_idle(struct pt_regs *regs)
{
	struct task_struct *p = NULL;
	p = (struct task_struct *) real_pick_next_task_idle(regs);
	if (p && p->pid == target_pid) 
	{
		add_sched_data(p, "pick_next_task_idle", IDLE_SCHED_CLASS);
	}
	return p;
}
#else
static bool (*real_yield_to_task_fair) (struct rq *rq, struct task_struct *p);

static bool yield_to_task_fair(struct rq *rq, struct task_struct *p)
{
    printk(KERN_INFO "yield_to_task_fair()");
    bool ret = real_yield_to_task_fair(rq, p);
    return ret;
}

static struct task_struct * (*real_pick_next_task_fair) (struct rq *rq);
static struct task_struct * (*real_pick_next_task_rt) (struct rq *rq);
static struct task_struct * (*real_pick_next_task_dl) (struct rq *rq);
static struct task_struct * (*real_pick_next_task_idle) (struct rq *rq);

static struct task_struct * fh_pick_next_task_fair(struct rq *rq)
{
    printk(KERN_INFO "__pick_next_task_fair()");
    return real_pick_next_task_fair(rq);
}

static struct task_struct * fh_pick_next_task_rt(struct rq *rq)
{
    printk(KERN_INFO "pick_next_task_rt()");
    return real_pick_next_task_rt(rq);
}

static struct task_struct * fh_pick_next_task_dl(struct rq *rq)
{
    printk(KERN_INFO "pick_next_task_dl()");
    return real_pick_next_task_dl(rq);
}

static struct task_struct * fh_pick_next_task_idle(struct rq *rq)
{
    printk(KERN_INFO "pick_next_task_idle()");
    return real_pick_next_task_idle(rq);
}
#endif

static void __kprobes kp_check_preempt_fair_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
	struct task_struct *curr = NULL;
	struct task_struct *task = NULL;
	struct my_rq *rq = NULL;
	rq = (struct my_rq *) regs->di;
	if (!rq)
		return;
	curr = (struct task_struct *) rq->curr;
	if (!curr)
		return;
	task = (struct task_struct *) regs->si;
	if (!task)
		return;
	if (test_tsk_need_resched(curr) && task->pid == target_pid)
	{
		printk(KERN_INFO "check_preempt_wakeup_fair, pid %d, task pid %d", curr->pid, task->pid);
		add_sched_data(task, "check_preempt_wakeup_fair preempt", CFS_SCHED_CLASS);
	}
	if (test_tsk_need_resched(curr) && curr->pid == target_pid)
	{
		printk(KERN_INFO "check_preempt_wakeup_fair, pid %d, task pid %d", curr->pid, task->pid);
		add_sched_data(task, "check_preempt_wakeup_fair curr", CFS_SCHED_CLASS);
	}
}

static int __kprobes kp_wakeup_preempt_dl_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct task_struct *curr = NULL;
	struct task_struct *task = NULL;
	struct my_rq *rq = NULL;
	rq = (struct my_rq *) regs->di;
	if (!rq)
		return 0;
	curr = (struct task_struct *) rq->curr;
	if (!curr)
		return 0;
	task = (struct task_struct *) regs->si;
	if (!task)
		return 0;
	if (task->pid == target_pid)
	{
		printk(KERN_INFO "wakeup_preempt_dl, pid %d, task pid %d", curr->pid, task->pid);
		add_sched_data(task, "wakeup_preempt_dl preempt", DL_SCHED_CLASS);
	}
	else if (curr->pid == target_pid)
	{
		printk(KERN_INFO "wakeup_preempt_dl, pid %d, task pid %d", curr->pid, task->pid);
		add_sched_data(task, "wakeup_preempt_dl curr", DL_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_wakeup_preempt_idle_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct task_struct *curr = NULL;
	struct task_struct *task = NULL;
	struct my_rq *rq = NULL;
	rq = (struct my_rq *) regs->di;
	if (!rq)
		return 0;
	curr = (struct task_struct *) rq->curr;
	if (!curr)
		return 0;
	task = (struct task_struct *) regs->si;
	if (!task)
		return 0;
	if (task->pid == target_pid)
	{
		printk(KERN_INFO "wakeup_preempt_idle, pid %d, task pid %d", curr->pid, task->pid);
		add_sched_data(task, "check_preempt_idle preempt", IDLE_SCHED_CLASS);
	}
	else if (curr->pid == target_pid)
	{
		printk(KERN_INFO "wakeup_preempt_idle, pid %d, task pid %d", curr->pid, task->pid);
		add_sched_data(task, "wakeup_preempt_idle curr", IDLE_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_wakeup_preempt_rt_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct task_struct *curr = NULL;
	struct task_struct *task = NULL;
	struct my_rq *rq = NULL;
	rq = (struct my_rq *) p_regs_get_first_arg(regs);
	if (!rq)
		return 0;
	curr = (struct task_struct *) rq->curr;
	if (!curr)
		return 0;
	task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (!task)
		return 0;
	if (task->pid == target_pid)
	{
		printk(KERN_INFO "wakeup_preempt_rt, pid %d, task pid %d", curr->pid, task->pid);
		add_sched_data(task, "wakeup_preempt_rt preempt", RT_SCHED_CLASS);
	}
	else if (curr->pid == target_pid)
	{
		printk(KERN_INFO "wakeup_preempt_rt, pid %d, task pid %d", curr->pid, task->pid);
		add_sched_data(task, "wakeup_preempt_rt curr", RT_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_enqueue_task_fair_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "enqueue_task_fair() %d", task->pid);
		add_sched_data(task, "enqueue_task_fair", CFS_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_enqueue_task_rt_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task)
		printk(KERN_INFO "enqueue_task_rt() %d, %s", task->pid, task->comm);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "enqueue_task_rt() %d, %s", task->pid, task->comm);
		add_sched_data(task, "enqueue_task_rt", RT_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_enqueue_task_dl_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task)
		printk(KERN_INFO "enqueue_task_dl() %d, %s", task->pid, task->comm);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "enqueue_task_dl() %d", task->pid);
		add_sched_data(task, "enqueue_task_dl", DL_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_dequeue_task_fair_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "dequeue_task_fair() %d", task->pid);
		add_sched_data(task, "dequeue_task_fair", CFS_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_dequeue_task_rt_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "dequeue_task_rt() %d", task->pid);
		add_sched_data(task, "dequeue_task_rt", RT_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_dequeue_task_dl_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "dequeue_task_dl() %d", task->pid);
		add_sched_data(task, "dequeue_task_dl", DL_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_put_prev_task_fair_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "put_prev_task_fair() %d", task->pid);
		add_sched_data(task, "put_prev_task_fair", CFS_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_put_prev_task_rt_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "put_prev_task_rt() %d", task->pid);
		add_sched_data(task, "put_prev_task_rt", RT_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_put_prev_task_dl_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "put_prev_task_dl() %d", task->pid);
		add_sched_data(task, "put_prev_task_dl", DL_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_set_next_task_fair_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "set_next_task_fair() %d", task->pid);
		add_sched_data(task, "set_next_task_fair", CFS_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_set_next_task_rt_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "set_next_task_rt() %d", task->pid);
		add_sched_data(task, "set_next_task_rt", RT_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_set_next_task_dl_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "set_next_task_dl() %d", task->pid);
		add_sched_data(task, "set_next_task_dl", DL_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_set_next_task_idle_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "set_next_task_idle() %d", task->pid);
		add_sched_data(task, "set_next_task_idle", IDLE_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_yield_task_fair_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct my_rq *rq = NULL;
	struct task_struct *task = NULL;
	rq = (struct my_rq *) p_regs_get_first_arg(regs);
	if (rq)
	{
		task = (struct task_struct *) rq->curr;
		if (task && task->pid == target_pid)
		{
			printk(KERN_INFO "yield_task_fair() %d", task->pid);
			add_sched_data(task, "yield_task_fair", CFS_SCHED_CLASS);
		}
	}
	return 0;
}

static int __kprobes kp_yield_task_rt_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct my_rq *rq = NULL;
	struct task_struct *task = NULL;
	rq = (struct my_rq *) p_regs_get_first_arg(regs);
	if (rq)
	{
		task = (struct task_struct *) rq->curr;
		if (task && task->pid == target_pid)
		{
			printk(KERN_INFO "yield_task_rt() %d", task->pid);
			add_sched_data(task, "yield_task_rt", RT_SCHED_CLASS);
		}
	}
	return 0;
}

static int __kprobes kp_yield_task_dl_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct my_rq *rq = NULL;
	struct task_struct *task = NULL;
	rq = (struct my_rq *) p_regs_get_first_arg(regs);
	if (rq)
	{
		task = (struct task_struct *) rq->curr;
		if (task && task->pid == target_pid)
		{
			printk(KERN_INFO "yield_task_dl() %d", task->pid);
			add_sched_data(task, "yield_task_dl", DL_SCHED_CLASS);
		}
	}
	return 0;
}

static int __kprobes kp_task_tick_fair_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = NULL;
	task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "before task_tick_fair() %d", task->pid);
		add_sched_data(task, "task_tick_fair before", CFS_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_task_tick_rt_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = NULL;
	task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "before task_tick_rt() %d", task->pid);
		add_sched_data(task, "task_tick_rt before", RT_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_task_tick_idle_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = NULL;
	task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "task_tick_idle() %d", task->pid);
		add_sched_data(task, "task_tick_idle", IDLE_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_task_tick_dl_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct task_struct *task = NULL;
	task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "before task_tick_dl() %d", task->pid);
		add_sched_data(task, "task_tick_dl before", DL_SCHED_CLASS);
	}
	return 0;
}

static void __kprobes kp_task_tick_fair_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags) 
{
	struct task_struct *task = NULL;
	task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "after task_tick_fair() %d", task->pid);
		add_sched_data(task, "task_tick_fair after", CFS_SCHED_CLASS);
	}
}

static void __kprobes kp_task_tick_rt_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags) 
{
	struct task_struct *task = NULL;
	task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task)
		printk(KERN_INFO "task_tick_rt() %d", task->pid);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "after task_tick_rt() %d", task->pid);
		add_sched_data(task, "task_tick_rt after", RT_SCHED_CLASS);
	}
}

static void __kprobes kp_task_tick_dl_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags) 
{
	struct task_struct *task = NULL;
	task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (task)
		printk(KERN_INFO "task_tick_dl() %d", task->pid);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "after task_tick_dl() %d", task->pid);
		add_sched_data(task, "task_tick_dl after", DL_SCHED_CLASS);
	}
}

#define TASK_ON_RQ_QUEUED	1

static int __kprobes kp_prio_changed_fair_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct my_rq *rq = NULL;
	struct task_struct *task = NULL;
	rq = (struct my_rq *) p_regs_get_first_arg(regs);
	if (!rq)
		return 0;
	task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (!task)
		return 0;
	if (task->pid == target_pid && task->on_rq == TASK_ON_RQ_QUEUED && rq->cfs.nr_running != 1)
	{
		printk(KERN_INFO "prio_changed_fair() %d", task->pid);
		add_sched_data(task, "prio_changed_fair", CFS_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_prio_changed_rt_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct my_rq *rq = NULL;
	struct task_struct *task = NULL;
	rq = (struct my_rq *) p_regs_get_first_arg(regs);
	if (!rq)
		return 0;
	task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (!task)
		return 0;
	if (task->pid == target_pid && task->on_rq == TASK_ON_RQ_QUEUED)
	{
		printk(KERN_INFO "prio_changed_rt() %d", task->pid);
		add_sched_data(task, "prio_changed_rt", RT_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_prio_changed_dl_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct my_rq *rq = NULL;
	struct task_struct *task = NULL;
	rq = (struct my_rq *) p_regs_get_first_arg(regs);
	if (!rq)
		return 0;
	task = (struct task_struct *) p_regs_get_second_arg(regs);
	if (!task)
		return 0;
	if (task->pid == target_pid && task->on_rq == TASK_ON_RQ_QUEUED)
	{
		printk(KERN_INFO "prio_changed_dl() %d", task->pid);
		add_sched_data(task, "prio_changed_dl", DL_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_update_curr_fair_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct my_rq *rq = NULL;
	struct task_struct *task = NULL;
	rq = (struct my_rq *) p_regs_get_first_arg(regs);
	if (!rq)
		return 0;
	task = rq->curr;
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "update_curr_fair() %d", task->pid);
		add_sched_data(task, "update_curr_fair", CFS_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_update_curr_rt_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct my_rq *rq = NULL;
	struct task_struct *task = NULL;
	rq = (struct my_rq *) p_regs_get_first_arg(regs);
	if (!rq)
		return 0;
	task = rq->curr;
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "update_curr_rt() %d", task->pid);
		add_sched_data(task, "update_curr_rt", RT_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_update_curr_idle_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct my_rq *rq = NULL;
	struct task_struct *task = NULL;
	rq = (struct my_rq *) p_regs_get_first_arg(regs);
	if (!rq)
		return 0;
	task = rq->curr;
	if (task)
		printk(KERN_INFO "update_curr_idle() %d, %s", task->pid, task->comm);
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "update_curr_idle() %d", task->pid);
		add_sched_data(task, "update_curr_idle", IDLE_SCHED_CLASS);
	}
	return 0;
}

static int __kprobes kp_update_curr_dl_pre(struct kprobe *p, struct pt_regs *regs) 
{
	struct my_rq *rq = NULL;
	struct task_struct *task = NULL;
	rq = (struct my_rq *) p_regs_get_first_arg(regs);
	if (!rq)
		return 0;
	task = rq->curr;
	if (task && task->pid == target_pid)
	{
		printk(KERN_INFO "update_curr_dl() %d", task->pid);
		add_sched_data(task, "update_curr_dl", DL_SCHED_CLASS);
	}
	return 0;
}

static struct kprobe kp_hooks[] = {
	{
		.symbol_name = "check_preempt_wakeup_fair",
		.post_handler = kp_check_preempt_fair_post,
	},
	{
		.symbol_name = "wakeup_preempt_dl",
		.pre_handler = kp_wakeup_preempt_dl_pre,
	},
	{
		.symbol_name = "wakeup_preempt_rt",
		.pre_handler = kp_wakeup_preempt_rt_pre,
	},
	{
		.symbol_name = "wakeup_preempt_idle",
		.pre_handler = kp_wakeup_preempt_idle_pre,
	},
	{
		.symbol_name = "enqueue_task_fair",
		.pre_handler = kp_enqueue_task_fair_pre,
	},
	{
		.symbol_name = "enqueue_task_rt",
		.pre_handler = kp_enqueue_task_rt_pre,
	},
	{
		.symbol_name = "enqueue_task_dl",
		.pre_handler = kp_enqueue_task_dl_pre,
	},
	{
		.symbol_name = "dequeue_task_fair",
		.pre_handler = kp_dequeue_task_fair_pre,
	},
	{
		.symbol_name = "dequeue_task_rt",
		.pre_handler = kp_dequeue_task_rt_pre,
	},
	{
		.symbol_name = "dequeue_task_dl",
		.pre_handler = kp_dequeue_task_dl_pre,
	},
	{
		.symbol_name = "put_prev_task_fair",
		.pre_handler = kp_put_prev_task_fair_pre,
	},
	{
		.symbol_name = "put_prev_task_rt",
		.pre_handler = kp_put_prev_task_rt_pre,
	},
	{
		.symbol_name = "put_prev_task_dl",
		.pre_handler = kp_put_prev_task_dl_pre,
	},
	{
		.symbol_name = "set_next_task_fair",
		.pre_handler = kp_set_next_task_fair_pre,
	},
	{
		.symbol_name = "set_next_task_rt",
		.pre_handler = kp_set_next_task_rt_pre,
	},
	{
		.symbol_name = "set_next_task_dl",
		.pre_handler = kp_set_next_task_dl_pre,
	},
	{
		.symbol_name = "set_next_task_idle",
		.pre_handler = kp_set_next_task_idle_pre,
	},
	{
		.symbol_name = "yield_task_fair",
		.pre_handler = kp_yield_task_fair_pre,
	},
	{
		.symbol_name = "yield_task_rt",
		.pre_handler = kp_yield_task_rt_pre,
	},
	{
		.symbol_name = "yield_task_dl",
		.pre_handler = kp_yield_task_dl_pre,
	},
	{
		.symbol_name = "task_tick_fair",
		.pre_handler = kp_task_tick_fair_pre,
		.post_handler = kp_task_tick_fair_post,
	},
	{
		.symbol_name = "task_tick_rt",
		.pre_handler = kp_task_tick_rt_pre,
		.post_handler = kp_task_tick_rt_post,
	},
	{
		.symbol_name = "task_tick_dl",
		.pre_handler = kp_task_tick_dl_pre,
		.post_handler = kp_task_tick_dl_post,
	},
	{
		.symbol_name = "task_tick_idle",
		.pre_handler = kp_task_tick_idle_pre,
	},
	{
		.symbol_name = "prio_changed_fair",
		.pre_handler = kp_prio_changed_fair_pre,
	},
	{
		.symbol_name = "prio_changed_rt",
		.pre_handler = kp_prio_changed_rt_pre,
	},
	{
		.symbol_name = "prio_changed_dl",
		.pre_handler = kp_prio_changed_dl_pre,
	},
	{
		.symbol_name = "update_curr_fair",
		.pre_handler = kp_update_curr_fair_pre,
	},
	{
		.symbol_name = "update_curr_rt",
		.pre_handler = kp_update_curr_rt_pre,
	},
	{
		.symbol_name = "update_curr_dl",
		.pre_handler = kp_update_curr_dl_pre,
	},
	{
		.symbol_name = "update_curr_idle",
		.pre_handler = kp_update_curr_idle_pre,
	},
};

#define KHOOK(_name, _function, _original)	\
	{					\
		.name = (_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook hooked_functions[] = {
        KHOOK("yield_to_task_fair", fh_yield_to_task_fair, &real_yield_to_task_fair),
        KHOOK("__pick_next_task_fair", fh_pick_next_task_fair, &real_pick_next_task_fair),
		KHOOK("pick_next_task_rt", fh_pick_next_task_rt, &real_pick_next_task_rt),
		KHOOK("pick_next_task_dl", fh_pick_next_task_dl, &real_pick_next_task_dl),
		KHOOK("pick_next_task_idle", fh_pick_next_task_idle, &real_pick_next_task_idle),
};

int install_hooks()
{
	int i = 0;
    int ret = fh_install_hooks(hooked_functions, ARRAY_SIZE(hooked_functions));
	if (ret < 0)
		return ret;
	for (;ret == 0 && i < ARRAY_SIZE(kp_hooks); i++) 
	{
		ret = register_kprobe(&kp_hooks[i]);
	}

	if (ret < 0)
	{
		fh_remove_hooks(hooked_functions, ARRAY_SIZE(hooked_functions));
		i--;
		for (;i >= 0; i--)
			unregister_kprobe(&kp_hooks[i]);
	}
	return ret;
}

void remove_hooks()
{
    fh_remove_hooks(hooked_functions, ARRAY_SIZE(hooked_functions));
	for (int i = 0; i < ARRAY_SIZE(kp_hooks); i++) 
	{
		unregister_kprobe(&kp_hooks[i]);
		printk(KERN_INFO "unregister kprobe %d", i);
	}
	printk(KERN_INFO "unregister kprobes");
}

static int __init md_init(void)
{
    printk(KERN_INFO "Initializing module\n");
    if (target_pid == 0) {
        printk(KERN_INFO "Error: Target PID is not specified\n");
        return -EINVAL;
    }
    printk(KERN_INFO "module: target pid is %d\n", target_pid);
	int ret;
	init_process_sched_data_list();
	if ((seq_file = proc_create(FILENAME, 0666, NULL, &fops)) == NULL) 
	{
		printk(KERN_ERR "+seq create file error\n");
		free_process_sched_data_list();
		return -ENOMEM;
	}
    int err = install_hooks();
    if (err) {
		free_process_sched_data_list();
        printk(KERN_INFO "module error\n");
        return err;
    }
    printk(KERN_INFO "Module: loaded\n");
    return 0;
}

static void __exit md_exit(void)
{
    printk(KERN_INFO "LKM CFS Interceptor: Unloading module\n");
    remove_hooks();
	remove_proc_entry(FILENAME, NULL);
	free_process_sched_data_list();
    printk(KERN_INFO "LKM CFS Interceptor: Jprobes removed\n");
}

module_init(md_init);
module_exit(md_exit);