/*
 *   Copyright (C) 2019 Tencent Ltd. All rights reserved.
 *
 *   File Name ：batch.h
 *   Author    ：
 *   Date      ：2019-12-26
 *   Descriptor：
 */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BATCH_H
#define _BATCH_H

// 调度的核心头文件，其中定义了众多的结构体，比如task_struct、rq、sched_avg、
#include <linux/sched.h>
// 在该文件定义了调度策略，从中添加了SCHED_BT调度策略，编号为7
#include <uapi/linux/sched.h>

/* nflag of task_struct */
#define TNF_SCHED_BT    0x00000001

// 带宽控制数据结构
struct bt_bandwidth {
	raw_spinlock_t	bt_runtime_lock;
	ktime_t         bt_period;                 // 一个周期的时长
	u64             bt_runtime;                // 本周期内剩下的可用时间
	struct hrtimer  bt_period_timer;           // 定时器
	int             timer_active;
};

// 离线进程运行队列
struct bt_rq {
	struct load_weight load;
	unsigned int nr_running, h_nr_running;
	unsigned long nr_uninterruptible;

	u64 exec_clock;
	u64 min_vruntime;
#ifndef CONFIG_64BIT
	u64 min_vruntime_copy;
#endif

	struct rb_root_cached tasks_timeline;
	struct rb_node *rb_leftmost;

	/*
	 * 'curr' points to currently running entity on this bt_rq.
	 * It is set to NULL otherwise (i.e when none are currently running).
	 */
	struct sched_entity *curr, *next, *last, *skip;

#ifdef	CONFIG_SCHED_DEBUG
	unsigned int nr_spread_over;
#endif

#ifdef CONFIG_SMP
/*
 * Load-tracking only depends on SMP, BT_GROUP_SCHED dependency below may be
 * removed when useful for applications beyond shares distribution (e.g.
 * load-balance).
 */
	/*
	 * BT Load tracking
	 */
	struct sched_avg_bt avg;
	u64 runnable_load_sum;
	unsigned long runnable_load_avg;

#ifdef CONFIG_BT_GROUP_SCHED
	unsigned long tg_load_avg_contrib;
#endif /* CONFIG_BT_GROUP_SCHED */
	atomic_long_t removed_load_avg, removed_util_avg;
#ifndef CONFIG_64BIT
	u64 load_last_update_time_copy;
#endif

	/*
	 *   h_load = weight * f(tg)
	 *
	 * Where f(tg) is the recursive weight fraction assigned to
	 * this group.
	 */
	unsigned long h_load;
#endif /* CONFIG_SMP */
#ifdef CONFIG_BT_GROUP_SCHED
	struct rq *rq;  /* cpu runqueue to which this bt_rq is attached */

	/*
	 * leaf cfs_rqs are those that hold tasks (lowest schedulable entity in
	 * a hierarchy). Non-leaf lrqs hold other higher schedulable entities
	 * (like users, containers etc.)
	 *
	 * leaf_cfs_rq_list ties together list of leaf cfs_rq's in a cpu. This
	 * list is used during load balance.
	 */
	int on_list;
	struct list_head leaf_bt_rq_list;
	struct task_group *tg;  /* group that "owns" this runqueue */
#endif /* CONFIG_BT_GROUP_SCHED */

	int bt_throttled;
	u64 bt_time;
	u64 bt_runtime;

	u64 throttled_clock, throttled_clock_task;
	u64 throttled_clock_task_time;

	/* Nests inside the rq lock: */
	raw_spinlock_t bt_runtime_lock;
};

// 引用其他文件中的对离线进程调度类的定义
extern const struct sched_class bt_sched_class;

// 初始化离线进程调度类
extern void init_bt_rq(struct bt_rq *bt_rq);
// 选择红黑树最左侧的调度实体
extern struct sched_entity *__pick_first_bt_entity(struct bt_rq *bt_rq);

extern struct sched_entity *__pick_last_bt_entity(struct bt_rq *bt_rq);
// 设置离线进程权重
extern void set_bt_load_weight(struct task_struct *p);

// 判断进程的调度策略是否为离线，即是否为离线进程
static inline int bt_policy(int policy)
{
	if (policy == SCHED_BT)
		return 1;
	return 0;
}

// 判断进程的调度策略是否为离线，即是否为离线进程，只不过又加了一层封装，而且是内联函数
static inline int task_has_bt_policy(struct task_struct *p)
{
	return bt_policy(p->policy);
}

// 更新离线进程运行时间
extern int update_bt_runtime(struct notifier_block *nfb, unsigned long action, void *hcpu);

// 离线进程默认带宽
extern struct bt_bandwidth def_bt_bandwidth;
// 初始化离线进程CPU带宽
extern void init_bt_bandwidth(struct bt_bandwidth *bt_b, u64 period, u64 runtime);

#endif   // _BATCH_H
