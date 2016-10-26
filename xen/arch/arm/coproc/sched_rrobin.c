/*
 * xen/arch/arm/coproc/sched_rrobin.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "coproc.h"

/* TODO for both generic and implementation:
 *      1. Split some functions
 *      2. Locks (inside and outside)!
 *      3. State machine */

static s_time_t rr_slice = MILLISECS(10);

/*
 * System-wide private data
 */
struct rr_private {
	spinlock_t lock;
	/* list of runnable vcoprocs */
	struct list_head runq;
};

/*
 * VCOPROC
 */
struct rr_vcoproc {
	/* on the runq list */
	struct list_head runq_elem;

	/* Up-pointers */
	struct rr_domain *sdom;
	struct vcoproc_info *vcoproc;

	/* TODO */
	bool_t awake;
};

/*
 * Domain
 */
struct rr_domain {
	/* pointer to upper domain */
	struct domain *dom;
};

static inline struct rr_private *rr_priv(const struct vcoproc_scheduler *ops)
{
	return ops->sched_data;
}

static inline struct rr_vcoproc *rr_vcoproc(const struct vcoproc_info *vcoproc)
{
	return vcoproc->sched_priv;
}

static inline struct list_head *rr_runq(const struct vcoproc_scheduler *ops)
{
	return &rr_priv(ops)->runq;
}

/* Helper functions for manipulating the runqueue */
static inline int on_runq(const struct rr_vcoproc *svc)
{
	return !list_empty(&svc->runq_elem);
}

static inline struct rr_vcoproc *runq_elem(struct list_head *elem)
{
	return list_entry(elem, struct rr_vcoproc, runq_elem);
}

static inline int runq_empty(const struct vcoproc_scheduler *ops)
{
	struct rr_private *priv = rr_priv(ops);

	return list_empty(&priv->runq);
}

static inline void runq_insert(const struct vcoproc_scheduler *ops, struct rr_vcoproc *svc)
{
	struct rr_private *priv = rr_priv(ops);

	ASSERT( !on_runq(svc) );
	list_add_tail(&svc->runq_elem, &priv->runq);
}

static inline void runq_remove(struct rr_vcoproc *svc)
{
	ASSERT( on_runq(svc) );
	list_del_init(&svc->runq_elem);
}

static struct rr_vcoproc *runq_pick(const struct vcoproc_scheduler *ops)
{
	struct list_head *runq = rr_runq(ops);
	struct list_head *iter;
	struct rr_vcoproc *svc = NULL;

	list_for_each ( iter, runq )
	{
		/* Just pick the first vcoproc */
		svc = runq_elem(iter);
		break;
	}

	return svc;
}

/* This function selects a VCOPROC to run */
static struct vcoproc_task_slice rr_do_schedule(const struct vcoproc_scheduler *ops, s_time_t now)
{
	struct vcoproc_info *vcoproc = vcoproc_scheduler_get_current(ops);
	struct rr_vcoproc *scurr = rr_vcoproc(vcoproc);
	struct rr_vcoproc *snext = NULL;
	struct vcoproc_task_slice ret = { .task = NULL, .time = -1 };
	int something = 0;

	if ( runq_empty(ops) )
		return ret;

	snext = runq_pick(ops);
	if ( !snext )
		return ret;

	/* TODO here we have to make decision about still picking scurr */
	if ( something && scurr )
		snext = scurr;

	if ( snext != scurr )
		runq_remove(snext);

	ret.task = snext->vcoproc;
	ret.time = rr_slice;

	return ret;
}

/* This function inserts a current VCOPROC back to the runqueue */
static void rr_context_saved(const struct vcoproc_scheduler *ops, struct vcoproc_info *vcoproc)
{
	struct rr_vcoproc *svc;

	if ( !vcoproc )
		return;

	svc = rr_vcoproc(vcoproc);

	runq_insert(ops, svc);
}

static void rr_yield(const struct vcoproc_scheduler *ops, struct vcoproc_info *vcoproc)
{

}

/* This function inserts VCOPROC to the runqueue (as rr_insert_vcoproc() does)  */
static void rr_wake(const struct vcoproc_scheduler *ops, struct vcoproc_info *vcoproc)
{
	struct rr_vcoproc *svc = rr_vcoproc(vcoproc);

	svc->awake = 1;

	if ( !on_runq(svc) )
		runq_insert(ops, svc);
}

/* This function removes VCOPROC from the runqueue (as rr_remove_vcoproc() does) */
static void rr_sleep(const struct vcoproc_scheduler *ops, struct vcoproc_info *vcoproc)
{
	struct rr_vcoproc *svc = rr_vcoproc(vcoproc);

	svc->awake = 0;

	if ( on_runq(svc) )
		runq_remove(svc);
}

/* This function inserts VCOPROC to the runqueue (as rr_wake() does)  */
static void rr_insert_vcoproc(const struct vcoproc_scheduler *ops, struct vcoproc_info *vcoproc)
{
	struct rr_vcoproc *svc = rr_vcoproc(vcoproc);

	if ( !on_runq(svc) )
		runq_insert(ops, svc);
}

/* This function removes VCOPROC from the runqueue (as rr_sleep() does) */
static void rr_remove_vcoproc(const struct vcoproc_scheduler *ops, struct vcoproc_info *vcoproc)
{
	struct rr_vcoproc *svc = rr_vcoproc(vcoproc);

	if ( on_runq(svc) )
		runq_remove(svc);
}

/* This function allocates scheduler-specific data for a VCOPROC */
static void *rr_alloc_vdata(const struct vcoproc_scheduler *ops,
		struct vcoproc_info *vcoproc, void *dd)
{
	struct rr_vcoproc *svc;

	svc = xzalloc(struct rr_vcoproc);
	if ( !svc )
		return NULL;

	INIT_LIST_HEAD(&svc->runq_elem);

	svc->sdom = dd;
	svc->vcoproc = vcoproc;
	svc->awake = 0;

	return svc;
}

/* This function frees scheduler-specific data for a VCOPROC */
static void rr_free_vdata(const struct vcoproc_scheduler *ops, void *priv)
{
	struct rr_vcoproc *svc = priv;

	xfree(svc);
}

/* This function performs initialization for an instance of the scheduler */
static int rr_init(struct vcoproc_scheduler *ops)
{
	struct rr_private *priv;

	priv = xzalloc(struct rr_private);
	if ( priv )
		return -ENOMEM;

	spin_lock_init(&priv->lock);
	INIT_LIST_HEAD(&priv->runq);

	ops->sched_data = priv;

	return 0;
}

/* This function performs deinitialization for an instance of the scheduler */
static void rr_deinit(struct vcoproc_scheduler *ops)
{
	struct rr_private *priv = rr_priv(ops);

	ops->sched_data = NULL;
	xfree(priv);
}

const struct vcoproc_scheduler vcoproc_sched_rrobin_def = {
    .name           = "Round-Robin Scheduler",
    .opt_name       = "rrobin",
    .sched_id       = 0,
    .sched_data     = NULL,

    .init           = rr_init,
    .deinit         = rr_deinit,
    .alloc_vdata    = rr_alloc_vdata,
    .free_vdata     = rr_free_vdata,
    .insert_vcoproc = rr_insert_vcoproc,
    .remove_vcoproc = rr_remove_vcoproc,
    .sleep          = rr_sleep,
    .wake           = rr_wake,
    .yield          = rr_yield,
    .context_saved  = rr_context_saved,
    .do_schedule    = rr_do_schedule,

    /* Fixme - remove from here (the algorithm shouldn't touch it and know about it) */
    .sd             = NULL,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
