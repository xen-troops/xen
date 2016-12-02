/*
 * xen/arch/arm/coproc/sched_rrobin.c
 *
 * The Round-Robin scheduling algorithm for the Remote processors
 * based on xen/common/sched_rt.c
 *
 * Oleksandr Tyshchenko <Oleksandr_Tyshchenko@epam.com>
 * Copyright (C) 2016 EPAM Systems Inc.
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

#include <xen/init.h>
#include <xen/err.h>

#include "coproc.h"

static s_time_t rr_slice = MILLISECS(1000);

/* system-wide private data */
struct rr_private {
    spinlock_t lock;
    /* list of runnable vcoprocs */
    struct list_head runq;
};

/* vcoproc */
struct rr_vcoproc {
    /* on the runq list */
    struct list_head runq_elem;
    struct vcoproc_instance *vcoproc;
    int awake;
};

static inline struct rr_private *rr_priv(const struct vcoproc_scheduler *ops)
{
    return ops->sched_data;
}

static inline struct rr_vcoproc *rr_vcoproc(const struct vcoproc_instance *vcoproc)
{
    return vcoproc ? vcoproc->sched_priv : NULL;
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

static inline void runq_insert_tail(const struct vcoproc_scheduler *ops,
                                    struct rr_vcoproc *svc)
{
    struct rr_private *priv = rr_priv(ops);

    ASSERT( !on_runq(svc) );
    list_add_tail(&svc->runq_elem, &priv->runq);
}

static inline void runq_insert_head(const struct vcoproc_scheduler *ops,
                                    struct rr_vcoproc *svc)
{
    struct rr_private *priv = rr_priv(ops);

    ASSERT( !on_runq(svc) );
    list_add(&svc->runq_elem, &priv->runq);
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

    if ( runq_empty(ops) )
        return NULL;

    list_for_each ( iter, runq )
    {
        /* Just pick the first vcoproc for now */
        svc = runq_elem(iter);
        break;
    }

    return svc;
}

static struct vcoproc_task_slice rr_do_schedule(const struct vcoproc_scheduler *ops,
                                                s_time_t now)
{
    struct rr_vcoproc *next;
    struct vcoproc_task_slice ret = { .task = NULL, .time = -1 };

    next = runq_pick(ops);
    if ( !next )
        return ret;

    runq_remove(next);

    ret.task = next->vcoproc;
    ret.time = rr_slice;

    return ret;
}

static void rr_schedule_completed(const struct vcoproc_scheduler *ops,
                                  struct vcoproc_instance *vcoproc,
                                  int scheduled)
{
    struct rr_vcoproc *svc = rr_vcoproc(vcoproc);

    if ( !svc )
        return;

    if ( scheduled )
        runq_insert_tail(ops, svc);
    else
        runq_insert_head(ops, svc);
}

static void rr_yield(const struct vcoproc_scheduler *ops,
                     struct vcoproc_instance *vcoproc)
{
    /* nothing to do */
}

static void rr_wake(const struct vcoproc_scheduler *ops,
                    struct vcoproc_instance *vcoproc)
{
    struct rr_vcoproc *svc = rr_vcoproc(vcoproc);

    if ( !svc )
        return;

    svc->awake = 1;

    if ( !on_runq(svc) )
        runq_insert_head(ops, svc);
}

static void rr_sleep(const struct vcoproc_scheduler *ops,
                     struct vcoproc_instance *vcoproc)
{
    struct rr_vcoproc *svc = rr_vcoproc(vcoproc);

    if ( !svc )
        return;

    svc->awake = 0;

    if ( on_runq(svc) )
        runq_remove(svc);
}

static void *rr_alloc_vdata(const struct vcoproc_scheduler *ops,
                            struct vcoproc_instance *vcoproc)
{
    struct rr_vcoproc *svc;

    svc = xzalloc(struct rr_vcoproc);
    if ( !svc )
        return NULL;

    INIT_LIST_HEAD(&svc->runq_elem);
    svc->vcoproc = vcoproc;
    svc->awake = 0;

    return svc;
}

static void rr_free_vdata(const struct vcoproc_scheduler *ops, void *priv)
{
    struct rr_vcoproc *svc = priv;

    xfree(svc);
}

static int rr_init(struct vcoproc_scheduler *ops)
{
    struct rr_private *priv;

    priv = xzalloc(struct rr_private);
    if ( !priv )
        return -ENOMEM;

    spin_lock_init(&priv->lock);
    INIT_LIST_HEAD(&priv->runq);

    ops->sched_data = priv;

    return 0;
}

static void rr_deinit(struct vcoproc_scheduler *ops)
{
    struct rr_private *priv = rr_priv(ops);

    ops->sched_data = NULL;
    xfree(priv);
}

const struct vcoproc_scheduler vcoproc_sched_rrobin_def = {
    .name                = "Round-Robin Scheduler",
    .opt_name            = "rrobin",
    .sched_id            = 0,
    .sched_data          = NULL,

    .init                = rr_init,
    .deinit              = rr_deinit,
    .alloc_vdata         = rr_alloc_vdata,
    .free_vdata          = rr_free_vdata,
    .sleep               = rr_sleep,
    .wake                = rr_wake,
    .yield               = rr_yield,
    .do_schedule         = rr_do_schedule,
    .schedule_completed  = rr_schedule_completed,

    .sched_priv          = NULL,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
