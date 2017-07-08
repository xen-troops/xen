/*
 * xen/arch/arm/coproc/schedule.c
 *
 * Generic Scheduler for the Remote processors
 * based on xen/common/schedule.c
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

/* TODO Each coproc may have its own algorithm */
static char __initdata opt_vcoproc_sched[10] = "rrobin";
string_param("vcoproc_sched", opt_vcoproc_sched);

extern struct vcoproc_scheduler vcoproc_sched_rrobin_def;

static struct vcoproc_scheduler *const vcoproc_schedulers[] = {
    &vcoproc_sched_rrobin_def,
    NULL
};

#define VCOPROC_SCHED_OP(opsptr, fn, ...) \
    (( (opsptr)->fn != NULL ) ? (opsptr)->fn(opsptr, ##__VA_ARGS__ ) \
    : (typeof((opsptr)->fn(opsptr, ##__VA_ARGS__)))0 )

static void vcoproc_scheduler_set_current(const struct vcoproc_scheduler *sched,
                                          struct vcoproc_instance *vcoproc)
{
    struct vcoproc_schedule_data *sched_data = sched->sched_priv;

    sched_data->curr = vcoproc;
}

static struct vcoproc_instance *vcoproc_scheduler_get_current(const struct vcoproc_scheduler *sched)
{
    struct vcoproc_schedule_data *sched_data = sched->sched_priv;

    return sched_data->curr;
}

static bool_t vcoproc_scheduler_vcoproc_is_destroyed(struct vcoproc_scheduler *sched,
                                                     struct vcoproc_instance *vcoproc)
{
    if ( !vcoproc )
        return true;

    return vcoproc->state == VCOPROC_UNKNOWN ? true : false;
}

int vcoproc_scheduler_vcoproc_init(struct vcoproc_scheduler *sched,
                                   struct vcoproc_instance *vcoproc)
{
    struct vcoproc_schedule_data *sched_data = sched->sched_priv;
    unsigned long flags;

    if ( !vcoproc_scheduler_vcoproc_is_destroyed(sched, vcoproc) )
        return -EINVAL;

    spin_lock_irqsave(&sched_data->schedule_lock, flags);
    vcoproc->sched_priv = VCOPROC_SCHED_OP(sched, alloc_vdata, vcoproc);
    if ( !vcoproc->sched_priv )
    {
        printk("Failed to allocate scheduler-specific data for vcoproc \"%s\"\n",
               dev_path(vcoproc->coproc->dev));
        spin_unlock_irqrestore(&sched_data->schedule_lock, flags);
        return -ENOMEM;
    }

    vcoproc->state = VCOPROC_SLEEPING;
    spin_unlock_irqrestore(&sched_data->schedule_lock, flags);

    return 0;
}

int vcoproc_scheduler_vcoproc_destroy(struct vcoproc_scheduler *sched,
                                      struct vcoproc_instance *vcoproc)
{
    struct vcoproc_schedule_data *sched_data = sched->sched_priv;
    unsigned long flags;

    if ( vcoproc_scheduler_vcoproc_is_destroyed(sched, vcoproc) )
        return 0;

    vcoproc_scheduler_vcoproc_sleep(sched, vcoproc);

    spin_lock_irqsave(&sched_data->schedule_lock, flags);
    if ( vcoproc->state == VCOPROC_ASKED_TO_SLEEP )
    {
        spin_unlock_irqrestore(&sched_data->schedule_lock, flags);
        return -EBUSY;
    }

    if ( vcoproc->sched_priv )
    {
        VCOPROC_SCHED_OP(sched, free_vdata, vcoproc->sched_priv);
        vcoproc->sched_priv = NULL;
    }
    vcoproc->state = VCOPROC_UNKNOWN;
    spin_unlock_irqrestore(&sched_data->schedule_lock, flags);

    return 0;
}

void vcoproc_scheduler_vcoproc_wake(struct vcoproc_scheduler *sched,
                                   struct vcoproc_instance *vcoproc)
{
    struct vcoproc_schedule_data *sched_data = sched->sched_priv;
    unsigned long flags;

    ASSERT(!vcoproc_scheduler_vcoproc_is_destroyed(sched, vcoproc));

    /* TODO What to do if we came with state ASKED_TO_SLEEP? */
    spin_lock_irqsave(&sched_data->schedule_lock, flags);
    if ( vcoproc->state != VCOPROC_SLEEPING )
    {
        spin_unlock_irqrestore(&sched_data->schedule_lock, flags);
        return;
    }

    VCOPROC_SCHED_OP(sched, wake, vcoproc);
    vcoproc->state = VCOPROC_WAITING;
    spin_unlock_irqrestore(&sched_data->schedule_lock, flags);

    vcoproc_schedule(sched);
}

void vcoproc_scheduler_vcoproc_sleep(struct vcoproc_scheduler *sched,
                                    struct vcoproc_instance *vcoproc)
{
    struct vcoproc_schedule_data *sched_data = sched->sched_priv;
    unsigned long flags;
    bool_t reschedule = false;

    ASSERT(!vcoproc_scheduler_vcoproc_is_destroyed(sched, vcoproc));

    spin_lock_irqsave(&sched_data->schedule_lock, flags);
    if ( vcoproc->state != VCOPROC_WAITING &&
         vcoproc->state != VCOPROC_RUNNING )
    {
        spin_unlock_irqrestore(&sched_data->schedule_lock, flags);
        return;
    }

    VCOPROC_SCHED_OP(sched, sleep, vcoproc);
    if ( vcoproc->state == VCOPROC_WAITING )
        vcoproc->state = VCOPROC_SLEEPING;
    else
    {
        vcoproc->state = VCOPROC_ASKED_TO_SLEEP;
        reschedule = true;
    }
    spin_unlock_irqrestore(&sched_data->schedule_lock, flags);

    if ( reschedule )
        vcoproc_schedule(sched);
}

void vcoproc_scheduler_vcoproc_yield(struct vcoproc_scheduler *sched,
                                    struct vcoproc_instance *vcoproc)
{
    struct vcoproc_schedule_data *sched_data = sched->sched_priv;
    unsigned long flags;

    ASSERT(!vcoproc_scheduler_vcoproc_is_destroyed(sched, vcoproc));

    spin_lock_irqsave(&sched_data->schedule_lock, flags);
    if ( vcoproc->state != VCOPROC_RUNNING )
    {
        spin_unlock_irqrestore(&sched_data->schedule_lock, flags);
        return;
    }
    VCOPROC_SCHED_OP(sched, yield, vcoproc);
    spin_unlock_irqrestore(&sched_data->schedule_lock, flags);

    vcoproc_schedule(sched);
}

static inline void schedule_trace(struct vcoproc_instance *curr,
                                  struct vcoproc_instance *next,
                                  int stage)
{
    switch ( stage )
    {
    case 0:
        COPROC_VERBOSE(NULL, "--NOTHING TO SCHEDULE--------------------\n");
        break;

    case 1:
        COPROC_VERBOSE(NULL, "--dom %d (%s) CONTINUE RUNNING (BUSY)----\n",
                       curr ? curr->domain->domain_id : -1,
                       curr ? dev_path(curr->coproc->dev) : "NULL");
        break;

    case 2:
        COPROC_VERBOSE(NULL, "--dom %d (%s) CONTINUE RUNNING (SINGLE)--\n",
                       curr ? curr->domain->domain_id : -1,
                       curr ? dev_path(curr->coproc->dev) : "NULL");
        break;

    case 3:
        if (next)
            COPROC_VERBOSE(NULL, "--dom %d (%s) START RUNNING--------------\n",
                           next ? next->domain->domain_id : -1,
                           next ? dev_path(next->coproc->dev) : "NULL");
        else
            COPROC_VERBOSE(NULL, "--dom %d (%s )STOP RUNNING---------------\n",
                           curr ? curr->domain->domain_id : -1,
                           curr ? dev_path(curr->coproc->dev) : "NULL");
        break;

    default:
        break;
    }
}

static s_time_t vcoproc_scheduler_context_switch(struct vcoproc_instance *curr,
                                                struct vcoproc_instance *next)
{
    struct coproc_device *coproc;
    int ret;

    if ( unlikely(curr == next) )
        return 0;

    coproc = next ? next->coproc : curr->coproc;

    if ( likely(curr) )
    {
        s_time_t wait_time;

        ASSERT(curr->state == VCOPROC_RUNNING ||
               curr->state == VCOPROC_ASKED_TO_SLEEP);

        wait_time = vcoproc_context_switch_from(curr);

        if ( wait_time == 0 )
        {
            ret = iommu_disable_coproc(curr->domain, dev_to_dt(coproc->dev));
            if ( unlikely(ret) )
                panic("Failed to disable IOMMU context for coproc \"%s\" in domain %u (%d)\n",
                      dev_path(coproc->dev), curr->domain->domain_id, ret);

            if (curr->state == VCOPROC_RUNNING)
                curr->state = VCOPROC_WAITING;
            else
                curr->state = VCOPROC_SLEEPING;
        }
        else if ( wait_time > 0 )
            return wait_time;
        else
        {
            panic("Failed to switch context from vcoproc \"%s\"\n",
                  dev_path(coproc->dev));
        }
    }

    if ( likely(next) )
    {
        ASSERT(next->state == VCOPROC_WAITING);

        ret = iommu_enable_coproc(next->domain, dev_to_dt(coproc->dev));
        if ( unlikely(ret) )
            panic("Failed to enable IOMMU context for coproc \"%s\" in domain %u (%d)\n",
                  dev_path(coproc->dev), next->domain->domain_id, ret);

        /* TODO What to do if we failed to switch to "next"? */
        ret = vcoproc_context_switch_to(next);
        if ( likely(!ret) )
            next->state = VCOPROC_RUNNING;
        else
            panic("Failed to switch context to vcoproc \"%s\" (%d)\n",
                  dev_path(coproc->dev), ret);
    }

    return 0;
}

/* TODO Taking lock for the whole func is might be an overhead */
void vcoproc_schedule(struct vcoproc_scheduler *sched)
{
    struct vcoproc_instance *curr, *next;
    struct vcoproc_schedule_data *sched_data = sched->sched_priv;
    struct vcoproc_task_slice next_slice;
    s_time_t wait_time, now;
    unsigned long flags;

    spin_lock_irqsave(&sched_data->schedule_lock, flags);

    curr = vcoproc_scheduler_get_current(sched);

    now = NOW();
    stop_timer(&sched_data->s_timer);

    next_slice = sched->do_schedule(sched, now);
    next = next_slice.task;

    if ( unlikely(!curr && !next) )
    {
        schedule_trace(curr, next, 0);
        goto out;
    }

    wait_time = vcoproc_scheduler_context_switch(curr, next);
    ASSERT(wait_time >= 0);

    if ( wait_time > 0 )
    {
        set_timer(&sched_data->s_timer, now + wait_time);
        VCOPROC_SCHED_OP(sched, schedule_completed, next, 0);
        schedule_trace(curr, next, 1);
        vcoproc_continue_running(curr);
        goto out;
    }

    vcoproc_scheduler_set_current(sched, next);
    VCOPROC_SCHED_OP(sched, schedule_completed, next, 1);

    if ( next_slice.time >= 0 )
        set_timer(&sched_data->s_timer, now + next_slice.time);

    if ( curr == next )
    {
        schedule_trace(curr, next, 2);
        vcoproc_continue_running(curr);
        goto out;
    }
    schedule_trace(curr, next, 3);

out:
    spin_unlock_irqrestore(&sched_data->schedule_lock, flags);
}

static void s_timer_fn(void *data)
{
    struct vcoproc_scheduler *sched = data;

    vcoproc_schedule(sched);
}

struct vcoproc_scheduler * __init vcoproc_scheduler_init(struct coproc_device *coproc)
{
    struct vcoproc_scheduler *sched;
    struct vcoproc_schedule_data *sched_data;
    int i, ret;

    if ( !coproc )
        return ERR_PTR(-EINVAL);

    for ( i = 0; vcoproc_schedulers[i]; i++ )
    {
        if ( !strncmp(vcoproc_schedulers[i]->opt_name, opt_vcoproc_sched,
             strlen(opt_vcoproc_sched)) )
        break;
    }

    if ( !vcoproc_schedulers[i] )
    {
        printk("Failed to find scheduler \"%s\" for coproc \"%s\"\n",
               opt_vcoproc_sched, dev_path(coproc->dev));
        return ERR_PTR(-ENODEV);
    }

    printk("Using scheduler \"%s\" for coproc \"%s\"\n",
           vcoproc_schedulers[i]->opt_name, dev_path(coproc->dev));

    sched = xmalloc(struct vcoproc_scheduler);
    if ( !sched )
    {
        printk("Failed to allocate scheduler for coproc \"%s\"\n",
               dev_path(coproc->dev));
        return ERR_PTR(-ENOMEM);
    }
    memcpy(sched, vcoproc_schedulers[i], sizeof(*sched));

    sched_data = xmalloc(struct vcoproc_schedule_data);
    if ( !sched_data )
    {
        printk("Failed to allocate schedule data for coproc \"%s\"\n",
               dev_path(coproc->dev));
        ret = -ENOMEM;
        goto out_free_sched;
    }
    sched->sched_priv = sched_data;
    init_timer(&sched_data->s_timer, s_timer_fn, sched, 0);
    vcoproc_scheduler_set_current(sched, NULL);
    spin_lock_init(&sched_data->schedule_lock);

    ret = VCOPROC_SCHED_OP(sched, init);
    if ( ret )
    {
        printk("Failed to init scheduler for coproc \"%s\"\n",
               dev_path(coproc->dev));
        goto out_free_data;
    }

    return sched;

out_free_data:
    kill_timer(&sched_data->s_timer);
    xfree(sched_data);
out_free_sched:
    xfree(sched);

    return ERR_PTR(ret);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
