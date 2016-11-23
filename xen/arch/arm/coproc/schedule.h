/*
 * xen/arch/arm/coproc/schedule.h
 *
 * Generic Scheduler for the Remote processors
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

#ifndef __ARCH_ARM_COPROC_SCHEDULE_H_
#define __ARCH_ARM_COPROC_SCHEDULE_H_

#include <xen/timer.h>
#include <xen/types.h>
#include <xen/list.h>
#include <xen/spinlock.h>

struct vcoproc_instance;

/* decision that was taken by the algorithm */
struct vcoproc_task_slice {
    /* vcoproc that was selected to run next */
    struct vcoproc_instance *task;
    /* amount of time to execute the task */
    s_time_t time;
};

/* per-coproc schedule data */
struct vcoproc_schedule_data {
    /* scheduling timer */
    struct timer s_timer;
    /* current task */
    struct vcoproc_instance *curr;
    /* lock to protect both the schedule data and the scheduler ops */
    spinlock_t schedule_lock;
};

/* per-coproc scheduler instance */
struct vcoproc_scheduler {
    /* full name for this scheduler */
    char *name;
    /* option name for this scheduler */
    char *opt_name;
    /* ID for this scheduler */
    unsigned int sched_id;
    /* global data pointer */
    void *sched_data;

    /* scheduler callback functions */
    /* callback to perform initialization for the scheduler instance */
    int (*init)(struct vcoproc_scheduler *);
    /* callback to perform deinitialization for the scheduler instance */
    void (*deinit)(struct vcoproc_scheduler *);
    /* callback to allocate scheduler-specific data for the vcoproc */
    void *(*alloc_vdata)(const struct vcoproc_scheduler *,
                         struct vcoproc_instance *);
    /* callback to free scheduler-specific data for the vcoproc */
    void (*free_vdata)(const struct vcoproc_scheduler *, void *);
    /* callback to sleep the vcoproc */
    void (*sleep)(const struct vcoproc_scheduler *, struct vcoproc_instance *);
    /* callback to wake up the vcoproc */
    void (*wake)(const struct vcoproc_scheduler *, struct vcoproc_instance *);
    /* callback to yield the vcoproc */
    void (*yield)(const struct vcoproc_scheduler *, struct vcoproc_instance *);
    /* callback to select the vcoproc to run */
    struct vcoproc_task_slice (*do_schedule)(const struct vcoproc_scheduler *,
                                             s_time_t);
    /* callback to notify about vcoproc that was previously selected to run */
    void (*schedule_completed)(const struct vcoproc_scheduler *,
                               struct vcoproc_instance *, int);

    /*
     * TODO Here the scheduler core stores *schedule_data to interact with.
     * The algorithm shouldn't touch it and even know about it.
     * So, it would be correctly to remove it from here,
     * but where to keep it?!
     */
    void *sched_priv;
};

struct coproc_device;

struct vcoproc_scheduler *vcoproc_scheduler_init(struct coproc_device *);
int vcoproc_scheduler_vcoproc_init(struct vcoproc_scheduler *,
                                   struct vcoproc_instance *);
int vcoproc_scheduler_vcoproc_destroy(struct vcoproc_scheduler *,
                                      struct vcoproc_instance *);
void vcoproc_schedule(struct vcoproc_scheduler *);
void vcoproc_sheduler_vcoproc_wake(struct vcoproc_scheduler *,
                                   struct vcoproc_instance *);
void vcoproc_sheduler_vcoproc_sleep(struct vcoproc_scheduler *,
                                    struct vcoproc_instance *);
void vcoproc_sheduler_vcoproc_yield(struct vcoproc_scheduler *,
                                    struct vcoproc_instance *);

#endif /* __ARCH_ARM_COPROC_SCHEDULE_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
