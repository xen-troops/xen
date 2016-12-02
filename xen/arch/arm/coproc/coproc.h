/*
 * xen/arch/arm/coproc/coproc.h
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

#ifndef __COPROC_H_
#define __COPROC_H_

#include <xen/sched.h>

struct mmio {
    void __iomem *base;
    u64 addr;
    u64 size;
};

struct coproc_device {
    char *name;
    struct device *dev;

    u32 num_mmios;
    struct mmio *mmios;
    u32 num_irqs;
    unsigned int *irqs;
    struct list_head list;

    struct vcoproc_scheduler *sched;

    spinlock_t vcoprocs_lock;
    /* The vcoprocs_list is used to keep track of all vcoproc instances
     * that have been created from this coproc */
    struct list_head vcoprocs_list;
    const struct vcoproc_ops *ops;
};

struct vcoproc_info {
    struct coproc_device *coproc;
    struct domain *domain;
    spinlock_t lock;
    /* list is used to append instances of vcoproc to vcoprocs_list */
    struct list_head list;

    /* TODO */
    bool_t is_running;
    /* scheduler-specific data */
    void *sched_priv;

    const struct vcoproc_domain_ops *ops;
};

struct vcoproc_ops {
    int (*vcoproc_init)(struct domain *, struct coproc_device *);
    void (*vcoproc_free)(struct domain *, struct vcoproc_info *);
    int (*ctx_switch_from)(struct vcoproc_info *);
    int (*ctx_switch_to)(struct vcoproc_info *);
};

struct vcoproc_domain_ops {
    int (*domain_init)(struct domain *, struct vcoproc_info *);
    void (*domain_free)(struct domain *, struct vcoproc_info *);
};

/* TODO - move all scheduler stuff out of this header */

struct vcoproc_task_slice {
    struct vcoproc_info *task;
    s_time_t time;
};

struct vcoproc_schedule_data {
    /* scheduling timer */
    struct timer s_timer;
    struct vcoproc_info *curr;
};

struct vcoproc_scheduler {
    char *name;
    char *opt_name;
    unsigned int sched_id;
    void *sched_data;

    int (*init)(struct vcoproc_scheduler *);
    void (*deinit)(struct vcoproc_scheduler *);

    void *(*alloc_vdata)(const struct vcoproc_scheduler *, struct vcoproc_info *, void *);
    void (*free_vdata)(const struct vcoproc_scheduler *, void *);

    void (*insert_vcoproc)(const struct vcoproc_scheduler *, struct vcoproc_info *);
    void (*remove_vcoproc)(const struct vcoproc_scheduler *, struct vcoproc_info *);

    void (*sleep)(const struct vcoproc_scheduler *, struct vcoproc_info *);
    void (*wake)(const struct vcoproc_scheduler *, struct vcoproc_info *);
    void (*yield)(const struct vcoproc_scheduler *, struct vcoproc_info *);
    void (*context_saved)(const struct vcoproc_scheduler *, struct vcoproc_info *);

    struct vcoproc_task_slice (*do_schedule)(const struct vcoproc_scheduler *, s_time_t);

    /* Fixme - really don't want to keep it here */
    struct vcoproc_schedule_data *sd;
};

void coproc_init(void);
int coproc_register(struct coproc_device *);
int vcoproc_attach(struct domain *, struct vcoproc_info *);
int domain_vcoproc_init(struct domain *);
void domain_vcoproc_free(struct domain *);

int vcoproc_context_switch(struct vcoproc_info *, struct vcoproc_info *);
void vcoproc_continue_running(struct vcoproc_info *);

struct vcoproc_scheduler *vcoproc_scheduler_init(struct coproc_device *);
int vcoproc_scheduler_vcoproc_init(struct vcoproc_scheduler *, struct vcoproc_info *);
void vcoproc_scheduler_vcoproc_destroy(struct vcoproc_scheduler *, struct vcoproc_info *);
void vcoproc_schedule(struct vcoproc_scheduler *);
void vcoproc_scheduler_set_current(const struct vcoproc_scheduler *, struct vcoproc_info *);
struct vcoproc_info *vcoproc_scheduler_get_current(const struct vcoproc_scheduler *);
void vcoproc_sheduler_context_saved(struct vcoproc_scheduler *, struct vcoproc_info *);
void vcoproc_sheduler_vcoproc_wake(struct vcoproc_scheduler *, struct vcoproc_info *);
void vcoproc_sheduler_vcoproc_sleep(struct vcoproc_scheduler *, struct vcoproc_info *);
void vcoproc_sheduler_vcoproc_yield(struct vcoproc_scheduler *, struct vcoproc_info *);


#endif /* __COPROC_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
