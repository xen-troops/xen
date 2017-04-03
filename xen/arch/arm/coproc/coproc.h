/*
 * xen/arch/arm/coproc/coproc.h
 *
 * Generic Remote processors framework
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

#ifndef __ARCH_ARM_COPROC_COPROC_H__
#define __ARCH_ARM_COPROC_COPROC_H__

#include <xen/types.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <xen/sched.h>
#include <xen/device_tree.h>
#include <public/domctl.h>

#include "schedule.h"

/* coproc memory range */
struct mmio {
    u64 addr;
    u64 size;
    /* ioremapped addr */
    void __iomem *base;

    struct coproc_device *coproc;
};

/* coproc device that represents the real remote processor */
struct coproc_device {
    struct device *dev;

    /* the number of memory ranges for this coproc */
    u32 num_mmios;
    /* the array of memory ranges for this coproc */
    struct mmio *mmios;
    /* the number of irqs for this coproc */
    u32 num_irqs;
    /* the array of irqs for this coproc */
    unsigned int *irqs;

    /*
     * this list is used to append this coproc
     * to the "framework's" global coprocs list
     */
    struct list_head coproc_elem;
    /* to protect the vcoprocs list */
    spinlock_t vcoprocs_lock;
    /*
     * this list is used to keep track of all vcoproc instances that
     * have been created from this coproc
     */
    struct list_head vcoprocs;

    /* coproc callback functions */
    const struct coproc_ops *ops;

    /* scheduler instance for this coproc */
    struct vcoproc_scheduler *sched;

    /* coproc implementation specific data */
    void *priv;
};

/* coproc callback functions */
struct coproc_ops {
    /* callback to perform initialization for the vcoproc instance */
    int (*vcoproc_init)(struct vcoproc_instance *);
    /* callback to perform deinitialization for the vcoproc instance */
    void (*vcoproc_deinit)(struct vcoproc_instance *);
    /* callback to perform context switch from the running vcoproc instance */
    s_time_t (*ctx_switch_from)(struct vcoproc_instance *);
    /* callback to perform context switch to the waiting vcoproc instance */
    int (*ctx_switch_to)(struct vcoproc_instance *);
};

/* vcoproc read/write operation context */
struct vcoproc_rw_context {
    struct coproc_device *coproc;
    struct hsr_dabt dabt;
    uint32_t offset;
    struct vcoproc_instance *vcoproc;
};

/* describe vcoproc state from the scheduler point of view */
enum vcoproc_state {
    /* vcoproc hasn't been created yet or it has already been destroyed */
    VCOPROC_UNKNOWN,
    /* vcoproc is neither running at the moment nor ready to be scheduled */
    VCOPROC_SLEEPING,
    /* vcoproc isn't running at the moment but is ready to be scheduled */
    VCOPROC_WAITING,
    /* vcoproc is running at the moment */
    VCOPROC_RUNNING,
    /* vcoproc was scheduled to sleep, but is still running */
    VCOPROC_ASKED_TO_SLEEP
};

/* per-domain vcoproc instance */
struct vcoproc_instance {
    struct coproc_device *coproc;
    struct domain *domain;
    spinlock_t lock;
    /* vcoproc state for scheduling */
    enum vcoproc_state state;

    /*
     * this list is used to append this vcoproc
     * to the "coproc's" vcoprocs list
     */
    struct list_head vcoproc_elem;
    /*
     * this list is used to append this vcoproc
     * to the "domain's" instances list
     * must not be touched by any of vcoprocs
     */
    struct list_head instance_elem;

    /* scheduler-specific data */
    void *sched_priv;

    /* vcoproc implementation specific data */
    void *priv;
};

/* coproc logger functions */

extern int coproc_debug;

#define coproc_dev_print(dev, lvl, coproc_lvl, fmt, ...)                       \
do                                                                             \
{                                                                              \
    if ( coproc_lvl <= coproc_debug )                                          \
        printk(lvl "coproc: %s: " fmt,                                         \
               dev ? dt_node_full_name(dev_to_dt(dev)) : "",                   \
               ## __VA_ARGS__);                                                \
} while (0)

/*
 * this is defined for convenience so we don't have to translate
 * XENLOG_XXX into corresponding numbers at runtime
 */
enum COPROC_DBG_LEVEL
{
    COPROC_DBG_ERROR,
    COPROC_DBG_WARN,
    COPROC_DBG_INFO,
    COPROC_DBG_DEBUG,
    COPROC_DBG_VERB,
    COPROC_DBG_LAST
};

#define COPROC_ERROR(dev, fmt, ...)                                            \
    coproc_dev_print(dev, XENLOG_ERR,     COPROC_DBG_ERROR, fmt, ## __VA_ARGS__)
#define COPROC_WARN(dev, fmt, ...)                                             \
    coproc_dev_print(dev, XENLOG_WARNING, COPROC_DBG_WARN, fmt, ## __VA_ARGS__)
#define COPROC_NOTE(dev, fmt, ...)                                             \
    coproc_dev_print(dev, XENLOG_INFO,    COPROC_DBG_INFO, fmt, ## __VA_ARGS__)
#define COPROC_DEBUG(dev, fmt, ...)                                            \
    coproc_dev_print(dev, XENLOG_DEBUG,   COPROC_DBG_DEBUG, fmt, ## __VA_ARGS__)
#define COPROC_VERBOSE(dev, fmt, ...)                                            \
    coproc_dev_print(dev, XENLOG_DEBUG,   COPROC_DBG_VERB, fmt, ## __VA_ARGS__)

void coproc_init(void);
struct coproc_device * coproc_alloc(struct dt_device_node *,
                                    const struct coproc_ops *);
int coproc_register(struct coproc_device *);
void coproc_release(struct coproc_device *);
struct vcoproc_instance *coproc_get_vcoproc(struct domain *,
                                            struct coproc_device *);
int vcoproc_domain_init(struct domain *);
void vcoproc_domain_free(struct domain *);
int coproc_do_domctl(struct xen_domctl *, struct domain *,
                     XEN_GUEST_HANDLE_PARAM(xen_domctl_t));
bool_t coproc_is_attached_to_domain(struct domain *, const char *);
void vcoproc_continue_running(struct vcoproc_instance *);
int coproc_release_vcoprocs(struct domain *);

#define dev_path(dev) dt_node_full_name(dev_to_dt(dev))

static inline void vcoproc_get_rw_context(struct domain *d, struct mmio *mmio,
                                          mmio_info_t *info,
                                          struct vcoproc_rw_context *ctx)
{
    ctx->coproc = mmio->coproc;
    ctx->dabt = info->dabt;
    ctx->offset = info->gpa - mmio->addr;
    ctx->vcoproc = coproc_get_vcoproc(d, ctx->coproc);
    BUG_ON(ctx->vcoproc == NULL);
}

/* time slice for this vcoproc has finished, save context and pause:
 * return value:
 *    0 - on success
 *   >0 - if more time is needed: time in ms that vcoproc still needs
 *        before next attempt to switch context should be made
 *   <0 - unrecoverable failure: no future context switches are possible,
 *        coproc must be considered as non-functional
 */
static inline s_time_t vcoproc_context_switch_from(struct vcoproc_instance *vcoproc)
{
    ASSERT(vcoproc);
    return vcoproc->coproc->ops->ctx_switch_from(vcoproc);
}

/* new vcoproc has time slice, restore context and unpause:
 * return value:
 *    0 - on success
 *   <0 - unrecoverable failure: no future context switches are possible,
 *        coproc must be considered as non-functional
 */
static inline int vcoproc_context_switch_to(struct vcoproc_instance *vcoproc)
{
    ASSERT(vcoproc);
    return vcoproc->coproc->ops->ctx_switch_to(vcoproc);
}

#endif /* __ARCH_ARM_COPROC_COPROC_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
