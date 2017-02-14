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

/*
 * In fields and function names following prefixes mean:
 * - [p] Platform specific. Means coprocessor IP specific stuff.
 * - [m] Machine specific. Means some stuff specific to a SoC which integrates
 *       a coprocessor.
 * - [v] Virtual. Means a virtual coprocessor related stuff.
 */

/*
 * Coprocessor platform memory mapped IO range description
 *
 * This is a structure what describes one particular mmio range of a
 * coprocessor IP block.
 * This description expected to be common for different SoCs which could
 * integrate this particular coprocessor IP.
 * This structure is used as static with following fields initialized at the
 * compilation time:
 *     name - to find in DT, ignored if a coproc has only one mmio range
 *     size - >0 for sanity check, =0 - no sanity check needed, filled from DT
 *               (f.e. for SRAM bank)
 *     ops  - IO registers access emulation (r/w) handlers
 */
struct pcoproc_mmio {
    const char *name;
    u64 size;
    struct mmio_handler_ops *ops;
};

/*
 * Coprocessor platform IRQ description
 *
 * This is a structure what describes one particular IRQ of a coprocessor IP
 * block. This description is expected to be common for different SoCs which
 * could integrate this particular coprocessor IP.
 * This structure is used as static with following fields initialized at the
 * compilation time:
 *     name - to find in DT, ignored if a coproc has only one IRQ
 *     handler - irq handler function aware of this particular IRQ functionality
 */
struct pcoproc_irq {
    const char *name;
    void (*handler)(int, void *, struct cpu_user_regs *);
};

/*
 * Coprocessor platform description
 * A structure what gathers coproc description (irq and mmio so far)
 */
struct pcoproc_desc {
    u32 p_mmio_num;
    struct pcoproc_mmio *p_mmio;
    u32 p_irq_num;
    struct pcoproc_irq *p_irq;
};

/*
 * Coprocessor machine IO memory range
 * This structure is initialized on dt parsing for each io range found for a
 * coprocessor
 */
struct mcoproc_mmio {
    /* iorange machine base address, taken from a device-tree by name */
    u64 addr;
    /* mmio range size from dt */
    u64 size;
    /* ioremapped base address, mapped on coproc iniitalization */
    void __iomem *base;
    /* pointer to a correspondent platform mmio range description */
    struct pcoproc_mmio *p_mmio;
};

/*
 * Coprocessor machine IRQ
 * This structure is initialized on dt parsing for each irq found for a
 * coprocessor.
 * An interrupt handler receives a triggered irq number and this seems to be
 * enough to inject an interrupt to a domain.
 * This description will be used in cases when we need to inject an interrupt
 * manually (without receiving it from HW).
 */
struct mcoproc_irq {
    /* actual IRQ number */
    int irq; 
    /* pointer to a correspondent platform IRQ description */
    struct pcoproc_irq *p_irq;
};

/*
 * Virtual coprocessor's IO memory range
 * This structure reflects how the coproc's specific mmio is mapped in this
 * particular domain for this unique vcoproc device
 */
struct vcoproc_mmio {
    /* address to which mmio range is mapped within a specific domain */
    u64 addr;
    /* link to a specific regs io range of the coproc */
    struct mcoproc_mmio *m_mmio;
     /* unique vcoproc device which corresponds to the domain of this vmmio */
    struct vcoproc_instance *vcoproc;
};

/*
 * Currently IRQ remapping is not supported by XEN so we do not define specific
 * v_ interrupt description.
 */

/* machine specific coproc device */
struct mcoproc_device {
    struct device *dev;

    /* the number of memory ranges for this coproc */
    u32 num_mmios;
    /* the array of memory ranges for this coproc */
    struct mcoproc_mmio *mmios;
    /* the number of irqs for this coproc */
    u32 num_irqs;
    /* the array of irqs for this coproc */
    struct mcoproc_irq *irqs;

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
    struct mcoproc_device *mcoproc;
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

    /* the number of memory ranges for this vcoproc */
    u32 num_mmios;
    /* the array of memory ranges for this vcoproc */
    struct vcoproc_mmio *mmios;

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
               (dev) ? dt_node_full_name(dev_to_dt(dev)) : "",                 \
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
#define COPROC_VERBOSE(dev, fmt, ...)                                          \
    coproc_dev_print(dev, XENLOG_DEBUG,   COPROC_DBG_VERB, fmt, ## __VA_ARGS__)

void coproc_init(void);
struct mcoproc_device * coproc_alloc(struct dt_device_node *,
                                     const struct pcoproc_desc *,
                                     const struct coproc_ops *);
int coproc_register(struct mcoproc_device *);
void coproc_release(struct mcoproc_device *);
int vcoproc_domain_init(struct domain *);
void vcoproc_domain_free(struct domain *);
int coproc_do_domctl(struct xen_domctl *, struct domain *,
                     XEN_GUEST_HANDLE_PARAM(xen_domctl_t));
void vcoproc_continue_running(struct vcoproc_instance *);
int coproc_release_vcoprocs(struct domain *);
int vcoproc_handle_node(struct domain *, void *, const struct dt_device_node *);

#define dev_path(dev) dt_node_full_name(dev_to_dt(dev))

static inline void
vcoproc_get_rw_context(struct domain *d, struct vcoproc_mmio *v_mmio,
                       mmio_info_t *info, struct vcoproc_rw_context *ctx)
{
    ctx->dabt = info->dabt;
    ctx->offset = info->gpa - v_mmio->addr;
    ctx->vcoproc = v_mmio->vcoproc;
}

/*
 * time slice for this vcoproc has finished, save context and pause:
 * return value:
 *    0 - on success
 *   >0 - if more time is needed: time in ms that vcoproc still needs
 *        before next attempt to switch context should be made
 *   <0 - unrecoverable failure: no future context switches are possible,
 *        coproc must be considered as non-functional
 */
static inline s_time_t
vcoproc_context_switch_from(struct vcoproc_instance *vcoproc)
{
    ASSERT(vcoproc);
    return vcoproc->mcoproc->ops->ctx_switch_from(vcoproc);
}

/*
 * new vcoproc has time slice, restore context and unpause:
 * return value:
 *    0 - on success
 *   <0 - unrecoverable failure: no future context switches are possible,
 *        coproc must be considered as non-functional
 */
static inline int vcoproc_context_switch_to(struct vcoproc_instance *vcoproc)
{
    ASSERT(vcoproc);
    return vcoproc->mcoproc->ops->ctx_switch_to(vcoproc);
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
