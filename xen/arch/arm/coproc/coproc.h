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

    const struct vcoproc_domain_ops *ops;
};

struct vcoproc_ops {
    int (*vcoproc_init)(struct domain *, struct coproc_device *);
    void (*vcoproc_free)(struct domain *, struct vcoproc_info *);
};

struct vcoproc_domain_ops {
    int (*domain_init)(struct domain *, struct vcoproc_info *);
    void (*domain_free)(struct domain *, struct vcoproc_info *);
};

void coproc_init(void);
int coproc_register(struct coproc_device *);
int vcoproc_attach(struct domain *, struct vcoproc_info *);
int domain_vcoproc_init(struct domain *);
void domain_vcoproc_free(struct domain *);

#endif /* __COPROC_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
