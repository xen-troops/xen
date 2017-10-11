/*
 * xen/include/asm-arm/tee/tee.h
 *
 * Generic part of TEE mediator subsystem
 *
 * Volodymyr Babchuk <volodymyr_babchuk@epam.com>
 * Copyright (c) 2018 EPAM Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __ARCH_ARM_TEE_TEE_H__
#define __ARCH_ARM_TEE_TEE_H__

#include <xen/lib.h>
#include <xen/types.h>
#include <asm/regs.h>

#ifdef CONFIG_TEE

struct tee_mediator_ops {
    /*
     * Probe for TEE. Should return true if TEE found and
     * mediator is initialized.
     */
    bool (*probe)(void);

    /*
     * Called during domain construction if toolstack requests to enable
     * TEE support so mediator can inform TEE about new
     * guest and create own structures for the new domain.
     */
    int (*enable)(struct domain *d);

    /*
     * Called during domain destruction to inform TEE that guest is now dead
     * and to destroy all resources allocated for the domain being destroyed.
     */
    void (*domain_destroy)(struct domain *d);

    /* Handle SMCCC call for current domain. */
    bool (*handle_call)(struct cpu_user_regs *regs);
};

struct tee_mediator_desc {
    /* Name of the TEE. Just for debugging purposes. */
    const char *name;

    /* Mediator callbacks as described above. */
    const struct tee_mediator_ops *ops;
};

bool tee_handle_call(struct cpu_user_regs *regs);
int tee_enable(struct domain *d);
void tee_domain_destroy(struct domain *d);

#define REGISTER_TEE_MEDIATOR(_name, _namestr, _ops)          \
static const struct tee_mediator_desc __tee_desc_##_name __used     \
__section(".teemediator.info") = {                                  \
    .name = _namestr,                                               \
    .ops = _ops                                                     \
}

#else

static inline bool tee_handle_call(struct cpu_user_regs *regs)
{
    return false;
}

static inline int tee_enable(struct domain *d)
{
    return -ENODEV;
}

static inline void tee_domain_destroy(struct domain *d) {}

#endif  /* CONFIG_TEE */

#endif /* __ARCH_ARM_TEE_TEE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
