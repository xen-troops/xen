/*
 * xen/arch/arm/tee/tee.c
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

#include <xen/errno.h>
#include <xen/init.h>
#include <xen/types.h>

#include <asm/tee/tee.h>

extern const struct tee_mediator_desc _steemediator[], _eteemediator[];
static const struct tee_mediator_ops *mediator_ops;

bool tee_handle_call(struct cpu_user_regs *regs)
{
    if ( !mediator_ops )
        return false;

    return mediator_ops->handle_call(regs);
}

int tee_domain_init(struct domain *d)
{
    if ( !mediator_ops )
        return -ENODEV;

    return mediator_ops->domain_init(d);
}

int tee_relinquish_resources(struct domain *d)
{
    if ( !mediator_ops )
        return 0;

    return mediator_ops->relinquish_resources(d);
}

void tee_domain_destroy(struct domain *d)
{
    if ( mediator_ops )
        mediator_ops->domain_destroy(d);
}

static int __init tee_init(void)
{
    const struct tee_mediator_desc *desc;

    for ( desc = _steemediator; desc != _eteemediator; desc++ )
    {
        if ( desc->ops->probe() )
        {
            printk(XENLOG_INFO "Using TEE mediator for %s\n", desc->name);
            mediator_ops = desc->ops;
            return 0;
        }
    }

    return 0;
}

__initcall(tee_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
