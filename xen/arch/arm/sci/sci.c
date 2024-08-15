/*
 * xen/arch/arm/sci/sci.c
 *
 * Generic part of SCI mediator driver
 *
 * Oleksii Moisieiev <oleksii_moisieiev@epam.com>
 * Copyright (C) 2021, EPAM Systems.
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

#include <xen/acpi.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/types.h>

#include <asm/sci/sci.h>

extern const struct sci_mediator_desc _sscimediator[], _escimediator[];
static const struct sci_mediator_desc __read_mostly *cur_mediator;

bool sci_handle_call(struct domain *d, void *args)
{
    if ( unlikely(!cur_mediator) )
        return false;

    return cur_mediator->ops->handle_call(d, args);
}

int sci_domain_init(struct domain *d, uint16_t sci_type,
                    struct xen_arch_domainconfig *config)
{
    if ( sci_type == XEN_DOMCTL_CONFIG_ARM_SCI_NONE )
        return 0;

    if ( !cur_mediator )
        return -ENODEV;

    if ( cur_mediator->sci_type != sci_type )
        return -EINVAL;

    return cur_mediator->ops->domain_init(d, config);
}

void sci_domain_destroy(struct domain *d)
{
    if ( !cur_mediator )
        return;

    cur_mediator->ops->domain_destroy(d);
}

int sci_relinquish_resources(struct domain *d)
{
    if ( !cur_mediator )
        return 0;

    return cur_mediator->ops->relinquish_resources(d);
}

uint16_t sci_get_type(void)
{
    if ( !cur_mediator )
        return XEN_DOMCTL_CONFIG_ARM_SCI_NONE;

    return cur_mediator->sci_type;
}

static int __init sci_init(void)
{
    const struct sci_mediator_desc *desc;
    struct dt_device_node *dt = NULL;


    for ( desc = _sscimediator; desc != _escimediator; desc++ )
    {
        if ( acpi_disabled )
        {
            dt = dt_find_matching_node(dt_host, desc->dt_match);
            if ( !dt )
                continue;
        }

        if ( desc->ops->probe(dt) )
        {
            printk(XENLOG_INFO "Using SCI mediator for %s\n", desc->name);
            cur_mediator = desc;
            return 0;
        }
    }

    return 0;
}

__initcall(sci_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
