/*
 * xen/arch/arm/coproc/plat/common.c
 *
 * Common platform code for all Remote processors
 * based on xen/drivers/passthrough/arm/smmu.c
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

#include <xen/err.h>
#include <xen/irq.h>
#include <xen/vmap.h>

#include "common.h"

/* Xen: Helpers to get device MMIO and IRQs */
struct resource *platform_get_resource(struct platform_device *pdev,
                                       unsigned int type,
                                       unsigned int num)
{
    /*
     * The resource is only used between 2 calls of platform_get_resource.
     * It's quite ugly but it's avoid to add too much code in the part
     * imported from Linux
     */
    static struct resource res;
    int ret = 0;

    res.type = type;

    switch ( type )
    {
    case IORESOURCE_MEM:
        ret = dt_device_get_address(pdev, num, &res.addr, &res.size);

    return ( (ret) ? NULL : &res );

    case IORESOURCE_IRQ:
        ret = platform_get_irq(pdev, num);
        if ( ret < 0 )
            return NULL;

        res.addr = ret;
        res.size = 1;

        return &res;

    default:
        return NULL;
    }
}

void __iomem *devm_ioremap_resource(struct device *dev, struct resource *res)
{
    void __iomem *ptr;

    if ( !res || res->type != IORESOURCE_MEM )
    {
        dev_err(dev, "Invalid resource\n");
        return ERR_PTR(-EINVAL);
    }

    ptr = ioremap_nocache(res->addr, res->size);
    if ( !ptr )
    {
        dev_err(dev, "ioremap failed (addr 0x%"PRIx64" size 0x%"PRIx64")\n",
                res->addr, res->size);
        return ERR_PTR(-ENOMEM);
    }

    return ptr;
}
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
