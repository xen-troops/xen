/*
 * xen/arch/arm/coproc/plat/platform_device.h
 *
 * Generic platform device
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

#ifndef __ARCH_ARM_COPROC_PLAT_PLATFORM_DEVICE_H__
#define __ARCH_ARM_COPROC_PLAT_PLATFORM_DEVICE_H__

/* Copied from smmu.c */

struct resource
{
    u64 addr;
    u64 size;
    unsigned int type;
};

#define resource_size(res) (res)->size;
#define resource_addr(res) (res)->addr;

#define platform_device dt_device_node

#define IORESOURCE_MEM 0
#define IORESOURCE_IRQ 1

struct resource *platform_get_resource(struct platform_device *pdev,
                                       unsigned int type,
                                       unsigned int num);

void __iomem *devm_ioremap_resource(struct device *dev,
                                    struct resource *res);

/* Device logger functions */
#define dev_print(dev, lvl, fmt, ...) \
    printk(lvl "coproc: %s: " fmt, dt_node_full_name(dev_to_dt(dev)), ## __VA_ARGS__)

#define dev_dbg(dev, fmt, ...) dev_print(dev, XENLOG_DEBUG, fmt, ## __VA_ARGS__)
#define dev_notice(dev, fmt, ...) dev_print(dev, XENLOG_INFO, fmt, ## __VA_ARGS__)
#define dev_warn(dev, fmt, ...) dev_print(dev, XENLOG_WARNING, fmt, ## __VA_ARGS__)
#define dev_err(dev, fmt, ...) dev_print(dev, XENLOG_ERR, fmt, ## __VA_ARGS__)

#define dev_err_ratelimited(dev, fmt, ...) \
    dev_print(dev, XENLOG_ERR, fmt, ## __VA_ARGS__)


#endif /* __ARCH_ARM_COPROC_PLAT_PLATFORM_DEVICE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
