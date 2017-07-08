/*
 * Code to interact with a coproc device described as a device tree node
 *
 * Oleksandr Tyshchenko <Oleksandr_Tyshchenko@epam.com>
 * Copyright (C) 2017 EPAM Systems Inc.
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

#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/guest_access.h>
#include <xen/iommu.h>
#include <xen/device_tree.h>
#include <xsm/xsm.h>

int iommu_assign_coproc(struct domain *d, struct dt_device_node *dev)
{
    const struct domain_iommu *hd = dom_iommu(d);
    int rc;

    if ( !iommu_enabled || !hd->platform_ops ||
         !hd->platform_ops->assign_coproc )
        return -EINVAL;

    if ( !dt_device_is_protected(dev) )
        return -EINVAL;

    if ( !dt_device_for_coproc(dev) )
        return -EINVAL;

    if ( need_iommu(d) <= 0 )
    {
        /*
         * The hwdom is forced to use IOMMU for protecting assigned
         * device. Therefore the IOMMU data is already set up.
         */
        ASSERT(!is_hardware_domain(d));
        rc = iommu_construct(d);
        if ( rc )
            return rc;
    }

    return hd->platform_ops->assign_coproc(d, dt_to_dev(dev));
}

int iommu_deassign_coproc(struct domain *d, struct dt_device_node *dev)
{
    const struct domain_iommu *hd = dom_iommu(d);

    if ( !iommu_enabled || !hd->platform_ops ||
         !hd->platform_ops->deassign_coproc )
        return -EINVAL;

    if ( !dt_device_is_protected(dev) )
        return -EINVAL;

    if ( !dt_device_for_coproc(dev) )
        return -EINVAL;

    return hd->platform_ops->deassign_coproc(d, dt_to_dev(dev));
}

int iommu_disable_coproc(struct domain *d, struct dt_device_node *dev)
{
    const struct domain_iommu *hd = dom_iommu(d);

    if ( !iommu_enabled || !hd->platform_ops ||
         !hd->platform_ops->disable_coproc )
        return -EINVAL;

    return hd->platform_ops->disable_coproc(d, dt_to_dev(dev));
}

int iommu_enable_coproc(struct domain *d, struct dt_device_node *dev)
{
    const struct domain_iommu *hd = dom_iommu(d);

    if ( !iommu_enabled || !hd->platform_ops ||
         !hd->platform_ops->enable_coproc )
        return -EINVAL;

    return hd->platform_ops->enable_coproc(d, dt_to_dev(dev));
}
