/*
 * xen/drivers/passthrough/arm/iommu_helpers.c
 *
 * Contains various helpers to be used by IOMMU drivers.
 *
 * Based on Xen's SMMU driver:
 *    xen/drivers/passthrough/arm/smmu.c
 *
 * Copyright (C) 2014 Linaro Limited.
 *
 * Copyright (C) 2019 EPAM Systems Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/iommu.h>
#include <xen/lib.h>
#include <xen/sched.h>

#include <asm/device.h>
#include <asm/iommu_fwspec.h>

/* Should only be used if P2M Table is shared between the CPU and the IOMMU. */
int __must_check arm_iommu_map_page(struct domain *d, dfn_t dfn, mfn_t mfn,
                                    unsigned int flags,
                                    unsigned int *flush_flags)
{
    p2m_type_t t;

    /*
     * Grant mappings can be used for DMA requests. The dev_bus_addr
     * returned by the hypercall is the MFN (not the IPA). For device
     * protected by an IOMMU, Xen needs to add a 1:1 mapping in the domain
     * p2m to allow DMA request to work.
     * This is only valid when the domain is directed mapped. Hence this
     * function should only be used by gnttab code with gfn == mfn == dfn.
     */
    BUG_ON(!is_domain_direct_mapped(d));
    BUG_ON(mfn_x(mfn) != dfn_x(dfn));

    /* We only support readable and writable flags */
    if ( !(flags & (IOMMUF_readable | IOMMUF_writable)) )
        return -EINVAL;

    t = (flags & IOMMUF_writable) ? p2m_iommu_map_rw : p2m_iommu_map_ro;

    /*
     * The function guest_physmap_add_entry replaces the current mapping
     * if there is already one...
     */
    return guest_physmap_add_entry(d, _gfn(dfn_x(dfn)), _mfn(dfn_x(dfn)), 0, t);
}

/* Should only be used if P2M Table is shared between the CPU and the IOMMU. */
int __must_check arm_iommu_unmap_page(struct domain *d, dfn_t dfn,
                                      unsigned int *flush_flags)
{
    /*
     * This function should only be used by gnttab code when the domain
     * is direct mapped (i.e. gfn == mfn == dfn).
     */
    if ( !is_domain_direct_mapped(d) )
        return -EINVAL;

    return guest_physmap_remove_page(d, _gfn(dfn_x(dfn)), _mfn(dfn_x(dfn)), 0);
}

#ifdef CONFIG_HAS_PCI
int arm_pci_iommu_map_rid(struct dt_device_node *np, u32 rid,
        const char *map_name, const char *map_mask_name,
        struct dt_device_node **target, u32 *id_out)
{
    u32 map_mask, masked_rid;
    u32 map_len;
    const __be32 *map = NULL;

    if ( !np || !map_name || (!target && !id_out))
        return -EINVAL;

    map = dt_get_property(np, map_name, &map_len);
    if ( !map )
    {
        if ( target )
            return -ENODEV;

        /* Otherwise, no map implies no translation */
        *id_out = rid;

        return 0;
    }

    if ( !map_len || map_len % (4 * sizeof(*map)) )
    {
        printk("%pOF: Error: Bad %s length: %d\n", np, map_name, map_len);
        return -EINVAL;
    }

    /* The default is to select all bits. */
    map_mask = 0xffffffff;

    /*
     * Can be overridden by "{iommu,msi}-map-mask" property.
     * If of_property_read_u32() fails, the default is used.
     */
    if ( map_mask_name )
        dt_property_read_u32(np, map_mask_name, &map_mask);

    masked_rid = map_mask & rid;

    for ( ; map_len > 0; map_len -= 4 * sizeof(*map), map += 4 )
    {
        struct dt_device_node *phandle_node = NULL;
        u32 rid_base = be32_to_cpup(map + 0);
        dt_phandle phandle = be32_to_cpup(map + 1);
        u32 out_base = be32_to_cpup(map + 2);
        u32 rid_len = be32_to_cpup(map + 3);

        if ( rid_base & ~map_mask )
        {
            printk("%pOF: Invalid %s translation - %s-mask (0x%x) ignores rid-base (0x%x)\n",
                    np, map_name, map_name, map_mask, rid_base);
            return -EFAULT;
        }

        if ( masked_rid < rid_base || masked_rid >= rid_base + rid_len )
            continue;

        phandle_node = dt_find_node_by_phandle(phandle);
        if ( !phandle_node )
            return -ENODEV;

        if ( target )
        {
            *target = phandle_node;

            if (*target != phandle_node)
                continue;
        }
        if ( id_out )
            *id_out = masked_rid - rid_base + out_base;

        printk("%pOF: %s, using mask %08x, rid-base: %08x, out-base: %08x, length: %08x, rid: %08x -> %08x\n",
                np, map_name, map_mask, rid_base, out_base,
                rid_len, rid, masked_rid - rid_base + out_base);

        return 0;
    }

    printk("%pOF: Invalid %s translation - no match for rid 0x%x on %pOF\n",
            np, map_name, rid, target && *target ? *target : NULL);

    return -EFAULT;
}

int arm_iommu_pci_init(struct pci_dev *pdev, u16 alias, void *data)
{
    const struct iommu_ops *ops = iommu_get_ops();
    struct arm_pci_iommu_alias_info *info = data;
    struct dt_phandle_args iommu_spec = { .args_count = 1 };
    int rc;

    rc = arm_pci_iommu_map_rid(info->np, alias, "iommu-map", "iommu-map-mask",
            &iommu_spec.np,iommu_spec.args);
    if ( rc )
        return rc == -ENODEV ? 1 : rc;

    rc = iommu_fwspec_init(info->dev, &iommu_spec.np->dev);
    if ( rc )
        return rc;

    rc = ops->dt_xlate(info->dev, &iommu_spec);

    return rc;
}

int pci_for_each_dma_alias2(struct pci_dev *pdev,
        int (*fn)(struct pci_dev *pdev, u16 alias,
            void *data), void *data)
{
    int ret = 0;
    u8 seg = pdev->seg, bus = pdev->bus, devfn = pdev->devfn, secbus;

    switch ( pdev->type )
    {
        case DEV_TYPE_PCI_HOST_BRIDGE:
            break;
        case DEV_TYPE_PCIe_BRIDGE:
        case DEV_TYPE_PCIe2PCI_BRIDGE:
        case DEV_TYPE_LEGACY_PCI_BRIDGE:
        case DEV_TYPE_PCIe_ENDPOINT:
            printk("%pd:PCIe_ENDPOINT: map %pp\n",
                    current->domain, &PCI_SBDF3(seg, bus, devfn));
            ret = fn(pdev, PCI_BDF2(bus, devfn), data);

            break;

        case DEV_TYPE_PCI:
            printk("%pd:PCI: map %pp\n",
                    current->domain, &PCI_SBDF3(seg, bus, devfn));

            ret = fn(pdev, PCI_BDF2(bus, devfn), data);

            if ( ret )
                break;

            if ( find_upstream_bridge(seg, &bus, &devfn, &secbus) < 1 )
                break;

            /*
             * Mapping a bridge should, if anything, pass the struct pci_dev of
             * that bridge. Since bridges don't normally get assigned to guests,
             * their owner would be the wrong one. Pass NULL instead.
             */
            ret = fn(pdev, PCI_BDF2(bus, devfn), data);

            /*
             * Devices behind PCIe-to-PCI/PCIx bridge may generate different
             * requester-id. It may originate from devfn=0 on the secondary bus
             * behind the bridge. Map that id as well if we didn't already.
             *
             * Somewhat similar as for bridges, we don't want to pass a struct
             * pci_dev here - there may not even exist one for this (secbus,0,0)
             * tuple. If there is one, without properly working device groups it
             * may again not have the correct owner.
             */
            if ( !ret && pdev_type(seg, bus, devfn) == DEV_TYPE_PCIe2PCI_BRIDGE &&
                    (secbus != pdev->bus || pdev->devfn != 0) )
                ret = fn(pdev, PCI_BDF2(secbus, 0), data);

            break;

        default:
            printk("%pd:unknown(%u): %pp\n",
                    current->domain, pdev->type, &PCI_SBDF3(seg, bus, devfn));
            ret = -EINVAL;
            break;
    }
    return ret;
}
#endif /* CONFIG_HAS_PCI */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
