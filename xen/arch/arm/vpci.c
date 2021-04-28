/*
 * xen/arch/arm/vpci.c
 * Copyright (c) 2020 Arm Ltd.
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
#include <xen/sched.h>
#include <asm/mmio.h>

struct vpci_mmio_priv {
    /*
     * Set to true if the MMIO handlers were set up for the emulated
     * ECAM host PCI bridge.
     */
    bool is_virt_ecam;
};

/* Do some sanity checks. */
static bool vpci_mmio_access_allowed(unsigned int reg, unsigned int len)
{
    /* Check access size. */
    if ( len != 1 && len != 2 && len != 4 && len != 8 )
        return false;

    /* Check that access is size aligned. */
    if ( (reg & (len - 1)) )
        return false;

    return true;
}

/*
 * Find a physical device which is mapped to this virtual device.
 */
static bool vpci_mmio_find_pdev(struct vcpu *v, pci_sbdf_t *sbdf)
{
    struct domain *d = v->domain;
    struct vpci_dev *vdev;

    list_for_each_entry ( vdev, &d->vdev_list, list )
    {
        if ( vdev->sbdf.sbdf == sbdf->sbdf )
        {
            /* Replace virtual SBDF with the physical one. */
            *sbdf = vdev->pdev->sbdf;
            return true;
        }
    }
    return false;
}

static int vpci_mmio_read(struct vcpu *v, mmio_info_t *info,
                          register_t *r, void *p)
{
    unsigned int reg;
    pci_sbdf_t sbdf;
    uint32_t data = 0;
    unsigned int size = 1U << info->dabt.size;
    struct vpci_mmio_priv *priv = (struct vpci_mmio_priv *)p;

    sbdf.sbdf = (((info->gpa) & 0x0ffff000) >> 12);
    reg = (((info->gpa) & 0x00000ffc) | (info->gpa & 3));

    if ( !vpci_mmio_access_allowed(reg, size) )
        return 1;

    /*
     * For the passed through devices we need to map their virtual SBDF
     * to the physical PCI device being passed through.
     */
    if ( priv->is_virt_ecam && !vpci_mmio_find_pdev(v, &sbdf) )
            return 1;

    data = vpci_read(sbdf, reg, size);

    memcpy(r, &data, size);

    return 1;
}

static int vpci_mmio_write(struct vcpu *v, mmio_info_t *info,
                           register_t r, void *p)
{
    unsigned int reg;
    pci_sbdf_t sbdf;
    uint32_t data = r;
    unsigned int size = 1U << info->dabt.size;
    struct vpci_mmio_priv *priv = (struct vpci_mmio_priv *)p;

    sbdf.sbdf = (((info->gpa) & 0x0ffff000) >> 12);
    reg = (((info->gpa) & 0x00000ffc) | (info->gpa & 3));

    if ( !vpci_mmio_access_allowed(reg, size) )
        return 1;

    /*
     * For the passed through devices we need to map their virtual SBDF
     * to the physical PCI device being passed through.
     */
    if ( priv->is_virt_ecam && !vpci_mmio_find_pdev(v, &sbdf) )
            return 1;

    vpci_write(sbdf, reg, size, data);

    return 1;
}

static const struct mmio_handler_ops vpci_mmio_handler = {
    .read  = vpci_mmio_read,
    .write = vpci_mmio_write,
};

/*
 * There are three  originators for the PCI configuration space access:
 * 1. The domain that owns physical host bridge: MMIO handlers are
 *    there so we can update vPCI register handlers with the values
 *    written by the hardware domain, e.g. physical view of the registers/
 *    configuration space.
 * 2. Guest access to the passed through PCI devices: we need to properly
 *    map virtual bus topology to the physical one, e.g. pass the configuration
 *    space access to the corresponding physical devices.
 * 3. Emulated host PCI bridge access. It doesn't exist in the physical
 *    topology, e.g. it can't be mapped to some physical host bridge.
 *    So, all access to the host bridge itself needs to be trapped and
 *    emulated.
 */
static int vpci_setup_mmio_handler(struct domain *d,
                                   struct pci_host_bridge *bridge)
{
    struct vpci_mmio_priv *priv;

    priv = xzalloc(struct vpci_mmio_priv);
    if ( !priv )
        return -ENOMEM;
    if ( pci_is_hardware_domain(d, bridge->segment, bridge->bus_start) )
    {
        if ( bridge->ops->register_mmio_handler )
        {
            /* TODO: free memory on bridge destroy */
            bridge->mmio_priv = priv;
            priv->is_virt_ecam = false;
            return bridge->ops->register_mmio_handler(d, bridge,
                                                      &vpci_mmio_handler,
                                                      priv);
        }
    }
    else
    {
        /* TODO: free memory on domain destroy */
        d->vpci_mmio_priv = priv;
        priv->is_virt_ecam = true;
        /* Guest domains use what is programmed in their device tree. */
        register_mmio_handler(d, &vpci_mmio_handler,
                GUEST_VPCI_ECAM_BASE,GUEST_VPCI_ECAM_SIZE, priv);
    }
    return 0;
}

int domain_vpci_init(struct domain *d)
{
    if ( !has_vpci(d) )
        return 0;

    return pci_host_iterate_bridges(d, vpci_setup_mmio_handler);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

