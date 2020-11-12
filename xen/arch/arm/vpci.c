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

static int vpci_mmio_read(struct vcpu *v, mmio_info_t *info,
        register_t *r, void *priv)
{
    unsigned int reg;
    pci_sbdf_t sbdf;
    uint32_t data = 0;
    unsigned int size = 1U << info->dabt.size;

    sbdf.bdf = (((info->gpa) & 0x0ffff000) >> 12);
    reg = (((info->gpa) & 0x00000ffc) | (info->gpa & 3));

    if ( !vpci_mmio_access_allowed(reg, size) )
        return 1;

    data = vpci_read(sbdf, reg, size);

    memcpy(r, &data, size);

    return 1;
}

static int vpci_mmio_write(struct vcpu *v, mmio_info_t *info,
        register_t r, void *priv)
{
    unsigned int reg;
    pci_sbdf_t sbdf;
    uint32_t data = r;
    unsigned int size = 1U << info->dabt.size;

    sbdf.bdf = (((info->gpa) & 0x0ffff000) >> 12);
    reg = (((info->gpa) & 0x00000ffc) | (info->gpa & 3));

    if ( !vpci_mmio_access_allowed(reg, size) )
        return 1;

    vpci_write(sbdf, reg, size, data);

    return 1;
}

static const struct mmio_handler_ops vpci_mmio_handler = {
    .read  = vpci_mmio_read,
    .write = vpci_mmio_write,
};

extern bool pci_under_qemu;

static int vpci_setup_mmio_handler(struct domain *d,
                                   struct pci_host_bridge *bridge)
{
#if 0
    if ( pci_is_hardware_domain(d, bridge->segment, bridge->bus_start) )
#else
    if ( pci_under_qemu ? pci_is_hardware_domain(d, bridge->segment,
                                                 bridge->bus_start) : false )
#endif
    {
        if ( bridge->ops->register_mmio_handler )
            return bridge->ops->register_mmio_handler(d, bridge,
                                                      &vpci_mmio_handler);
    }
    else
    {
        /* Guest domains use what is programmed in their device tree. */
        register_mmio_handler(d, &vpci_mmio_handler,
                GUEST_VPCI_ECAM_BASE,GUEST_VPCI_ECAM_SIZE,NULL);
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

