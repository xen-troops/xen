/*
 * xen/arch/arm/vhostbridge.h
 * Copyright (c) 2021 EPAM Systems Inc.
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
 *
 * Code is partially based on QEMU implementation of the PCI host bridge.
 */

#include <xen/pci.h>
#include <xen/sched.h>
#include <xen/vpci.h>

#include "pci-bridge-emul.h"
#include "vhostbridge.h"

struct vhostbridge_priv {
    /* Physical host bridge we are emulating. */
    const struct pci_dev *pdev;
    struct pci_bridge_emul bridge;
    struct domain *d;
    /*
     * Helper variable to track secondary bus changes: registers are often
     * written as 32-bit values and the secondary bus is 8-bit, so not all
     * the register writes at PCI_PRIMARY_BUS change the secondary bus number.
     */
    uint8_t secondary_bus;
};

static pci_bridge_emul_read_status_t
vhostbridge_emul_ops_conf_read(struct pci_bridge_emul *bridge,
                               int reg, u32 *value)
{
    struct vhostbridge_priv *priv = bridge->data;

    priv = priv;
    return PCI_BRIDGE_EMUL_NOT_HANDLED;
}

static void
vhostbridge_emul_ops_conf_write(struct pci_bridge_emul *bridge,
                                int reg, u32 old, u32 new, u32 mask)
{
    struct vhostbridge_priv *priv = bridge->data;

    priv = priv;
}

static void
vhostbridge_emul_ops_conf_write_base(struct pci_bridge_emul *bridge,
                                     int reg, u32 old, u32 new, u32 mask)
{
    struct vhostbridge_priv *priv = bridge->data;

    if ( (reg / 4 == PCI_PRIMARY_BUS / 4) &&
         (bridge->conf.secondary_bus != priv->secondary_bus) )
    {
        pci_set_virtual_device_bus_number(priv->d, 0,
                                          bridge->conf.secondary_bus);
        priv->secondary_bus = bridge->conf.secondary_bus;
    }
}

static struct pci_bridge_emul_ops vhostbridge_emul_ops = {
    .read_pcie = vhostbridge_emul_ops_conf_read,
    .write_pcie = vhostbridge_emul_ops_conf_write,
    .write_base = vhostbridge_emul_ops_conf_write_base,
};

int vhostbridge_init(struct domain *d, const struct pci_dev *pdev)
{
    struct vhostbridge_priv *priv;
    struct pci_bridge_emul *bridge;

    if ( !pdev )
    {
        printk(XENLOG_G_ERR
               "d%d: vhostbridge: Can't find physical PCI host bridge\n",
               d->domain_id);
        return -EINVAL;
    }

    priv = xzalloc(struct vhostbridge_priv);
    if ( !priv )
        return -ENOMEM;

    d->vhostbridge_priv = priv;

    priv->pdev = pdev;
    priv->d = d;

    bridge = &priv->bridge;

    /* XenSource, Inc. */
    bridge->conf.vendor = 0x5853;
    /* 0xc3xx- are not yet assigned - steal one ID. */
    bridge->conf.device = 0xc300;

    /* We support 32 bits I/O addressing */
    bridge->conf.iobase = PCI_IO_RANGE_TYPE_32;
    bridge->conf.iolimit = PCI_IO_RANGE_TYPE_32;

    /* Support 64 bits memory pref */
    bridge->conf.pref_mem_base = cpu_to_le16(PCI_PREF_RANGE_TYPE_64);
    bridge->conf.pref_mem_limit = cpu_to_le16(PCI_PREF_RANGE_TYPE_64);

    bridge->has_pcie = true;
    bridge->data = priv;
    bridge->ops = &vhostbridge_emul_ops;

    pci_bridge_emul_init(bridge, 0);
    return 0;
}

void vhostbridge_fini(struct domain *d)
{
    if ( d->vhostbridge_priv )
    {
        xfree(d->vhostbridge_priv);
        d->vhostbridge_priv = NULL;
    }
}

uint32_t vhostbridge_read(struct domain *d, pci_sbdf_t sbdf, unsigned int reg,
                    unsigned int size)
{
    struct vhostbridge_priv *priv = d->vhostbridge_priv;
    struct pci_bridge_emul *bridge = &priv->bridge;
    uint32_t data;

    if ( pci_bridge_emul_conf_read(bridge, reg, size, &data) )
        data = ~0;
    return data;
}

void vhostbridge_write(struct domain *d, pci_sbdf_t sbdf, unsigned int reg,
                 unsigned int size, uint32_t data)
{
    struct vhostbridge_priv *priv = d->vhostbridge_priv;
    struct pci_bridge_emul *bridge = &priv->bridge;

    if ( pci_bridge_emul_conf_write(bridge, reg, size, data) )
        data = ~0;
}
