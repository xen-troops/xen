/*
 * Copyright (C) 2020 Arm Ltd.
 *
 * Based on Linux drivers/pci/controller/pci-host-common.c
 * Based on Linux drivers/pci/controller/pci-host-generic.c
 * Copyright (C) 2014 ARM Limited Will Deacon <will.deacon@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/device.h>
#include <asm/io.h>
#include <xen/pci.h>
#include <asm/pci.h>

/*
 * Function to get the config space base.
 */
static void __iomem *pci_config_base(struct pci_host_bridge *bridge,
        uint32_t sbdf, int where)
{
    struct pci_config_window *cfg = bridge->sysdata;
    unsigned int devfn_shift = cfg->ops->bus_shift - 8;

    pci_sbdf_t sbdf_t = (pci_sbdf_t) sbdf ;

    unsigned int busn = sbdf_t.bus;
    void __iomem *base;

    if ( busn < cfg->busn_start || busn > cfg->busn_end )
        return NULL;

    base = cfg->win + (busn << cfg->ops->bus_shift);

    return base + (PCI_DEVFN(sbdf_t.dev, sbdf_t.fn) << devfn_shift) + where;
}

int pci_ecam_config_write(struct pci_host_bridge *bridge, uint32_t sbdf,
        int where, int size, u32 val)
{
    void __iomem *addr;

    addr = pci_config_base(bridge, sbdf, where);
    if ( !addr )
        return -ENODEV;

    if ( size == 1 )
        writeb(val, addr);
    else if ( size == 2 )
        writew(val, addr);
    else
        writel(val, addr);

    return 0;
}

int pci_ecam_config_read(struct pci_host_bridge *bridge, uint32_t sbdf,
        int where, int size, u32 *val)
{
    void __iomem *addr;

    addr = pci_config_base(bridge, sbdf, where);
    if ( !addr ) {
        *val = ~0;
        return -ENODEV;
    }

    if ( size == 1 )
        *val = readb(addr);
    else if ( size == 2 )
        *val = readw(addr);
    else
        *val = readl(addr);

    return 0;
}

/* ECAM ops */
struct pci_ecam_ops pci_generic_ecam_ops = {
    .bus_shift  = 20,
    .pci_ops    = {
        .read       = pci_ecam_config_read,
        .write      = pci_ecam_config_write,
    }
};

static const struct dt_device_match gen_pci_dt_match[] = {
    { .compatible = "pci-host-ecam-generic",
      .data =       &pci_generic_ecam_ops },

    { },
};

static int gen_pci_dt_init(struct dt_device_node *dev, const void *data)
{
    const struct dt_device_match *of_id;
    struct pci_ecam_ops *ops;

    of_id = dt_match_node(gen_pci_dt_match, dev->dev.of_node);
    ops = (struct pci_ecam_ops *) of_id->data;

    printk(XENLOG_INFO "Found PCI host bridge %s compatible:%s \n",
            dt_node_full_name(dev), of_id->compatible);

    return pci_host_common_probe(dev, ops);
}

DT_DEVICE_START(pci_gen, "PCI HOST GENERIC", DEVICE_PCI)
.dt_match = gen_pci_dt_match,
.init = gen_pci_dt_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
