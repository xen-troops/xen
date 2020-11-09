/*
 * Copyright (C) 2020 Arm Ltd.
 *
 * Based on Linux drivers/pci/ecam.c
 * Copyright 2016 Broadcom
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

#include <xen/pci.h>
#include <xen/sched.h>

/*
 * Function to implement the pci_ops ->map_bus method.
 */
void __iomem *pci_ecam_map_bus(struct pci_host_bridge *bridge,
                                      uint32_t sbdf, uint32_t where)
{
    const struct pci_config_window *cfg = bridge->sysdata;
    unsigned int devfn_shift = cfg->ops->bus_shift - 8;
    void __iomem *base;

    pci_sbdf_t sbdf_t = (pci_sbdf_t) sbdf ;
    unsigned int busn = sbdf_t.bus;

    if ( busn < cfg->busn_start || busn > cfg->busn_end )
        return NULL;

    busn -= cfg->busn_start;
    base = cfg->win + (busn << cfg->ops->bus_shift);

    return base + (PCI_DEVFN(sbdf_t.dev, sbdf_t.fn) << devfn_shift) + where;
}

static int pci_ecam_register_mmio_handler(struct domain *d,
                                          struct pci_host_bridge *bridge,
                                          const struct mmio_handler_ops *ops)
{
    struct pci_config_window *cfg = bridge->sysdata;

    register_mmio_handler(d, ops, cfg->phys_addr, cfg->size, NULL);
    return 0;
}

static int pci_ecam_need_mapping(struct domain *d,
                                 struct pci_host_bridge *bridge,
                                 u64 addr, u64 len)
{
    struct pci_config_window *cfg = bridge->sysdata;

    /* Only check for control domain which owns HW PCI host bridge. */
    if ( !is_control_domain(d) )
        return true;

    return cfg->phys_addr != addr;
}

/* ECAM ops */
const struct pci_ecam_ops pci_generic_ecam_ops = {
    .bus_shift  = 20,
    .pci_ops    = {
        .map_bus                = pci_ecam_map_bus,
        .read                   = pci_generic_config_read,
        .write                  = pci_generic_config_write,
        .register_mmio_handler  = pci_ecam_register_mmio_handler,
        .need_mapping           = pci_ecam_need_mapping,
    }
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
