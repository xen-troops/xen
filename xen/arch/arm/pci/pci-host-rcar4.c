/*
 * Based on Linux drivers/pci/controller/pci-host-common.c
 * Based on Linux drivers/pci/controller/pci-host-generic.c
 * Based on xen/arch/arm/pci/pci-host-generic.c
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

#include <xen/init.h>
#include <xen/pci.h>
#include <asm/device.h>
#include <asm/pci.h>

/*
 * PCI host bridges often have different ways to access the root and child
 * bus config spaces:
 *   "dbi"   : the aperture where root port's own configuration registers
 *             are available.
 *   "config": child's configuration space
 */
static int __init rcar4_cfg_reg_index(struct dt_device_node *np)
{
    return dt_property_match_string(np, "reg-names", "dbi");
}

static int __init rcar4_child_cfg_reg_index(struct dt_device_node *np)
{
    return dt_property_match_string(np, "reg-names", "config");
}

/* ECAM ops */
const struct pci_ecam_ops rcar4_pcie_ops = {
    .bus_shift  = 20,
    .cfg_reg_index = rcar4_cfg_reg_index,
    .pci_ops    = {
        .map_bus                = pci_ecam_map_bus,
        .read                   = pci_generic_config_read,
        .write                  = pci_generic_config_write,
        .need_p2m_hwdom_mapping = pci_ecam_need_p2m_hwdom_mapping,
    }
};

static void __iomem *rcar4_child_map_bus(struct pci_host_bridge *bridge,
                                         pci_sbdf_t sbdf, uint32_t where)
{
    return pci_ecam_map_bus(bridge, sbdf, where);
}

static int rcar4_child_config_read(struct pci_host_bridge *bridge,
                                   pci_sbdf_t sbdf, uint32_t reg,
                                   uint32_t len, uint32_t *value)
{
    return pci_generic_config_read(bridge, sbdf, reg, len, value);
}

static int rcar4_child_config_write(struct pci_host_bridge *bridge,
                                    pci_sbdf_t sbdf, uint32_t reg,
                                    uint32_t len, uint32_t value)
{
    return pci_generic_config_write(bridge, sbdf, reg, len, value);
}

bool __init rcar4_child_need_p2m_hwdom_mapping(struct domain *d,
                                               struct pci_host_bridge *bridge,
                                               uint64_t addr)
{
    struct pci_config_window *cfg = bridge->child_cfg;

    /*
     * We do not want ECAM address space to be mapped in Domain-0's p2m,
     * so we can trap access to it.
     */
    return cfg->phys_addr != addr;
}

const struct pci_ecam_ops rcar4_pcie_child_ops = {
    .bus_shift  = 20,
    .cfg_reg_index = rcar4_child_cfg_reg_index,
    .pci_ops    = {
        .map_bus                = rcar4_child_map_bus,
        .read                   = rcar4_child_config_read,
        .write                  = rcar4_child_config_write,
        .need_p2m_hwdom_mapping = rcar4_child_need_p2m_hwdom_mapping,
    }
};

static const struct dt_device_match __initconstrel rcar4_pcie_dt_match[] =
{
    { .compatible = "renesas,r8a779f0-pcie" },
    { },
};

static int __init pci_host_generic_probe(struct dt_device_node *dev,
                                         const void *data)
{
    return PTR_RET(pci_host_common_probe(dev, &rcar4_pcie_ops,
                   &rcar4_pcie_child_ops, 0));
}

DT_DEVICE_START(pci_gen, "PCI HOST R-CAR GEN4", DEVICE_PCI_HOSTBRIDGE)
.dt_match = rcar4_pcie_dt_match,
.init = pci_host_generic_probe,
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
