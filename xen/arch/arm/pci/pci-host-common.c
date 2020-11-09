/*
 * Copyright (C) 2020 Arm Ltd.
 *
 * Based on Linux drivers/pci/ecam.c
 * Copyright 2016 Broadcom.
 *
 * Based on Linux drivers/pci/controller/pci-host-common.c
 * Based on Linux drivers/pci/controller/pci-host-generic.c
 * Copyright (C) 2014 ARM Limited Will Deacon <will.deacon@arm.com>
 *
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
#include <asm/pci.h>
#include <xen/rwlock.h>
#include <xen/vmap.h>

/*
 * List for all the pci host bridges.
 */

static LIST_HEAD(pci_host_bridges);

bool dt_pci_parse_bus_range(struct dt_device_node *dev,
                            struct pci_config_window *cfg)
{
    const __be32 *cells;
    uint32_t len;

    cells = dt_get_property(dev, "bus-range", &len);
    /* bus-range should at least be 2 cells */
    if ( !cells || (len < (sizeof(*cells) * 2)) )
        return false;

    cfg->busn_start = dt_next_cell(1, &cells);
    cfg->busn_end = dt_next_cell(1, &cells);

    return true;
}

static inline void __iomem *pci_remap_cfgspace(paddr_t start, size_t len)
{
    return ioremap_nocache(start, len);
}

static void pci_ecam_free(struct pci_config_window *cfg)
{
    if ( cfg->win )
        iounmap(cfg->win);

    xfree(cfg);
}

static struct pci_config_window *gen_pci_init(struct dt_device_node *dev,
        struct pci_ecam_ops *ops, bool xlnx_nwl)
{
    int err;
    struct pci_config_window *cfg;
    paddr_t addr, size;

    cfg = xzalloc(struct pci_config_window);
    if ( !cfg )
        return NULL;

    err = dt_pci_parse_bus_range(dev, cfg);
    if ( !err ) {
        cfg->busn_start = 0;
        cfg->busn_end = 0xff;
        printk(XENLOG_ERR "No bus range found for pci controller\n");
    } else {
        if ( cfg->busn_end > cfg->busn_start + 0xff )
            cfg->busn_end = cfg->busn_start + 0xff;
    }

    /* Parse our PCI ecam register address*/
    err = dt_device_get_address(dev, 0, &addr, &size);
    if ( err )
        goto err_exit;

    cfg->phys_addr = addr;
    cfg->size = size;
    cfg->ops = ops;

    if ( xlnx_nwl )
    {
        cfg->phys_addr = 0x8000000000;
        cfg->size = 0x1000000;
    }

    /*
     * On 64-bit systems, we do a single ioremap for the whole config space
     * since we have enough virtual address range available.  On 32-bit, we
     * ioremap the config space for each bus individually.
     *
     * As of now only 64-bit is supported 32-bit is not supported.
     */
    cfg->win = pci_remap_cfgspace(cfg->phys_addr, cfg->size);
    if ( !cfg->win )
        goto err_exit_remap;

    printk("ECAM at [mem %lx-%lx] for [bus %x-%x] \n",cfg->phys_addr,
            cfg->phys_addr + cfg->size - 1,cfg->busn_start,cfg->busn_end);

    if ( ops->init ) {
        err = ops->init(cfg);
        if (err)
            goto err_exit;
    }

    return cfg;

err_exit_remap:
    printk(XENLOG_ERR "ECAM ioremap failed\n");
err_exit:
    pci_ecam_free(cfg);
    return NULL;
}

struct pci_host_bridge * pci_alloc_host_bridge(void)
{
    struct pci_host_bridge *bridge = xzalloc(struct pci_host_bridge);

    if ( !bridge )
        return NULL;

    INIT_LIST_HEAD(&bridge->node);
    return bridge;
}

void pci_add_host_bridge(struct pci_host_bridge *bridge)
{
    list_add_tail(&bridge->node, &pci_host_bridges);
}

int pci_host_common_probe(struct dt_device_node *dev,
        struct pci_ecam_ops *ops, bool xlnx_nwl)
{
    struct pci_host_bridge *bridge;
    struct pci_config_window *cfg;
    u32 segment;

    bridge = pci_alloc_host_bridge();
    if ( !bridge )
        return -ENOMEM;

    /* Parse and map our Configuration Space windows */
    cfg = gen_pci_init(dev, ops, xlnx_nwl);
    if ( !cfg )
        return -ENOMEM;

    bridge->dt_node = dev;
    bridge->sysdata = cfg;
    bridge->ops = &ops->pci_ops;

    if( !dt_property_read_u32(dev, "linux,pci-domain", &segment) )
    {
        printk(XENLOG_ERR "\"linux,pci-domain\" property in not available in DT\n");
        if ( !xlnx_nwl )
            return -ENODEV;
        else
            segment = 0;
    }

    bridge->segment = (u16)segment;

    pci_add_host_bridge(bridge);

    return 0;
}

/*
 * This function will lookup an hostbridge based on the segment and bus
 * number.
 */
struct pci_host_bridge *pci_find_host_bridge(uint16_t segment, uint8_t bus)
{
    struct pci_host_bridge *bridge;
    bool found = false;

    list_for_each_entry( bridge, &pci_host_bridges, node )
    {
        if ( bridge->segment != segment )
            continue;

        found = true;
        break;
    }

    return (found) ? bridge : NULL;
}

/*
 * Get host bridge device given a device attached to it.
 */
struct device *pci_find_host_bridge_device(struct device *dev)
{
    struct pci_host_bridge *bridge;
    struct pci_dev *pdev = dev_to_pci(dev);

    bridge = pci_find_host_bridge(pdev->seg, pdev->bus);
    if ( unlikely(!bridge) )
    {
        printk(XENLOG_ERR "Unable to find PCI bridge for "PRI_pci"\n",
               pdev->seg, pdev->bus, pdev->sbdf.dev, pdev->sbdf.fn);
        return NULL;
    }
    return dt_to_dev(bridge->dt_node);
}

int pci_host_iterate_bridges(struct domain *d,
                             int (*clb)(struct domain *d,
                                        struct pci_host_bridge *bridge))
{
    struct pci_host_bridge *bridge;
    int err;

    list_for_each_entry( bridge, &pci_host_bridges, node )
    {
        err = clb(d, bridge);
        if ( err )
            return err;
    }
    return 0;
}

static int pci_host_bridge_update_mapping(struct domain *d,
                                          struct pci_host_bridge *bridge)
{
    if ( !bridge->ops->update_mappings )
        return 0;

    return bridge->ops->update_mappings(d, bridge);
}

int pci_host_bridge_update_mappings(struct domain *d)
{
    return pci_host_iterate_bridges(d, pci_host_bridge_update_mapping);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
