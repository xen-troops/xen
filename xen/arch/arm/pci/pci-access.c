/*
 * Copyright (C) 2020 Arm Ltd.
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

static uint32_t pci_config_read(pci_sbdf_t sbdf, unsigned int reg,
                            unsigned int len)
{
    int rc;
    uint32_t val = GENMASK(0, len * 8);

    struct pci_host_bridge *bridge = pci_find_host_bridge(sbdf.seg, sbdf.bus);

    if ( unlikely(!bridge) )
    {
        printk(XENLOG_ERR "Unable to find bridge for "PRI_pci"\n",
                sbdf.seg, sbdf.bus, sbdf.dev, sbdf.fn);
        return val;
    }

    if ( unlikely(!bridge->ops->read) )
        return val;

    rc = bridge->ops->read(bridge, (uint32_t) sbdf.sbdf, reg, len, &val);
    if ( rc )
        printk(XENLOG_ERR "Failed to read reg %#x len %u for "PRI_pci"\n",
                reg, len, sbdf.seg, sbdf.bus, sbdf.dev, sbdf.fn);

    return val;
}

static void pci_config_write(pci_sbdf_t sbdf, unsigned int reg,
        unsigned int len, uint32_t val)
{
    int rc;
    struct pci_host_bridge *bridge = pci_find_host_bridge(sbdf.seg, sbdf.bus);

    if ( unlikely(!bridge) )
    {
        printk(XENLOG_ERR "Unable to find bridge for "PRI_pci"\n",
                sbdf.seg, sbdf.bus, sbdf.dev, sbdf.fn);
        return;
    }

    if ( unlikely(!bridge->ops->write) )
        return;

    rc = bridge->ops->write(bridge, (uint32_t) sbdf.sbdf, reg, len, val);
    if ( rc )
        printk(XENLOG_ERR "Failed to write reg %#x len %u for "PRI_pci"\n",
                reg, len, sbdf.seg, sbdf.bus, sbdf.dev, sbdf.fn);
}

/*
 * Wrappers for all PCI configuration access functions.
 */

#define PCI_OP_WRITE(size, type) \
    void pci_conf_write##size (pci_sbdf_t sbdf,unsigned int reg, type val) \
{                                               \
    pci_config_write(sbdf, reg, size / 8, val);     \
}

#define PCI_OP_READ(size, type) \
    type pci_conf_read##size (pci_sbdf_t sbdf, unsigned int reg)  \
{                                               \
    return pci_config_read(sbdf, reg, size / 8);     \
}

PCI_OP_READ(8, u8)
PCI_OP_READ(16, u16)
PCI_OP_READ(32, u32)
PCI_OP_WRITE(8, u8)
PCI_OP_WRITE(16, u16)
PCI_OP_WRITE(32, u32)

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
