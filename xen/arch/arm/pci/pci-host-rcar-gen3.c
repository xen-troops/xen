/*
 * Copyright (C) 2020 EPAM Systems Inc.
 *
 * Based on Linux drivers/pci/host/pcie-rcar.c
 * PCIe driver for Renesas R-Car SoCs
 *  Copyright (C) 2014 Renesas Electronics Europe Ltd
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
#include <xen/vmap.h>

/* Error values that may be returned by PCI functions */
#define PCIBIOS_SUCCESSFUL		0x00
#define PCIBIOS_FUNC_NOT_SUPPORTED	0x81
#define PCIBIOS_BAD_VENDOR_ID		0x83
#define PCIBIOS_DEVICE_NOT_FOUND	0x86
#define PCIBIOS_BAD_REGISTER_NUMBER	0x87
#define PCIBIOS_SET_FAILED		0x88
#define PCIBIOS_BUFFER_TOO_SMALL	0x89

#undef BIT
#define BIT(nr)                 (1UL << (nr))

#define PCIECAR			0x000010
#define PCIECCTLR		0x000018
#define  CONFIG_SEND_ENABLE	BIT(31)
#define  TYPE0			(0 << 8)
#define  TYPE1			BIT(8)
#define PCIECDR			0x000020
#define PCIEMSR			0x000028
#define PCIEINTXR		0x000400
#define PCIEPHYSR		0x0007f0
#define  PHYRDY			BIT(0)
#define PCIEMSITXR		0x000840

/* Transfer control */
#define PCIETCTLR		0x02000
#define  CFINIT			1
#define PCIETSTR		0x02004
#define  DATA_LINK_ACTIVE	1
#define PCIEERRFR		0x02020
#define  UNSUPPORTED_REQUEST	BIT(4)
#define PCIEMSIFR		0x02044
#define PCIEMSIALR		0x02048
#define  MSIFE			1
#define PCIEMSIAUR		0x0204c
#define PCIEMSIIER		0x02050

/* Configuration */
#define PCICONF(x)		(0x010000 + ((x) * 0x4))

#define RCONF(x)		(PCICONF(0) + (x))

/* Access sizes for PCI reads and writes */
enum pci_size_t
{
    PCI_SIZE_8,
    PCI_SIZE_16,
    PCI_SIZE_32,
};

enum {
    RCAR_PCI_ACCESS_READ,
    RCAR_PCI_ACCESS_WRITE,
};

#define clrbits_le32(addr, clear) writel((readl(addr) & ~(clear)), (addr))

uint32_t pci_conv_32_to_size(uint32_t value, uint32_t offset,
                             enum pci_size_t size)
{
    switch (size)
    {
    case PCI_SIZE_8:
        return (value >> ((offset & 3) * 8)) & 0xff;
    case PCI_SIZE_16:
        return (value >> ((offset & 2) * 8)) & 0xffff;
    default:
        return value;
    }
}

int pci_get_ff(enum pci_size_t size)
{
    switch (size)
    {
    case PCI_SIZE_8:
        return 0xff;
    case PCI_SIZE_16:
        return 0xffff;
    default:
        return 0xffffffff;
    }
}

static unsigned long rcar_pci_read_reg(struct pci_host_bridge *bridge,
                                       unsigned long reg)
{
    struct pci_config_window *cfg = bridge->sysdata;

    /* cfg->win is a remapped reg from devtree */
    return readl(cfg->win + reg);
}

static void rcar_pci_write_reg(struct pci_host_bridge *bridge,
                               unsigned long val, unsigned long reg)
{
    struct pci_config_window *cfg = bridge->sysdata;

    writel(val, cfg->win + reg);
}

static u32 rcar_read_conf(struct pci_host_bridge *bridge, int where)
{
    int shift = 8 * (where & 3);
    u32 val = rcar_pci_read_reg(bridge, where & ~3);

    return val >> shift;
}

#define PCIE_CONF_BUS(b)        (((b) & 0xff) << 24)
#define PCIE_CONF_DEV(d)        (((d) & 0x1f) << 19)
#define PCIE_CONF_FUNC(f)       (((f) & 0x7) << 16)

static bool pci_is_root_bus(unsigned int busn)
{
    return busn == 0;
}

static int rcar_pcie_config_access(struct pci_host_bridge *bridge,
                                   unsigned char access_type,
                                   unsigned int busn, unsigned int devfn,
                                   int where, u32 *data)
{
    struct pci_config_window *cfg = bridge->sysdata;
    int dev, func, reg, index;
#if 0
    u32 val;
    int ret;
#endif

    dev = PCI_SLOT(devfn);
    func = PCI_FUNC(devfn);
    reg = where & ~3;
    index = reg / 4;

    /*
     * While each channel has its own memory-mapped extended config
     * space, it's generally only accessible when in endpoint mode.
     * When in root complex mode, the controller is unable to target
     * itself with either type 0 or type 1 accesses, and indeed, any
     * controller initiated target transfer to its own config space
     * result in a completer abort.
     *
     * Each channel effectively only supports a single device, but as
     * the same channel <-> device access works for any PCI_SLOT()
     * value, we cheat a bit here and bind the controller's config
     * space to devfn 0 in order to enable self-enumeration. In this
     * case the regular ECAR/ECDR path is sidelined and the mangled
     * config access itself is initiated as an internal bus transaction.
     */
    if ( pci_is_root_bus(busn) )
    {
        if ( dev != 0 )
            return PCIBIOS_DEVICE_NOT_FOUND;

        if ( access_type == RCAR_PCI_ACCESS_READ )
            *data = rcar_pci_read_reg(bridge, PCICONF(index));
        else
        {
#if 0
            /* FIXME: this part is done by Linux only */
            /* Keep an eye out for changes to the root bus number */
            if ( pci_is_root_bus(busn) && (reg == PCI_PRIMARY_BUS) )
            {
                pcie->root_bus_nr = *data & 0xff;
            }
#endif
            rcar_pci_write_reg(bridge, *data, PCICONF(index));
        }
        return PCIBIOS_SUCCESSFUL;
    }

    /*
     * [    1.469190] pci_bus 0000:01: pcie-config-read: bus=  1 devfn=0x0000 where=0x0018 size=4 val=0x00000004
     * root_bus_nr = 4
     */


    if ( cfg->root_bus_nr < 0 )
        return PCIBIOS_DEVICE_NOT_FOUND;

    /* Clear errors */
    rcar_pci_write_reg(bridge, rcar_pci_read_reg(bridge, PCIEERRFR), PCIEERRFR);

    /* Set the PIO address */
    rcar_pci_write_reg(bridge, PCIE_CONF_BUS(busn) |
                       PCIE_CONF_DEV(dev) | PCIE_CONF_FUNC(func) | reg, PCIECAR);
#if 0
    printk("PCIE_CONF %x reg %x\n", PCIE_CONF_BUS(busn) |
           PCIE_CONF_DEV(dev) | PCIE_CONF_FUNC(func), reg);
#endif

    /* Enable the configuration access */
    if (/*bus->parent->number == cfg->root_bus_nr*/true)
        rcar_pci_write_reg(bridge, CONFIG_SEND_ENABLE | TYPE0, PCIECCTLR);
    else
        rcar_pci_write_reg(bridge, CONFIG_SEND_ENABLE | TYPE1, PCIECCTLR);

    /* Check for errors */
    if ( rcar_pci_read_reg(bridge, PCIEERRFR) & UNSUPPORTED_REQUEST )
        return PCIBIOS_DEVICE_NOT_FOUND;

    /* Check for master and target aborts */
    if ( rcar_read_conf(bridge, RCONF(PCI_STATUS)) &
        (PCI_STATUS_REC_MASTER_ABORT | PCI_STATUS_REC_TARGET_ABORT) )
        return PCIBIOS_DEVICE_NOT_FOUND;

    if ( access_type == RCAR_PCI_ACCESS_READ )
        *data = rcar_pci_read_reg(bridge, PCIECDR);
    else
        rcar_pci_write_reg(bridge, *data, PCIECDR);

    /* Disable the configuration access */
    rcar_pci_write_reg(bridge, 0, PCIECCTLR);

    return PCIBIOS_SUCCESSFUL;
}

int pci_rcar_gen3_config_read(struct pci_host_bridge *bridge, uint32_t _sbdf,
                              uint32_t where, uint32_t size, u32 *val)
{
    pci_sbdf_t sbdf;
    int ret;

    sbdf.sbdf = _sbdf;

    ret = rcar_pcie_config_access(bridge, RCAR_PCI_ACCESS_READ,
                                  sbdf.bus, sbdf.devfn, where, val);
    if ( ret != PCIBIOS_SUCCESSFUL ) {
        *val = 0xffffffff;
        return ret;
    }

    if ( size == 1 )
        *val = (*val >> (8 * (where & 3))) & 0xff;
    else if ( size == 2 )
        *val = (*val >> (8 * (where & 2))) & 0xffff;

#if 0
    printk("pcie-config-read: bus=%3d devfn=0x%04x where=0x%04x size=%d val=0x%08lx\n",
           sbdf.bus, sbdf.devfn, where, size, (unsigned long)*val);
#endif

    return ret;
}

int pci_rcar_gen3_config_write(struct pci_host_bridge *bridge, uint32_t _sbdf,
                               uint32_t where, uint32_t size, uint32_t val)
{
    pci_sbdf_t sbdf;
    int shift, ret;
    u32 data;

    sbdf.sbdf = _sbdf;

    ret = rcar_pcie_config_access(bridge, RCAR_PCI_ACCESS_READ,
                                  sbdf.bus, sbdf.devfn, where, &data);
    if ( ret != PCIBIOS_SUCCESSFUL )
        return ret;

#if 0
    printk("pcie-config-write: bus=%3d devfn=0x%04x where=0x%04x size=%d val=0x%08lx\n",
           sbdf.bus, sbdf.devfn, where, size, (unsigned long)val);
#endif

    if ( size == 1 )
    {
        shift = 8 * (where & 3);
        data &= ~(0xff << shift);
        data |= ((val & 0xff) << shift);
    } else if ( size == 2 ) {
        shift = 8 * (where & 2);
        data &= ~(0xffff << shift);
        data |= ((val & 0xffff) << shift);
    } else
        data = val;

    ret = rcar_pcie_config_access(bridge, RCAR_PCI_ACCESS_WRITE,
                                  sbdf.bus, sbdf.devfn, where, &data);

    return ret;
}

/* R-Car Gen3 ops */
static struct pci_ecam_ops pci_rcar_gen3_ops = {
    .bus_shift  = 20, /* FIXME: this is not used by RCar */
    .pci_ops    = {
        .read       = pci_rcar_gen3_config_read,
        .write      = pci_rcar_gen3_config_write,
    }
};

static const struct dt_device_match rcar_gen3_dt_match[] =
{
    DT_MATCH_COMPATIBLE("renesas,pcie-r8a7795"),
    DT_MATCH_COMPATIBLE("renesas,pcie-rcar-gen3"),
    { /* sentinel */ },
};

static void __iomem *pci_remap_reg(paddr_t start, size_t len)
{
    return ioremap_nocache(start, len);
}

#if 0
static void pci_unmap_reg(struct pci_config_window *cfg)
{
    if ( cfg->win )
        iounmap(cfg->win);

    xfree(cfg);
}
#endif

static int rcar_gen3_pci_host_probe(struct dt_device_node *dev)
{
    struct pci_host_bridge *bridge;
    u32 segment;
    int err;
    struct pci_config_window *cfg;
    paddr_t addr, size;

    bridge = pci_alloc_host_bridge();
    if ( !bridge )
    {
        /* TODO: remove entry */
        return -ENOMEM;
    }

    cfg = xzalloc(struct pci_config_window);
    if ( !cfg )
        return -ENOMEM;

    /* Parse our PCI ecam register address*/
    err = dt_device_get_address(dev, 0, &addr, &size);
    if ( err )
    {
        /* TODO: remove cfg */
        printk("%s Can't read reg property\n", __func__);
        return -EINVAL;
    }

    err = dt_pci_parse_bus_range(dev, cfg);
    if ( !err )
    {
        cfg->busn_start = 0;
        cfg->busn_end = 0xff;
        printk(XENLOG_ERR "No bus range found for pci controller\n");
    }
    printk("bus range [%02x - %02x]\n", cfg->busn_start, cfg->busn_end);

    /*
     * TODO:
     * [    0.431494] rcar_pcie_setup *************************************************** pci->root_bus_nr 0x0
     * [    0.431618] rcar-pcie fe000000.pcie: PCI host bridge to bus 0000:00
     * [    0.431649] pci_bus 0000:00: root bus resource [bus 00-ff]
     * [    0.431666] pci_bus 0000:00: root bus resource [io  0x0000-0xfffff]
     * [    0.431690] pci_bus 0000:00: root bus resource [mem 0xfe200000-0xfe3fffff]
     * [    0.431708] pci_bus 0000:00: root bus resource [mem 0x30000000-0x37ffffff]
     * [    0.431727] pci_bus 0000:00: root bus resource [mem 0x38000000-0x3fffffff pref]
     * case IORESOURCE_BUS:
     * pci->root_bus_nr = res->start;
     */
    cfg->root_bus_nr = 0;

    cfg->phys_addr = addr;
    cfg->size = size;

    cfg->win = pci_remap_reg(cfg->phys_addr, cfg->size);
    if ( !cfg->win )
    {
        /* TODO: cleanup */
        printk("%s Can't remap reg space\n", __func__);
        return -ENOMEM;
    }

    printk("RCAR GEN3 PCI at [mem %lx-%lx] mapped to %p\n", cfg->phys_addr,
           cfg->phys_addr + cfg->size - 1, cfg->win);

    bridge->dt_node = dev;
    /* This is configuration space MCFG which we do not have. */
    bridge->sysdata = cfg;
    bridge->ops = &pci_rcar_gen3_ops.pci_ops;
    bridge->bus_start = cfg->busn_start;
    bridge->bus_end = cfg->busn_end;

    if ( !dt_property_read_u32(dev, "linux,pci-domain", &segment) )
    {
        printk(XENLOG_ERR "\"linux,pci-domain\" property in not available in DT\n");
        segment = 0;
    }

    bridge->segment = (u16)segment;

    pci_add_host_bridge(bridge);

    return 0;
}

static int rcar_gen3_pci_dt_init(struct dt_device_node *dev, const void *data)
{
    const struct dt_device_match *of_id;

    of_id = dt_match_node(rcar_gen3_dt_match, dev->dev.of_node);

    printk(XENLOG_INFO "Found PCI host bridge %s compatible:%s \n",
           dt_node_full_name(dev), of_id->compatible);

    return rcar_gen3_pci_host_probe(dev);
}

DT_DEVICE_START(pci_rcar_gen3, "PCI HOST RCAR GEN3", DEVICE_PCI)
.dt_match = rcar_gen3_dt_match,
.init = rcar_gen3_pci_dt_init,
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
