/*
 * Generic functionality for handling accesses to the PCI header from the
 * configuration space.
 *
 * Copyright (C) 2017 Citrix Systems R&D
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

#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/vpci.h>

#include <asm/event.h>
#include <asm/p2m.h>

#define MAPPABLE_BAR(x)                                                 \
    ((x)->type == VPCI_BAR_MEM32 || (x)->type == VPCI_BAR_MEM64_LO ||   \
     (x)->type == VPCI_BAR_ROM)

struct map_data {
    struct domain *d;
    gfn_t start_gfn;
    bool map;
};

static int map_range(unsigned long s, unsigned long e, void *data,
                     unsigned long *c)
{
    struct map_data *map = data;
    int rc;

    for ( ; ; )
    {
        unsigned long size = e - s + 1;

        printk(XENLOG_G_DEBUG
               "%smap [%lx, %lx] -> %#"PRI_gfn" for d%d\n",
               map->map ? "" : "un", s, e, gfn_x(map->start_gfn),
               map->d->domain_id);
        /*
         * ARM TODOs:
         * - On ARM whether the memory is prefetchable or not should be passed
         *   to map_mmio_regions in order to decide which memory attributes
         *   should be used.
         *
         * - {un}map_mmio_regions doesn't support preemption.
         */

        rc = map->map ? map_mmio_regions(map->d, map->start_gfn,
                                         size, _mfn(s))
                      : unmap_mmio_regions(map->d, map->start_gfn,
                                           size, _mfn(s));
        if ( rc == 0 )
        {
            *c += size;
            break;
        }
        if ( rc < 0 )
        {
            printk(XENLOG_G_WARNING
                   "Failed to identity %smap [%lx, %lx] for d%d: %d\n",
                   map->map ? "" : "un", s, e, map->d->domain_id, rc);
            break;
        }
        ASSERT(rc < size);
        *c += rc;
        s += rc;
        gfn_add(map->start_gfn, rc);
        if ( general_preempt_check() )
                return -ERESTART;
    }

    return rc;
}

/*
 * The rom_only parameter is used to signal the map/unmap helpers that the ROM
 * BAR's enable bit has changed with the memory decoding bit already enabled.
 * If rom_only is not set then it's the memory decoding bit that changed.
 */
static void modify_decoding(const struct pci_dev *pdev, uint16_t cmd,
                            bool rom_only)
{
    struct vpci_header *header = &pdev->vpci->header;
    bool map = cmd & PCI_COMMAND_MEMORY;
    unsigned int i;

    /*
     * Make sure there are no mappings in the MSIX MMIO areas, so that accesses
     * can be trapped (and emulated) by Xen when the memory decoding bit is
     * enabled.
     *
     * FIXME: punching holes after the p2m has been set up might be racy for
     * DomU usage, needs to be revisited.
     */
#ifdef CONFIG_HAS_PCI_MSI
    if ( map && !rom_only && vpci_make_msix_hole(pdev) )
        return;
#endif

    for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
    {
        if ( !MAPPABLE_BAR(&header->bars[i]) )
            continue;

        if ( rom_only && header->bars[i].type == VPCI_BAR_ROM )
        {
            unsigned int rom_pos = (i == PCI_HEADER_NORMAL_NR_BARS)
                                   ? PCI_ROM_ADDRESS : PCI_ROM_ADDRESS1;
            uint32_t val = header->bars[i].addr |
                           (map ? PCI_ROM_ADDRESS_ENABLE : 0);

            header->bars[i].enabled = header->rom_enabled = map;
            pci_conf_write32(pdev->sbdf, rom_pos, val);
            return;
        }

        if ( !rom_only &&
             (header->bars[i].type != VPCI_BAR_ROM || header->rom_enabled) )
            header->bars[i].enabled = map;
    }

    if ( !rom_only )
        pci_conf_write16(pdev->sbdf, PCI_COMMAND, cmd);
    else
        ASSERT_UNREACHABLE();
}

bool vpci_process_pending(struct vcpu *v)
{
    if ( v->vpci.num_mem_ranges )
    {
        struct map_data data = {
            .d = v->domain,
            .map = v->vpci.cmd & PCI_COMMAND_MEMORY,
        };
        struct pci_dev *pdev = v->vpci.pdev;
        struct vpci_header *header = &pdev->vpci->header;
        unsigned int i;

        for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
        {
            struct vpci_bar *bar = &header->bars[i];
            int rc;

            if ( !bar->mem )
                continue;

            data.start_gfn = pci_is_hardware_domain(v->domain,
                                                    pdev->seg, pdev->bus) ?
                _gfn(PFN_DOWN(bar->addr)) :
                _gfn(PFN_DOWN(bar->guest_addr));
            rc = rangeset_consume_ranges(bar->mem, map_range, &data);

            if ( rc == -ERESTART )
                return true;

            spin_lock(&pdev->vpci->lock);
            /* Disable memory decoding unconditionally on failure. */
            modify_decoding(pdev,
                            rc ? v->vpci.cmd & ~PCI_COMMAND_MEMORY : v->vpci.cmd,
                            !rc && v->vpci.rom_only);
            spin_unlock(&pdev->vpci->lock);

            rangeset_destroy(bar->mem);
            bar->mem = NULL;
            v->vpci.num_mem_ranges--;
            if ( rc )
                /*
                 * FIXME: in case of failure remove the device from the domain.
                 * Note that there might still be leftover mappings. While this is
                 * safe for Dom0, for DomUs the domain will likely need to be
                 * killed in order to avoid leaking stale p2m mappings on
                 * failure.
                 */
                vpci_remove_device(pdev);
        }
    }

    return false;
}

static int __init apply_map(struct domain *d, const struct pci_dev *pdev,
                            uint16_t cmd)
{
    struct map_data data = { .d = d, .map = true };
    struct vpci_header *header = &pdev->vpci->header;
    int rc = 0;
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
    {
        struct vpci_bar *bar = &header->bars[i];

        if ( !bar->mem )
            continue;

        data.start_gfn = pci_is_hardware_domain(d, pdev->seg, pdev->bus) ?
            _gfn(PFN_DOWN(bar->addr)) :
            _gfn(PFN_DOWN(bar->guest_addr));
        while ( (rc = rangeset_consume_ranges(bar->mem, map_range,
                                              &data)) == -ERESTART )
            process_pending_softirqs();
        rangeset_destroy(bar->mem);
        bar->mem = NULL;
    }
    if ( !rc )
        modify_decoding(pdev, cmd, false);

    return rc;
}

static void defer_map(struct domain *d, struct pci_dev *pdev,
                      uint16_t cmd, bool rom_only, uint8_t num_mem_ranges)
{
    struct vcpu *curr = current;

    /*
     * FIXME: when deferring the {un}map the state of the device should not
     * be trusted. For example the enable bit is toggled after the device
     * is mapped. This can lead to parallel mapping operations being
     * started for the same device if the domain is not well-behaved.
     */
    curr->vpci.pdev = pdev;
    curr->vpci.cmd = cmd;
    curr->vpci.rom_only = rom_only;
    curr->vpci.num_mem_ranges = num_mem_ranges;
    /*
     * Raise a scheduler softirq in order to prevent the guest from resuming
     * execution with pending mapping operations, to trigger the invocation
     * of vpci_process_pending().
     */
    raise_softirq(SCHEDULE_SOFTIRQ);
}

static int modify_bars(const struct pci_dev *pdev, uint16_t cmd, bool rom_only)
{
    struct vpci_header *header = &pdev->vpci->header;
    struct pci_dev *tmp, *dev = NULL;
#ifdef CONFIG_HAS_PCI_MSI
    const struct vpci_msix *msix = pdev->vpci->msix;
    unsigned int j;
#endif
    unsigned int i;
    int rc;
    uint8_t num_mem_ranges;

    /*
     * Create a rangeset per BAR that represents the current device memory region
     * and compare it against all the currently active BAR memory regions. If
     * an overlap is found, subtract it from the region to be mapped/unmapped.
     *
     * First fill the rangesets with all the BARs of this device or with the ROM
     * BAR only, depending on whether the guest is toggling the memory decode
     * bit of the command register, or the enable bit of the ROM BAR register.
     */
    for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
    {
        struct vpci_bar *bar = &header->bars[i];
        unsigned long start = PFN_DOWN(bar->addr);
        unsigned long end = PFN_DOWN(bar->addr + bar->size - 1);

        bar->mem = NULL;

        if ( !MAPPABLE_BAR(bar) ||
             (rom_only ? bar->type != VPCI_BAR_ROM
                       : (bar->type == VPCI_BAR_ROM && !header->rom_enabled)) )
            continue;

        bar->mem = rangeset_new(NULL, NULL, 0);
        if ( !bar->mem )
        {
            rc = -ENOMEM;
            goto fail;
        }

        rc = rangeset_add_range(bar->mem, start, end);
        if ( rc )
        {
            printk(XENLOG_G_WARNING "Failed to add [%lx, %lx]: %d\n",
                   start, end, rc);
            goto fail;
        }
    }

#ifdef CONFIG_HAS_PCI_MSI
    /* Remove any MSIX regions if present. */
    for ( i = 0; msix && i < ARRAY_SIZE(msix->tables); i++ )
    {
        unsigned long start = PFN_DOWN(vmsix_table_addr(pdev->vpci, i));
        unsigned long end = PFN_DOWN(vmsix_table_addr(pdev->vpci, i) +
                                     vmsix_table_size(pdev->vpci, i) - 1);

        for ( j = 0; j < ARRAY_SIZE(header->bars); j++ )
        {
            const struct vpci_bar *bar = &header->bars[j];

            if ( !bar->mem )
                continue;

            rc = rangeset_remove_range(bar->mem, start, end);
            if ( rc )
            {
                printk(XENLOG_G_WARNING
                       "Failed to remove MSIX table [%lx, %lx]: %d\n",
                       start, end, rc);
                goto fail;
            }
        }
    }
#endif /* CONFIG_HAS_PCI_MSI */

    /*
     * Check for overlaps with other BARs. Note that only BARs that are
     * currently mapped (enabled) are checked for overlaps.
     */
    for_each_pdev ( pdev->domain, tmp )
    {
        if ( tmp == pdev )
        {
            /*
             * Need to store the device so it's not constified and defer_map
             * can modify it in case of error.
             */
            dev = tmp;
            if ( !rom_only )
                /*
                 * If memory decoding is toggled avoid checking against the
                 * same device, or else all regions will be removed from the
                 * memory map in the unmap case.
                 */
                continue;
        }

        for ( i = 0; i < ARRAY_SIZE(tmp->vpci->header.bars); i++ )
        {
            const struct vpci_bar *bar = &tmp->vpci->header.bars[i];
            unsigned long start = PFN_DOWN(bar->addr);
            unsigned long end = PFN_DOWN(bar->addr + bar->size - 1);

            if ( !bar->enabled ||
                 !rangeset_overlaps_range(bar->mem, start, end) ||
                 /*
                  * If only the ROM enable bit is toggled check against other
                  * BARs in the same device for overlaps, but not against the
                  * same ROM BAR.
                  */
                 (rom_only && tmp == pdev && bar->type == VPCI_BAR_ROM) )
                continue;

            rc = rangeset_remove_range(bar->mem, start, end);
            if ( rc )
            {
                printk(XENLOG_G_WARNING "Failed to remove [%lx, %lx]: %d\n",
                       start, end, rc);
                goto fail;
            }
        }
    }

    ASSERT(dev);

    if ( system_state < SYS_STATE_active )
    {
        /*
         * Mappings might be created when building Dom0 if the memory decoding
         * bit of PCI devices is enabled. In that case it's not possible to
         * defer the operation, so call apply_map in order to create the
         * mappings right away. Note that at build time this function will only
         * be called iff the memory decoding bit is enabled, thus the operation
         * will always be to establish mappings and process all the BARs.
         */
        ASSERT((cmd & PCI_COMMAND_MEMORY) && !rom_only);
        return apply_map(pdev->domain, pdev, cmd);
    }

    /* Find out how many memory ranges has left after MSI and overlaps. */
    num_mem_ranges = 0;
    for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
    {
        struct vpci_bar *bar = &header->bars[i];

        if ( !rangeset_is_empty(bar->mem) )
            num_mem_ranges++;
    }

    if ( !num_mem_ranges )
        pci_conf_write16(pdev->sbdf, PCI_COMMAND, cmd);
    else
        defer_map(dev->domain, dev, cmd, rom_only, num_mem_ranges);

    return 0;

fail:
    for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
    {
        struct vpci_bar *bar = &header->bars[i];

        rangeset_destroy(bar->mem);
        bar->mem = NULL;
    }
    return rc;
}

static void cmd_write(const struct pci_dev *pdev, unsigned int reg,
                      uint32_t cmd, void *data)
{
    uint16_t current_cmd = pci_conf_read16(pdev->sbdf, reg);

    /*
     * Let Dom0 play with all the bits directly except for the memory
     * decoding one.
     */
    if ( (cmd ^ current_cmd) & PCI_COMMAND_MEMORY )
        /*
         * Ignore the error. No memory has been added or removed from the p2m
         * (because the actual p2m changes are deferred in defer_map) and the
         * memory decoding bit has not been changed, so leave everything as-is,
         * hoping the guest will realize and try again.
         */
        modify_bars(pdev, cmd, false);
    else
        pci_conf_write16(pdev->sbdf, reg, cmd);
}

static void bar_write(const struct pci_dev *pdev, unsigned int reg,
                      uint32_t val, void *data)
{
    struct vpci_bar *bar = data;
    bool hi = false;

    if ( bar->type == VPCI_BAR_MEM64_HI )
    {
        ASSERT(reg > PCI_BASE_ADDRESS_0);
        bar--;
        hi = true;
    }
    else
        val &= PCI_BASE_ADDRESS_MEM_MASK;

    if ( pci_conf_read16(pdev->sbdf, PCI_COMMAND) & PCI_COMMAND_MEMORY )
    {
        /* If the value written is the current one avoid printing a warning. */
        if ( val != (uint32_t)(bar->addr >> (hi ? 32 : 0)) )
            gprintk(XENLOG_WARNING,
                    "%pp: ignored BAR %lu write with memory decoding enabled\n",
                    &pdev->sbdf, bar - pdev->vpci->header.bars + hi);
        return;
    }


    /*
     * Update the cached address, so that when memory decoding is enabled
     * Xen can map the BAR into the guest p2m.
     */
    bar->addr &= ~(0xffffffffull << (hi ? 32 : 0));
    bar->addr |= (uint64_t)val << (hi ? 32 : 0);

    /* Make sure Xen writes back the same value for the BAR RO bits. */
    if ( !hi )
    {
        val |= bar->type == VPCI_BAR_MEM32 ? PCI_BASE_ADDRESS_MEM_TYPE_32
                                           : PCI_BASE_ADDRESS_MEM_TYPE_64;
        val |= bar->prefetchable ? PCI_BASE_ADDRESS_MEM_PREFETCH : 0;
    }

    pci_conf_write32(pdev->sbdf, reg, val);
}

static void guest_bar_write(const struct pci_dev *pdev, unsigned int reg,
                            uint32_t val, void *data)
{
    struct vpci_bar *bar = data;
    bool hi = false;

    if ( bar->type == VPCI_BAR_MEM64_HI )
    {
        ASSERT(reg > PCI_BASE_ADDRESS_0);
        bar--;
        hi = true;
    }
    else
        val &= PCI_BASE_ADDRESS_MEM_MASK;
    bar->guest_addr &= ~(0xffffffffull << (hi ? 32 : 0));
    bar->guest_addr |= (uint64_t)val << (hi ? 32 : 0);
}

static uint32_t guest_bar_read(const struct pci_dev *pdev, unsigned int reg,
                               void *data)
{
    struct vpci_bar *bar = data;
    uint32_t val;
    bool hi = false;

    switch ( bar->type )
    {
    case VPCI_BAR_MEM64_HI:
        ASSERT(reg > PCI_BASE_ADDRESS_0);
        bar--;
        hi = true;
        /* fallthrough */
    case VPCI_BAR_MEM64_LO:
    {
        if ( hi )
            val = bar->guest_addr >> 32;
        else
            val = bar->guest_addr & 0xffffffff;
        if ( (val & PCI_BASE_ADDRESS_MEM_MASK_32) ==  PCI_BASE_ADDRESS_MEM_MASK_32 )
        {
            /* Guests detects BAR's properties and sizes. */
            if ( hi )
                val = bar->size >> 32;
            else
                val = 0xffffffff & ~(bar->size - 1);
        }
        if ( !hi )
        {
            val |= PCI_BASE_ADDRESS_MEM_TYPE_64;
            val |= bar->prefetchable ? PCI_BASE_ADDRESS_MEM_PREFETCH : 0;
        }
        bar->guest_addr &= ~(0xffffffffull << (hi ? 32 : 0));
        bar->guest_addr |= (uint64_t)val << (hi ? 32 : 0);
        break;
    }
    case VPCI_BAR_MEM32:
    {
        val = bar->guest_addr;
        if ( (val & PCI_BASE_ADDRESS_MEM_MASK_32) ==  PCI_BASE_ADDRESS_MEM_MASK_32 )
            val = 0xffffffff & ~(bar->size - 1);
        val |= PCI_BASE_ADDRESS_MEM_TYPE_32;
        val |= bar->prefetchable ? PCI_BASE_ADDRESS_MEM_PREFETCH : 0;
        break;
    }
    default:
        val = bar->guest_addr;
        break;
    }
    return val;
}

static void rom_write(const struct pci_dev *pdev, unsigned int reg,
                      uint32_t val, void *data)
{
    struct vpci_header *header = &pdev->vpci->header;
    struct vpci_bar *rom = data;
    uint16_t cmd = pci_conf_read16(pdev->sbdf, PCI_COMMAND);
    bool new_enabled = val & PCI_ROM_ADDRESS_ENABLE;

    if ( (cmd & PCI_COMMAND_MEMORY) && header->rom_enabled && new_enabled )
    {
        gprintk(XENLOG_WARNING,
                "%pp: ignored ROM BAR write with memory decoding enabled\n",
                &pdev->sbdf);
        return;
    }

    if ( !header->rom_enabled )
        /*
         * If the ROM BAR is not enabled update the address field so the
         * correct address is mapped into the p2m.
         */
        rom->addr = val & PCI_ROM_ADDRESS_MASK;

    if ( !(cmd & PCI_COMMAND_MEMORY) || header->rom_enabled == new_enabled )
    {
        /* Just update the ROM BAR field. */
        header->rom_enabled = new_enabled;
        pci_conf_write32(pdev->sbdf, reg, val);
    }
    /*
     * Pass PCI_COMMAND_MEMORY or 0 to signal a map/unmap request, note that
     * this fabricated command is never going to be written to the register.
     */
    else if ( modify_bars(pdev, new_enabled ? PCI_COMMAND_MEMORY : 0, true) )
        /*
         * No memory has been added or removed from the p2m (because the actual
         * p2m changes are deferred in defer_map) and the ROM enable bit has
         * not been changed, so leave everything as-is, hoping the guest will
         * realize and try again. It's important to not update rom->addr in the
         * unmap case if modify_bars has failed, or future attempts would
         * attempt to unmap the wrong address.
         */
        return;

    if ( !new_enabled )
        rom->addr = val & PCI_ROM_ADDRESS_MASK;
}

static void guest_rom_write(const struct pci_dev *pdev, unsigned int reg,
                            uint32_t val, void *data)
{
}

static uint32_t guest_rom_read(const struct pci_dev *pdev, unsigned int reg,
                               void *data)
{
    return 0xffffffff;
}

static int add_bar_handlers(struct pci_dev *pdev, bool is_hwdom)
{
    unsigned int i;
    struct vpci_header *header = &pdev->vpci->header;
    struct vpci_bar *bars = header->bars;
    int rc;

    /* Setup a handler for the command register: same for hwdom and guests. */
    rc = vpci_add_register(pdev->vpci, vpci_hw_read16, cmd_write, PCI_COMMAND,
                           2, header);
    if ( rc )
        return rc;

    if ( pdev->ignore_bars )
        return 0;

    for ( i = 0; i < PCI_HEADER_NORMAL_NR_BARS + 1; i++ )
    {
        if ( (bars[i].type == VPCI_BAR_IO) || (bars[i].type == VPCI_BAR_EMPTY) )
            continue;

        if ( bars[i].type == VPCI_BAR_ROM )
        {
            unsigned int rom_reg;
            uint8_t header_type = pci_conf_read8(pdev->sbdf,
                                                 PCI_HEADER_TYPE) & 0x7f;
            if ( header_type == PCI_HEADER_TYPE_NORMAL )
                rom_reg = PCI_ROM_ADDRESS;
            else
                rom_reg = PCI_ROM_ADDRESS1;
            if ( is_hwdom )
                rc = vpci_add_register(pdev->vpci, vpci_hw_read32, rom_write,
                                       rom_reg, 4, &bars[i]);
            else
                rc = vpci_add_register(pdev->vpci,
                                       guest_rom_read, guest_rom_write,
                                       rom_reg, 4, &bars[i]);
            if ( rc )
                return rc;
        }
        else
        {
            uint8_t reg = PCI_BASE_ADDRESS_0 + i * 4;

            /* This is either VPCI_BAR_MEM32 or VPCI_BAR_MEM64_{LO|HI}. */
            if ( is_hwdom )
                rc = vpci_add_register(pdev->vpci, vpci_hw_read32, bar_write,
                                       reg, 4, &bars[i]);
            else
                rc = vpci_add_register(pdev->vpci,
                                       guest_bar_read, guest_bar_write,
                                       reg, 4, &bars[i]);
            if ( rc )
                return rc;
        }
        bars[i].guest_addr = 0;
    }
    return 0;
}

static int init_bars(struct pci_dev *pdev)
{
    uint16_t cmd;
    uint64_t addr, size;
    unsigned int i, num_bars, rom_reg;
    struct vpci_header *header = &pdev->vpci->header;
    struct vpci_bar *bars = header->bars;
    int rc;

    switch ( pci_conf_read8(pdev->sbdf, PCI_HEADER_TYPE) & 0x7f )
    {
    case PCI_HEADER_TYPE_NORMAL:
        num_bars = PCI_HEADER_NORMAL_NR_BARS;
        rom_reg = PCI_ROM_ADDRESS;
        break;

    case PCI_HEADER_TYPE_BRIDGE:
        num_bars = PCI_HEADER_BRIDGE_NR_BARS;
        rom_reg = PCI_ROM_ADDRESS1;
        break;

    default:
        return -EOPNOTSUPP;
    }

    if ( pdev->ignore_bars )
        return add_bar_handlers(pdev, true);

    /* Disable memory decoding before sizing. */
    cmd = pci_conf_read16(pdev->sbdf, PCI_COMMAND);
    if ( cmd & PCI_COMMAND_MEMORY )
        pci_conf_write16(pdev->sbdf, PCI_COMMAND, cmd & ~PCI_COMMAND_MEMORY);

    for ( i = 0; i < num_bars; i++ )
    {
        uint8_t reg = PCI_BASE_ADDRESS_0 + i * 4;
        uint32_t val;

        if ( i && bars[i - 1].type == VPCI_BAR_MEM64_LO )
        {
            bars[i].type = VPCI_BAR_MEM64_HI;
            continue;
        }

        val = pci_conf_read32(pdev->sbdf, reg);
        if ( (val & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_IO )
        {
            bars[i].type = VPCI_BAR_IO;
            continue;
        }
        if ( (val & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
             PCI_BASE_ADDRESS_MEM_TYPE_64 )
            bars[i].type = VPCI_BAR_MEM64_LO;
        else
            bars[i].type = VPCI_BAR_MEM32;

        rc = pci_size_mem_bar(pdev->sbdf, reg, &addr, &size,
                              (i == num_bars - 1) ? PCI_BAR_LAST : 0);
        if ( rc < 0 )
        {
            pci_conf_write16(pdev->sbdf, PCI_COMMAND, cmd);
            return rc;
        }

        if ( size == 0 )
        {
            bars[i].type = VPCI_BAR_EMPTY;
            continue;
        }

        bars[i].addr = addr;
        bars[i].size = size;
        bars[i].prefetchable = val & PCI_BASE_ADDRESS_MEM_PREFETCH;
    }

    /* Check expansion ROM. */
    rc = pci_size_mem_bar(pdev->sbdf, rom_reg, &addr, &size, PCI_BAR_ROM);
    if ( rc > 0 && size )
    {
        struct vpci_bar *rom = &header->bars[num_bars];

        rom->type = VPCI_BAR_ROM;
        rom->size = size;
        rom->addr = addr;
        header->rom_enabled = pci_conf_read32(pdev->sbdf, rom_reg) &
                              PCI_ROM_ADDRESS_ENABLE;
    }

    rc = add_bar_handlers(pdev, true);
    if ( rc )
    {
        pci_conf_write16(pdev->sbdf, PCI_COMMAND, cmd);
        return rc;
    }

    return (cmd & PCI_COMMAND_MEMORY) ? modify_bars(pdev, cmd, false) : 0;
}
REGISTER_VPCI_INIT(init_bars, VPCI_PRIORITY_MIDDLE);

int vpci_bar_add_handlers(const struct domain *d, struct pci_dev *pdev)
{
    int rc;

    /* Remove previously added registers. */
    vpci_remove_device_registers(pdev);

    /* It only makes sense to add registers for hwdom or guest domain. */
    if ( d->domain_id >= DOMID_FIRST_RESERVED )
        return 0;

    if ( pci_is_hardware_domain(d, pdev->seg, pdev->bus) )
        rc = add_bar_handlers(pdev, true);
    else
        rc = add_bar_handlers(pdev, false);

    if ( rc )
        gprintk(XENLOG_ERR,
            "%pp: failed to add BAR handlers for dom%d\n", &pdev->sbdf,
            d->domain_id);

    /*
     * Reset the command register: it is possible that when passing
     * through a PCI device its memory decoding bits in the command
     * register are already set. Thus, a guest OS may not write to the
     * command register to update memory decoding, so guest mappings
     * (guest's view of the BARs) are left not updated.
     */
    pci_conf_write16(pdev->sbdf, PCI_COMMAND, 0);

    return rc;
}

int vpci_bar_remove_handlers(const struct domain *d, struct pci_dev *pdev)
{
    /* Remove previously added registers. */
    vpci_remove_device_registers(pdev);
    return 0;
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
