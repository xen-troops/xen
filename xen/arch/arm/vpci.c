/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/vpci.c
 */
#include <xen/ioreq.h>
#include <xen/sched.h>
#include <xen/sizes.h>
#include <xen/vpci.h>

#include <asm/ioreq.h>
#include <asm/mmio.h>

static pci_sbdf_t vpci_sbdf_from_gpa(const struct pci_host_bridge *bridge,
                                     paddr_t gpa)
{
    pci_sbdf_t sbdf;

    if ( bridge )
    {
        sbdf.sbdf = VPCI_ECAM_BDF(gpa - bridge->cfg->phys_addr);
        sbdf.seg = bridge->segment;
        sbdf.bus += bridge->cfg->busn_start;
    }
    else
        sbdf.sbdf = VPCI_ECAM_BDF(gpa - GUEST_VPCI_ECAM_BASE);

    return sbdf;
}

bool virtio_pci_ioreq_server_get_addr(const struct domain *d,
                                      paddr_t gpa, uint64_t *addr)
{
    pci_sbdf_t sbdf;

    if ( !has_vpci(d) )
        return false;

    if ( gpa < GUEST_VIRTIO_PCI_ECAM_BASE ||
         gpa >= GUEST_VIRTIO_PCI_ECAM_BASE + GUEST_VIRTIO_PCI_TOTAL_ECAM_SIZE )
        return false;

    sbdf.sbdf = VPCI_ECAM_BDF((gpa - GUEST_VIRTIO_PCI_ECAM_BASE) %
        GUEST_VIRTIO_PCI_HOST_ECAM_SIZE);
    sbdf.seg = (gpa - GUEST_VIRTIO_PCI_ECAM_BASE) /
        GUEST_VIRTIO_PCI_HOST_ECAM_SIZE;
    *addr = ((uint64_t)sbdf.sbdf << 32) | ECAM_REG_OFFSET(gpa);

    return true;
}

static int vpci_mmio_read(struct vcpu *v, mmio_info_t *info,
                          register_t *r, void *p)
{
    struct pci_host_bridge *bridge = p;
    pci_sbdf_t sbdf;
    /* data is needed to prevent a pointer cast on 32bit */
    unsigned long data;
    const uint8_t access_size = (1 << info->dabt.size) * 8;
    const uint64_t access_mask = GENMASK_ULL(access_size - 1, 0);

    ASSERT(!bridge == !is_hardware_domain(v->domain));

    sbdf = vpci_sbdf_from_gpa(bridge, info->gpa);

    /*
     * For the passed through devices we need to map their virtual SBDF
     * to the physical PCI device being passed through.
     */
    if ( !bridge )
    {
        bool translated;

        read_lock(&v->domain->pci_lock);
        translated = vpci_translate_virtual_device(v->domain, &sbdf);
        read_unlock(&v->domain->pci_lock);

        if ( !translated )
        {
            *r = access_mask;
            return IO_HANDLED;
        }
    }

    if ( vpci_ecam_read(sbdf, ECAM_REG_OFFSET(info->gpa),
                        1U << info->dabt.size, &data) )
    {
        *r = data;
        return IO_HANDLED;
    }

    *r = access_mask;

    return IO_ABORT;
}

static int vpci_mmio_write(struct vcpu *v, mmio_info_t *info,
                           register_t r, void *p)
{
    struct pci_host_bridge *bridge = p;
    pci_sbdf_t sbdf;

    ASSERT(!bridge == !is_hardware_domain(v->domain));

    sbdf = vpci_sbdf_from_gpa(bridge, info->gpa);

    /*
     * For the passed through devices we need to map their virtual SBDF
     * to the physical PCI device being passed through.
     */
    if ( !bridge )
    {
        bool translated;

        read_lock(&v->domain->pci_lock);
        translated = vpci_translate_virtual_device(v->domain, &sbdf);
        read_unlock(&v->domain->pci_lock);

        if ( !translated )
            return IO_HANDLED;
    }

    return vpci_ecam_write(sbdf, ECAM_REG_OFFSET(info->gpa),
                           1U << info->dabt.size, r);
}

static const struct mmio_handler_ops vpci_mmio_handler = {
    .read  = vpci_mmio_read,
    .write = vpci_mmio_write,
};

#ifdef CONFIG_VIRTIO_PCI
static int virtio_pci_mmio_read(struct vcpu *v, mmio_info_t *info,
                                register_t *r, void *p)
{
    const uint8_t access_size = (1 << info->dabt.size) * 8;
    const uint64_t access_mask = GENMASK_ULL(access_size - 1, 0);
    int rc = IO_HANDLED;

    ASSERT(!is_hardware_domain(v->domain));

    if ( domain_has_ioreq_server(v->domain) )
    {
        rc = try_fwd_ioserv(guest_cpu_user_regs(), v, info);
        if ( rc == IO_HANDLED )
        {
            *r = v->io.req.data;
            v->io.req.state = STATE_IOREQ_NONE;
            return IO_HANDLED;
        }
        else if ( rc == IO_UNHANDLED )
            rc = IO_HANDLED;
    }

    *r = access_mask;
    return rc;
}

static int virtio_pci_mmio_write(struct vcpu *v, mmio_info_t *info,
                                 register_t r, void *p)
{
    int rc = IO_HANDLED;

    ASSERT(!is_hardware_domain(v->domain));

    if ( domain_has_ioreq_server(v->domain) )
    {
        rc = try_fwd_ioserv(guest_cpu_user_regs(), v, info);
        if ( rc == IO_HANDLED )
        {
            v->io.req.state = STATE_IOREQ_NONE;
            return IO_HANDLED;
        }
        else if ( rc == IO_UNHANDLED )
            rc = IO_HANDLED;
    }

    return rc;
}

static const struct mmio_handler_ops virtio_pci_mmio_handler = {
    .read  = virtio_pci_mmio_read,
    .write = virtio_pci_mmio_write,
};
#endif

static int vpci_setup_mmio_handler_cb(struct domain *d,
                                      struct pci_host_bridge *bridge)
{
    struct pci_config_window *cfg = bridge->cfg;

    register_mmio_handler(d, &vpci_mmio_handler,
                          cfg->phys_addr, cfg->size, bridge);

    /* We have registered a single MMIO handler. */
    return 1;
}

int domain_vpci_init(struct domain *d)
{
    if ( !has_vpci(d) )
        return 0;

    /*
     * The hardware domain gets as many MMIOs as required by the
     * physical host bridge.
     * Guests get the virtual platform layout: one virtual host bridge for now.
     */
    if ( is_hardware_domain(d) )
    {
        int ret;

        ret = pci_host_iterate_bridges_and_count(d, vpci_setup_mmio_handler_cb);
        if ( ret < 0 )
            return ret;
    }
    else
    {
        register_mmio_handler(d, &vpci_mmio_handler,
                              GUEST_VPCI_ECAM_BASE, GUEST_VPCI_ECAM_SIZE, NULL);

#ifdef CONFIG_VIRTIO_PCI
        register_mmio_handler(d, &virtio_pci_mmio_handler,
                              GUEST_VIRTIO_PCI_ECAM_BASE,
                              GUEST_VIRTIO_PCI_TOTAL_ECAM_SIZE, NULL);
#endif
    }

    return 0;
}

static int vpci_get_num_handlers_cb(struct domain *d,
                                    struct pci_host_bridge *bridge)
{
    /* Each bridge has a single MMIO handler for the configuration space. */
    return 1;
}

unsigned int domain_vpci_get_num_mmio_handlers(struct domain *d)
{
    unsigned int count;

    if ( !has_vpci(d) )
        return 0;

    if ( is_hardware_domain(d) )
    {
        int ret = pci_host_iterate_bridges_and_count(d, vpci_get_num_handlers_cb);

        if ( ret < 0 )
        {
            ASSERT_UNREACHABLE();
            return 0;
        }

        return ret;
    }

    /*
     * For guests each host bridge requires one region to cover the
     * configuration space. At the moment, we only expose a single host bridge.
     */
    count = 1;

    /*
     * In order to not mix PCI passthrough with virtio-pci features we add
     * one more region to cover the total configuration space for all possible
     * host bridges which can serve virtio devices for that guest.
     * We expose one host bridge per virtio backend domain.
     */
    if ( IS_ENABLED(CONFIG_VIRTIO_PCI) )
        count++;

    /*
     * There's a single MSI-X MMIO handler that deals with both PBA
     * and MSI-X tables per each PCI device being passed through.
     * Maximum number of emulated virtual devices is VPCI_MAX_VIRT_DEV.
     */
    if ( IS_ENABLED(CONFIG_HAS_PCI_MSI) )
        count += VPCI_MAX_VIRT_DEV;

    return count;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

