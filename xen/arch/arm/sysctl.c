/******************************************************************************
 * Arch-specific sysctl.c
 *
 * System management operations. For use by node control stack.
 *
 * Copyright (c) 2012, Citrix Systems
 */

#include <xen/types.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/hypercall.h>
#include <xen/guest_access.h>
#include <public/sysctl.h>

void arch_do_physinfo(struct xen_sysctl_physinfo *pi)
{
    pi->capabilities |= XEN_SYSCTL_PHYSCAP_hvm | XEN_SYSCTL_PHYSCAP_hap;
}

long arch_do_sysctl(struct xen_sysctl *sysctl,
                    XEN_GUEST_HANDLE_PARAM(xen_sysctl_t) u_sysctl)
{
    long ret = 0;
    bool copyback = 0;

    switch ( sysctl->cmd )
    {
    case XEN_SYSCTL_pci_device_set_assigned:
    {
        u16 seg;
        u8 bus, devfn;
        uint32_t machine_sbdf;

        machine_sbdf = sysctl->u.pci_set_assigned.machine_sbdf;

#if 0
        ret = xsm_pci_device_set_assigned(XSM_HOOK, d);
        if ( ret )
            break;
#endif

        seg = machine_sbdf >> 16;
        bus = PCI_BUS(machine_sbdf);
        devfn = PCI_DEVFN2(machine_sbdf);

        pcidevs_lock();
        ret = pci_device_set_assigned(seg, bus, devfn,
                                      !!sysctl->u.pci_set_assigned.assigned);
        pcidevs_unlock();
        break;
    }
    case XEN_SYSCTL_pci_device_get_assigned:
    {
        u16 seg;
        u8 bus, devfn;
        uint32_t machine_sbdf;

        machine_sbdf = sysctl->u.pci_set_assigned.machine_sbdf;

        seg = machine_sbdf >> 16;
        bus = PCI_BUS(machine_sbdf);
        devfn = PCI_DEVFN2(machine_sbdf);

        pcidevs_lock();
        ret = pci_device_get_assigned(seg, bus, devfn);
        pcidevs_unlock();
        break;
    }
    case XEN_SYSCTL_pci_device_enum_assigned:
    {
        ret = pci_device_enum_assigned(sysctl->u.pci_enum_assigned.report_not_assigned,
                                       sysctl->u.pci_enum_assigned.idx,
                                       &sysctl->u.pci_enum_assigned.domain,
                                       &sysctl->u.pci_enum_assigned.machine_sbdf);
        copyback = 1;
        break;
    }
    default:
        ret = -ENOSYS;
        break;
    }
    if ( copyback && (!ret || copyback > 0) &&
         __copy_to_guest(u_sysctl, sysctl, 1) )
        ret = -EFAULT;

    return ret;
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
