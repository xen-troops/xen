/******************************************************************************
 * arch/x86/x86_64/domain.c
 *
 */

#include <xen/types.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <compat/vcpu.h>

#define xen_vcpu_get_physid vcpu_get_physid
CHECK_vcpu_get_physid;
#undef xen_vcpu_get_physid

int
arch_compat_vcpu_op(
    int cmd, struct vcpu *v, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    int rc = -ENOSYS;

    switch ( cmd )
    {
    case VCPUOP_register_runstate_memory_area:
    {
        union {
            struct compat_vcpu_register_runstate_memory_area compat;
            struct vcpu_register_runstate_memory_area native;
        } area = { };

        rc = -EFAULT;
        if ( copy_from_guest(&area.compat.addr.v, arg, 1) )
            break;

        unmap_runstate_area(v);
        rc = map_runstate_area(v, &area.native);
        if ( rc )
            break;

        update_runstate_area(v);

        break;
    }

    case VCPUOP_get_physid:
        rc = arch_do_vcpu_op(cmd, v, arg);
        break;
    }

    return rc;
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
