/*
 * arch/arm/hvm.c
 *
 * Arch-specific hardware virtual machine abstractions.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/sched.h>
#include <xen/monitor.h>

#include <xsm/xsm.h>

#include <public/xen.h>
#include <public/hvm/params.h>
#include <public/hvm/hvm_op.h>

#include <asm/hypercall.h>

static int hvm_allow_set_param(const struct domain *d, unsigned int param)
{
    switch ( param )
    {
        /*
         * The following parameters are intended for toolstack usage only.
         * They may not be set by the domain.
         *
         * The {STORE,CONSOLE}_EVTCHN values will need to become read/write to
         * the guest (not just the toolstack) if a new ABI hasn't appeared by
         * the time migration support is added.
         */
    case HVM_PARAM_CALLBACK_IRQ:
    case HVM_PARAM_STORE_PFN:
    case HVM_PARAM_STORE_EVTCHN:
    case HVM_PARAM_CONSOLE_PFN:
    case HVM_PARAM_CONSOLE_EVTCHN:
    case HVM_PARAM_MONITOR_RING_PFN:
        return d == current->domain ? -EPERM : 0;

        /*
         * XXX Do we need to follow x86's logic here:
         * "The following parameters should only be changed once"?
         */
    case HVM_PARAM_IOREQ_SERVER_PFN:
    case HVM_PARAM_NR_IOREQ_SERVER_PAGES:
        return 0;

        /* Writeable only by Xen, hole, deprecated, or out-of-range. */
    default:
        return -EINVAL;
    }
}

static int hvm_allow_get_param(const struct domain *d, unsigned int param)
{
    switch ( param )
    {
        /* The following parameters can be read by the guest and toolstack. */
    case HVM_PARAM_CALLBACK_IRQ:
    case HVM_PARAM_STORE_PFN:
    case HVM_PARAM_STORE_EVTCHN:
    case HVM_PARAM_CONSOLE_PFN:
    case HVM_PARAM_CONSOLE_EVTCHN:
        return 0;

        /* XXX Can these be read by someone? What policy to apply? */
    case HVM_PARAM_IOREQ_SERVER_PFN:
    case HVM_PARAM_NR_IOREQ_SERVER_PAGES:
        return 0;

        /*
         * The following parameters are intended for toolstack usage only.
         * They may not be read by the domain.
         */
    case HVM_PARAM_MONITOR_RING_PFN:
        return d == current->domain ? -EPERM : 0;

        /* Hole, deprecated, or out-of-range. */
    default:
        return -EINVAL;
    }
}

static int hvmop_set_param(struct domain *d, const struct xen_hvm_param *a)
{
    int rc = 0;

    switch ( a->index )
    {
    case HVM_PARAM_IOREQ_SERVER_PFN:
        d->arch.hvm.ioreq_gfn.base = a->value;
        break;
    case HVM_PARAM_NR_IOREQ_SERVER_PAGES:
    {
        unsigned int i;

        if ( a->value == 0 ||
             a->value > sizeof(d->arch.hvm.ioreq_gfn.mask) * 8 )
        {
            rc = -EINVAL;
            break;
        }
        for ( i = 0; i < a->value; i++ )
            set_bit(i, &d->arch.hvm.ioreq_gfn.mask);

        break;
    }
    }

    d->arch.hvm.params[a->index] = a->value;

    return rc;
}

long do_hvm_op(unsigned long op, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    long rc = 0;

    switch ( op )
    {
    case HVMOP_set_param:
    case HVMOP_get_param:
    {
        struct xen_hvm_param a;
        struct domain *d;

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        d = rcu_lock_domain_by_any_id(a.domid);
        if ( d == NULL )
            return -ESRCH;

        rc = xsm_hvm_param(XSM_TARGET, d, op);
        if ( rc )
            goto param_fail;

        if ( op == HVMOP_set_param )
        {
            rc = hvm_allow_set_param(d, a.index);
            if ( rc )
                goto param_fail;

            rc = hvmop_set_param(d, &a);
        }
        else
        {
            rc = hvm_allow_get_param(d, a.index);
            if ( rc )
                goto param_fail;

            a.value = d->arch.hvm.params[a.index];
            printk("d%u: GET %u = %lu\n",
                   d->domain_id, a.index, a.value);
            rc = copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
        }

    param_fail:
        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_guest_request_vm_event:
        if ( guest_handle_is_null(arg) )
            monitor_guest_request();
        else
            rc = -EINVAL;
        break;

    default:
    {
        gdprintk(XENLOG_DEBUG, "HVMOP op=%lu: not implemented\n", op);
        rc = -ENOSYS;
        break;
    }
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
