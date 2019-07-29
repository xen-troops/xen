/*
 * guest_pm.c
 *
 * Per-guest power management options
 *
 * Copyright (C) 2019 EPAM Systems
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

#include <xen/guest_pm.h>
#include <xen/notifier.h>
#include <xen/sched.h>
#include <xen/spinlock.h>
#include <asm/vscmi.h>
#include <public/domctl.h>

static DEFINE_SPINLOCK(add_remove_lock);
static NOTIFIER_HEAD(guest_pm_chain);

void register_guest_pm_notifier(struct notifier_block *nb)
{
    spin_lock(&add_remove_lock);
    notifier_chain_register(&guest_pm_chain, nb);
    spin_unlock(&add_remove_lock);
}

int guest_pm_init_domain(struct domain *d)
{
    /* By default PM control is disabled for the guest */
    d->pm.enabled = false;
    d->pm.opp_min = UINT8_MAX;
    d->pm.opp_max = 0;

    return 0;
}

int guest_pm_hadle_op(struct domain *d, struct xen_domctl_pm_op *pm_op)
{
    switch ( pm_op->cmd )
    {
    case XEN_DOMCTL_PM_OP_GET_CONFIG:
        pm_op->flags = d->pm.enabled ? XEN_DOMCTL_PM_OP_FLAG_ENABLED : 0;
        pm_op->opp_min = d->pm.opp_min;
        pm_op->opp_max = d->pm.opp_max;
        return 0;

    case XEN_DOMCTL_PM_OP_SET_CONFIG:
        if ( pm_op->flags & ~XEN_DOMCTL_PM_OP_FLAG_ENABLED )
        {
            gprintk(XENLOG_WARNING, "Unknown guest pm flags: 0x%X\n",
                    pm_op->flags);
            return -EINVAL;
        }

        if ( pm_op->flags & XEN_DOMCTL_PM_OP_FLAG_ENABLED )
        {
            if ( pm_op->opp_max > XEN_DOMCTL_PM_OP_OPP_LIMIT )
            {
                gprintk(XENLOG_WARNING, "Max OPP is above the limit: %d\n",
                        pm_op->opp_max);
                return -EINVAL;
            }
            d->pm.enabled = true;
            d->pm.opp_min = pm_op->opp_min;
            d->pm.opp_max = pm_op->opp_max;
        }
        else
        {
            d->pm.enabled = false;
            d->pm.opp_min = UINT8_MAX;
            d->pm.opp_max = 0;
        }

        notifier_call_chain(&guest_pm_chain, 0, d, NULL);

        return 0;

    default:
        gprintk(XENLOG_WARNING, "Unknown guest pm op %d\n", pm_op->cmd);
        return -EINVAL;
    }
}

uint8_t guest_pm_clamp_opp(struct domain *d, uint8_t opp)
{
    if ( !d->pm.enabled )
        return 0;

    if ( opp < d->pm.opp_min )
        return d->pm.opp_min;

    if ( opp > d->pm.opp_max )
        return d->pm.opp_max;

    return opp;
}

void guest_pm_force_enable(struct domain *d)
{
    if ( d->pm.enabled )
        return;

    d->pm.enabled = true;
    d->pm.opp_min = 0;
    d->pm.opp_max = XEN_DOMCTL_PM_OP_OPP_LIMIT;
}

bool guest_pm_enabled(struct domain *d)
{
    return d->pm.enabled;
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
