/*
 * guest_pm.h
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
 * License along with this program; If not, see <http://www.gnu.org/
 */

#ifndef __XEN_GUEST_PM_H__
#define __XEN_GUEST_PM_H__

#include <xen/notifier.h>
#include <public/domctl.h>

struct guest_pm {
    bool enabled;
    uint8_t opp_min;
    uint8_t opp_max;
};

void register_guest_pm_notifier(struct notifier_block *nb);
int guest_pm_init_domain(struct domain *d);
int guest_pm_hadle_op(struct domain *d, struct xen_domctl_pm_op *pm_op);
uint8_t guest_pm_clamp_opp(struct domain *d, uint8_t opp);
void guest_pm_force_enable(struct domain *d);
bool guest_pm_enabled(struct domain *d);

#endif  /* __XEN_GUEST_PM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
