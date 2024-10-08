/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Generic access-controller framework via the device tree
 *
 * Copyright (c) 2024 EPAM Systems
 */

#ifndef _ACCESSC_CONTROLLER_H_
#define _ACCESSC_CONTROLLER_H_

#include <xen/device_tree.h>
#include <xen/sched.h>

/* Access-controller driver ops */
struct ac_ops {
    /* Set device to act as an access-controller */
    int (*assign_device)(struct dt_device_node *dev,
                         struct dt_phandle_args *ac_spec,
                         struct domain *d);
    /* Remove previously added access-controller device */
    int (*deassign_device)(struct dt_device_node *dev,
                           struct dt_phandle_args *ac_spec,
                           struct domain *d);
};

/*
 * Register access-controller device.
 * Access-controller device is responsible to handle
 * hardware access to the different domains.
 */
int ac_register(struct dt_device_node *dev, struct ac_ops *ops);

/*
 * Unregister access controller device.
 * Remove device from access-controller list.
 */
int ac_assign_dt_device(struct dt_device_node *dev, struct domain *d);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
