// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Generic access-controller framework via the device tree
 *
 * Copyright (c) 2024 EPAM Systems
 */

#include <xen/device_tree.h>
#include <xen/sched.h>
#include <xen/access_controller.h>
#include <xen/lib.h>

struct access_controller {
    struct dt_device_node *np;
    struct ac_ops *ops;
    struct list_head next;
};

LIST_HEAD(ac_list);

int ac_register(struct dt_device_node *np, struct ac_ops *ops)
{
    struct access_controller *ac;

    ac = xzalloc(struct access_controller);

    if ( !ac )
        return -ENOMEM;

    ac->np = np;
    ac->ops = ops;
    list_add(&ac->next, &ac_list);

    return 0;
}

static struct access_controller *ac_find(struct dt_device_node *np)
{
    struct access_controller *ac;

    list_for_each_entry(ac, &ac_list, next)
    {
        if ( ac->np == np )
            return ac;
    }

    return NULL;
}

int ac_assign_dt_device(struct dt_device_node *dev, struct domain *d)
{
    struct dt_phandle_args ac_spec;
    int index = 0;
    int ret;

    printk(XENLOG_DEBUG"ac assign device %s to %pd\n", dt_node_name(dev), d);

    while ( !dt_parse_phandle_with_args(dev, "access-controllers",
                                        "#access-controller-cells",
                                        index, &ac_spec) )
    {
        struct access_controller *ac = ac_find(ac_spec.np);

        if ( !ac )
        {
            printk(XENLOG_INFO
                   "ac: [%d] Could not find access-controller ops for %s\n",
                   d->domain_id, dt_node_name(dev));
            continue;
        }

        ret = ac->ops->assign_device(dev, &ac_spec, d);
        /* TODO: Remove added devices */
        if ( ret )
            return ret;

        index++;
    }

    return 0;
}
