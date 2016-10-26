/*
 * xen/arch/arm/coproc/coproc.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/init.h>
#include <xen/sched.h>
#include <xen/list.h>
#include <asm/device.h>

#include "coproc.h"

static DEFINE_SPINLOCK(coproc_devices_lock);
static LIST_HEAD(coproc_devices);
static int num_coprocs_devices;

int vcoproc_context_switch(struct vcoproc_info *prev, struct vcoproc_info *next)
{
    struct coproc_device *coproc;
    int ret = 0;

    if ( unlikely(prev == next) )
        return 0;

    coproc = next ? next->coproc : prev->coproc;

    if ( coproc->ops && coproc->ops->ctx_switch_from )
    {
        ret = coproc->ops->ctx_switch_from(prev);
        if ( ret )
            return ret;
    }

    if ( coproc->ops && coproc->ops->ctx_switch_to )
    {
        ret = coproc->ops->ctx_switch_to(next);
        if ( ret )
            panic("Could not switch context to coproc %s\n", coproc->name);
    }

    return ret;
}

void vcoproc_continue_running(struct vcoproc_info *same)
{
    /* nothing to do */
}

int vcoproc_attach(struct domain *d, struct vcoproc_info *info)
{
    struct vcoproc *vcoproc = &d->arch.vcoproc;
    struct vcoproc_instance *instance;

    if ( !info )
        return -EINVAL;

    BUG_ON(vcoproc->num_instances >= num_coprocs_devices);

    instance = &vcoproc->instances[vcoproc->num_instances];
    instance->idx = vcoproc->num_instances;
    instance->info = info;
    vcoproc->num_instances++;

    printk("Attached vcoproc %s to domain %d\n", info->coproc->name, d->domain_id);

    return 0;
}

static int vcoproc_preinit(struct domain *d)
{
    struct vcoproc *vcoproc = &d->arch.vcoproc;
    struct coproc_device *coproc;

    if ( !num_coprocs_devices )
    {
        printk("There is no registered coprocs for creating vcoproc\n");
        return -ENODEV;
    }

    vcoproc->instances = xzalloc_array(struct vcoproc_instance, num_coprocs_devices);
    if ( !vcoproc->instances )
        return -ENOMEM;
    spin_lock_init(&vcoproc->lock);

    /* For the moment, we'll create vcoproc for each registered coproc */
    spin_lock(&coproc_devices_lock);
    list_for_each_entry(coproc, &coproc_devices, list)
    {
        if ( coproc->ops && coproc->ops->vcoproc_init )
            coproc->ops->vcoproc_init(d, coproc);
    }
    spin_unlock(&coproc_devices_lock);

    return 0;
}

int domain_vcoproc_init(struct domain *d)
{
    struct vcoproc *vcoproc = &d->arch.vcoproc;
    struct vcoproc_info *info;
    int i, ret;

    vcoproc->num_instances = 0;

    ret = vcoproc_preinit(d);
    if ( ret )
        return ret;

    BUG_ON(!vcoproc->num_instances);

    for ( i = 0; i < vcoproc->num_instances; ++i )
    {
        info = vcoproc->instances[i].info;
        if ( info->ops && info->ops->domain_init )
        {
            ret = info->ops->domain_init(d, info);
            if ( ret )
                return ret;
        }
    }

    return 0;
}

void domain_vcoproc_free(struct domain *d)
{
    struct vcoproc *vcoproc = &d->arch.vcoproc;
    struct vcoproc_info *info;
    struct coproc_device *coproc;
    int i;

    for ( i = 0; i < vcoproc->num_instances; ++i )
    {
        info = vcoproc->instances[i].info;
        if ( info->ops && info->ops->domain_free )
            info->ops->domain_free(d, info);
        coproc = info->coproc;
        if ( coproc->ops && coproc->ops->vcoproc_free )
            coproc->ops->vcoproc_free(d, info);
    }

    vcoproc->num_instances = 0;
    xfree(vcoproc->instances);
}

static const struct coproc_device *find_coproc_by_name(const char *name)
{
    struct coproc_device *coproc;
    bool found = false;

    if ( !name )
        return NULL;

    spin_lock(&coproc_devices_lock);
    list_for_each_entry(coproc, &coproc_devices, list)
    {
        if ( !strcmp(coproc->name, name) )
        {
            found = true;
            break;
        }
    }
    spin_unlock(&coproc_devices_lock);

    return (found) ? coproc : NULL;
}

int __init coproc_register(struct coproc_device *coproc)
{
    if ( !coproc )
        return -EINVAL;

    if ( find_coproc_by_name(coproc->name) )
        return -EEXIST;

    spin_lock(&coproc_devices_lock);
    list_add(&coproc->list, &coproc_devices);
    spin_unlock(&coproc_devices_lock);

    num_coprocs_devices++;

    printk("Registered new coproc %s\n", coproc->name);

    return 0;
}

void __init coproc_init(void)
{
    struct dt_device_node *node;
    unsigned int num_coprocs = 0;
    int ret;

    /* For the moment, we'll create coproc for each device that presents in device tree */
    dt_for_each_device_node(dt_host, node)
    {
        ret = device_init(node, DEVICE_COPROC, NULL);
        if ( !ret )
            num_coprocs++;
    }

    if ( !num_coprocs )
        printk("Unable to find compatible coprocs in the device tree\n");
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
