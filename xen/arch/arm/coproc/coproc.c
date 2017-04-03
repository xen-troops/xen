/*
 * xen/arch/arm/coproc/coproc.c
 *
 * Generic Remote processors framework
 *
 * Oleksandr Tyshchenko <Oleksandr_Tyshchenko@epam.com>
 * Copyright (C) 2016 EPAM Systems Inc.
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
#include <xen/err.h>
#include <xen/guest_access.h>
#include <xen/keyhandler.h>
#include <xen/vmap.h>
#include <xen/libfdt/libfdt.h>

#include "coproc.h"

/*
 * the "framework's" global list is used to keep track
 * of all coproc devices that have been registered in the framework
 */
static LIST_HEAD(coprocs);
/* to protect both operations with the coproc and global coprocs list here */
static DEFINE_SPINLOCK(coprocs_lock);

void vcoproc_continue_running(struct vcoproc_instance *same)
{
    /* nothing to do */
}

static struct mcoproc_device *mcoproc_find_by_path(const char *path)
{
    struct mcoproc_device *coproc;
    bool_t found = false;

    if ( !path )
        return NULL;

    spin_lock(&coprocs_lock);

    if ( list_empty(&coprocs) )
        goto out;

    list_for_each_entry(coproc, &coprocs, coproc_elem)
    {
        if ( !strncmp(dev_path(coproc->dev), path, strlen(path)) )
        {
            found = true;
            break;
        }
    }

out:
    spin_unlock(&coprocs_lock);

    return found ? coproc : NULL;
}

static struct vcoproc_instance *
coproc_init_vcoproc(struct domain *d, struct mcoproc_device *mcoproc,
                    const struct dt_device_node *np_vcoproc)
{
    struct vcoproc_instance *vcoproc;
    int ret = 0;
    int i;

    vcoproc = xzalloc(struct vcoproc_instance);
    if ( !vcoproc )
    {
        printk("Failed to allocate vcoproc_instance for %s\n",
               dev_path(mcoproc->dev));
        return ERR_PTR(-ENOMEM);
    }

    vcoproc->mcoproc = mcoproc;
    vcoproc->domain = d;
    vcoproc->state = VCOPROC_UNKNOWN;
    spin_lock_init(&vcoproc->lock);

    vcoproc->num_mmios = dt_number_of_address(np_vcoproc);

    if ( vcoproc->num_mmios != mcoproc->num_mmios )
    {
        printk("MMIO num mistmatch for \"%s\", %u vs %u\n",
               dt_node_full_name(np_vcoproc), vcoproc->num_mmios,
               mcoproc->num_mmios);
        ret = -ENODEV;
        goto err;
    }

    vcoproc->mmios = xzalloc_array(struct vcoproc_mmio, vcoproc->num_mmios );
    if ( !vcoproc->mmios )
    {
        printk("Failed to allocate %d mmio(s) for \"%s\"\n", vcoproc->num_mmios,
               dev_path(mcoproc->dev));
        ret = -ENOMEM;
        goto err;
    }

    for ( i = 0; vcoproc->num_mmios > i; i++ )
    {
        struct mcoproc_mmio *m_mmio = &mcoproc->mmios[i];
        struct pcoproc_mmio *p_mmio = m_mmio->p_mmio;
        u64 size;
        int index = dt_property_match_string(np_vcoproc, "reg-names",
                                             p_mmio->name);

        vcoproc->mmios[i].vcoproc = vcoproc;

        if (index < 0)
        {
            if ( vcoproc->num_mmios > 1 )
            {
                printk("More than one mmio and failed name match for %s\n",
                       dev_path(mcoproc->dev));
                goto err;
            }
            else
                index = 0;
        }

        ret = dt_device_get_address(np_vcoproc, index,
                                    &vcoproc->mmios[i].addr,
                                    &size);
        if ( ret )
        {
            printk("Unable to retrieve address %u for %s\n",
                   0, dev_path(mcoproc->dev));
            goto err;
        }
        if ( size != m_mmio->size )
        {
            printk("MMIO size mistmatch for \"%s\"\n",
                   dt_node_full_name(np_vcoproc));
            ret = -ENODEV;
            goto err;
        }
        vcoproc->mmios[i].m_mmio = m_mmio;
        printk("Register MMIO handler: domain %d, vcoproc %s, addr %"PRIX64", "
               "size %"PRIX64"\n", vcoproc->domain->domain_id,
               dt_node_full_name(np_vcoproc), vcoproc->mmios[i].addr, size);
        register_mmio_handler(vcoproc->domain,
                              p_mmio->ops,
                              vcoproc->mmios[i].addr,
                              size,
                              &vcoproc->mmios[i]);
    }
/*  TODO: Decide if we need to do something with IRQ here */

    ret = mcoproc->ops->vcoproc_init(vcoproc);
    if ( ret )
    {
        printk("Failed to initialize vcoproc_instance for %s\n",
               dev_path(mcoproc->dev));
        goto err;
    }

    spin_lock(&mcoproc->vcoprocs_lock);
    list_add(&vcoproc->vcoproc_elem, &mcoproc->vcoprocs);
    spin_unlock(&mcoproc->vcoprocs_lock);

    return vcoproc;

err:
    xfree(vcoproc->mmios);
    xfree(vcoproc);
    return ERR_PTR(ret);
}

static void coproc_deinit_vcoproc(struct vcoproc_instance *vcoproc)
{
    struct mcoproc_device *mcoproc;

    if ( !vcoproc )
        return;

    mcoproc = vcoproc->mcoproc;
    spin_lock(&mcoproc->vcoprocs_lock);
    list_del(&vcoproc->vcoproc_elem);
    spin_unlock(&mcoproc->vcoprocs_lock);
    mcoproc->ops->vcoproc_deinit(vcoproc);
    xfree(vcoproc);
}

static int vcoproc_spawn(struct domain *d,
                         struct mcoproc_device *mcoproc,
                         const struct dt_device_node *np_vcoproc)
{
    struct vcoproc *vcoproc_d = &d->arch.vcoproc;
    struct vcoproc_instance *vcoproc;
    int ret;

    if ( !mcoproc )
        return -EINVAL;

    spin_lock(&coprocs_lock);

    vcoproc = coproc_init_vcoproc(d, mcoproc, np_vcoproc);
    if ( IS_ERR(vcoproc) )
    {
        printk("coproc_init_vcoproc failed\n");
        ret = PTR_ERR(vcoproc);
        goto out;
    }

    ret = vcoproc_scheduler_vcoproc_init(mcoproc->sched, vcoproc);
    if ( ret )
    {
        coproc_deinit_vcoproc(vcoproc);
        goto out;
    }

    list_add_tail(&vcoproc->instance_elem, &vcoproc_d->instances);
    vcoproc_d->num_instances++;

    printk("Spawned vcoproc \"%s\" for dom%u\n",
           dt_node_full_name(np_vcoproc), d->domain_id);

out:
    spin_unlock(&coprocs_lock);

    return ret;
}

static int vcoproc_spawn_path(struct domain *d, const char *path,
                              const struct dt_device_node *np_vcoproc)
{
    struct mcoproc_device *mcoproc;

    mcoproc = mcoproc_find_by_path(path);
    if ( !mcoproc )
    {
        printk("coproc %s is not found\n", path);
        return -ENODEV;
    }

    return vcoproc_spawn(d, mcoproc, np_vcoproc);
}

static int vcoproc_make_node(const struct domain *d, void *fdt,
                             const struct dt_device_node *cnode,
                             const struct dt_device_node *vnode)
{
    const struct dt_property *cprop, *vprop;
    const char *name, *path;
    int ret = 0;

    path = dt_node_full_name(vnode);
    name = strrchr(path, '/');
    name = name ? name + 1 : path;

    ret = fdt_begin_node(fdt, name);
    if ( ret )
        return ret;

    /*
     * Run through the coproc's properties,
     * search for the same property in vcoproc, if found in vcoproc
     * copy value property from vcoproc, otherwise from coproc. With
     * some exceptions.
     */
    dt_for_each_property_node (cnode, cprop)
    {
        const void *prop_data = cprop->value;
        u32 prop_len = cprop->length;

        /* Don't expose the property "xen,coproc" to the guest */
        if ( dt_property_name_is_equal(cprop, "xen,coproc") )
            continue;

        /* Copy interrupts from the real coproc solely*/
        if ( dt_property_name_is_equal(cprop, "interrupts")
             || dt_property_name_is_equal(cprop, "interrupt-names") )
        {
            ret = fdt_property(fdt, cprop->name, prop_data, prop_len);
            if ( ret )
                return ret;
            continue;
        }

        dt_for_each_property_node (vnode, vprop) 
        {
            if ( dt_property_name_is_equal(vprop, cprop->name) )
            {
                prop_data = vprop->value;
                prop_len = vprop->length;
            }
        }

        ret = fdt_property(fdt, cprop->name, prop_data, prop_len);
        if ( ret )
            return ret;
    }

    ret = fdt_end_node(fdt);

    dprintk(XENLOG_INFO, "Created vcoproc node \"%s\"\n", name);
    return ret;
}

int vcoproc_handle_node(struct domain *d, void *fdt,
                              const struct dt_device_node *node)
{
    int ret;
    const char *path;
    const struct dt_device_node *cnode;

    ret = dt_property_read_string(node, "xen,vcoproc", &path);
    if ( ret )
    {
        printk("Node is not a vcoproc description node\n");
        return -EINVAL;
    }

    dprintk(XENLOG_INFO, "Handle vcoproc node %s\n", dt_node_full_name(node));
    dprintk(XENLOG_INFO, "\txen,vcoproc = \"%s\"\n", path);

    if ( *path == '/' )
        cnode = dt_find_node_by_path(path);
    else
    {
        cnode = dt_find_node_by_alias(path);
        path = dt_node_full_name(cnode);
    }

    if ( cnode == NULL )
    {
        printk("Vcoproc node does not refer a coproc node\n");
        return -EINVAL;
    }

    ret = vcoproc_spawn_path(d, path, node);
    if ( ret )
        return ret;

    if ( fdt != NULL )
        ret = vcoproc_make_node(d, fdt, cnode, node);

    return ret;
}

static int vcoproc_browse_node(struct domain *d,
                               const struct dt_device_node *node)
{
    struct dt_device_node *child;
    int ret;

    if ( dt_device_is_vcoproc(node) )
    {
        return vcoproc_handle_node(d, NULL, node);
    }

    for ( child = node->child; child != NULL; child = child->sibling )
    {
        ret = vcoproc_browse_node(d, child);
        if ( ret )
            return ret;
    }

    return 0;
}

static int vcoproc_eliminate(struct domain *d,
                             struct vcoproc_instance *vcoproc)
{
    struct vcoproc *vcoproc_d = &d->arch.vcoproc;
    struct mcoproc_device *mcoproc;
    int ret;

    if ( !vcoproc )
        return 0;

    spin_lock(&coprocs_lock);

    mcoproc = vcoproc->mcoproc;

    ret = vcoproc_scheduler_vcoproc_destroy(mcoproc->sched, vcoproc);
    if ( ret )
    {
        if ( ret == -EBUSY )
            ret = -ERESTART;
        goto out;
    }

    BUG_ON(!vcoproc_d->num_instances);
    list_del_init(&vcoproc->instance_elem);
    vcoproc_d->num_instances--;

    coproc_deinit_vcoproc(vcoproc);

    dprintk(XENLOG_INFO, "Destroyed vcoproc \"%s\" for dom%u\n",
            dev_path(mcoproc->dev), d->domain_id);

out:
    spin_unlock(&coprocs_lock);

    return ret;
}

static int mcoproc_acquire_mmios(struct mcoproc_device *mcoproc,
                                 const struct pcoproc_desc *desc)
{
    int i;
    int ret = 0;
    u32 num_mmios;
    struct dt_device_node *np = dev_to_dt(mcoproc->dev);

    num_mmios = dt_number_of_address(np);

    if ( !num_mmios )
    {
        printk("Failed to find at least one mmio for \"%s\"\n",
               dev_path(mcoproc->dev));
        ret = -ENODEV;
        goto out;
    }

    if ( num_mmios != desc->p_mmio_num )
    {
        printk("MMIO num mistmatch for \"%s\"\n",
               dev_path(mcoproc->dev));
        ret = -ENODEV;
        goto out;
    }

    mcoproc->mmios = xzalloc_array(struct mcoproc_mmio, num_mmios);
    if ( !mcoproc->mmios )
    {
        printk("Failed to allocate %d mmio(s) for \"%s\"\n", num_mmios,
               dev_path(mcoproc->dev));
        ret = -ENOMEM;
        goto out;
    }

    for ( i = 0; i < num_mmios; ++i )
    {
        struct mcoproc_mmio *m_mmio = &mcoproc->mmios[i];
        struct pcoproc_mmio *p_mmio = &desc->p_mmio[i];
        int index = dt_property_match_string(np, "reg-names", p_mmio->name);

        if (index < 0)
        {
            if ( num_mmios > 1 )
            {
                printk("More than one mmio and failed name match for %s\n",
                       dev_path(mcoproc->dev));
                goto out;
            }
            else
                index = 0;
        }

        ret = dt_device_get_address(np, index, &m_mmio->addr, &m_mmio->size);
        if ( ret )
        {
            printk("Failed to get single mmio range for \"%s\"\n",
                   dev_path(mcoproc->dev));
            goto out;
        }

        if (p_mmio->size && p_mmio->size != m_mmio->size)
        {
            printk("MMIO size mistmatch for \"%s\"\n",
                   dev_path(mcoproc->dev));
            ret = -ENODEV;
            goto out;
        }

        m_mmio->base = ioremap_nocache(m_mmio->addr, m_mmio->size);
        if ( IS_ERR(m_mmio->base) )
        {
            printk("Failed to remap single mmio range for \"%s\"\n",
                   dev_path(mcoproc->dev));
            ret = -ENOMEM;
            goto out;
        }
        m_mmio->p_mmio = p_mmio;
    }

    mcoproc->num_mmios = num_mmios;

out:
    return ret;
}

static int mcoproc_acquire_irqs(struct mcoproc_device *mcoproc,
                                 const struct pcoproc_desc *desc)
{
    int i;
    int ret = 0;
    unsigned int num_irqs;
    struct dt_device_node *np = dev_to_dt(mcoproc->dev);

    num_irqs = dt_number_of_irq(np);

    if ( !num_irqs )
    {
        printk("Failed to find at least one irq for \"%s\"\n",
               dev_path(mcoproc->dev));
        ret = -ENODEV;
        goto out;
    }

    if ( num_irqs != desc->p_irq_num )
    {
        printk("IRQ num mistmatch for \"%s\"\n",
               dev_path(mcoproc->dev));
        ret = -ENODEV;
        goto out;
    }

    mcoproc->irqs = xzalloc_array(struct mcoproc_irq, num_irqs);
    if ( !mcoproc->irqs )
    {
        printk("Failed to allocate %d irq(s) for \"%s\"\n", num_irqs,
               dev_path(mcoproc->dev));
        ret = -ENOMEM;
        goto out;
    }

    for ( i = 0; i < num_irqs; ++i )
    {
        struct pcoproc_irq *p_irq = &desc->p_irq[i];
        struct mcoproc_irq *m_irq = &mcoproc->irqs[i];
        int index = dt_property_match_string(np, "interrupt-names",
                                             p_irq->name);
        int irq;

        if (index < 0)
        {
            if ( num_irqs > 1 )
            {
                printk("More than one irq and failed name match for %s\n",
                       dev_path(mcoproc->dev));
                goto out;
            }
            else
                index = 0;
        }

        irq = platform_get_irq(np, index);
        if ( irq < 0 )
        {
            printk("Failed to get irq index %d for \"%s\"\n", 0,
                   dev_path(mcoproc->dev));
            ret = -ENODEV;
            goto out;
        }
        ret = request_irq(irq,
                          IRQF_SHARED,
                          p_irq->handler,
                          p_irq->name,
                          mcoproc);
        if ( ret )
        {
            printk("Failed to request irq %d for \"%s\"\n", irq,
                   dev_path(mcoproc->dev));
            ret = -ENODEV;
            goto out;
        }
        m_irq->irq = irq;
        m_irq->p_irq = p_irq;
    }

    mcoproc->num_irqs = num_irqs;

out:
    return ret;
}

struct mcoproc_device *coproc_alloc(struct dt_device_node *np,
                                    const struct pcoproc_desc *desc,
                                    const struct coproc_ops *ops)
{
    struct mcoproc_device *mcoproc;
    struct device *dev = &np->dev;
    int ret = 0;

    mcoproc = xzalloc(struct mcoproc_device);
    if ( !mcoproc )
    {
        printk("Failed to allocate mcoproc_device for \"%s\"\n",
               dev_path(dev));
        return ERR_PTR(-ENOMEM);
    }
    mcoproc->dev = dev;

    ret = mcoproc_acquire_mmios(mcoproc, desc);
    if ( ret )
        goto out;

    ret = mcoproc_acquire_irqs(mcoproc, desc);
    if ( ret )
        goto out;

    INIT_LIST_HEAD(&mcoproc->vcoprocs);
    spin_lock_init(&mcoproc->vcoprocs_lock);
    mcoproc->ops = ops;

    return mcoproc;

out:
    coproc_release(mcoproc);
    return ERR_PTR(ret);
}

void coproc_release(struct mcoproc_device *mcoproc)
{
    int i;

    if ( IS_ERR_OR_NULL(mcoproc) )
        return;

    for ( i = 0; i < mcoproc->num_irqs; i++ )
        if ( mcoproc->irqs[i].irq )
            release_irq(mcoproc->irqs[i].irq, mcoproc);

    for ( i = 0; i < mcoproc->num_mmios; i++ )
        if ( !IS_ERR_OR_NULL(mcoproc->mmios[i].base) )
            iounmap(mcoproc->mmios[i].base);

    xfree(mcoproc->irqs);
    xfree(mcoproc->mmios);
    xfree(mcoproc);
}

int vcoproc_domain_init(struct domain *d)
{
    struct vcoproc *vcoproc_d = &d->arch.vcoproc;
    int ret = 0;

    vcoproc_d->num_instances = 0;
    INIT_LIST_HEAD(&vcoproc_d->instances);

    return ret;
}

void vcoproc_domain_free(struct domain *d)
{
    coproc_release_vcoprocs(d);
}

int coproc_release_vcoprocs(struct domain *d)
{
    struct vcoproc *vcoproc_d = &d->arch.vcoproc;
    struct vcoproc_instance *vcoproc, *temp;
    int ret;

    list_for_each_entry_safe( vcoproc, temp, &vcoproc_d->instances,
                              instance_elem )
    {
        ret = vcoproc_eliminate(d, vcoproc);
        if ( ret )
            return ret;
    }

    return 0;
}

int coproc_do_domctl(struct xen_domctl *domctl, struct domain *d,
                     XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    void *fdt, *raw;
    int ret = 0;
    struct dt_device_node *pdt;

    switch ( domctl->cmd )
    {
    case XEN_DOMCTL_browse_pfdt:
        if ( unlikely(d->is_dying) )
        {
            ret = -EINVAL;
            break;
        }

        fdt = xmalloc_bytes(domctl->u.attach_coproc.size);

        if ( !fdt )
        {
            ret = -ENOMEM;
            break;
        }

        ret = copy_from_guest(fdt, domctl->u.attach_coproc.fdt,
                              domctl->u.attach_coproc.size);

        if ( ret )
        {
            xfree(fdt);
            break;
        }

        dprintk(XENLOG_INFO, "Got pfdt with size %u for dom%u\n",
                domctl->u.attach_coproc.size, d->domain_id);

        raw = dt_unflatten_device_tree(fdt, &pdt);

        if ( raw )
        {
            ret = vcoproc_browse_node(d, pdt);
            if ( ret )
                printk("Failed to attach vcoprocs from pfdt to dom%u (%d)\n",
                       d->domain_id, ret);
            xfree(raw);
        }
        else
            ret = -ENOMEM;

        xfree(fdt);

        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

int __init coproc_register(struct mcoproc_device *mcoproc)
{
    if ( !mcoproc || !mcoproc->ops )
        return -EINVAL;

    if ( mcoproc_find_by_path(dev_path(mcoproc->dev)) )
        return -EEXIST;

    mcoproc->sched = vcoproc_scheduler_init(mcoproc);
    if ( IS_ERR(mcoproc->sched) )
        return PTR_ERR(mcoproc->sched);

    spin_lock(&coprocs_lock);
    list_add_tail(&mcoproc->coproc_elem, &coprocs);
    spin_unlock(&coprocs_lock);

    dprintk(XENLOG_INFO, "Registered new coproc \"%s\"\n",
            dev_path(mcoproc->dev));

    return 0;
}

int coproc_debug = COPROC_DBG_ERROR;

void coproc_debug_toggle(unsigned char key)
{
    if ( key == 'c' )
    {
        /* FIXME: this corresponds to XENLOG_DEBUG */
        if ( coproc_debug < COPROC_DBG_LAST )
            coproc_debug++;
    }
    else
    {
        if ( coproc_debug > 0 )
            coproc_debug--;
    }
    printk("coproc debug level is %d\n", coproc_debug);
}

void __init coproc_init(void)
{
    struct dt_device_node *node;
    int ret;

    register_keyhandler('c', coproc_debug_toggle,
                        "increase debug level for coproc", 0);
    register_keyhandler('v', coproc_debug_toggle,
                        "decrease debug level for coproc", 0);

    /*
     * For the moment, we'll create coproc for each device that presents
     * in the device tree and has "xen,coproc" property.
     */
    dt_for_each_device_node(dt_host, node)
    {
        if ( !dt_device_for_scf(node) )
            continue;

        ret = device_init(node, DEVICE_COPROC, NULL);
        if ( ret )
            printk("SCF driver missed for %s\n", dt_node_full_name(node) );
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
