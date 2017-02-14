/*
 * xen/arch/arm/coproc/plat/coproc_xxx.c
 *
 * COPROC_XXX platform specific code
 * based on xen/drivers/passthrough/arm/smmu.c
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
#include <xen/irq.h>
#include <xen/vmap.h>

#include "coproc_xxx.h"

/* TODO Some common code from here might be moved to framework */

/* the amount of time to wait for the particular coproc */
static s_time_t coproc_wait_time = MILLISECS(500);

#define DT_MATCH_COPROC_XXX DT_MATCH_COMPATIBLE("vendor_xxx,coproc_xxx")

static int vcoproc_xxx_read(struct vcpu *v, mmio_info_t *info, register_t *r,
                            void *priv)
{
    struct mmio *mmio = priv;
    struct vcoproc_rw_context ctx;

    vcoproc_get_rw_context(v->domain, mmio, info, &ctx);
    dev_dbg(ctx.coproc->dev, "read r%d=%"PRIregister" offset %#08x base %#08x\n",
            ctx.dabt.reg, *r, ctx.offset, (uint32_t)mmio->addr);

    return 1;
}

static int vcoproc_xxx_write(struct vcpu *v, mmio_info_t *info, register_t r,
                             void *priv)
{
    struct mmio *mmio = priv;
    struct vcoproc_rw_context ctx;

    vcoproc_get_rw_context(v->domain, mmio, info, &ctx);
    dev_dbg(ctx.coproc->dev, "write r%d=%"PRIregister" offset %#08x base %#08x\n",
            ctx.dabt.reg, r, ctx.offset, (uint32_t)mmio->addr);

#if 1
    /* for debug purposes */
#define COPROC_XXX_POWER_REG	0x10
#define CORPOC_XXX_ENABLE		(1 << 0)

    if ( ctx.offset == COPROC_XXX_POWER_REG )
    {
        int i;

        /* Just inject all irqs that coproc has */
        for ( i = 0; i < ctx.coproc->num_irqs; i++ )
            vgic_vcpu_inject_spi(ctx.vcoproc->domain, ctx.coproc->irqs[i]);

        if ( r & CORPOC_XXX_ENABLE )
            vcoproc_sheduler_vcoproc_wake(ctx.coproc->sched, ctx.vcoproc);
        else
            vcoproc_sheduler_vcoproc_sleep(ctx.coproc->sched, ctx.vcoproc);
    }
#endif

    return 1;
}

static const struct mmio_handler_ops vcoproc_xxx_mmio_handler = {
    .read = vcoproc_xxx_read,
    .write = vcoproc_xxx_write,
};

s_time_t vcoproc_xxx_ctx_switch_from(struct vcoproc_instance *curr)
{
    /* random for now */
    return NOW() & 1 ? coproc_wait_time : 0;
}

static int vcoproc_xxx_ctx_switch_to(struct vcoproc_instance *next)
{
    /* nothing to do */
    return 0;
}

static int vcoproc_xxx_vcoproc_init(struct domain *d,
                                    struct coproc_device *coproc,
                                    struct vcoproc_instance *vcoproc)
{
    int i;

    for ( i = 0; i < coproc->num_mmios; i++ )
    {
        struct mmio *mmio = &coproc->mmios[i];
        register_mmio_handler(d, &vcoproc_xxx_mmio_handler,
                              mmio->addr, mmio->size, mmio);
    }

    return 0;
}

static void vcoproc_xxx_vcoproc_deinit(struct domain *d,
                                       struct vcoproc_instance *vcoproc_xxx)
{
    /* nothing to do */
}

static const struct coproc_ops vcoproc_xxx_vcoproc_ops = {
    .vcoproc_init        = vcoproc_xxx_vcoproc_init,
    .vcoproc_deinit      = vcoproc_xxx_vcoproc_deinit,
    .ctx_switch_from     = vcoproc_xxx_ctx_switch_from,
    .ctx_switch_to       = vcoproc_xxx_ctx_switch_to,
};

static void coproc_xxx_irq_handler(int irq, void *dev,
                                   struct cpu_user_regs *regs)
{
    struct coproc_device *coproc_xxx = dev;

    (void)coproc_xxx;
}

static int coproc_xxx_dt_probe(struct platform_device *pdev)
{
    struct coproc_device *coproc_xxx;
    struct device *dev = &pdev->dev;
    int i, ret;

    coproc_xxx = coproc_alloc(pdev, &vcoproc_xxx_vcoproc_ops);
    if ( IS_ERR_OR_NULL(coproc_xxx) )
        return PTR_ERR(coproc_xxx);

    for ( i = 0; i < coproc_xxx->num_irqs; ++i )
    {
        ret = request_irq(coproc_xxx->irqs[i],
                         IRQF_SHARED,
                         coproc_xxx_irq_handler,
                         "coproc_xxx irq",
                         coproc_xxx);
        if ( ret )
        {
            dev_err(dev, "failed to request irq %d (%u)\n", i, coproc_xxx->irqs[i]);
            goto out_release_irqs;
        }
    }

    ret = coproc_register(coproc_xxx);
    if ( ret )
    {
        dev_err(dev, "failed to register coproc (%d)\n", ret);
        goto out_release_irqs;
    }

    return 0;

out_release_irqs:
    while ( i-- )
        release_irq(coproc_xxx->irqs[i], coproc_xxx);
    coproc_release(coproc_xxx);
    return ret;
}

static const struct dt_device_match coproc_xxx_dt_match[] __initconst =
{
    DT_MATCH_COPROC_XXX,
    { /* sentinel */ },
};

static __init int coproc_xxx_init(struct dt_device_node *dev, const void *data)
{
    int ret;

    dt_device_set_used_by(dev, DOMID_XEN);

    ret = coproc_xxx_dt_probe(dev);
    if ( ret )
        return ret;

    return 0;
}

DT_DEVICE_START(coproc_xxx, "COPROC_XXX", DEVICE_COPROC)
    .dt_match = coproc_xxx_dt_match,
    .init = coproc_xxx_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
