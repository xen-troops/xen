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

#include "coproc_xxx.h"

/* the amount of time to wait for the particular coproc */
static s_time_t coproc_wait_time = MILLISECS(500);

#define DT_MATCH_COPROC_XXX DT_MATCH_COMPATIBLE("vendor_xxx,coproc_xxx")

int vcoproc_xxx_read(struct vcpu *v, mmio_info_t *info, register_t *r,
                            void *priv)
{
    struct vcoproc_mmio *mmio = priv;
    struct vcoproc_rw_context ctx;
    struct mcoproc_device *mcoproc;

    vcoproc_get_rw_context(v->domain, mmio, info, &ctx);
    mcoproc = ctx.vcoproc->mcoproc;
    COPROC_DEBUG(mcoproc->dev, "domain %u, read r%d=%"PRIregister
                 " offset %#08x base %#08x\n", v->domain->domain_id,
                 ctx.dabt.reg, *r, ctx.offset, (uint32_t)mmio->addr);

    return 1;
}

int vcoproc_xxx_write(struct vcpu *v, mmio_info_t *info, register_t r,
                             void *priv)
{
    struct vcoproc_mmio *mmio = priv;
    struct vcoproc_rw_context ctx;
    struct mcoproc_device *mcoproc;

    vcoproc_get_rw_context(v->domain, mmio, info, &ctx);
    mcoproc = ctx.vcoproc->mcoproc;
    COPROC_DEBUG(mcoproc->dev, "domain %u, write r%d=%"PRIregister
                 " offset %#08x base %#08x\n", v->domain->domain_id,
                 ctx.dabt.reg, r, ctx.offset, (uint32_t)mmio->addr);

#if 1
    /* for debug purposes */
#define COPROC_XXX_POWER_REG	0x10
#define CORPOC_XXX_ENABLE		(1 << 0)

    if ( ctx.offset == COPROC_XXX_POWER_REG )
    {
        int i;

        /* Just inject all irqs that coproc has */
        for ( i = 0; i < mcoproc->num_irqs; i++ )
            vgic_vcpu_inject_spi(ctx.vcoproc->domain, mcoproc->irqs[i].irq);

        if ( r & CORPOC_XXX_ENABLE )
            vcoproc_scheduler_vcoproc_wake(mcoproc->sched, ctx.vcoproc);
        else
            vcoproc_scheduler_vcoproc_sleep(mcoproc->sched, ctx.vcoproc);
    }
#endif

    return 1;
}

static struct mmio_handler_ops vcoproc_xxx_mmio_handler = {
    .read = vcoproc_xxx_read,
    .write = vcoproc_xxx_write,
};

static struct pcoproc_mmio coproc_xxx_mmio[] = {
    {
        .size = 0,
        .ops = &vcoproc_xxx_mmio_handler,
    },
};

void coproc_xxx_irq_handler(int irq, void *dev,
                                   struct cpu_user_regs *regs)
{
    struct mcoproc_device *coproc_xxx = dev;

    (void)coproc_xxx;
}

static struct pcoproc_irq coproc_xxx_irq[] = {
    {
        .handler = coproc_xxx_irq_handler,
    },
};

static const struct pcoproc_desc coproc_xxx_desc = {
    .p_mmio_num = ARRAY_SIZE(coproc_xxx_mmio),
    .p_mmio = coproc_xxx_mmio,
    .p_irq_num = ARRAY_SIZE(coproc_xxx_irq),
    .p_irq = coproc_xxx_irq,
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

static int vcoproc_xxx_vcoproc_init(struct vcoproc_instance *vcoproc)
{
    /* nothing to do */
    return 0;
}

static void vcoproc_xxx_vcoproc_deinit(struct vcoproc_instance *vcoproc_xxx)
{
    /* nothing to do */
}

struct coproc_ops vcoproc_xxx_vcoproc_ops = {
    .vcoproc_init        = vcoproc_xxx_vcoproc_init,
    .vcoproc_deinit      = vcoproc_xxx_vcoproc_deinit,
    .ctx_switch_from     = vcoproc_xxx_ctx_switch_from,
    .ctx_switch_to       = vcoproc_xxx_ctx_switch_to,
};

static int coproc_xxx_dt_probe(struct dt_device_node *np)
{
    struct mcoproc_device *coproc_xxx;
    struct device *dev = &np->dev;
    int ret;

    coproc_xxx = coproc_alloc(np,  &coproc_xxx_desc, &vcoproc_xxx_vcoproc_ops);
    if ( IS_ERR_OR_NULL(coproc_xxx) )
    {
        ret = PTR_ERR(coproc_xxx);
        COPROC_DEBUG(dev, "failed to allocate coproc (%d)\n", ret);
        return ret;
    }

    ret = coproc_register(coproc_xxx);
    if ( ret )
    {
        COPROC_DEBUG(dev, "failed to register coproc (%d)\n", ret);
        coproc_release(coproc_xxx);
        return ret;
    }

    return 0;
}

static const struct dt_device_match coproc_xxx_dt_match[] __initconst =
{
    DT_MATCH_COPROC_XXX,
    { /* sentinel */ },
};

static __init int coproc_xxx_init(struct dt_device_node *np, const void *data)
{
    /*TODO: Decide should we still need used by DOMID_XEN */
    dt_device_set_used_by(np, DOMID_XEN);

    return coproc_xxx_dt_probe(np);
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
