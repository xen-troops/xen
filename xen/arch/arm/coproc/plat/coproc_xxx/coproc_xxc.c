/*
 * xen/arch/arm/coproc/plat/coproc_xxc.c
 *
 * COPROC_XXC platform specific code
 * This is an example of description of a complex coprocessor platform code.
 * This is an example of a coprocessor description which shares common code
 * with another coprocessor.
 *
 * Andrii Anisov <Andrii_Anisov@epam.com>
 * Copyright (C) 2017 EPAM Systems Inc.
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

#define DT_MATCH_COPROC_XXC DT_MATCH_COMPATIBLE("vendor_xxx,coproc_xxc")

static int vcoproc_xxc_op_write(struct vcpu *v, mmio_info_t *info, register_t r,
                                void *priv);
static int vcoproc_xxc_mmu_write(struct vcpu *v, mmio_info_t *info,
                                 register_t r, void *priv);

static struct mmio_handler_ops vcoproc_xxc_op_mmio_handler = {
    .read = vcoproc_xxx_read,
    .write = vcoproc_xxc_op_write,
};

static struct mmio_handler_ops vcoproc_xxc_mmu_mmio_handler = {
    .read = vcoproc_xxx_read,
    .write = vcoproc_xxc_mmu_write,
};

static struct mmio_handler_ops vcoproc_xxc_sram_mmio_handler = {
    .read = vcoproc_xxx_read,
    .write = vcoproc_xxx_write,
};

static struct pcoproc_mmio coproc_xxc_mmio[] = {
    {
        .name = "op",
        .size = 0x1000,
        .ops = &vcoproc_xxc_op_mmio_handler,
    },
    {
        .name = "mmu",
        .size = 0x1000,
        .ops = &vcoproc_xxc_mmu_mmio_handler,
    },
    {
        .name = "sram",
        .size = 0,
        .ops = &vcoproc_xxc_sram_mmio_handler,
    },
};

enum {
    COPROC_XXC_OP = 0,
    COPROC_XXC_MMU
};

static struct pcoproc_irq coproc_xxc_irq[] = {
    {
        .name = "op",
        .handler = coproc_xxx_irq_handler,
    },
    {
        .name = "mmu",
        .handler = coproc_xxx_irq_handler,
    },
};

static const struct pcoproc_desc coproc_xxc_desc = {
    .p_mmio_num = ARRAY_SIZE(coproc_xxc_mmio),
    .p_mmio = coproc_xxc_mmio,
    .p_irq_num = ARRAY_SIZE(coproc_xxc_irq),
    .p_irq = coproc_xxc_irq,
};

static int vcoproc_xxc_op_write(struct vcpu *v, mmio_info_t *info, register_t r,
                                void *priv)
{
    struct vcoproc_mmio *mmio = priv;
    struct vcoproc_rw_context ctx;
    struct mcoproc_device *mcoproc;

    vcoproc_get_rw_context(v->domain, mmio, info, &ctx);
    mcoproc = ctx.vcoproc->mcoproc;
    COPROC_DEBUG(mcoproc->dev, "domain %u, write r%d=%"PRIregister
                 " offset %#08x base %#08x name %s\n",
                 v->domain->domain_id, ctx.dabt.reg, r, ctx.offset,
                 (uint32_t)mmio->addr, mmio->m_mmio->p_mmio->name?:"NONAME");

#if 1
    /* for debug purposes */
#define COPROC_XXC_OP_INT_REG   0x20
    if ( ctx.offset == COPROC_XXC_OP_INT_REG )
    {
        int i;

        /* Look for OP irq to inject */
        for ( i = 0; i < mcoproc->num_irqs; i++ )
            if ( mcoproc->irqs[i].p_irq == &coproc_xxc_irq[COPROC_XXC_OP] )
            {
                vgic_vcpu_inject_spi(ctx.vcoproc->domain, mcoproc->irqs[i].irq);
                break;
            }
    }
    else
        vcoproc_xxx_write(v, info, r, priv);
#endif

    return 1;
}

static int vcoproc_xxc_mmu_write(struct vcpu *v, mmio_info_t *info,
                                 register_t r, void *priv)
{
    struct vcoproc_mmio *mmio = priv;
    struct vcoproc_rw_context ctx;
    struct mcoproc_device *mcoproc;

    vcoproc_get_rw_context(v->domain, mmio, info, &ctx);
    mcoproc = ctx.vcoproc->mcoproc;
    COPROC_DEBUG(mcoproc->dev, "domain %u, write r%d=%"PRIregister
                 " offset %#08x base %#08x name %s\n",
                 v->domain->domain_id, ctx.dabt.reg, r, ctx.offset,
                 (uint32_t)mmio->addr, mmio->m_mmio->p_mmio->name?:"NONAME");

#if 1
    /* for debug purposes */
#define COPROC_XXC_MMU_INT_REG   0x30
    if ( ctx.offset == COPROC_XXC_MMU_INT_REG )
    {
        int i;

        /* Look for MMU irq to inject */
        for ( i = 0; i < mcoproc->num_irqs; i++ )
            if ( mcoproc->irqs[i].p_irq == &coproc_xxc_irq[COPROC_XXC_MMU] )
            {
                vgic_vcpu_inject_spi(ctx.vcoproc->domain, mcoproc->irqs[i].irq);
                break;
            }
    }
#endif

    return 1;
}

extern const struct coproc_ops vcoproc_xxx_vcoproc_ops;

static int coproc_xxc_dt_probe(struct dt_device_node *np)
{
    struct mcoproc_device *coproc_xxc;
    struct device *dev = &np->dev;
    int ret;

    coproc_xxc = coproc_alloc(np,  &coproc_xxc_desc, &vcoproc_xxx_vcoproc_ops);
    if ( IS_ERR_OR_NULL(coproc_xxc) )
    {
        ret = PTR_ERR(coproc_xxc);
        COPROC_DEBUG(dev, "failed to allocate coproc xxc (%d)\n", ret);
        return ret;
    }

    ret = coproc_register(coproc_xxc);
    if ( ret )
    {
        COPROC_DEBUG(dev, "failed to register coproc xxc (%d)\n", ret);
        coproc_release(coproc_xxc);
        return ret;
    }

    return 0;
}

static const struct dt_device_match coproc_xxc_dt_match[] __initconst =
{
    DT_MATCH_COPROC_XXC,
    { /* sentinel */ },
};

static __init int coproc_xxc_init(struct dt_device_node *np, const void *data)
{
    /*TODO: Decide should we still need used by DOMID_XEN */
    dt_device_set_used_by(np, DOMID_XEN);

    return coproc_xxc_dt_probe(np);
}

DT_DEVICE_START(coproc_xxc, "COPROC_XXC", DEVICE_COPROC)
    .dt_match = coproc_xxc_dt_match,
    .init = coproc_xxc_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

