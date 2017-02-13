/*
 * xen/arch/arm/coproc/plat/coproc_gpu_gx6gpu_gx6xxx.c
 *
 * COPROC_GPU_GX6GPU_GX6XXX platform specific code
 *
 * Oleksandr Andrushchenko <oleksandr_andrushchenko@epam.com>
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
#include <xen/vmap.h>
#include <asm/io.h>

#include "../coproc.h"
#include "common.h"

#define DT_MATCH_COPROC_GX6GPU_GX6XXX DT_MATCH_COMPATIBLE("renesas,gsx")

struct vgpu_gx6xxx_info
{
    /* This is the current IRQ status reported/updated to/from domains.
     * Set on real IRQ from GPU.
     */
    uint32_t irq_status;

};

struct gpu_gx6xxx_info
{
    struct vcoproc_instance *curr;
    uint32_t *reg_irq_status;
    uint32_t *reg_irq_clear;
};

#if 0
#define RGX_CR_MIPS_WRAPPER_IRQ_STATUS                (0x08A8U)
#define RGX_CR_MIPS_WRAPPER_IRQ_STATUS_MASKFULL       (IMG_UINT64_C(0x0000000000000001))
#define RGX_CR_MIPS_WRAPPER_IRQ_STATUS_EVENT_SHIFT    (0U)
#define RGX_CR_MIPS_WRAPPER_IRQ_STATUS_EVENT_CLRMSK   (0XFFFFFFFEU)
#define RGX_CR_MIPS_WRAPPER_IRQ_STATUS_EVENT_EN       (0X00000001U)

#define RGX_CR_MIPS_WRAPPER_IRQ_CLEAR                 (0x08B0U)
#define RGX_CR_MIPS_WRAPPER_IRQ_CLEAR_MASKFULL        (IMG_UINT64_C(0x0000000000000001))
#define RGX_CR_MIPS_WRAPPER_IRQ_CLEAR_EVENT_SHIFT     (0U)
#define RGX_CR_MIPS_WRAPPER_IRQ_CLEAR_EVENT_CLRMSK    (0XFFFFFFFEU)
#define RGX_CR_MIPS_WRAPPER_IRQ_CLEAR_EVENT_EN        (0X00000001U)

#define RGXFW_CR_IRQ_STATUS                           RGX_CR_MIPS_WRAPPER_IRQ_STATUS
#define RGXFW_CR_IRQ_STATUS_EVENT_EN                  RGX_CR_MIPS_WRAPPER_IRQ_STATUS_EVENT_EN
#define RGXFW_CR_IRQ_CLEAR                            RGX_CR_MIPS_WRAPPER_IRQ_CLEAR
#define RGXFW_CR_IRQ_CLEAR_MASK                       RGX_CR_MIPS_WRAPPER_IRQ_CLEAR_EVENT_EN
#else
#define RGX_CR_META_SP_MSLVIRQSTATUS                  (0x0AC8U)
#define RGX_CR_META_SP_MSLVIRQSTATUS_MASKFULL         (IMG_UINT64_C(0x000000000000000C))
#define RGX_CR_META_SP_MSLVIRQSTATUS_TRIGVECT3_SHIFT  (3U)
#define RGX_CR_META_SP_MSLVIRQSTATUS_TRIGVECT3_CLRMSK (0XFFFFFFF7U)
#define RGX_CR_META_SP_MSLVIRQSTATUS_TRIGVECT3_EN     (0X00000008U)
#define RGX_CR_META_SP_MSLVIRQSTATUS_TRIGVECT2_SHIFT  (2U)
#define RGX_CR_META_SP_MSLVIRQSTATUS_TRIGVECT2_CLRMSK (0XFFFFFFFBU)
#define RGX_CR_META_SP_MSLVIRQSTATUS_TRIGVECT2_EN     (0X00000004U)

#define RGXFW_CR_IRQ_STATUS                           RGX_CR_META_SP_MSLVIRQSTATUS
#define RGXFW_CR_IRQ_STATUS_EVENT_EN                  RGX_CR_META_SP_MSLVIRQSTATUS_TRIGVECT2_EN
#define RGXFW_CR_IRQ_CLEAR                            RGX_CR_META_SP_MSLVIRQSTATUS
#define RGXFW_CR_IRQ_CLEAR_MASK                       RGX_CR_META_SP_MSLVIRQSTATUS_TRIGVECT2_CLRMSK
#endif

static int vcoproc_gpu_gx6xxx_read(struct vcpu *v, mmio_info_t *info,
                                   register_t *r, void *priv)
{
    struct mmio *mmio = priv;
    struct vcoproc_rw_context ctx;
    static int start = 1;
    uint32_t *vaddr;

    vcoproc_get_rw_context(v->domain, mmio, info, &ctx);
    if (ctx.offset == RGXFW_CR_IRQ_STATUS) {
        struct vgpu_gx6xxx_info *vinfo = (struct vgpu_gx6xxx_info *)ctx.vcoproc->priv;

        *r = vinfo->irq_status;
        return 1;
    }
    if (start) {
        start = 0;
        vcoproc_sheduler_vcoproc_wake(ctx.coproc->sched, ctx.vcoproc);
    }

    vaddr = (uint32_t *)((char *)mmio->base + ctx.offset);
//    spin_lock(&ctx.vcoproc->lock);
    *r = readl(vaddr);
//    spin_unlock(&ctx.vcoproc->lock);
    return 1;
}

static int vcoproc_gpu_gx6xxx_write(struct vcpu *v, mmio_info_t *info,
                                    register_t r, void *priv)
{
    struct mmio *mmio = priv;
    struct vcoproc_rw_context ctx;
    uint32_t *vaddr;

   vcoproc_get_rw_context(v->domain, mmio, info, &ctx);
   if (ctx.offset == RGXFW_CR_IRQ_STATUS) {
       struct vgpu_gx6xxx_info *vinfo = (struct vgpu_gx6xxx_info *)ctx.vcoproc->priv;

       vinfo->irq_status = r;
       return 1;
   }

    vaddr = (uint32_t *)((char *)mmio->base + ctx.offset);
//    spin_lock(&ctx.vcoproc->lock);
    writel(r, vaddr);
//    spin_unlock(&ctx.vcoproc->lock);
    return 1;
}

static const struct mmio_handler_ops vcoproc_gpu_gx6xxx_mmio_handler = {
    .read = vcoproc_gpu_gx6xxx_read,
    .write = vcoproc_gpu_gx6xxx_write,
};

s_time_t vcoproc_gpu_gx6xxx_ctx_switch_from(struct vcoproc_instance *curr)
{
    return 0;
}

static int vcoproc_gpu_gx6xxx_ctx_switch_to(struct vcoproc_instance *next)
{
    struct gpu_gx6xxx_info *info = (struct gpu_gx6xxx_info *)next->coproc->priv;

    info->curr = next;
    return 0;
}

static int vcoproc_gpu_gx6xxx_vcoproc_init(struct domain *d,
                                    struct coproc_device *coproc,
                                    struct vcoproc_instance *vcoproc)
{
    struct mmio *mmio = &coproc->mmios[0];

    vcoproc->priv = xzalloc(struct vgpu_gx6xxx_info);
    if ( !vcoproc->priv )
    {
        dev_err(coproc->dev, "failed to allocate vcoproc private data\n");
        return -ENOMEM;
    }

    register_mmio_handler(d, &vcoproc_gpu_gx6xxx_mmio_handler,
                          mmio->addr, mmio->size, mmio);

    return 0;
}

static void vcoproc_gpu_gx6xxx_vcoproc_deinit(struct domain *d,
                                       struct vcoproc_instance *vcoproc)
{
    xfree(vcoproc->priv);
}

static const struct coproc_ops vcoproc_gpu_gx6xxx_vcoproc_ops = {
    .vcoproc_init        = vcoproc_gpu_gx6xxx_vcoproc_init,
    .vcoproc_deinit      = vcoproc_gpu_gx6xxx_vcoproc_deinit,
    .ctx_switch_from     = vcoproc_gpu_gx6xxx_ctx_switch_from,
    .ctx_switch_to       = vcoproc_gpu_gx6xxx_ctx_switch_to,
};

static void coproc_gpu_gx6xxx_irq_handler(int irq, void *dev,
                                   struct cpu_user_regs *regs)
{
    struct coproc_device *coproc = dev;
    struct gpu_gx6xxx_info *info = (struct gpu_gx6xxx_info *)coproc->priv;
    uint32_t irq_status;

//    spin_lock(&ctx.vcoproc->lock);

    irq_status = readl(info->reg_irq_status);
    if (irq_status & RGXFW_CR_IRQ_STATUS_EVENT_EN)
    {
        struct vcoproc_instance *vcoproc = info->curr;
        struct vgpu_gx6xxx_info *vinfo = (struct vgpu_gx6xxx_info *)vcoproc->priv;

        writel(RGXFW_CR_IRQ_CLEAR_MASK, info->reg_irq_clear);

        /* Save interrupt status register, so we can deliver to domain later. */
        vinfo->irq_status = irq_status;
        vgic_vcpu_inject_spi(vcoproc->domain, irq);
    }
}

static int coproc_gpu_gx6xxx_dt_probe(struct platform_device *pdev)
{
    struct coproc_device *coproc;
    struct device *dev = &pdev->dev;
    struct gpu_gx6xxx_info *info;
    int ret;

    coproc = coproc_alloc(pdev, &vcoproc_gpu_gx6xxx_vcoproc_ops);
    if ( IS_ERR_OR_NULL(coproc) )
        return PTR_ERR(coproc);

    if ( (coproc->num_irqs != 1) || (coproc->num_mmios != 1) )
    {
        dev_err(dev, "wrong number of IRQs/MMIOs\n");
        ret = -EINVAL;
        goto out_release_coproc;
    }
    coproc->priv = xzalloc(struct gpu_gx6xxx_info);
    if ( !coproc->priv )
    {
        dev_err(dev, "failed to allocate coproc private data\n");
        ret = -ENOMEM;
        goto out_release_priv;
    }
    info = (struct gpu_gx6xxx_info *)coproc->priv;
    info->reg_irq_status = (uint32_t *)((char *)coproc->mmios[0].base + RGXFW_CR_IRQ_STATUS);
    info->reg_irq_clear = (uint32_t *)((char *)coproc->mmios[0].base + RGXFW_CR_IRQ_CLEAR);

    ret = request_irq(coproc->irqs[0], IRQF_SHARED,
                      coproc_gpu_gx6xxx_irq_handler, "GPU GX6xxx irq", coproc);
    if ( ret )
    {
        dev_err(dev, "failed to request irq (%u)\n", coproc->irqs[0]);
        goto out_release_irqs;
    }

    ret = coproc_register(coproc);
    if ( ret )
    {
        dev_err(dev, "failed to register coproc (%d)\n", ret);
        goto out_release_irqs;
    }

    return 0;

out_release_irqs:
    release_irq(coproc->irqs[0], coproc);
out_release_priv:
    xfree(coproc->priv);
out_release_coproc:
    coproc_release(coproc);
    return ret;
}

static const struct dt_device_match coproc_gpu_gx6xxx_dt_match[] __initconst =
{
    DT_MATCH_COPROC_GX6GPU_GX6XXX,
    { /* sentinel */ },
};

static __init int coproc_gpu_gx6xxx_init(struct dt_device_node *dev,
                                         const void *data)
{
    int ret;

    dt_device_set_used_by(dev, DOMID_XEN);

    ret = coproc_gpu_gx6xxx_dt_probe(dev);
    if ( ret )
        return ret;

    return 0;
}

DT_DEVICE_START(coproc_gpu_gx6xxx, "COPROC_GPU_GX6XXX", DEVICE_COPROC)
    .dt_match = coproc_gpu_gx6xxx_dt_match,
    .init = coproc_gpu_gx6xxx_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
