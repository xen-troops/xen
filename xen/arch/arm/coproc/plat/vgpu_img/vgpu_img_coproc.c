#include <asm/io.h>
#include <xen/init.h>
#include <xen/err.h>
#include <xen/irq.h>

#include "vgpu_img_coproc.h"

#define DT_MATCH_COPROC_VGPU_IMG DT_MATCH_COMPATIBLE("renesas,gsx")

#define RGX_CR_META_SP_MSLVIRQSTATUS                      (0x0AC8U)
#define RGX_CR_META_SP_MSLVIRQSTATUS_TRIGVECT2_CLRMSK     (0XFFFFFFFBU)
#define RGX_CR_META_SP_MSLVIRQSTATUS_TRIGVECT2_EN         (0X00000004U)

#define RGXFW_CR_IRQ_STATUS           RGX_CR_META_SP_MSLVIRQSTATUS
#define RGXFW_CR_IRQ_STATUS_EVENT_EN  RGX_CR_META_SP_MSLVIRQSTATUS_TRIGVECT2_EN
#define RGXFW_CR_IRQ_CLEAR_MASK       RGX_CR_META_SP_MSLVIRQSTATUS_TRIGVECT2_CLRMSK

struct gsx_info
{
    uint32_t irq_status;
};

struct vgsx_info
{
    bool check_1to1_done;
};

static inline uint32_t vgpu_img_read32(struct coproc_device *coproc,
                                       uint32_t offset)
{
    return readl((char *)coproc->mmios[0].base + offset);
}

static inline void vgpu_img_write32(struct coproc_device *coproc,
                                    uint32_t offset, uint32_t val)
{
    writel(val, (char *)coproc->mmios[0].base + offset);
}

static bool vgpu_img_1to1_map_check(struct vcoproc_instance *vcoproc,
                                    paddr_t start, size_t size)
{
    struct domain *d = vcoproc->domain;
    mfn_t mfn;
    pfn_t i;

    for (i = paddr_to_pfn(start); i < paddr_to_pfn(start + size + 1); i++)
    {
        mfn = p2m_lookup(d, _gfn(i), NULL);
        if ( i != mfn )
        {
            COPROC_DEBUG(vcoproc->coproc->dev,
                         "mfn %lx != pfn %lx\n", mfn, i);
            return false;
        }
    }
    return true;
}

static int vcoproc_vgpu_img_read(struct vcpu *v, mmio_info_t *info,
                                 register_t *r, void *priv)
{
    struct mmio *mmio = priv;
    struct vcoproc_rw_context ctx;
    unsigned long flags;

    vcoproc_get_rw_context(v->domain, mmio, info, &ctx);

    spin_lock_irqsave(&ctx.coproc->vcoprocs_lock, flags);

    COPROC_DEBUG(ctx.coproc->dev,
                 "dom%d read r%d=%"PRIregister" offset %#08x base %#08x\n",
                 ctx.vcoproc->domain->domain_id,
                 ctx.dabt.reg, *r, ctx.offset, (uint32_t)mmio->addr);

    if ( ctx.offset == RGXFW_CR_IRQ_STATUS )
    {
        struct gsx_info *cinfo = (struct gsx_info *)ctx.coproc->priv;

        *r = cinfo->irq_status;
    }
    else
    {
        *r = vgpu_img_read32(ctx.coproc, ctx.offset);
    }

    spin_unlock_irqrestore(&ctx.coproc->vcoprocs_lock, flags);
    return 1;
}

static int vcoproc_vgpu_img_write(struct vcpu *v, mmio_info_t *info,
                                  register_t r, void *priv)
{
    struct mmio *mmio = priv;
    struct vcoproc_rw_context ctx;

    vcoproc_get_rw_context(v->domain, mmio, info, &ctx);
    if ( ctx.vcoproc->domain->domain_id )
    {
        struct vgsx_info *vinfo = (struct vgsx_info *)ctx.vcoproc->priv;

        ctx.offset += 0x10000;

        if ( unlikely(!vinfo->check_1to1_done) )
        {
            bool map1to1;

            map1to1 = vgpu_img_1to1_map_check(ctx.vcoproc, 0x6c100000, 0x2000000);
            COPROC_DEBUG(ctx.coproc->dev, "dom%d 1 to 1 mapping is %s\n",
                         ctx.vcoproc->domain->domain_id, map1to1 ? "OK" : "WRONG");
            vinfo->check_1to1_done = true;
        }
    }
    COPROC_DEBUG(ctx.coproc->dev,
                 "dom%d write r%d=%"PRIregister" offset %#08x base %#08x\n",
                 ctx.vcoproc->domain->domain_id,
                 ctx.dabt.reg, r, ctx.offset, (uint32_t)mmio->addr);
    /*
     * FIXME: do not allow host driver to clear interrupt, so we don't
     * miss one
     */
    if ( ctx.offset != RGXFW_CR_IRQ_STATUS )
        vgpu_img_write32(ctx.coproc, ctx.offset, r);
    return 1;
}

static const struct mmio_handler_ops vcoproc_vgpu_img_mmio_handler = {
    .read = vcoproc_vgpu_img_read,
    .write = vcoproc_vgpu_img_write,
};

s_time_t vcoproc_vgpu_img_ctx_switch_from(struct vcoproc_instance *curr)
{
    /* nothing to do */
    return 0;
}

static int vcoproc_vgpu_img_ctx_switch_to(struct vcoproc_instance *next)
{
    /* nothing to do */
    return 0;
}

static int vcoproc_vgpu_img_vcoproc_init(struct vcoproc_instance *vcoproc)
{
    int i;

    vcoproc->priv = xzalloc(struct vgsx_info);
    if ( !vcoproc->priv )
    {
        COPROC_ERROR(vcoproc->coproc->dev,
                     "failed to allocate vcoproc private data\n");
        return -ENOMEM;
    }

    for ( i = 0; i < vcoproc->coproc->num_mmios; i++ )
    {
        struct mmio *mmio = &vcoproc->coproc->mmios[i];
        register_mmio_handler(vcoproc->domain, &vcoproc_vgpu_img_mmio_handler,
                              mmio->addr, mmio->size, mmio);
    }

    return 0;
}

static void vcoproc_vgpu_img_vcoproc_deinit(struct vcoproc_instance *vcoproc)
{
    xfree(vcoproc->priv);
}

static const struct coproc_ops vcoproc_vgpu_img_ops = {
    .vcoproc_init        = vcoproc_vgpu_img_vcoproc_init,
    .vcoproc_deinit      = vcoproc_vgpu_img_vcoproc_deinit,
    .ctx_switch_from     = vcoproc_vgpu_img_ctx_switch_from,
    .ctx_switch_to       = vcoproc_vgpu_img_ctx_switch_to,
};

static void coproc_vgpu_img_irq_handler(int irq, void *dev,
                                   struct cpu_user_regs *regs)
{
    struct coproc_device *coproc = dev;
    uint32_t irq_status;
    unsigned long flags;

    spin_lock_irqsave(&coproc->vcoprocs_lock, flags);

    irq_status = vgpu_img_read32(coproc, RGXFW_CR_IRQ_STATUS);

    if ( irq_status & RGXFW_CR_IRQ_STATUS_EVENT_EN )
    {
        struct gsx_info *cinfo = (struct gsx_info *)coproc->priv;
        struct vcoproc_instance *vcoproc = NULL;

        vgpu_img_write32(coproc, RGXFW_CR_IRQ_STATUS, RGXFW_CR_IRQ_CLEAR_MASK);
        cinfo->irq_status = irq_status;

        if ( list_empty(&coproc->vcoprocs) )
            goto out;

        /* inject into ALL domains */
        list_for_each_entry( vcoproc, &coproc->vcoprocs, vcoproc_elem )
        {
            COPROC_DEBUG(coproc->dev,
                         "Inject IRQ into dom%d\n", vcoproc->domain->domain_id);
            vgic_vcpu_inject_spi(vcoproc->domain, irq);
        }
    }

out:
    spin_unlock_irqrestore(&coproc->vcoprocs_lock, flags);
}

static int coproc_vgpu_img_dt_probe(struct dt_device_node *np)
{
    struct coproc_device *coproc;
    struct device *dev = &np->dev;
    int i, ret;

    coproc = coproc_alloc(np, &vcoproc_vgpu_img_ops);
    if ( IS_ERR_OR_NULL(coproc) )
        return PTR_ERR(coproc);

    /* Just to be sure */
    coproc->need_iommu = false;

    coproc->priv = xzalloc(struct gsx_info);
    if ( !coproc->priv )
    {
        COPROC_ERROR(dev, "failed to allocate coproc private data\n");
        ret = -ENOMEM;
        goto out_release_coproc;
    }

    for ( i = 0; i < coproc->num_irqs; ++i )
    {
        ret = request_irq(coproc->irqs[i],
                         IRQF_SHARED,
                         coproc_vgpu_img_irq_handler,
                         "coproc_vgpu_img irq",
                         coproc);
        if ( ret )
        {
            COPROC_ERROR(dev, "failed to request irq %d (%u)\n", i,
                         coproc->irqs[i]);
            goto out_release_irqs;
        }
    }

    ret = coproc_register(coproc);
    if ( ret )
    {
        COPROC_DEBUG(dev, "failed to register coproc (%d)\n", ret);
        goto out_release_irqs;
    }

    return 0;

out_release_irqs:
    while ( i-- )
        release_irq(coproc->irqs[i], coproc);
    xfree(coproc->priv);
out_release_coproc:
    coproc_release(coproc);
    return ret;
}

static const struct dt_device_match coproc_vgpu_img_dt_match[] __initconst =
{
    DT_MATCH_COPROC_VGPU_IMG,
    { /* sentinel */ },
};

static __init int coproc_vgpu_img_init(struct dt_device_node *dev, const void *data)
{
    int ret;

    dt_device_set_used_by(dev, DOMID_XEN);

    ret = coproc_vgpu_img_dt_probe(dev);
    if ( ret )
        return ret;

#if 0
    coproc_debug = COPROC_DBG_LAST;
#endif

    return 0;
}

DT_DEVICE_START(coproc_vgpu_img, "coproc_vgpu_img", DEVICE_COPROC)
    .dt_match = coproc_vgpu_img_dt_match,
    .init = coproc_vgpu_img_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
