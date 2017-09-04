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

/* offset of the page which contains IRQ status register */
#define RGXFW_CR_IRQ_STATUS_PG_OFS    (RGXFW_CR_IRQ_STATUS & PAGE_MASK)
/* offset of the IRQ status register within the page */
#define RGXFW_CR_IRQ_STATUS_REG_OFS   (RGXFW_CR_IRQ_STATUS & ~PAGE_MASK)

struct gsx_info
{
    uint32_t irq_status;
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
                 ctx.dabt.reg, *r, ctx.offset,
                 (uint32_t)(mmio->addr + RGXFW_CR_IRQ_STATUS_PG_OFS));

    if ( ctx.offset == RGXFW_CR_IRQ_STATUS_REG_OFS )
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
    unsigned long flags;

    vcoproc_get_rw_context(v->domain, mmio, info, &ctx);

    spin_lock_irqsave(&ctx.coproc->vcoprocs_lock, flags);

    COPROC_DEBUG(ctx.coproc->dev,
                 "dom%d write r%d=%"PRIregister" offset %#08x base %#08x\n",
                 ctx.vcoproc->domain->domain_id,
                 ctx.dabt.reg, r, ctx.offset,
                 (uint32_t)(mmio->addr + RGXFW_CR_IRQ_STATUS_PG_OFS));

    /*
     * FIXME: do not allow host driver to clear interrupt, so we don't
     * miss one
     */
    if ( ctx.offset != RGXFW_CR_IRQ_STATUS_REG_OFS )
        vgpu_img_write32(ctx.coproc, ctx.offset, r);

    spin_unlock_irqrestore(&ctx.coproc->vcoprocs_lock, flags);
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
    struct mmio *mmio;

    /*
     * FIXME: we only need a single page with IRQ status register,
     * so we can read/clear IRQ status
     */
    if ( !vcoproc->coproc->num_mmios )
    {
        COPROC_ERROR(vcoproc->coproc->dev,
                     "at least one MMIO range must be defined\n");
        return -EINVAL;
    }

    /* expect IRQ status register in the very first MMIO range */
    mmio = &vcoproc->coproc->mmios[0];
    mmio->base = coproc_map_offset(vcoproc->coproc, 0,
                                   RGXFW_CR_IRQ_STATUS_PG_OFS, PAGE_SIZE);
    if ( IS_ERR_OR_NULL(mmio->base) )
        return PTR_ERR(mmio->base);

    register_mmio_handler(vcoproc->domain, &vcoproc_vgpu_img_mmio_handler,
                          mmio->addr + RGXFW_CR_IRQ_STATUS_PG_OFS,
                          PAGE_SIZE, mmio);
    return 0;
}

static void vcoproc_vgpu_img_vcoproc_deinit(struct vcoproc_instance *vcoproc)
{
}

bool_t vcoproc_vgpu_img_need_map_range_to_domain(struct vcoproc_instance *vcoproc,
                                                 u64 range_addr, u64 range_size,
                                                 u64 *map_addr, u64 *map_size)
{
    if ( range_addr == vcoproc->coproc->mmios[0].addr )
    {
        /* map all pages to domain, but the very first with IRQ status reg */
        BUILD_BUG_ON(RGXFW_CR_IRQ_STATUS_PG_OFS != 0);
        *map_addr = range_addr + PAGE_SIZE;
        *map_size = range_size - PAGE_SIZE;
        return true;
    }
    return false;
}

static const struct coproc_ops vcoproc_vgpu_img_ops = {
    .vcoproc_init             = vcoproc_vgpu_img_vcoproc_init,
    .vcoproc_deinit           = vcoproc_vgpu_img_vcoproc_deinit,
    .ctx_switch_from          = vcoproc_vgpu_img_ctx_switch_from,
    .ctx_switch_to            = vcoproc_vgpu_img_ctx_switch_to,
    .need_map_range_to_domain = vcoproc_vgpu_img_need_map_range_to_domain,
};

static void coproc_vgpu_img_irq_handler(int irq, void *dev,
                                        struct cpu_user_regs *regs)
{
    struct coproc_device *coproc = dev;
    uint32_t irq_status;
    unsigned long flags;

    spin_lock_irqsave(&coproc->vcoprocs_lock, flags);

    irq_status = vgpu_img_read32(coproc, RGXFW_CR_IRQ_STATUS_REG_OFS);

    if ( irq_status & RGXFW_CR_IRQ_STATUS_EVENT_EN )
    {
        struct gsx_info *cinfo = (struct gsx_info *)coproc->priv;
        struct vcoproc_instance *vcoproc = NULL;

        vgpu_img_write32(coproc, RGXFW_CR_IRQ_STATUS_REG_OFS,
                         RGXFW_CR_IRQ_CLEAR_MASK);
        cinfo->irq_status = irq_status;

        if ( list_empty(&coproc->vcoprocs) )
            goto out;

        /* inject into ALL domains */
        list_for_each_entry( vcoproc, &coproc->vcoprocs, vcoproc_elem )
            vgic_vcpu_inject_spi(vcoproc->domain, irq);
    }

out:
    spin_unlock_irqrestore(&coproc->vcoprocs_lock, flags);
}

static int coproc_vgpu_img_dt_probe(struct dt_device_node *np)
{
    struct coproc_device *coproc;
    struct device *dev = &np->dev;
    int i, ret;

    coproc = coproc_alloc(np, &vcoproc_vgpu_img_ops,
                          COPROC_DRIVER_NO_SCHEDULER |
                          COPROC_DRIVER_NO_MMIO_MAP);
    if ( IS_ERR_OR_NULL(coproc) )
        return PTR_ERR(coproc);

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
