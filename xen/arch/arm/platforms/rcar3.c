/*
 * xen/arch/arm/platforms/rcar3.c
 *
 * Renesas R-Car Gen3 Platform Code
 *
 * Volodymyr Babchuk <volodymyr_babchuk@epam.com>
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
#include <xen/types.h>
#include <xen/vmap.h>

#include <asm/io.h>
#include <asm/platform.h>
#include <asm/regs.h>
#include <asm/smccc.h>

#define MFIS_MAX_CHANNELS 8
#define MFIS_SPI          265 /* "Reserved" on Gen3 */
#define MFIS_IICR(n) (0x0400 + n * 0x8)
#define MFIS_EICR(n) (0x0404 + n * 0x8)
#define MFIS_IMBR(n) (0x0440 + n * 0x4)
#define MFIS_EMBR(n) (0x0460 + n * 0x4)

#define MFIS_SMC_TRIG  ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,         \
                                          ARM_SMCCC_CONV_32,           \
                                          ARM_SMCCC_OWNER_SIP,         \
                                          0x100)
#define MFIS_SMC_ERR_BUSY               0x01
#define MFIS_SMC_ERR_NOT_AVAILABLE      0x02


struct mfis_data
{
    void *base;
    uint8_t chan_cnt;
    int irqs[MFIS_MAX_CHANNELS];
    struct domain* domains[MFIS_MAX_CHANNELS];
};

static struct mfis_data *mfis_data;

static const char *const rcar3_dt_compat[] __initconst =
{
    "renesas,r8a7795",
    "renesas,r8a7796",
    NULL
};

static void mfis_irq_handler(int irq, void *dev_id, struct cpu_user_regs *regs)
{
    int i;

    ASSERT(dev_id == mfis_data);

    /* Find domain for irq */
    for ( i = 0; i < mfis_data->chan_cnt; i++)
        /* TODO: in general case i != chan */
        if ( mfis_data->irqs[i] == irq )
        {
            uint32_t val;

            val = readl(mfis_data->base + MFIS_EICR(i));

            if ( !(val & 0x1 ) )
            {
                printk(XENLOG_WARNING"MFIS: Spurious IRQ for chan %d\n", i);
                break;
            }

            writel(val & ~0x1, mfis_data->base + MFIS_EICR(i));

            if ( mfis_data->domains[i] )
                vgic_inject_irq(mfis_data->domains[i], NULL, MFIS_SPI, true);
            else
                printk(XENLOG_WARNING"MFIS: IRQ for chan %d without domain\n", i);

            break;
        }
}

static int mfis_add_domain(struct domain* d, int chan)
{
    int ret;

    if ( chan >= mfis_data->chan_cnt )
        return -EINVAL;

    ret = vgic_reserve_virq(d, MFIS_SPI);
    if ( ret < 0)
        return ret;

    mfis_data->domains[chan] = d;

    printk("MFIS: Added chan %d for domain %d\n", chan, d->domain_id);////

    return 0;
}

static int mfis_trigger_chan(struct domain *d)
{
    int i;
    uint32_t val;

    /* Find chan for domain */
    for ( i = 0; i < mfis_data->chan_cnt; i++)
        if ( mfis_data->domains[i] == d )
        {
            val = readl(mfis_data->base + MFIS_IICR(i));

            if ( val & 0x1 )
                return -EBUSY;

            writel(1, mfis_data->base + MFIS_IICR(i));
            return 0;
        }

    return -ENOENT;
}

static int mfis_probe(void)
{
    struct dt_device_node *node;
    paddr_t start, len;
    int ret, i;
    u32 prop_len;
    const __be32 *prop_val;

    node = dt_find_compatible_node(NULL, NULL, "renesas,mfis");
    if ( !node )
        return -ENODEV;

    mfis_data = xzalloc(struct mfis_data);
    if (!mfis_data)
        return -ENOMEM;

    ret = dt_device_get_address(node, 0, &start, &len);
    if ( ret )
    {
        printk(XENLOG_ERR"Cannot read MFIS base address\n");
        goto err;
    }

    mfis_data->base = ioremap_nocache(start, len);
    if ( !mfis_data->base )
    {
        printk(XENLOG_ERR"Unable to map MFIS region!\n");
        goto err;
    }

    prop_val = dt_get_property(node, "renesas,mfis-channels", &prop_len);
    if ( !prop_val || prop_len < sizeof(uint32_t) )
        goto err;

    mfis_data->chan_cnt = prop_len / sizeof(uint32_t);

    if ( mfis_data->chan_cnt > MFIS_MAX_CHANNELS )
        mfis_data->chan_cnt = MFIS_MAX_CHANNELS;

    printk(XENLOG_INFO"MFIS: Found %d channels\n", mfis_data->chan_cnt);

    for ( i = 0; i < mfis_data->chan_cnt; i++)
    {
        uint32_t chan_id = be32_to_cpu(prop_val[i]);
        int irq = platform_get_irq(node, chan_id);

        if ( chan_id != i )
        {
            printk(XENLOG_ERR"MFIS: TODO: Setup where i != chan_id is not supported yet\n");
            goto err_free_irq;
        }
        if ( irq <= 0 )
        {
            printk(XENLOG_ERR "MFIS: Can't get irq for chan %d\n", chan_id);
            goto err_free_irq;
        }

        printk(XENLOG_INFO "MFIS: chan %d irq %d\n", chan_id, irq);

        if ( request_irq(irq, 0, mfis_irq_handler, "rcar-mfis",
                         mfis_data ) < 0 )
        {
            printk(XENLOG_ERR "MFIS: Can't request irq %d for chan %d\n", irq, chan_id);
            goto err_free_irq;
        }

        mfis_data->irqs[i] = irq;
    }

    dt_device_set_used_by(node, DOMID_XEN);

    return 0;

err_free_irq:
    for ( i = 0; i < mfis_data->chan_cnt; i++)
        if ( mfis_data->irqs[i] )
            release_irq(mfis_data->irqs[i], mfis_data);

err:
    iounmap(mfis_data->base);
    xfree(mfis_data);
    return -ENODEV;
}

static int __init rcar3_late_init(void)
{
    if ( mfis_probe() < 0 )
        printk(XENLOG_ERR" **** MFIS will be not available! **** \n");

    return 0;
}

static int rcar3_specific_mapping(struct domain *d)
{
    if ( mfis_data )
        mfis_add_domain(d, 0);

    return 0;
}

static bool rcar3_smc(struct cpu_user_regs *regs)
{
    switch ( get_user_reg(regs, 0) )
    {
    case MFIS_SMC_TRIG:
    {
        int ret;

        ret = mfis_trigger_chan(current->domain);
        if ( ret == 0 )
            set_user_reg(regs, 0, ARM_SMCCC_SUCCESS);
        else if ( ret == -EBUSY )
            set_user_reg(regs, 0, MFIS_SMC_ERR_BUSY);
        else if ( ret == -EINVAL )
            set_user_reg(regs, 0, MFIS_SMC_ERR_NOT_AVAILABLE);
        else
            set_user_reg(regs, 0, ARM_SMCCC_ERR_UNKNOWN_FUNCTION);
        return true;
    }
    default:
        return false;
    }
}

PLATFORM_START(rcar3, "Renesas R-Car Gen3")
    .compatible = rcar3_dt_compat,
    .smc = rcar3_smc,
    .late_init = rcar3_late_init,
    .specific_mapping = rcar3_specific_mapping,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
