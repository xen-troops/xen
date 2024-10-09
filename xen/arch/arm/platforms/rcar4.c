#include <asm/platform.h>
#include <asm/platforms/rcar.h>
#include <xen/vmap.h>
#include <asm/io.h>

#define RST_BASE        0xE6160000
#define RST_SRESCR0     (RST_BASE + 0x18)
#define RST_SPRES       0x5AA58000

static void rcar4_reset(void)
{
    void __iomem *addr;

    addr = ioremap_nocache(RST_SRESCR0, sizeof(uint64_t));

    if ( !addr )
    {
        printk("Gen4: Unable to map reset address\n");
        return;
    }

    /* Write reset mask to base address */
    writel(RST_SPRES, addr);

    ASSERT_UNREACHABLE();
}

static const char * const rcar4_dt_compat[] __initconst =
{
    "renesas,spider-breakout",
    "renesas,spider-cpu",
    "renesas,r8a779f0",
    "renesas,r8a779g0",
    NULL
};

static void rcar4_domain_destroy(struct domain *d)
{
    if (!rproc_ops) return;

    rproc_ops->remove_domain(d);
}

/* TODO: move to domctl.c */
static int rcar4_do_domctl(struct xen_domctl *domctl, struct domain *d,
                           XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    switch ( domctl->cmd )
    {
    case XEN_DOMCTL_enable_rproc:
    {
        int chan = domctl->u.enable_rproc.chan_id;

        if ( !rproc_ops )
        {
            printk(XENLOG_WARNING"rcar4: rproc is not initialized, can't set it for a domain\n");
            return -ENODEV;
        }

	return rproc_ops->assign_domain(d, chan);
    }
    default:
        return -ENOSYS;
    }
}

static bool rcar4_smc(struct cpu_user_regs *regs)
{
    if ( !rproc_ops )
        return false;

    return rproc_ops->handle_smc(regs);
}

PLATFORM_START(rcar4, "Renesas R-Car Gen4")
    .compatible = rcar4_dt_compat,
    .reset = rcar4_reset,
    .smc = rcar4_smc,
    .do_domctl = rcar4_do_domctl,
    .domain_destroy = rcar4_domain_destroy,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
