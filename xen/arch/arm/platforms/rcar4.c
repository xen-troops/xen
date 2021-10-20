#include <asm/platform.h>
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
    NULL
};

PLATFORM_START(rcar4, "Renesas R-Car Gen4")
    .compatible = rcar4_dt_compat,
    .reset = rcar4_reset,
PLATFORM_END
