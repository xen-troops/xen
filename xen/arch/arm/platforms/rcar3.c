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

#include <asm/regs.h>
#include <asm/platform.h>

static const char *const rcar3_dt_compat[] __initconst =
{
    "renesas,r8a7795",
    "renesas,r8a7796",
    NULL
};

bool rcar3_smc(struct cpu_user_regs *regs)
{
    switch ( get_user_reg(regs, 0) )
    {
    default:
        return false;
    }
}

PLATFORM_START(rcar3, "Renesas R-Car Gen3")
    .compatible = rcar3_dt_compat,
    .smc = rcar3_smc,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
