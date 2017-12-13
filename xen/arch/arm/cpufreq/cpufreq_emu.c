/*
 * xen/arch/arm/cpufreq/cpufreq_emu.c
 *
 * CPUFreq emulation
 *
 * Oleksandr Tyshchenko <oleksandr_tyshchenko@epam.com>
 * Copyright (c) 2017 EPAM Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/types.h>
#include <xen/delay.h>
#include <xen/xmalloc.h>
#include <xen/err.h>
#include <asm/bug.h>
#include <asm/percpu.h>

#include <xen/vmap.h>
#include <asm/io.h>

#include "rcar_def.h"
#include "iic_dvfs.h"

#define EFUSE_AVS0			(0U)
#define EFUSE_AVS_NUM		(7U)
static uint32_t efuse_avs = EFUSE_AVS0;

struct op_points
{
	unsigned long freq; /* Hz */
	unsigned long volt; /* uV */
};

#define NR_H3_OPP	5
#define NR_M3_OPP	6

static const struct op_points rcar_h3_op_points[EFUSE_AVS_NUM][NR_H3_OPP] = {
	{
		{ 500000000,  820000, },
		{ 1000000000, 820000, },
		{ 1500000000, 820000, },
		{ 1600000000, 900000, },
		{ 1700000000, 960000, },
	},
	{
		{ 500000000,  820000, },
		{ 1000000000, 820000, },
		{ 1500000000, 820000, },
		{ 1600000000, 900000, },
		{ 1700000000, 960000, },
	},
	{
		{ 500000000,  820000, },
		{ 1000000000, 820000, },
		{ 1500000000, 820000, },
		{ 1600000000, 900000, },
		{ 1700000000, 960000, },
	},
	{
		{ 500000000,  790000, },
		{ 1000000000, 790000, },
		{ 1500000000, 790000, },
		{ 1600000000, 870000, },
		{ 1700000000, 910000, },
	},
	{
		{ 500000000,  790000, },
		{ 1000000000, 790000, },
		{ 1500000000, 790000, },
		{ 1600000000, 870000, },
		{ 1700000000, 890000, },
	},
	{
		{ 500000000,  770000, },
		{ 1000000000, 770000, },
		{ 1500000000, 770000, },
		{ 1600000000, 850000, },
		{ 1700000000, 870000, },
	},
	{
		{ 500000000,  750000, },
		{ 1000000000, 750000, },
		{ 1500000000, 750000, },
		{ 1600000000, 830000, },
		{ 1700000000, 860000, },
	},
};

static const struct op_points rcar_m3_op_points[EFUSE_AVS_NUM][NR_M3_OPP] = {
	{
		{ 500000000,  820000, },
		{ 1000000000, 820000, },
		{ 1500000000, 820000, },
		{ 1600000000, 900000, },
		{ 1700000000, 900000, },
		{ 1800000000, 960000, },
	},
	{
		{ 500000000,  820000, },
		{ 1000000000, 820000, },
		{ 1500000000, 820000, },
		{ 1600000000, 900000, },
		{ 1700000000, 900000, },
		{ 1800000000, 960000, },
	},
	{
		{ 500000000,  820000, },
		{ 1000000000, 820000, },
		{ 1500000000, 820000, },
		{ 1600000000, 900000, },
		{ 1700000000, 900000, },
		{ 1800000000, 960000, },
	},
	{
		{ 500000000,  790000, },
		{ 1000000000, 790000, },
		{ 1500000000, 790000, },
		{ 1600000000, 870000, },
		{ 1700000000, 870000, },
		{ 1800000000, 910000, },
	},
	{
		{ 500000000,  790000, },
		{ 1000000000, 790000, },
		{ 1500000000, 790000, },
		{ 1600000000, 870000, },
		{ 1700000000, 870000, },
		{ 1800000000, 890000, },
	},
	{
		{ 500000000,  770000, },
		{ 1000000000, 770000, },
		{ 1500000000, 770000, },
		{ 1600000000, 850000, },
		{ 1700000000, 850000, },
		{ 1800000000, 870000, },
	},
	{
		{ 500000000,  750000, },
		{ 1000000000, 750000, },
		{ 1500000000, 750000, },
		{ 1600000000, 830000, },
		{ 1700000000, 830000, },
		{ 1800000000, 860000, },
	},
};

/* CPG base address */
#define	CPG_BASE		(0xE6150000U)

#define CPG_PLL0CR		0x00d8

/* Implementation for customized clocks (Z-clk, Z2-clk, PLL0-clk) for CPUFreq */
#define CPG_PLLECR     0x00D0
#define CPG_PLLECR_PLL0ST (1 << 8)

/* Define for PLL0 clk driver */
#define CPG_PLL0CR_STC_MASK             0x7f000000
#define CPG_PLL0CR_STC_SHIFT            24

/* Modify for Z-clock and Z2-clock
 *
 * Traits of this clock:
 * prepare - clk_prepare only ensures that parents are prepared
 * enable - clk_enable only ensures that parents are enabled
 * rate - rate is adjustable.  clk->rate = parent->rate * mult / 32
 * parent - fixed parent.  No clk_set_parent support
 */
#define CPG_FRQCRB			0x00000004
#define CPG_FRQCRB_KICK			BIT(31)
#define CPG_FRQCRC			0x000000e0
#define CPG_FRQCRC_ZFC_MASK		(0x1f << 8)
#define CPG_FRQCRC_ZFC_SHIFT		8
#define CPG_FRQCRC_Z2FC_MASK		0x1f

#define Z_CLK_MAX_THRESHOLD             1500000000U

void mmio_write_32(uintptr_t addr, uint32_t value)
{
	void __iomem *ptr;

	ptr = ioremap_nocache(addr, sizeof(uint32_t));
	if ( !ptr )
		return;

	writel(value, ptr);
	iounmap(ptr);
}

uint32_t mmio_read_32(uintptr_t addr)
{
	void __iomem *ptr;
	uint32_t data;

	ptr = ioremap_nocache(addr, sizeof(uint32_t));
	if ( !ptr )
		return -ENOMEM;

	data = readl(ptr);
	iounmap(ptr);

	return data;
}

void mmio_write_8(uintptr_t addr, uint8_t value)
{
	void __iomem *ptr;

	ptr = ioremap_nocache(addr, sizeof(uint32_t));
	if ( !ptr )
		return;

	writeb(value, ptr);
	iounmap(ptr);
}

uint8_t mmio_read_8(uintptr_t addr)
{
	void __iomem *ptr;
	uint8_t data;

	ptr = ioremap_nocache(addr, sizeof(uint32_t));
	if ( !ptr )
		return -ENOMEM;

	data = readb(ptr);
	iounmap(ptr);

	return data;
}

static unsigned long pll0_clk_parent_rate(void)
{
	static const unsigned long extal_freq[] = {
			16660000U,	/* MD14_MD13_TYPE_0 */
			20000000U,	/* MD14_MD13_TYPE_1 */
			25000000U,	/* MD14_MD13_TYPE_2 */
			33330000U,	/* MD14_MD13_TYPE_3 */
	};
	unsigned long rate;
	int idx;

	idx = (mmio_read_32(RCAR_MODEMR) & MODEMR_BOOT_PLL_MASK)
			>> MODEMR_BOOT_PLL_SHIFT;

	rate = extal_freq[idx];
	/* Divider setting of EXTAL input is 1/2 when MD14=1 MD13=1 */
	if (idx == MD14_MD13_TYPE_3)
		rate = DIV_ROUND(rate, 2);

	return rate;
}

static unsigned long pll0_clk_round_rate(unsigned long rate)
{
	unsigned long parent_rate = pll0_clk_parent_rate();
	unsigned int mult;

	if (rate < Z_CLK_MAX_THRESHOLD)
		rate = Z_CLK_MAX_THRESHOLD; /* Set lowest value: 1.5GHz */

	mult = DIV_ROUND(rate, parent_rate);
	mult = max(mult, 90U); /* Lowest value is 1.5GHz (stc == 90) */
	mult = min(mult, 120U);

	rate = parent_rate * mult;
	/* Round to closest value at 100MHz unit */
	rate = 100000000 * DIV_ROUND(rate, 100000000);

	return rate;
}

static unsigned long pll0_clk_recalc_rate(void)
{
	unsigned long parent_rate = pll0_clk_parent_rate();
	unsigned int val;
	unsigned long rate;

	val = (mmio_read_32(CPG_BASE + CPG_PLL0CR) & CPG_PLL0CR_STC_MASK)
			>> CPG_PLL0CR_STC_SHIFT;

	rate = parent_rate * (val + 1);
	/* Round to closest value at 100MHz unit */
	rate = 100000000 * DIV_ROUND(rate, 100000000);

	/*printk("%s(): rate: %lu, prate: %lu, pll0-mult: %d\n",
			__func__, rate, parent_rate, val + 1);*/

	return rate;
}

static int pll0_clk_set_rate(unsigned long rate)
{
	unsigned long parent_rate = pll0_clk_parent_rate();
	unsigned int stc_val;
	u32 val;
	int i;

	stc_val = DIV_ROUND(rate, parent_rate);
	stc_val = max(stc_val, 90U); /* Lowest value is 1.5GHz (stc == 90) */
	stc_val = min(stc_val, 120U);

	/*printk("%s(): rate: %lu, prate: %lu, pll0-mult: %d\n",
			__func__, rate, parent_rate, stc_val);*/

	stc_val -= 1;
	val = mmio_read_32(CPG_BASE + CPG_PLL0CR);
	val &= ~CPG_PLL0CR_STC_MASK;
	val |= stc_val << CPG_PLL0CR_STC_SHIFT;
	mmio_write_32(CPG_BASE + CPG_PLL0CR, val);

	i = 0;
	while (!(mmio_read_32(CPG_BASE + CPG_PLLECR) & CPG_PLLECR_PLL0ST)) {
		cpu_relax();
		i++;
	}

	if (i > 1000)
		printk("%s(): PLL0: long settled time: %d\n", __func__, i);

	return 0;
}

static unsigned long z_clk_round_rate(unsigned long rate, unsigned long *parent_rate)
{
	unsigned long prate = *parent_rate;
	unsigned int mult;

	if (!prate)
		prate = 1;

	if (rate <= Z_CLK_MAX_THRESHOLD) { /* Focus on changing z-clock */
		prate = Z_CLK_MAX_THRESHOLD; /* Set parent to: 1.5GHz */
		mult = DIV_ROUND(rate * 32, prate);
	} else {
		/* Focus on changing parent. Fix z-clock divider is 32/32 */
		mult = 32;
	}
	mult = max(mult, 1U);
	mult = min(mult, 32U);

	/* Re-calculate the parent_rate to propagate new rate for it */
	prate = DIV_ROUND(rate * 32, mult);
	prate = 100000000 * DIV_ROUND(prate, 100000000);
	rate = 100000000 * DIV_ROUND(prate / 32 * mult, 100000000);
	*parent_rate = prate;

	return rate;
}

static unsigned long z_clk_recalc_rate(unsigned long parent_rate)
{
	unsigned int mult;
	unsigned int val;
	unsigned long rate;

	val = (mmio_read_32(CPG_BASE + CPG_FRQCRC) & CPG_FRQCRC_ZFC_MASK)
			>> CPG_FRQCRC_ZFC_SHIFT;
	mult = 32 - val;

	rate = DIV_ROUND(parent_rate * mult, 32);
	/* Round to closest value at 100MHz unit */
	rate = 100000000 * DIV_ROUND(rate, 100000000);

	/*printk("%s(): rate: %lu, prate: %lu, z-clk mult: %d\n",
			__func__, rate, parent_rate, mult);*/

	return rate;
}

static int z_clk_set_rate(unsigned long rate, unsigned long parent_rate)
{
	unsigned int mult;
	u32 val, kick;
	unsigned int i;

	if (rate <= Z_CLK_MAX_THRESHOLD) { /* Focus on changing z-clock */
		parent_rate = Z_CLK_MAX_THRESHOLD; /* Set parent to: 1.5GHz */
		mult = DIV_ROUND(rate * 32, parent_rate);
	} else {
		mult = 32;
	}
	mult = max(mult, 1U);
	mult = min(mult, 32U);

	/*printk("%s(): rate: %lu, prate(*): %lu, z-clk mult: %d\n",
			__func__, rate, parent_rate, mult);*/

	if (mmio_read_32(CPG_BASE + CPG_FRQCRB) & CPG_FRQCRB_KICK)
		return -EBUSY;

	val = mmio_read_32(CPG_BASE + CPG_FRQCRC);
	val &= ~CPG_FRQCRC_ZFC_MASK;
	val |= (32 - mult) << CPG_FRQCRC_ZFC_SHIFT;
	mmio_write_32(CPG_BASE + CPG_FRQCRC, val);

	/*
	 * Set KICK bit in FRQCRB to update hardware setting and wait for
	 * clock change completion.
	 */
	kick = mmio_read_32(CPG_BASE + CPG_FRQCRB);
	kick |= CPG_FRQCRB_KICK;
	mmio_write_32(CPG_BASE + CPG_FRQCRB, kick);

	/*
	 * Note: There is no HW information about the worst case latency.
	 *
	 * Using experimental measurements, it seems that no more than
	 * ~10 iterations are needed, independently of the CPU rate.
	 * Since this value might be dependent of external xtal rate, pll1
	 * rate or even the other emulation clocks rate, use 1000 as a
	 * "super" safe value.
	 */
	for (i = 1000; i; i--) {
		if (!(mmio_read_32(CPG_BASE + CPG_FRQCRB) & CPG_FRQCRB_KICK))
			return 0;

		cpu_relax();
	}

	return 0;
}

/* Default limits measured in millivolts and milliamps */
#define BD9571MWV_MIN_MV		750
#define BD9571MWV_MAX_MV		1030
#define BD9571MWV_STEP_MV		10

/* Define Register */
#define BD9571_DVFS_SETVID		0x54
#define BD9571_DVFS_SETVID_MASK		0x7E

static int set_voltage(unsigned long volt)
{
	uint8_t val;
	int ret;

	if (volt < BD9571MWV_MIN_MV * 1000 || volt > BD9571MWV_MAX_MV * 1000)
		return -EINVAL;

	val = DIV_ROUND(volt, BD9571MWV_STEP_MV * 1000);
	val &= BD9571_DVFS_SETVID_MASK;

	ret = rcar_iic_dvfs_send(SLAVE_ADDR_PMIC, BD9571_DVFS_SETVID, val);
	if (ret) {
		printk("%s(): failed to write PMIC register: %d\n", __func__, ret);
		return ret;
	}

	/*printk("%s(): write PMIC register: address=0x%x value=0x%x\n",
			__func__, BD9571_DVFS_SETVID, val);*/

	return 0;
}

static unsigned long __maybe_unused get_voltage(void)
{
	uint8_t val;
	unsigned long volt;
	int ret;

	ret = rcar_iic_dvfs_recieve(SLAVE_ADDR_PMIC, BD9571_DVFS_SETVID, &val);
	if (ret) {
		printk("%s(): failed to read PMIC register: %d\n", __func__, ret);
		return ret;
	}

	/*printk("%s(): read PMIC register: address=0x%x value=0x%x\n",
			__func__, BD9571_DVFS_SETVID, val);*/

	val &= BD9571_DVFS_SETVID_MASK;
	volt = (unsigned long)val * BD9571MWV_STEP_MV * 1000;

	return volt;
}

static const struct op_points *find_opp(unsigned long freq)
{
	const struct op_points *opp;
	int i, count;
	uint32_t product = mmio_read_32(RCAR_PRR) & RCAR_PRODUCT_MASK;

	/* TODO Do we want to support H3 Ver1.0? */
	if (product == RCAR_PRODUCT_H3) {
		count = ARRAY_SIZE(rcar_h3_op_points[efuse_avs]);
		opp = &rcar_h3_op_points[efuse_avs][0];
	} else if (product == RCAR_PRODUCT_M3) {
		count = ARRAY_SIZE(rcar_m3_op_points[efuse_avs]);
		opp = &rcar_m3_op_points[efuse_avs][0];
	} else
		return NULL;

	for (i = 0; i < count; i++, opp ++) {
		if (opp->freq == freq)
			return opp;
	}

	return NULL;
}

int dev_pm_opp_set_rate(unsigned long target_freq)
{
	unsigned long freq, old_freq, prate, old_prate;
	const struct op_points *opp, *old_opp;
	int ret;

	prate = 0;
	freq = z_clk_round_rate(target_freq, &prate);

	old_prate = pll0_clk_recalc_rate();
	old_freq = z_clk_recalc_rate(old_prate);

	/* Return early if nothing to do */
	if (old_freq == freq) {
		printk("%s(): old/new frequencies (%lu Hz) are same, nothing to do\n",
			__func__, freq);
		return 0;
	}

	old_opp = find_opp(old_freq);
	if (!old_opp) {
		printk("%s(): failed to find current OPP for freq %lu\n",
				__func__, old_freq);
	} else {
		/*printk("%s(): found current OPP: %lu Hz %lu uV\n",
				__func__, old_opp->freq, old_opp->volt);*/
	}

	opp = find_opp(freq);
	if (!opp) {
		printk("%s(): failed to find new OPP for freq %lu\n",
				__func__, freq);
		return -EINVAL;
	}

	/*printk("%s(): found new OPP: %lu Hz %lu uV\n",
			__func__, opp->freq, opp->volt);*/

	/* Scaling up? Scale voltage before frequency */
	if (freq > old_freq) {
		ret = set_voltage(opp->volt);
		if (ret) {
			printk("%s(): failed to set voltage: %lu uV\n",
					__func__, opp->volt);
			goto restore_voltage;
		}

		/*printk("%s(): set voltage before: %lu uV\n", __func__, get_voltage());*/
	}

	/* Change frequency */
	printk("%s(): switching OPP: %lu Hz --> %lu Hz\n",
			__func__, old_freq, freq);

	prate = pll0_clk_round_rate(prate);
	if (old_prate != prate)
		pll0_clk_set_rate(prate);

	ret = z_clk_set_rate(freq, prate);
	if (ret) {
		printk("%s(): failed to set clock rate: %d\n", __func__, ret);
		if (old_prate != prate)
			pll0_clk_set_rate(old_prate);
		goto restore_voltage;
	}

	/* Scaling down? Scale voltage after frequency */
	if (freq < old_freq) {
		ret = set_voltage(opp->volt);
		if (ret) {
			printk("%s(): failed to set voltage: %lu uV\n",
					__func__, opp->volt);
			goto restore_freq;
		}

		/*printk("%s(): set voltage after: %lu uV\n", __func__, get_voltage());*/
	}

	return 0;

restore_freq:
	if (old_prate != prate)
		pll0_clk_set_rate(old_prate);
	if (z_clk_set_rate(old_freq, old_prate))
		printk("%s(): failed to restore old freq: %lu Hz\n",
				__func__, old_freq);
	/*printk("%s(): restored old freq: %lu Hz\n", __func__, old_freq);*/

restore_voltage:
	/* This shouldn't harm even if the voltages weren't updated earlier */
	if (old_opp) {
		if (set_voltage(old_opp->volt))
			printk("%s(): failed to restore old voltage: %lu uV\n",
					__func__, old_opp->volt);
		/*printk("%s(): restored old voltage: %lu uV\n", __func__, old_opp->volt);*/
	}

	return ret;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
