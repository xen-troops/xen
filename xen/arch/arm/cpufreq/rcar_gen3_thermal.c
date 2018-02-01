/*
 *  R-Car Gen3 THS/CIVM thermal sensor driver
 *  Based on drivers/thermal/rcar_thermal.c
 *
 * Copyright (C) 2015-2016 Renesas Electronics Corporation.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  Based on Linux drivers/thermal/rcar_gen3_thermal.c
 *  => commit 5570bd640a32b551ed69b9275f5bd90fa21d9c9c
 *  git://git.kernel.org/pub/scm/linux/kernel/git/horms/renesas-bsp.git
 *  branch: rcar-3.5.9
 *
 *  Xen modification:
 *  Oleksandr Tyshchenko <Oleksandr_Tyshchenko@epam.com>
 *  Copyright (C) 2018 EPAM Systems Inc.
 *
 */

#include <xen/device_tree.h>
#include <xen/tasklet.h>
#include <xen/delay.h>
#include <xen/err.h>
#include <xen/vmap.h>
#include <xen/irq.h>
#include <xen/shutdown.h>
#include <asm/device.h>
#include <asm/io.h>

extern bool cpufreq_debug;

extern void mmio_write_32(uintptr_t addr, uint32_t value);
extern uint32_t mmio_read_32(uintptr_t addr);

extern int scpi_cpufreq_throttle(bool enable);

static bool throttle_enabled = false;

struct thermal_trip_point {
	/*
	 * To show what action must be performed if current temperature exceeds
	 * trip point temperature: reboot system if this flag is set and do
	 * CPU throttling otherwise.
	 */
	bool critical;
	int temp;
	int hyst;
};

static const struct thermal_trip_point trip_points[2] = {
	{
		.critical = false,
		/* Linux's IPA service starts working at 90 C, but we set 80 C */
		.temp = 80000,
		.hyst = 4000,
	},
	{
		.critical = true,
		/* Linux's EMS service starts working at 110 C, but we set 100 C */
		.temp = 100000,
		.hyst = 0,
	},
};

/* Add missed #define-s to control THS clock */
/* CPG base address */
#define	CPG_BASE		(0xE6150000U)
/* CPG system module stop control 5 */
#define CPG_SMSTPCR5	(CPG_BASE + 0x0144U)
/* CPG module stop status 5 */
#define CPG_MSTPSR5		(CPG_BASE + 0x003CU)
/* THS/TSC bit in CPG registers */
#define CPG_THS_BIT		(0x00400000U)
/* CPG write protect */
#define CPG_CPGWPR		(CPG_BASE + 0x0900U)
/* CPG write protect control */
#define CPG_CPGWPCR		(CPG_BASE + 0x0904U)

#define dev_name(dev) dt_node_full_name(dev_to_dt(dev))

/*
 * Divide positive or negative dividend by positive or negative divisor
 * and round to closest integer. Result is undefined for negative
 * divisors if the dividend variable type is unsigned and for negative
 * dividends if the divisor variable type is unsigned.
 */
#define DIV_ROUND_CLOSEST(x, divisor)(			\
{							\
	typeof(x) __x = x;				\
	typeof(divisor) __d = divisor;			\
	(((typeof(x))-1) > 0 ||				\
	 ((typeof(divisor))-1) > 0 ||			\
	 (((__x) > 0) == ((__d) > 0))) ?		\
		(((__x) + ((__d) / 2)) / (__d)) :	\
		(((__x) - ((__d) / 2)) / (__d));	\
}							\
)

/* Register offset */
#define REG_GEN3_CTSR		0x20
#define REG_GEN3_THCTR		0x20
#define REG_GEN3_IRQSTR		0x04
#define REG_GEN3_IRQMSK		0x08
#define REG_GEN3_IRQCTL		0x0C
#define REG_GEN3_IRQEN		0x10
#define REG_GEN3_IRQTEMP1	0x14
#define REG_GEN3_IRQTEMP2	0x18
#define REG_GEN3_IRQTEMP3	0x1C
#define REG_GEN3_TEMP		0x28
#define REG_GEN3_THCODE1	0x50
#define REG_GEN3_THCODE2	0x54
#define REG_GEN3_THCODE3	0x58

#define PTAT_BASE		0xE6198000
#define REG_GEN3_PTAT1		0x5C
#define REG_GEN3_PTAT2		0x60
#define REG_GEN3_PTAT3		0x64
#define REG_GEN3_THSCP		0x68
#define REG_GEN3_MAX_SIZE	(REG_GEN3_THSCP + 0x4)

/* THSCP bit */
#define COR_PARA_VLD		(0x3 << 14)

/* CTSR bit */
#define PONM1            (0x1 << 8)	/* For H3 ES1.x */
#define AOUT            (0x1 << 7)
#define THBGR           (0x1 << 5)
#define VMEN            (0x1 << 4)
#define VMST            (0x1 << 1)
#define THSST           (0x1 << 0)

/* THCTR bit */
#define PONM2            (0x1 << 6)	/* For H3 ES2.0 and M3 ES1.0 */

#define CTEMP_MASK	0xFFF

#define IRQ_TEMP1_BIT	(0x1 << 0)
#define IRQ_TEMP2_BIT	(0x1 << 1)
#define IRQ_TEMP3_BIT	(0x1 << 2)
#define IRQ_TEMPD1_BIT	(0x1 << 3)
#define IRQ_TEMPD2_BIT	(0x1 << 4)
#define IRQ_TEMPD3_BIT	(0x1 << 5)

#define MCELSIUS(temp)			((temp) * 1000)
#define TEMP_IRQ_SHIFT(tsc_id)	(0x1 << tsc_id)
#define TEMPD_IRQ_SHIFT(tsc_id)	(0x1 << (tsc_id + 3))
#define GEN3_FUSE_MASK	0xFFF

/* Equation coefficients for thermal calculation formula.*/
struct equation_coefs {
	long a1;
	long b1;
	long a2;
	long b2;
};


struct fuse_factors {
	int thcode_1;
	int thcode_2;
	int thcode_3;
	int ptat_1;
	int ptat_2;
	int ptat_3;
};

struct rcar_thermal_priv {
	void __iomem *base;
	struct device *dev;
	struct tasklet work;
	struct fuse_factors factor;
	struct equation_coefs coef;
	spinlock_t lock;
	int id;
	int irq;
};

#define rcar_priv_to_dev(priv)		((priv)->dev)
#define rcar_has_irq_support(priv)	((priv)->irq)

/* Temperature calculation  */
#define CODETSD(x)		((x) * 1000)
#define TJ_1 116000L
#define TJ_3 (-41000L)

#define rcar_thermal_read(p, r) _rcar_thermal_read(p, r)
static u32 _rcar_thermal_read(struct rcar_thermal_priv *priv, u32 reg)
{
	return readl(priv->base + reg);
}

#define rcar_thermal_write(p, r, d) _rcar_thermal_write(p, r, d)
static void _rcar_thermal_write(struct rcar_thermal_priv *priv,
				u32 reg, u32 data)
{
	writel(data, priv->base + reg);
}

static int round_temp(int temp)
{
	int tmp1, tmp2;
	int result = 0;

	tmp1 = ABS(temp) % 1000;
	tmp2 = ABS(temp) / 1000;

	if (tmp1 < 250)
		result = CODETSD(tmp2);
	else if ((tmp1 < 750) && (tmp1 >= 250))
		result = CODETSD(tmp2) + 500;
	else
		result = CODETSD(tmp2) + 1000;

	return ((temp < 0) ? (result * (-1)) : result);
}

static int thermal_read_fuse_factor(struct rcar_thermal_priv *priv)
{
	void __iomem *ptat_base;
	unsigned int cor_para_value;
	struct device *dev = rcar_priv_to_dev(priv);

	ptat_base = ioremap_nocache(PTAT_BASE, REG_GEN3_MAX_SIZE);
	if (!ptat_base) {
		printk("%s: Cannot map FUSE register\n", dev_name(dev));
		return -ENOMEM;
	}

	cor_para_value = readl(ptat_base + REG_GEN3_THSCP) & COR_PARA_VLD;

	/* Checking whether Fuse values have been programmed or not.
	 * Base on that, it decides using fixed pseudo values or Fuse values.
	 */

	if (cor_para_value != COR_PARA_VLD) {
		printk(XENLOG_INFO "%s: is using pseudo fixed values\n", dev_name(dev));

		priv->factor.ptat_1 = 2631;
		priv->factor.ptat_2 = 1509;
		priv->factor.ptat_3 = 435;
		switch (priv->id) {
		case 0:
			priv->factor.thcode_1 = 3397;
			priv->factor.thcode_2 = 2800;
			priv->factor.thcode_3 = 2221;
			break;
		case 1:
			priv->factor.thcode_1 = 3393;
			priv->factor.thcode_2 = 2795;
			priv->factor.thcode_3 = 2216;
			break;
		case 2:
			priv->factor.thcode_1 = 3389;
			priv->factor.thcode_2 = 2805;
			priv->factor.thcode_3 = 2237;
			break;
		}
	} else {
		printk(XENLOG_INFO "%s: is using Fuse values\n", dev_name(dev));

		priv->factor.thcode_1 = rcar_thermal_read(priv,
						REG_GEN3_THCODE1)
				& GEN3_FUSE_MASK;
		priv->factor.thcode_2 = rcar_thermal_read(priv,
						REG_GEN3_THCODE2)
				& GEN3_FUSE_MASK;
		priv->factor.thcode_3 = rcar_thermal_read(priv,
						REG_GEN3_THCODE3)
				& GEN3_FUSE_MASK;
		priv->factor.ptat_1 = readl(ptat_base + REG_GEN3_PTAT1)
				& GEN3_FUSE_MASK;
		priv->factor.ptat_2 = readl(ptat_base + REG_GEN3_PTAT2)
				& GEN3_FUSE_MASK;
		priv->factor.ptat_3 = readl(ptat_base + REG_GEN3_PTAT3)
				& GEN3_FUSE_MASK;
	}

	iounmap(ptat_base);

	return 0;
}

static void thermal_coefficient_calculation(struct rcar_thermal_priv *priv)
{
	int tj_2 = 0;
	long a1, b1;
	long a2, b2;
	long a1_num, a1_den;
	long a2_num, a2_den;

	tj_2 = (CODETSD((priv->factor.ptat_2 - priv->factor.ptat_3) * 157)
		/ (priv->factor.ptat_1 - priv->factor.ptat_3)) - CODETSD(41);

	/*
	 * The following code is to calculate coefficients.
	 */
	/* Coefficient a1 and b1 */
	a1_num = CODETSD(priv->factor.thcode_2 - priv->factor.thcode_3);
	a1_den = tj_2 - TJ_3;
	a1 = (10000 * a1_num) / a1_den;
	b1 = (10000 * priv->factor.thcode_3) - ((a1 * TJ_3) / 1000);

	/* Coefficient a2 and b2 */
	a2_num = CODETSD(priv->factor.thcode_2 - priv->factor.thcode_1);
	a2_den = tj_2 - TJ_1;
	a2 = (10000 * a2_num) / a2_den;
	b2 = (10000 * priv->factor.thcode_1) - ((a2 * TJ_1) / 1000);

	priv->coef.a1 = DIV_ROUND_CLOSEST(a1, 10);
	priv->coef.b1 = DIV_ROUND_CLOSEST(b1, 10);
	priv->coef.a2 = DIV_ROUND_CLOSEST(a2, 10);
	priv->coef.b2 = DIV_ROUND_CLOSEST(b2, 10);
}

int thermal_temp_converter(struct equation_coefs coef,
					int temp_code)
{
	int temp, temp1, temp2;

	temp1 = MCELSIUS((CODETSD(temp_code) - coef.b1)) / coef.a1;
	temp2 = MCELSIUS((CODETSD(temp_code) - coef.b2)) / coef.a2;
	temp = (temp1 + temp2) / 2;

	return round_temp(temp);
}

int thermal_celsius_to_temp(struct equation_coefs coef,
					int ctemp)
{
	int temp_code, temp1, temp2;

	temp1 = (((ctemp * coef.a1) / 1000) + coef.b1) / 1000;
	temp2 = (((ctemp * coef.a2) / 1000) + coef.b2) / 1000;
	temp_code = (temp1 + temp2) / 2;

	return temp_code;
}

/*
 *		Zone device functions
 */
static int rcar_gen3_thermal_update_temp(struct rcar_thermal_priv *priv)
{
	u32 ctemp;
	unsigned long flags;
	int temp_cel, temp_code;

	spin_lock_irqsave(&priv->lock, flags);

	ctemp = rcar_thermal_read(priv, REG_GEN3_TEMP) & CTEMP_MASK;
	if (rcar_has_irq_support(priv)) {
		temp_cel = thermal_temp_converter(priv->coef, ctemp);

		/* set the interrupts to exceed the temperature */
		temp_code = thermal_celsius_to_temp(priv->coef,
						    temp_cel + MCELSIUS(1));
		rcar_thermal_write(priv, REG_GEN3_IRQTEMP1, temp_code);

		/* set the interrupts to fall below the temperature */
		temp_code = thermal_celsius_to_temp(priv->coef,
						    temp_cel - MCELSIUS(1));
		rcar_thermal_write(priv, REG_GEN3_IRQTEMP2, temp_code);
	}

	spin_unlock_irqrestore(&priv->lock, flags);

	return 0;
}

static int rcar_gen3_thermal_get_temp(void *devdata, int *temp)
{
	struct rcar_thermal_priv *priv = devdata;
	int ctemp;
	unsigned long flags;
	u32 ctemp_code;

	spin_lock_irqsave(&priv->lock, flags);
	ctemp_code = rcar_thermal_read(priv, REG_GEN3_TEMP) & CTEMP_MASK;
	ctemp = thermal_temp_converter(priv->coef, ctemp_code);
	spin_unlock_irqrestore(&priv->lock, flags);

	if ((ctemp < MCELSIUS(-40)) || (ctemp > MCELSIUS(125))) {
		struct device *dev = rcar_priv_to_dev(priv);

		printk(XENLOG_WARNING "%s: Temperature is not measured correctly!\n",
				dev_name(dev));

		return -EIO;
	}

	*temp = ctemp;

	return 0;
}

/* Applicable for both M3 1.x and H3 ES2.0, but not for H3 1.x */
static int rcar_gen3_r8a7796_thermal_init(struct rcar_thermal_priv *priv)
{
	unsigned long flags;
	unsigned long reg_val;

	spin_lock_irqsave(&priv->lock, flags);
	reg_val = rcar_thermal_read(priv, REG_GEN3_THCTR);
	reg_val &= ~PONM2;
	rcar_thermal_write(priv, REG_GEN3_THCTR, reg_val);
	udelay(1000);
	rcar_thermal_write(priv, REG_GEN3_IRQCTL, 0x3F);
	rcar_thermal_write(priv, REG_GEN3_IRQMSK, 0);
	rcar_thermal_write(priv, REG_GEN3_IRQEN,
			   IRQ_TEMP1_BIT | IRQ_TEMPD2_BIT);
	reg_val = rcar_thermal_read(priv, REG_GEN3_THCTR);
	reg_val |= THSST;
	rcar_thermal_write(priv, REG_GEN3_THCTR, reg_val);

	spin_unlock_irqrestore(&priv->lock, flags);

	return 0;
}

/*
 *		Interrupt
 */
#define rcar_thermal_irq_enable(p)	_rcar_thermal_irq_ctrl(p, 1)
#define rcar_thermal_irq_disable(p)	_rcar_thermal_irq_ctrl(p, 0)
static void _rcar_thermal_irq_ctrl(struct rcar_thermal_priv *priv, int enable)
{
	unsigned long flags;

	if (!rcar_has_irq_support(priv))
		return;

	spin_lock_irqsave(&priv->lock, flags);
	rcar_thermal_write(priv, REG_GEN3_IRQSTR, 0);
	rcar_thermal_write(priv, REG_GEN3_IRQMSK,
		enable ? (IRQ_TEMP1_BIT | IRQ_TEMPD2_BIT) : 0);
	spin_unlock_irqrestore(&priv->lock, flags);
}

static void handle_thermal_trip(int temp, int trip)
{
	/* Don't analyze if trip point temperature is not set */
	if (trip_points[trip].temp <= 0)
		return;

	if (trip_points[trip].critical) {
		/* If we have not crossed the trip point temperature, we do not care. */
		if (temp < trip_points[trip].temp)
			return;

		printk("Reached critical temperature (%d C): rebooting machine\n",
				temp / 1000);

		machine_restart(0);
	} else {
		/* Simple two point regulation */
		if (temp > trip_points[trip].temp) {
			if (throttle_enabled)
				return;

			if (scpi_cpufreq_throttle(true)) {
				printk("Failed to enable CPU throttling\n");
				return;
			}
			throttle_enabled = true;
		} else if (temp < trip_points[trip].temp - trip_points[trip].hyst) {
			if (!throttle_enabled)
				return;

			scpi_cpufreq_throttle(false);
			throttle_enabled = false;
		}
	}
}

static void thermal_zone_device_update(struct rcar_thermal_priv *priv)
{
	int i, ret, temp;

	ret = rcar_gen3_thermal_get_temp(priv, &temp);
	if (ret)
		return;

	if (cpufreq_debug)
		printk("Current CPU temperature: %d mC\n", temp);

	for (i = 0; i < ARRAY_SIZE(trip_points); i++)
		handle_thermal_trip(temp, i);
}

static void rcar_gen3_thermal_work(unsigned long data)
{
	struct rcar_thermal_priv *priv = (struct rcar_thermal_priv *)data;

	rcar_gen3_thermal_update_temp(priv);
	thermal_zone_device_update(priv);
	rcar_thermal_irq_enable(priv);
}

static void rcar_gen3_thermal_irq(int irq, void *data,
		struct cpu_user_regs *regs)
{
	struct rcar_thermal_priv *priv = data;
	unsigned long flags;
	int status;

	spin_lock_irqsave(&priv->lock, flags);
	status = rcar_thermal_read(priv, REG_GEN3_IRQSTR);
	rcar_thermal_write(priv, REG_GEN3_IRQSTR, 0);
	spin_unlock_irqrestore(&priv->lock, flags);

	if (status == 0)
		return;

	if (status & (IRQ_TEMP1_BIT | IRQ_TEMPD2_BIT)) {
		rcar_thermal_irq_disable(priv);
		tasklet_schedule(&priv->work);
	}
}

static const struct dt_device_match rcar_thermal_dt_ids[] __initconst = {
	{ .compatible = "renesas,thermal-r8a7795", },
	{ .compatible = "renesas,thermal-r8a7796", },
	{ },
};

static int __init rcar_gen3_thermal_probe(struct dt_device_node *np)
{
	struct rcar_thermal_priv *priv;
	struct device *dev = &np->dev;
	int ret, i, irq_cnt, irqs[3];
	uint64_t addr, size;

	priv = xzalloc(struct rcar_thermal_priv);
	if (!priv)
		return -ENOMEM;

	priv->dev = dev;

	/* Preliminary check for IRQ(s) to present */
	irq_cnt = dt_number_of_irq(np);
	if (!irq_cnt || irq_cnt > ARRAY_SIZE(irqs)) {
		printk("%s: Got wrong IRQ count!\n", dev_name(dev));
		ret = -ENODEV;
		goto err_free;
	}
	priv->irq = 1;

	ret = dt_device_get_address(np, 0, &addr, &size);
	if (ret) {
		printk("%s: Failed to get MMIO base address\n", dev_name(dev));
		goto err_free;
	}

	priv->base = ioremap_nocache(addr, size);
	if (!priv->base) {
		printk("%s: Failed to map MMIO range\n", dev_name(dev));
		ret = -ENOMEM;
		goto err_free;
	}

	spin_lock_init(&priv->lock);
	tasklet_init(&priv->work, rcar_gen3_thermal_work, (unsigned long)priv);

	priv->id = dt_alias_get_id(dev->of_node, "tsc");

	rcar_gen3_r8a7796_thermal_init(priv);
	ret = thermal_read_fuse_factor(priv);
	if (ret)
		goto err_iounmap;

	thermal_coefficient_calculation(priv);
	ret = rcar_gen3_thermal_update_temp(priv);
	if (ret < 0)
		goto err_iounmap;

	if (rcar_has_irq_support(priv)) {
		for (i = 0; i < irq_cnt; i++) {
			irqs[i] = platform_get_irq(np, i);
			if (irqs[i] < 0) {
				printk("%s: Failed to get IRQ index %d\n", dev_name(dev), i);
				goto err_release;
			}

			ret = request_irq(irqs[i], IRQF_SHARED, rcar_gen3_thermal_irq,
					dev_name(dev), priv);
			if (ret) {
				printk("%s: Failed to request IRQ %d\n", dev_name(dev), irqs[i]);
				goto err_release;
			}
		}
		rcar_thermal_irq_enable(priv);
	}

	printk(XENLOG_INFO "%s: Thermal sensor probed id%d\n",
			dev_name(dev), priv->id);

	return 0;

err_release:
	while (i--)
		release_irq(irqs[i], priv);
err_iounmap:
	tasklet_kill(&priv->work);
	iounmap(priv->base);
err_free:
	xfree(priv);

	return ret;
}

static inline void cpg_write(uintptr_t regadr, uint32_t regval)
{
	uint32_t value = (regval);
	mmio_write_32((uintptr_t)CPG_CPGWPR, ~value);
	mmio_write_32(regadr, value);
}

static void rcar_gen3_thermal_enable_clock(void)
{
	/* Is the clock supply to the CPG disabled ? */
	while ((mmio_read_32(CPG_MSTPSR5) & CPG_THS_BIT) != 0U) {
		/* Enables the clock supply to the CPG. */
		cpg_write(CPG_SMSTPCR5, mmio_read_32(CPG_SMSTPCR5) & (~CPG_THS_BIT));
	}
}

static int __init rcar_gen3_thermal_init(struct dt_device_node *np,
		const void *data)
{
	int ret;

	rcar_gen3_thermal_enable_clock();

	ret = rcar_gen3_thermal_probe(np);
	if (ret) {
		printk(XENLOG_ERR "%s: failed to init R-Car Gen3 THS (%d)\n",
				dev_name(&np->dev), ret);
		return ret;
	}

	return 0;
}

DT_DEVICE_START(rcar_gen3_thermal, "R-Car Gen3 THS", DEVICE_THS)
	.dt_match = rcar_thermal_dt_ids,
	.init = rcar_gen3_thermal_init,
DT_DEVICE_END
