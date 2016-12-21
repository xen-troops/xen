/*
 * IPMMU VMSA
 *
 * Copyright (C) 2014 Renesas Electronics Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * Based on Linux drivers/iommu/ipmmu-vmsa.c
 * => commit 59ddda852048e4706a103b689a15d6f99bb1cf6b (not in mainline yet)
 * (iommu/ipmmu-vmsa: Correct the backup/restore for context)
 *
 * Xen modification:
 * Oleksandr Tyshchenko <Oleksandr_Tyshchenko@epam.com>
 * Copyright (C) 2016 EPAM Systems Inc.
 */

#include <xen/config.h>
#include <xen/delay.h>
#include <xen/errno.h>
#include <xen/err.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/list.h>
#include <xen/mm.h>
#include <xen/vmap.h>
#include <xen/rbtree.h>
#include <xen/sched.h>
#include <xen/sizes.h>
#include <asm/atomic.h>
#include <asm/device.h>
#include <asm/io.h>
#include <asm/platform.h>

#include "io-pgtable.h"

/* TODO:
 * 1. Optimize xen_domain->lock usage.
 *
 */

/***** Start of Xen specific code *****/

#define IOMMU_READ	(1 << 0)
#define IOMMU_WRITE	(1 << 1)
#define IOMMU_CACHE	(1 << 2) /* DMA cache coherency */
#define IOMMU_NOEXEC	(1 << 3)
#define IOMMU_MMIO	(1 << 4) /* e.g. things like MSI doorbells */

#define __fls(x) (fls(x) - 1)
#define __ffs(x) (ffs(x) - 1)

#define IO_PGTABLE_QUIRK_ARM_NS		BIT(0)

#define ioread32 readl
#define iowrite32 writel

#define dev_info dev_notice

#define kcalloc(size, n, flags)	_xzalloc_array(size, sizeof(void *), n)

#define of_find_property dt_find_property
#define of_count_phandle_with_args dt_count_phandle_with_args

#define devm_request_irq(unused, irq, func, flags, name, dev) \
	request_irq(irq, flags, func, name, dev)

/* Alias to Xen device tree helpers */
#define device_node dt_device_node
#define of_phandle_args dt_phandle_args
#define of_device_id dt_device_match
#define of_match_node dt_match_node
#define of_parse_phandle_with_args dt_parse_phandle_with_args

/* Xen: Helpers to get device MMIO and IRQs */
struct resource
{
	u64 addr;
	u64 size;
	unsigned int type;
};

#define resource_size(res) (res)->size;

#define platform_device dt_device_node

#define IORESOURCE_MEM 0
#define IORESOURCE_IRQ 1

static struct resource *platform_get_resource(struct platform_device *pdev,
					      unsigned int type,
					      unsigned int num)
{
	/*
	 * The resource is only used between 2 calls of platform_get_resource.
	 * It's quite ugly but it's avoid to add too much code in the part
	 * imported from Linux
	 */
	static struct resource res;
	int ret = 0;

	res.type = type;

	switch (type) {
	case IORESOURCE_MEM:
		ret = dt_device_get_address(pdev, num, &res.addr, &res.size);

		return ((ret) ? NULL : &res);

	case IORESOURCE_IRQ:
		ret = platform_get_irq(pdev, num);
		if (ret < 0)
			return NULL;

		res.addr = ret;
		res.size = 1;

		return &res;

	default:
		return NULL;
	}
}

enum irqreturn {
	IRQ_NONE	= (0 << 0),
	IRQ_HANDLED	= (1 << 0),
};

typedef enum irqreturn irqreturn_t;

/* Device logger functions */
#define dev_print(dev, lvl, fmt, ...)						\
	 printk(lvl "ipmmu: %s: " fmt, dt_node_full_name(dev_to_dt(dev)), ## __VA_ARGS__)

#define dev_dbg(dev, fmt, ...) dev_print(dev, XENLOG_DEBUG, fmt, ## __VA_ARGS__)
#define dev_notice(dev, fmt, ...) dev_print(dev, XENLOG_INFO, fmt, ## __VA_ARGS__)
#define dev_warn(dev, fmt, ...) dev_print(dev, XENLOG_WARNING, fmt, ## __VA_ARGS__)
#define dev_err(dev, fmt, ...) dev_print(dev, XENLOG_ERR, fmt, ## __VA_ARGS__)

#define dev_err_ratelimited(dev, fmt, ...)					\
	 dev_print(dev, XENLOG_ERR, fmt, ## __VA_ARGS__)

#define dev_name(dev) dt_node_full_name(dev_to_dt(dev))

/* Alias to Xen allocation helpers */
#define kfree xfree
#define kmalloc(size, flags)		_xmalloc(size, sizeof(void *))
#define kzalloc(size, flags)		_xzalloc(size, sizeof(void *))
#define devm_kzalloc(dev, size, flags)	_xzalloc(size, sizeof(void *))
#define kmalloc_array(size, n, flags)	_xmalloc_array(size, sizeof(void *), n)

static void __iomem *devm_ioremap_resource(struct device *dev,
					   struct resource *res)
{
	void __iomem *ptr;

	if (!res || res->type != IORESOURCE_MEM) {
		dev_err(dev, "Invalid resource\n");
		return ERR_PTR(-EINVAL);
	}

	ptr = ioremap_nocache(res->addr, res->size);
	if (!ptr) {
		dev_err(dev,
			"ioremap failed (addr 0x%"PRIx64" size 0x%"PRIx64")\n",
			res->addr, res->size);
		return ERR_PTR(-ENOMEM);
	}

	return ptr;
}

/* Xen doesn't handle IOMMU fault */
#define report_iommu_fault(...)	1

#define MODULE_DEVICE_TABLE(type, name)
#define module_param_named(name, value, type, perm)
#define MODULE_PARM_DESC(_parm, desc)

/* Xen: Dummy iommu_domain */
struct iommu_domain
{
	atomic_t ref;
	/* Used to link iommu_domain contexts for a same domain.
	 * There is at least one per-IPMMU to used by the domain.
	 * */
	struct list_head		list;
};

/* Xen: Describes informations required for a Xen domain */
struct ipmmu_vmsa_xen_domain {
	spinlock_t			lock;
	/* List of context (i.e iommu_domain) associated to this domain */
	struct list_head		contexts;
	struct iommu_domain		*base_context;
};

/*
 * Xen: Information about each device stored in dev->archdata.iommu
 *
 * On Linux the dev->archdata.iommu only stores the arch specific information,
 * but, on Xen, we also have to store the iommu domain.
 */
struct ipmmu_vmsa_xen_device {
	struct iommu_domain *domain;
	struct ipmmu_vmsa_archdata *archdata;
};

#define dev_iommu(dev) ((struct ipmmu_vmsa_xen_device *)dev->archdata.iommu)
#define dev_iommu_domain(dev) (dev_iommu(dev)->domain)
#define dev_iommu_archdata(dev) (dev_iommu(dev)->archdata)

/***** Start of Linux IPMMU code *****/

#define IPMMU_CTX_MAX 8

struct ipmmu_features {
	bool use_ns_alias_offset;
	bool has_cache_leaf_nodes;
	bool has_eight_ctx;
	bool setup_imbuscr;
	bool twobit_imttbcr_sl0;
};

struct ipmmu_vmsa_device {
	struct device *dev;
	void __iomem *base;
	struct list_head list;
	const struct ipmmu_features *features;
	bool is_leaf;
	unsigned int num_utlbs;
	unsigned int num_ctx;
	spinlock_t lock;			/* Protects ctx and domains[] */
	DECLARE_BITMAP(ctx, IPMMU_CTX_MAX);
	struct ipmmu_vmsa_domain *domains[IPMMU_CTX_MAX];

#if 0 /* Xen: Not needed */
	struct dma_iommu_mapping *mapping;
#endif
};

struct ipmmu_vmsa_domain {
	struct ipmmu_vmsa_device *mmu;
	struct ipmmu_vmsa_device *root;
	struct iommu_domain io_domain;

	struct io_pgtable_cfg cfg;
	struct io_pgtable_ops *iop;

	unsigned int context_id;
	spinlock_t lock;			/* Protects mappings */

	/* Xen: Domain associated to this configuration */
	struct domain *d;
};

struct ipmmu_vmsa_archdata {
	struct ipmmu_vmsa_device *mmu;
	unsigned int *utlbs;
	unsigned int num_utlbs;
	struct device *dev;
	struct list_head list;
};

static DEFINE_SPINLOCK(ipmmu_devices_lock);
static LIST_HEAD(ipmmu_devices);

#if 0 /* Xen: Not needed */
static DEFINE_SPINLOCK(ipmmu_slave_devices_lock);
static LIST_HEAD(ipmmu_slave_devices);
#endif

static struct ipmmu_vmsa_domain *to_vmsa_domain(struct iommu_domain *dom)
{
	return container_of(dom, struct ipmmu_vmsa_domain, io_domain);
}

#if 0 /* Xen: Not needed */
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
static struct ipmmu_vmsa_archdata *to_archdata(struct device *dev)
{
	return dev->archdata.iommu;
}
static void set_archdata(struct device *dev, struct ipmmu_vmsa_archdata *p)
{
	dev->archdata.iommu = p;
}
#else
static struct ipmmu_vmsa_archdata *to_archdata(struct device *dev)
{
	return NULL;
}
static void set_archdata(struct device *dev, struct ipmmu_vmsa_archdata *p)
{
}
#endif
#endif

#define TLB_LOOP_TIMEOUT		100	/* 100us */

/* -----------------------------------------------------------------------------
 * Registers Definition
 */

#define IM_NS_ALIAS_OFFSET		0x800

#define IM_CTX_SIZE			0x40

#define IMCTR				0x0000
#define IMCTR_TRE			(1 << 17)
#define IMCTR_AFE			(1 << 16)
#define IMCTR_RTSEL_MASK		(3 << 4)
#define IMCTR_RTSEL_SHIFT		4
#define IMCTR_TREN			(1 << 3)
#define IMCTR_INTEN			(1 << 2)
#define IMCTR_FLUSH			(1 << 1)
#define IMCTR_MMUEN			(1 << 0)

#define IMCAAR				0x0004

#define IMTTBCR				0x0008
#define IMTTBCR_EAE			(1 << 31)
#define IMTTBCR_PMB			(1 << 30)
#define IMTTBCR_SH1_NON_SHAREABLE	(0 << 28)
#define IMTTBCR_SH1_OUTER_SHAREABLE	(2 << 28)
#define IMTTBCR_SH1_INNER_SHAREABLE	(3 << 28)
#define IMTTBCR_SH1_MASK		(3 << 28)
#define IMTTBCR_ORGN1_NC		(0 << 26)
#define IMTTBCR_ORGN1_WB_WA		(1 << 26)
#define IMTTBCR_ORGN1_WT		(2 << 26)
#define IMTTBCR_ORGN1_WB		(3 << 26)
#define IMTTBCR_ORGN1_MASK		(3 << 26)
#define IMTTBCR_IRGN1_NC		(0 << 24)
#define IMTTBCR_IRGN1_WB_WA		(1 << 24)
#define IMTTBCR_IRGN1_WT		(2 << 24)
#define IMTTBCR_IRGN1_WB		(3 << 24)
#define IMTTBCR_IRGN1_MASK		(3 << 24)
#define IMTTBCR_TSZ1_MASK		(7 << 16)
#define IMTTBCR_TSZ1_SHIFT		16
#define IMTTBCR_SH0_NON_SHAREABLE	(0 << 12)
#define IMTTBCR_SH0_OUTER_SHAREABLE	(2 << 12)
#define IMTTBCR_SH0_INNER_SHAREABLE	(3 << 12)
#define IMTTBCR_SH0_MASK		(3 << 12)
#define IMTTBCR_ORGN0_NC		(0 << 10)
#define IMTTBCR_ORGN0_WB_WA		(1 << 10)
#define IMTTBCR_ORGN0_WT		(2 << 10)
#define IMTTBCR_ORGN0_WB		(3 << 10)
#define IMTTBCR_ORGN0_MASK		(3 << 10)
#define IMTTBCR_IRGN0_NC		(0 << 8)
#define IMTTBCR_IRGN0_WB_WA		(1 << 8)
#define IMTTBCR_IRGN0_WT		(2 << 8)
#define IMTTBCR_IRGN0_WB		(3 << 8)
#define IMTTBCR_IRGN0_MASK		(3 << 8)
#define IMTTBCR_SL0_LVL_2		(0 << 4)
#define IMTTBCR_SL0_LVL_1		(1 << 4)
#define IMTTBCR_TSZ0_MASK		(7 << 0)
#define IMTTBCR_TSZ0_SHIFT		O

#define IMTTBCR_SL0_TWOBIT_LVL_3	(0 << 6)
#define IMTTBCR_SL0_TWOBIT_LVL_2	(1 << 6)
#define IMTTBCR_SL0_TWOBIT_LVL_1	(2 << 6)

#define IMBUSCR				0x000c
#define IMBUSCR_DVM			(1 << 2)
#define IMBUSCR_BUSSEL_SYS		(0 << 0)
#define IMBUSCR_BUSSEL_CCI		(1 << 0)
#define IMBUSCR_BUSSEL_IMCAAR		(2 << 0)
#define IMBUSCR_BUSSEL_CCI_IMCAAR	(3 << 0)
#define IMBUSCR_BUSSEL_MASK		(3 << 0)

#define IMTTLBR0			0x0010
#define IMTTUBR0			0x0014
#define IMTTLBR1			0x0018
#define IMTTUBR1			0x001c

#define IMSTR				0x0020
#define IMSTR_ERRLVL_MASK		(3 << 12)
#define IMSTR_ERRLVL_SHIFT		12
#define IMSTR_ERRCODE_TLB_FORMAT	(1 << 8)
#define IMSTR_ERRCODE_ACCESS_PERM	(4 << 8)
#define IMSTR_ERRCODE_SECURE_ACCESS	(5 << 8)
#define IMSTR_ERRCODE_MASK		(7 << 8)
#define IMSTR_MHIT			(1 << 4)
#define IMSTR_ABORT			(1 << 2)
#define IMSTR_PF			(1 << 1)
#define IMSTR_TF			(1 << 0)

#define IMMAIR0				0x0028
#define IMMAIR1				0x002c
#define IMMAIR_ATTR_MASK		0xff
#define IMMAIR_ATTR_DEVICE		0x04
#define IMMAIR_ATTR_NC			0x44
#define IMMAIR_ATTR_WBRWA		0xff
#define IMMAIR_ATTR_SHIFT(n)		((n) << 3)
#define IMMAIR_ATTR_IDX_NC		0
#define IMMAIR_ATTR_IDX_WBRWA		1
#define IMMAIR_ATTR_IDX_DEV		2

#define IMEAR				0x0030

#define IMPCTR				0x0200
#define IMPSTR				0x0208
#define IMPEAR				0x020c
#define IMPMBA(n)			(0x0280 + ((n) * 4))
#define IMPMBD(n)			(0x02c0 + ((n) * 4))

#define IMUCTR(n)			(0x0300 + ((n) * 16))
#define IMUCTR2(n)			(0x0600 + ((n) * 16))
#define IMUCTR_FIXADDEN			(1 << 31)
#define IMUCTR_FIXADD_MASK		(0xff << 16)
#define IMUCTR_FIXADD_SHIFT		16
#define IMUCTR_TTSEL_MMU(n)		((n) << 4)
#define IMUCTR_TTSEL_PMB		(8 << 4)
#define IMUCTR_TTSEL_MASK		(15 << 4)
#define IMUCTR_FLUSH			(1 << 1)
#define IMUCTR_MMUEN			(1 << 0)

#define IMUASID(n)			(0x0308 + ((n) * 16))
#define IMUASID2(n)			(0x0608 + ((n) * 16))
#define IMUASID_ASID8_MASK		(0xff << 8)
#define IMUASID_ASID8_SHIFT		8
#define IMUASID_ASID0_MASK		(0xff << 0)
#define IMUASID_ASID0_SHIFT		0

/* -----------------------------------------------------------------------------
 * Root device handling
 */

static bool ipmmu_is_root(struct ipmmu_vmsa_device *mmu)
{
	/* Xen: Fix */
	if (!mmu)
		return false;

	if (mmu->features->has_cache_leaf_nodes)
		return mmu->is_leaf ? false : true;
	else
		return true; /* older IPMMU hardware treated as single root */
}

static struct ipmmu_vmsa_device *ipmmu_find_root(struct ipmmu_vmsa_device *leaf)
{
	struct ipmmu_vmsa_device *mmu = NULL;

	if (ipmmu_is_root(leaf))
		return leaf;

	spin_lock(&ipmmu_devices_lock);

	list_for_each_entry(mmu, &ipmmu_devices, list) {
		if (ipmmu_is_root(mmu))
			break;
	}

	spin_unlock(&ipmmu_devices_lock);
	return mmu;
}

/* -----------------------------------------------------------------------------
 * Read/Write Access
 */

static u32 ipmmu_read(struct ipmmu_vmsa_device *mmu, unsigned int offset)
{
	return ioread32(mmu->base + offset);
}

static void ipmmu_write(struct ipmmu_vmsa_device *mmu, unsigned int offset,
			u32 data)
{
	iowrite32(data, mmu->base + offset);
}

static u32 ipmmu_ctx_read(struct ipmmu_vmsa_domain *domain, unsigned int reg)
{
	return ipmmu_read(domain->root, domain->context_id * IM_CTX_SIZE + reg);
}

static void ipmmu_ctx_write(struct ipmmu_vmsa_domain *domain, unsigned int reg,
			    u32 data)
{
	ipmmu_write(domain->root, domain->context_id * IM_CTX_SIZE + reg, data);
}

/* Xen: Write the context for cache IPMMU only. */
static void ipmmu_ctx_write1(struct ipmmu_vmsa_domain *domain, unsigned int reg,
			     u32 data)
{
	if (domain->mmu != domain->root)
		ipmmu_write(domain->mmu, domain->context_id * IM_CTX_SIZE + reg, data);
}

/*
 * Xen: Write the context for both root IPMMU and all cache IPMMUs
 * that assigned to this Xen domain.
 */
static void ipmmu_ctx_write2(struct ipmmu_vmsa_domain *domain, unsigned int reg,
			     u32 data)
{
	struct ipmmu_vmsa_xen_domain *xen_domain = dom_iommu(domain->d)->arch.priv;
	struct iommu_domain *io_domain;

	list_for_each_entry(io_domain, &xen_domain->contexts, list)
		ipmmu_ctx_write1(to_vmsa_domain(io_domain), reg, data);

	ipmmu_ctx_write(domain, reg, data);
}

/* -----------------------------------------------------------------------------
 * TLB and microTLB Management
 */

/* Wait for any pending TLB invalidations to complete */
static void ipmmu_tlb_sync(struct ipmmu_vmsa_domain *domain)
{
	unsigned int count = 0;

	while (ipmmu_ctx_read(domain, IMCTR) & IMCTR_FLUSH) {
		cpu_relax();
		if (++count == TLB_LOOP_TIMEOUT) {
			dev_err_ratelimited(domain->mmu->dev,
			"TLB sync timed out -- MMU may be deadlocked\n");
			return;
		}
		udelay(1);
	}
}

static void ipmmu_tlb_invalidate(struct ipmmu_vmsa_domain *domain)
{
	u32 reg;

	reg = ipmmu_ctx_read(domain, IMCTR);
	reg |= IMCTR_FLUSH;
	ipmmu_ctx_write2(domain, IMCTR, reg);

	ipmmu_tlb_sync(domain);
}

/*
 * Enable MMU translation for the microTLB.
 */
static void ipmmu_utlb_enable(struct ipmmu_vmsa_domain *domain,
			      unsigned int utlb)
{
	struct ipmmu_vmsa_device *mmu = domain->mmu;
	unsigned int offset;

	/*
	 * TODO: Reference-count the microTLB as several bus masters can be
	 * connected to the same microTLB.
	 */

	/* TODO: What should we set the ASID to ? */
	offset = (utlb < 32) ? IMUASID(utlb) : IMUASID2(utlb - 32);
	ipmmu_write(mmu, offset, 0);

	/* TODO: Do we need to flush the microTLB ? */
	offset = (utlb < 32) ? IMUCTR(utlb) : IMUCTR2(utlb - 32);
	ipmmu_write(mmu, offset,
		    IMUCTR_TTSEL_MMU(domain->context_id) | IMUCTR_FLUSH |
		    IMUCTR_MMUEN);
}

/*
 * Disable MMU translation for the microTLB.
 */
static void ipmmu_utlb_disable(struct ipmmu_vmsa_domain *domain,
			       unsigned int utlb)
{
	struct ipmmu_vmsa_device *mmu = domain->mmu;
	unsigned int offset;

	offset = (utlb < 32) ? IMUCTR(utlb) : IMUCTR2(utlb - 32);
	ipmmu_write(mmu, offset, 0);
}

static void ipmmu_tlb_flush_all(void *cookie)
{
	struct ipmmu_vmsa_domain *domain = cookie;

	/* Xen: Just return if context_id has wrong value */
	if (domain->context_id >= domain->root->num_ctx)
		return;

	ipmmu_tlb_invalidate(domain);
}

static void ipmmu_tlb_add_flush(unsigned long iova, size_t size,
				size_t granule, bool leaf, void *cookie)
{
	/* The hardware doesn't support selective TLB flush. */
}

static struct iommu_gather_ops ipmmu_gather_ops = {
	.tlb_flush_all = ipmmu_tlb_flush_all,
	.tlb_add_flush = ipmmu_tlb_add_flush,
	.tlb_sync = ipmmu_tlb_flush_all,
};

/* -----------------------------------------------------------------------------
 * Domain/Context Management
 */

static int ipmmu_domain_allocate_context(struct ipmmu_vmsa_device *mmu,
					 struct ipmmu_vmsa_domain *domain)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&mmu->lock, flags);

	ret = find_first_zero_bit(mmu->ctx, mmu->num_ctx);
	if (ret != mmu->num_ctx) {
		mmu->domains[ret] = domain;
		set_bit(ret, mmu->ctx);
	} else
		ret = -EBUSY;

	spin_unlock_irqrestore(&mmu->lock, flags);

	return ret;
}

static int ipmmu_domain_init_context(struct ipmmu_vmsa_domain *domain)
{
	u64 ttbr;
	u32 tmp;
	int ret;

	/*
	 * Allocate the page table operations.
	 *
	 * VMSA states in section B3.6.3 "Control of Secure or Non-secure memory
	 * access, Long-descriptor format" that the NStable bit being set in a
	 * table descriptor will result in the NStable and NS bits of all child
	 * entries being ignored and considered as being set. The IPMMU seems
	 * not to comply with this, as it generates a secure access page fault
	 * if any of the NStable and NS bits isn't set when running in
	 * non-secure mode.
	 */
	domain->cfg.quirks = IO_PGTABLE_QUIRK_ARM_NS;
	domain->cfg.pgsize_bitmap = SZ_1G | SZ_2M | SZ_4K,
	domain->cfg.ias = 32;
	domain->cfg.oas = 40;
	domain->cfg.tlb = &ipmmu_gather_ops;
	/*
	 * TODO: Add support for coherent walk through CCI with DVM and remove
	 * cache handling. For now, delegate it to the io-pgtable code.
	 */
	domain->cfg.iommu_dev = domain->root->dev;

	domain->iop = alloc_io_pgtable_ops(ARM_32_LPAE_S1, &domain->cfg,
					   domain);
	if (!domain->iop)
		return -EINVAL;

	/* Xen: Initialize context_id with wrong value */
	domain->context_id = domain->root->num_ctx;

	/*
	 * Find an unused context.
	 */
	ret = ipmmu_domain_allocate_context(domain->root, domain);
	if (ret < 0) {
		free_io_pgtable_ops(domain->iop);
		return ret;
	}

	domain->context_id = ret;

	/* TTBR0 */
	ttbr = domain->cfg.arm_lpae_s1_cfg.ttbr[0];

	/* Xen: */
	dev_notice(domain->root->dev, "d%d: Set IPMMU context %u (pgd 0x%"PRIx64")\n",
			domain->d->domain_id, domain->context_id, ttbr);

	ipmmu_ctx_write(domain, IMTTLBR0, ttbr);
	ipmmu_ctx_write(domain, IMTTUBR0, ttbr >> 32);

	/*
	 * TTBCR
	 * We use long descriptors with inner-shareable WBWA tables and allocate
	 * the whole 32-bit VA space to TTBR0.
	 */

	if (domain->root->features->twobit_imttbcr_sl0)
		tmp = IMTTBCR_SL0_TWOBIT_LVL_1;
	else
		tmp = IMTTBCR_SL0_LVL_1;

	ipmmu_ctx_write(domain, IMTTBCR, IMTTBCR_EAE |
			IMTTBCR_SH0_INNER_SHAREABLE | IMTTBCR_ORGN0_WB_WA |
			IMTTBCR_IRGN0_WB_WA | tmp);

	/* MAIR0 */
	ipmmu_ctx_write(domain, IMMAIR0, domain->cfg.arm_lpae_s1_cfg.mair[0]);

	/* IMBUSCR */
	if (domain->root->features->setup_imbuscr)
		ipmmu_ctx_write(domain, IMBUSCR,
				ipmmu_ctx_read(domain, IMBUSCR) &
				~(IMBUSCR_DVM | IMBUSCR_BUSSEL_MASK));
	/*
	 * IMSTR
	 * Clear all interrupt flags.
	 */
	ipmmu_ctx_write(domain, IMSTR, ipmmu_ctx_read(domain, IMSTR));

	/*
	 * IMCTR
	 * Enable the MMU and interrupt generation. The long-descriptor
	 * translation table format doesn't use TEX remapping. Don't enable AF
	 * software management as we have no use for it. Flush the TLB as
	 * required when modifying the context registers.
	 */
	ipmmu_ctx_write2(domain, IMCTR,
			 IMCTR_INTEN | IMCTR_FLUSH | IMCTR_MMUEN);

	return 0;
}

static void ipmmu_domain_free_context(struct ipmmu_vmsa_device *mmu,
				      unsigned int context_id)
{
	unsigned long flags;

	spin_lock_irqsave(&mmu->lock, flags);

	clear_bit(context_id, mmu->ctx);
	mmu->domains[context_id] = NULL;

	spin_unlock_irqrestore(&mmu->lock, flags);
}

static void ipmmu_domain_destroy_context(struct ipmmu_vmsa_domain *domain)
{
	/* Xen: Just return if context_id has wrong value */
	if (domain->context_id >= domain->root->num_ctx)
		return;

	/*
	 * Disable the context. Flush the TLB as required when modifying the
	 * context registers.
	 *
	 * TODO: Is TLB flush really needed ?
	 */
	ipmmu_ctx_write2(domain, IMCTR, IMCTR_FLUSH);
	ipmmu_tlb_sync(domain);

	ipmmu_domain_free_context(domain->root, domain->context_id);

	/* Xen: Initialize context_id with wrong value */
	domain->context_id = domain->root->num_ctx;
}

/* -----------------------------------------------------------------------------
 * Fault Handling
 */

/* Xen: Show domain_id in every printk */
static irqreturn_t ipmmu_domain_irq(struct ipmmu_vmsa_domain *domain)
{
	const u32 err_mask = IMSTR_MHIT | IMSTR_ABORT | IMSTR_PF | IMSTR_TF;
	/* Xen: It would be correct to use domain->root here... */
	struct ipmmu_vmsa_device *mmu = domain->mmu;
	u32 status;
	u32 iova;

	status = ipmmu_ctx_read(domain, IMSTR);
	if (!(status & err_mask))
		return IRQ_NONE;

	iova = ipmmu_ctx_read(domain, IMEAR);

	/*
	 * Clear the error status flags. Unlike traditional interrupt flag
	 * registers that must be cleared by writing 1, this status register
	 * seems to require 0. The error address register must be read before,
	 * otherwise its value will be 0.
	 */
	ipmmu_ctx_write(domain, IMSTR, 0);

	/* Log fatal errors. */
	if (status & IMSTR_MHIT)
		dev_err_ratelimited(mmu->dev, "d%d: Multiple TLB hits @0x%08x\n",
				domain->d->domain_id, iova);
	if (status & IMSTR_ABORT)
		dev_err_ratelimited(mmu->dev, "d%d: Page Table Walk Abort @0x%08x\n",
				domain->d->domain_id, iova);

	if (!(status & (IMSTR_PF | IMSTR_TF)))
		return IRQ_NONE;

	/*
	 * Try to handle page faults and translation faults.
	 *
	 * TODO: We need to look up the faulty device based on the I/O VA. Use
	 * the IOMMU device for now.
	 */
	if (!report_iommu_fault(&domain->io_domain, mmu->dev, iova, 0))
		return IRQ_HANDLED;

	dev_err_ratelimited(mmu->dev,
			"d%d: Unhandled fault: status 0x%08x iova 0x%08x\n",
			domain->d->domain_id, status, iova);

	return IRQ_HANDLED;
}

static irqreturn_t ipmmu_irq(int irq, void *dev)
{
	struct ipmmu_vmsa_device *mmu = dev;
	irqreturn_t status = IRQ_NONE;
	unsigned int i;
	unsigned long flags;

	spin_lock_irqsave(&mmu->lock, flags);

	/*
	 * Check interrupts for all active contexts.
	 */
	for (i = 0; i < mmu->num_ctx; i++) {
		if (!mmu->domains[i])
			continue;
		if (ipmmu_domain_irq(mmu->domains[i]) == IRQ_HANDLED)
			status = IRQ_HANDLED;
	}

	spin_unlock_irqrestore(&mmu->lock, flags);

	return status;
}

/* Xen: Interrupt handlers wrapper */
static void ipmmu_irq_xen(int irq, void *dev,
				      struct cpu_user_regs *regs)
{
	ipmmu_irq(irq, dev);
}

#define ipmmu_irq ipmmu_irq_xen

#if 0 /* Xen: Not needed */
/* -----------------------------------------------------------------------------
 * IOMMU Operations
 */

static struct iommu_domain *__ipmmu_domain_alloc(unsigned type)
{
	struct ipmmu_vmsa_domain *domain;

	domain = kzalloc(sizeof(*domain), GFP_KERNEL);
	if (!domain)
		return NULL;

	spin_lock_init(&domain->lock);

	return &domain->io_domain;
}

static void ipmmu_domain_free(struct iommu_domain *io_domain)
{
	struct ipmmu_vmsa_domain *domain = to_vmsa_domain(io_domain);

	/*
	 * Free the domain resources. We assume that all devices have already
	 * been detached.
	 */
	ipmmu_domain_destroy_context(domain);
	free_io_pgtable_ops(domain->iop);
	kfree(domain);
}

/* Hack to identity map address ranges needed by the DMAC hardware */
static struct {
	phys_addr_t base;
	size_t size;
} dmac_workaround[] = {
	{
		.base = 0xe6e60000, /* SCIF0 */
		.size = SZ_4K,
	},
	{
		.base = 0xe6e68000, /* SCIF1 */
		.size = SZ_4K,
	},
	/* DMA transfer of SCIF2 is not supported */
	{
		.base = 0xe6c50000, /* SCIF3 */
		.size = SZ_4K,
	},
	{
		.base = 0xe6c40000, /* SCIF4 */
		.size = SZ_4K,
	},
	{
		.base = 0xe6f30000, /* SCIF5 */
		.size = SZ_4K,
	},
	{
		.base = 0xe6540000, /* HSCIF0 */
		.size = SZ_4K,
	},
	{
		.base = 0xe6550000, /* HSCIF1 */
		.size = SZ_4K,
	},
	{
		.base = 0xe6560000, /* HSCIF2 */
		.size = SZ_4K,
	},
	{
		.base = 0xe66a0000, /* HSCIF3 */
		.size = SZ_4K,
	},
	{
		.base = 0xe66b0000, /* HSCIF4 */
		.size = SZ_4K,
	},
	{
		.base = 0xe6e90000, /* MSIOF0 */
		.size = SZ_4K,
	},
	{
		.base = 0xe6ea0000, /* MSIOF1 */
		.size = SZ_4K,
	},
	{
		.base = 0xe6c00000, /* MSIOF2 */
		.size = SZ_4K,
	},
	{
		.base = 0xe6c10000, /* MSIOF3 */
		.size = SZ_4K,
	},
};

static void ipmmu_workaround(struct iommu_domain *io_domain,
			     struct device *dev)
{
	int k;

	/* only apply workaround for DMA controllers */
	if (!strstr(dev_name(dev), "dma-controller"))
		return;

	dev_info(dev, "Adding iommu workaround\n");

	for (k = 0; k < ARRAY_SIZE(dmac_workaround); k++) {
		phys_addr_t phys_addr;

		phys_addr = iommu_iova_to_phys(io_domain,
					       dmac_workaround[k].base);
		if (phys_addr)
			continue;

		iommu_map(io_domain, dmac_workaround[k].base,
			  dmac_workaround[k].base, dmac_workaround[k].size,
			  IOMMU_READ | IOMMU_WRITE);
	}
}
#endif

static int ipmmu_attach_device(struct iommu_domain *io_domain,
			       struct device *dev)
{
	struct ipmmu_vmsa_archdata *archdata = dev_iommu_archdata(dev);
	struct ipmmu_vmsa_device *root, *mmu = archdata->mmu;
	struct ipmmu_vmsa_domain *domain = to_vmsa_domain(io_domain);
	unsigned long flags;
	unsigned int i;
	int ret = 0;

	if (!mmu) {
		dev_err(dev, "Cannot attach to IPMMU\n");
		return -ENXIO;
	}

	root = ipmmu_find_root(archdata->mmu);
	if (!root) {
		dev_err(dev, "Unable to locate root IPMMU\n");
		return -EAGAIN;
	}

	spin_lock_irqsave(&domain->lock, flags);

	if (!domain->mmu) {
		/* The domain hasn't been used yet, initialize it. */
		domain->mmu = mmu;
		domain->root = root;

/*
 * Xen: We have already initialized and enabled context for root IPMMU
 * for this Xen domain. Enable context for given cache IPMMU only.
 * Flush the TLB as required when modifying the context registers.
 */
#if 0
		ret = ipmmu_domain_init_context(domain);
#endif
		ipmmu_ctx_write1(domain, IMCTR,
				ipmmu_ctx_read(domain, IMCTR) | IMCTR_FLUSH);

		if (ret < 0) {
			dev_err(dev, "Unable to initialize IPMMU context\n");
			domain->mmu = NULL;
		} else {
			dev_info(dev, "Using IPMMU context %u\n",
				 domain->context_id);
		}
	} else if (domain->mmu != mmu) {
		/*
		 * Something is wrong, we can't attach two devices using
		 * different IOMMUs to the same domain.
		 */
		dev_err(dev, "Can't attach IPMMU %s to domain on IPMMU %s\n",
			dev_name(mmu->dev), dev_name(domain->mmu->dev));
		ret = -EINVAL;
	} else {
			dev_info(dev, "Reusing IPMMU context %u\n",
				 domain->context_id);
	}

	spin_unlock_irqrestore(&domain->lock, flags);

	if (ret < 0)
		return ret;

#if 0 /* Xen: Not needed */
	ipmmu_workaround(io_domain, dev);
#endif

	for (i = 0; i < archdata->num_utlbs; ++i)
		ipmmu_utlb_enable(domain, archdata->utlbs[i]);

	return 0;
}

static void ipmmu_detach_device(struct iommu_domain *io_domain,
				struct device *dev)
{
	struct ipmmu_vmsa_archdata *archdata = dev_iommu_archdata(dev);
	struct ipmmu_vmsa_domain *domain = to_vmsa_domain(io_domain);
	unsigned int i;

	for (i = 0; i < archdata->num_utlbs; ++i)
		ipmmu_utlb_disable(domain, archdata->utlbs[i]);

	/*
	 * TODO: Optimize by disabling the context when no device is attached.
	 */
}

/*
 * Xen: The current implementation of these callbacks is insufficient for us
 * since the they are intended to be called from Linux IOMMU core that
 * has already done all required actions such as doing various checks,
 * splitting into memory block the hardware supports and so on.
 * So, overwrite them with more completely functions.
 */
#if 0
static int ipmmu_map(struct iommu_domain *io_domain, unsigned long iova,
		     phys_addr_t paddr, size_t size, int prot)
{
	struct ipmmu_vmsa_domain *domain = to_vmsa_domain(io_domain);

	if (!domain)
		return -ENODEV;

	return domain->iop->map(domain->iop, iova, paddr, size, prot);
}

static size_t ipmmu_unmap(struct iommu_domain *io_domain, unsigned long iova,
			  size_t size)
{
	struct ipmmu_vmsa_domain *domain = to_vmsa_domain(io_domain);

	return domain->iop->unmap(domain->iop, iova, size);
}

static phys_addr_t ipmmu_iova_to_phys(struct iommu_domain *io_domain,
				      dma_addr_t iova)
{
	struct ipmmu_vmsa_domain *domain = to_vmsa_domain(io_domain);

	/* TODO: Is locking needed ? */

	return domain->iop->iova_to_phys(domain->iop, iova);
}
#endif

static size_t ipmmu_pgsize(struct iommu_domain *io_domain,
		unsigned long addr_merge, size_t size)
{
	struct ipmmu_vmsa_domain *domain = to_vmsa_domain(io_domain);
	unsigned int pgsize_idx;
	size_t pgsize;

	/* Max page size that still fits into 'size' */
	pgsize_idx = __fls(size);

	/* need to consider alignment requirements ? */
	if (likely(addr_merge)) {
		/* Max page size allowed by address */
		unsigned int align_pgsize_idx = __ffs(addr_merge);
		pgsize_idx = min(pgsize_idx, align_pgsize_idx);
	}

	/* build a mask of acceptable page sizes */
	pgsize = (1UL << (pgsize_idx + 1)) - 1;

	/* throw away page sizes not supported by the hardware */
	pgsize &= domain->cfg.pgsize_bitmap;

	/* make sure we're still sane */
	BUG_ON(!pgsize);

	/* pick the biggest page */
	pgsize_idx = __fls(pgsize);
	pgsize = 1UL << pgsize_idx;

	return pgsize;
}

phys_addr_t ipmmu_iova_to_phys(struct iommu_domain *io_domain, dma_addr_t iova)
{
	struct ipmmu_vmsa_domain *domain = to_vmsa_domain(io_domain);

	if (unlikely(domain->iop->iova_to_phys == NULL))
		return 0;

	return domain->iop->iova_to_phys(domain->iop, iova);
}

size_t ipmmu_unmap(struct iommu_domain *io_domain, unsigned long iova, size_t size)
{
	struct ipmmu_vmsa_domain *domain = to_vmsa_domain(io_domain);
	size_t unmapped_page, unmapped = 0;
	dma_addr_t max_iova;
	unsigned int min_pagesz;

	if (unlikely(domain->iop->unmap == NULL ||
			domain->cfg.pgsize_bitmap == 0UL))
		return -ENODEV;

	/* find out the minimum page size supported */
	min_pagesz = 1 << __ffs(domain->cfg.pgsize_bitmap);

	/*
	 * The virtual address, as well as the size of the mapping, must be
	 * aligned (at least) to the size of the smallest page supported
	 * by the hardware
	 */
	if (!IS_ALIGNED(iova | size, min_pagesz)) {
		printk("unaligned: iova 0x%lx size 0x%zx min_pagesz 0x%x\n",
		       iova, size, min_pagesz);
		return -EINVAL;
	}

	/*
	 * the sum of virtual address and size must be inside the IOVA space
	 * that hardware supports
	 */
	max_iova = (1UL << domain->cfg.ias) - 1;
	if ((dma_addr_t)iova + size > max_iova) {
		printk("out-of-bound: iova 0x%lx + size 0x%zx > max_iova 0x%"PRIx64"\n",
			   iova, size, max_iova);
		/* TODO Return -EINVAL instead */
		return 0;
		/*return -EINVAL;*/
	}

	/*
	 * Keep iterating until we either unmap 'size' bytes (or more)
	 * or we hit an area that isn't mapped.
	 */
	while (unmapped < size) {
		size_t pgsize = ipmmu_pgsize(io_domain, iova, size - unmapped);

		unmapped_page = domain->iop->unmap(domain->iop, iova, pgsize);
		if (!unmapped_page)
			break;

		iova += unmapped_page;
		unmapped += unmapped_page;
	}

	return unmapped;
}

int ipmmu_map(struct iommu_domain *io_domain, unsigned long iova,
		phys_addr_t paddr, size_t size, int prot)
{
	struct ipmmu_vmsa_domain *domain = to_vmsa_domain(io_domain);
	unsigned long orig_iova = iova;
	dma_addr_t max_iova;
	unsigned int min_pagesz;
	size_t orig_size = size;
	int ret = 0;

	if (unlikely(domain->iop->map == NULL ||
			domain->cfg.pgsize_bitmap == 0UL))
		return -ENODEV;

	/* find out the minimum page size supported */
	min_pagesz = 1 << __ffs(domain->cfg.pgsize_bitmap);

	/*
	 * both the virtual address and the physical one, as well as
	 * the size of the mapping, must be aligned (at least) to the
	 * size of the smallest page supported by the hardware
	 */
	if (!IS_ALIGNED(iova | paddr | size, min_pagesz)) {
		printk("unaligned: iova 0x%lx pa 0x%"PRIx64" size 0x%zx min_pagesz 0x%x\n",
		       iova, paddr, size, min_pagesz);
		return -EINVAL;
	}

	/*
	 * the sum of virtual address and size must be inside the IOVA space
	 * that hardware supports
	 */
	max_iova = (1UL << domain->cfg.ias) - 1;
	if ((dma_addr_t)iova + size > max_iova) {
		printk("out-of-bound: iova 0x%lx + size 0x%zx > max_iova 0x%"PRIx64"\n",
		       iova, size, max_iova);
		/* TODO Return -EINVAL instead */
		return 0;
		/*return -EINVAL;*/
	}

	while (size) {
		size_t pgsize = ipmmu_pgsize(io_domain, iova | paddr, size);

		ret = domain->iop->map(domain->iop, iova, paddr, pgsize, prot);
		if (ret == -EEXIST) {
			phys_addr_t exist_paddr = ipmmu_iova_to_phys(io_domain, iova);
			if (exist_paddr == paddr)
				ret = 0;
			else if (exist_paddr) {
				printk("remap: iova 0x%lx pa 0x%"PRIx64" pgsize 0x%zx\n",
						iova, paddr, pgsize);
				ipmmu_unmap(io_domain, iova, pgsize);
				ret = domain->iop->map(domain->iop, iova, paddr, pgsize, prot);
			}
		}
		if (ret)
			break;

		iova += pgsize;
		paddr += pgsize;
		size -= pgsize;
	}

	/* unroll mapping in case something went wrong */
	if (ret && orig_size != size)
		ipmmu_unmap(io_domain, orig_iova, orig_size - size);

	return ret;
}

#if 0 /* Xen: Not needed */
static struct device *ipmmu_find_sibling_device(struct device *dev)
{
	struct ipmmu_vmsa_archdata *archdata = dev->archdata.iommu;
	struct ipmmu_vmsa_archdata *sibling_archdata = NULL;
	bool found = false;

	spin_lock(&ipmmu_slave_devices_lock);

	list_for_each_entry(sibling_archdata, &ipmmu_slave_devices, list) {
		if (archdata == sibling_archdata)
			continue;
		if (sibling_archdata->mmu == archdata->mmu) {
			found = true;
			break;
		}
	}

	spin_unlock(&ipmmu_slave_devices_lock);

	return found ? sibling_archdata->dev : NULL;
}

static struct iommu_group *ipmmu_find_group(struct device *dev)
{
	struct iommu_group *group;
	struct device *sibling;

	sibling = ipmmu_find_sibling_device(dev);
	if (sibling)
		group = iommu_group_get(sibling);
	if (!sibling || IS_ERR(group))
		group = generic_device_group(dev);

	return group;
}
#endif

static int ipmmu_find_utlbs(struct ipmmu_vmsa_device *mmu, struct device *dev,
			    unsigned int *utlbs, unsigned int num_utlbs)
{
	unsigned int i;

	for (i = 0; i < num_utlbs; ++i) {
		struct of_phandle_args args;
		int ret;

		ret = of_parse_phandle_with_args(dev->of_node, "iommus",
						 "#iommu-cells", i, &args);
		if (ret < 0)
			return ret;

#if 0 /* Xen: Not needed */
		of_node_put(args.np);
#endif

		if (args.np != mmu->dev->of_node || args.args_count != 1)
			return -EINVAL;

		utlbs[i] = args.args[0];
	}

	return 0;
}

/* Xen: To roll back actions that took place it init */
static __maybe_unused void ipmmu_destroy_platform_device(struct device *dev)
{
	struct ipmmu_vmsa_archdata *archdata = dev_iommu_archdata(dev);

	if (!archdata)
		return;

	kfree(archdata->utlbs);
	kfree(archdata);
	dev_iommu_archdata(dev) = NULL;
}

static int ipmmu_init_platform_device(struct device *dev)
{
	struct ipmmu_vmsa_archdata *archdata;
	struct ipmmu_vmsa_device *mmu;
	unsigned int *utlbs;
	unsigned int i;
	int num_utlbs;
	int ret = -ENODEV;

	/* Find the master corresponding to the device. */

	num_utlbs = of_count_phandle_with_args(dev->of_node, "iommus",
					       "#iommu-cells");
	if (num_utlbs < 0)
		return -ENODEV;

	utlbs = kcalloc(num_utlbs, sizeof(*utlbs), GFP_KERNEL);
	if (!utlbs)
		return -ENOMEM;

	spin_lock(&ipmmu_devices_lock);

	list_for_each_entry(mmu, &ipmmu_devices, list) {
		ret = ipmmu_find_utlbs(mmu, dev, utlbs, num_utlbs);
		if (!ret) {
			/*
			 * TODO Take a reference to the MMU to protect
			 * against device removal.
			 */
			break;
		}
	}

	spin_unlock(&ipmmu_devices_lock);

	if (ret < 0)
		goto error;

	for (i = 0; i < num_utlbs; ++i) {
		if (utlbs[i] >= mmu->num_utlbs) {
			ret = -EINVAL;
			goto error;
		}
	}

	archdata = kzalloc(sizeof(*archdata), GFP_KERNEL);
	if (!archdata) {
		ret = -ENOMEM;
		goto error;
	}

	archdata->mmu = mmu;
	archdata->utlbs = utlbs;
	archdata->num_utlbs = num_utlbs;
	archdata->dev = dev;
	dev_iommu_archdata(dev) = archdata;

	/* Xen: */
	dev_notice(dev, "initialized slave device (IPMMU %s micro-TLBs %u)\n",
			dev_name(mmu->dev), num_utlbs);

	return 0;

error:
	kfree(utlbs);
	return ret;
}

#if 0 /* Xen: Not needed */
#if defined(CONFIG_ARM) && !defined(CONFIG_IOMMU_DMA)

static int ipmmu_add_device(struct device *dev)
{
	struct ipmmu_vmsa_device *mmu = NULL;
	struct iommu_group *group;
	int ret;

	if (to_archdata(dev)) {
		dev_warn(dev, "IOMMU driver already assigned to device %s\n",
			 dev_name(dev));
		return -EINVAL;
	}

	/* Create a device group and add the device to it. */
	group = iommu_group_alloc();
	if (IS_ERR(group)) {
		dev_err(dev, "Failed to allocate IOMMU group\n");
		ret = PTR_ERR(group);
		goto error;
	}

	ret = iommu_group_add_device(group, dev);
	iommu_group_put(group);

	if (ret < 0) {
		dev_err(dev, "Failed to add device to IPMMU group\n");
		group = NULL;
		goto error;
	}

	ret = ipmmu_init_platform_device(dev);
	if (ret < 0)
		goto error;

	/*
	 * Create the ARM mapping, used by the ARM DMA mapping core to allocate
	 * VAs. This will allocate a corresponding IOMMU domain.
	 *
	 * TODO:
	 * - Create one mapping per context (TLB).
	 * - Make the mapping size configurable ? We currently use a 2GB mapping
	 *   at a 1GB offset to ensure that NULL VAs will fault.
	 */
	mmu = to_archdata(dev)->mmu;
	if (!mmu->mapping) {
		struct dma_iommu_mapping *mapping;

		mapping = arm_iommu_create_mapping(&platform_bus_type,
						   SZ_1G, SZ_2G);
		if (IS_ERR(mapping)) {
			dev_err(mmu->dev, "failed to create ARM IOMMU mapping\n");
			ret = PTR_ERR(mapping);
			goto error;
		}

		mmu->mapping = mapping;
	}

	/* Attach the ARM VA mapping to the device. */
	ret = arm_iommu_attach_device(dev, mmu->mapping);
	if (ret < 0) {
		dev_err(dev, "Failed to attach device to VA mapping\n");
		goto error;
	}

	return 0;

error:
	if (mmu)
		arm_iommu_release_mapping(mmu->mapping);

	set_archdata(dev, NULL);

	if (!IS_ERR_OR_NULL(group))
		iommu_group_remove_device(dev);

	return ret;
}

static void ipmmu_remove_device(struct device *dev)
{
	struct ipmmu_vmsa_archdata *archdata = to_archdata(dev);

	arm_iommu_detach_device(dev);
	iommu_group_remove_device(dev);

	kfree(archdata->utlbs);
	kfree(archdata);

	set_archdata(dev, NULL);
}

static struct iommu_domain *ipmmu_domain_alloc(unsigned type)
{
	if (type != IOMMU_DOMAIN_UNMANAGED)
		return NULL;

	return __ipmmu_domain_alloc(type);
}

static const struct iommu_ops ipmmu_ops = {
	.domain_alloc = ipmmu_domain_alloc,
	.domain_free = ipmmu_domain_free,
	.attach_dev = ipmmu_attach_device,
	.detach_dev = ipmmu_detach_device,
	.map = ipmmu_map,
	.unmap = ipmmu_unmap,
	.map_sg = default_iommu_map_sg,
	.iova_to_phys = ipmmu_iova_to_phys,
	.add_device = ipmmu_add_device,
	.remove_device = ipmmu_remove_device,
	.pgsize_bitmap = SZ_1G | SZ_2M | SZ_4K,
};

#endif /* !CONFIG_ARM && CONFIG_IOMMU_DMA */

#ifdef CONFIG_IOMMU_DMA

static struct iommu_domain *ipmmu_domain_alloc_dma(unsigned type)
{
	struct iommu_domain *io_domain;

	if (type != IOMMU_DOMAIN_DMA)
		return NULL;

	io_domain = __ipmmu_domain_alloc(type);
	if (io_domain)
		iommu_get_dma_cookie(io_domain);

	return io_domain;
}

static void ipmmu_domain_free_dma(struct iommu_domain *io_domain)
{
	iommu_put_dma_cookie(io_domain);
	ipmmu_domain_free(io_domain);
}

static int ipmmu_add_device_dma(struct device *dev)
{
	struct ipmmu_vmsa_archdata *archdata = dev->archdata.iommu;
	struct iommu_group *group;

	/* only accept devices with iommus property */
	if (of_count_phandle_with_args(dev->of_node, "iommus",
				       "#iommu-cells") < 0)
		return -ENODEV;

	group = iommu_group_get_for_dev(dev);
	if (IS_ERR(group))
		return PTR_ERR(group);

	archdata = dev->archdata.iommu;
	spin_lock(&ipmmu_slave_devices_lock);
	list_add(&archdata->list, &ipmmu_slave_devices);
	spin_unlock(&ipmmu_slave_devices_lock);
	return 0;
}

static void ipmmu_remove_device_dma(struct device *dev)
{
	struct ipmmu_vmsa_archdata *archdata = dev->archdata.iommu;

	spin_lock(&ipmmu_slave_devices_lock);
	list_del(&archdata->list);
	spin_unlock(&ipmmu_slave_devices_lock);

	iommu_group_remove_device(dev);
}

static struct iommu_group *ipmmu_device_group_dma(struct device *dev)
{
	struct iommu_group *group;
	int ret;

	ret = ipmmu_init_platform_device(dev);
	if (!ret)
		group = ipmmu_find_group(dev);
	else
		group = ERR_PTR(ret);

	return group;
}

static int ipmmu_of_xlate_dma(struct device *dev,
			      struct of_phandle_args *spec)
{
	/* If the IPMMU device is disabled in DT then return error
	 * to make sure the of_iommu code does not install ops
	 * even though the iommu device is disabled
	 */
	if (!of_device_is_available(spec->np))
		return -ENODEV;

	return 0;
}

static const struct iommu_ops ipmmu_ops = {
	.domain_alloc = ipmmu_domain_alloc_dma,
	.domain_free = ipmmu_domain_free_dma,
	.attach_dev = ipmmu_attach_device,
	.detach_dev = ipmmu_detach_device,
	.map = ipmmu_map,
	.unmap = ipmmu_unmap,
	.map_sg = default_iommu_map_sg,
	.iova_to_phys = ipmmu_iova_to_phys,
	.add_device = ipmmu_add_device_dma,
	.remove_device = ipmmu_remove_device_dma,
	.device_group = ipmmu_device_group_dma,
	.pgsize_bitmap = SZ_1G | SZ_2M | SZ_4K,
	.of_xlate = ipmmu_of_xlate_dma,
};

#endif /* CONFIG_IOMMU_DMA */
#endif

/* -----------------------------------------------------------------------------
 * Probe/remove and init
 */

static void ipmmu_device_reset(struct ipmmu_vmsa_device *mmu)
{
	unsigned int i;

	/* Disable all contexts. */
	for (i = 0; i < mmu->num_ctx; ++i)
		ipmmu_write(mmu, i * IM_CTX_SIZE + IMCTR, 0);
}

static const struct ipmmu_features ipmmu_features_default = {
	.use_ns_alias_offset = true,
	.has_cache_leaf_nodes = false,
	.has_eight_ctx = false,
	.setup_imbuscr = true,
	.twobit_imttbcr_sl0 = false,
};

static const struct ipmmu_features ipmmu_features_rcar_gen3 = {
	.use_ns_alias_offset = false,
	.has_cache_leaf_nodes = true,
	.has_eight_ctx = true,
	.setup_imbuscr = false,
	.twobit_imttbcr_sl0 = true,
};

static const struct of_device_id ipmmu_of_ids[] = {
	{
		.compatible = "renesas,ipmmu-vmsa",
		.data = &ipmmu_features_default,
	}, {
		.compatible = "renesas,ipmmu-r8a7795",
		.data = &ipmmu_features_rcar_gen3,
	}, {
		.compatible = "renesas,ipmmu-r8a7796",
		.data = &ipmmu_features_rcar_gen3,
	}, {
		/* Xen: It is not clear how to deal with it */
		.compatible = "renesas,ipmmu-pmb-r8a7795",
		.data = NULL,
	}, {
		/* Terminator */
	},
};

MODULE_DEVICE_TABLE(of, ipmmu_of_ids);

/*
 * Xen: We don't have refcount for allocated memory so manually free memory
 * when an error occured.
 */
static int ipmmu_probe(struct platform_device *pdev)
{
	struct ipmmu_vmsa_device *mmu;
	const struct of_device_id *match;
	struct resource *res;
	int irq;
	int ret;

	match = of_match_node(ipmmu_of_ids, pdev->dev.of_node);
	if (!match)
		return -EINVAL;

	mmu = devm_kzalloc(&pdev->dev, sizeof(*mmu), GFP_KERNEL);
	if (!mmu) {
		dev_err(&pdev->dev, "cannot allocate device data\n");
		return -ENOMEM;
	}

	mmu->dev = &pdev->dev;
	mmu->num_utlbs = 48;
	spin_lock_init(&mmu->lock);
	bitmap_zero(mmu->ctx, IPMMU_CTX_MAX);
	mmu->features = match->data;
#if 0 /* Xen: Not needed */
	dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
#endif

	/* Map I/O memory and request IRQ. */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	mmu->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(mmu->base)) {
		ret = PTR_ERR(mmu->base);
		goto out;
	}

	/*
	 * The IPMMU has two register banks, for secure and non-secure modes.
	 * The bank mapped at the beginning of the IPMMU address space
	 * corresponds to the running mode of the CPU. When running in secure
	 * mode the non-secure register bank is also available at an offset.
	 *
	 * Secure mode operation isn't clearly documented and is thus currently
	 * not implemented in the driver. Furthermore, preliminary tests of
	 * non-secure operation with the main register bank were not successful.
	 * Offset the registers base unconditionally to point to the non-secure
	 * alias space for now.
	 */
	if (mmu->features->use_ns_alias_offset)
		mmu->base += IM_NS_ALIAS_OFFSET;

	/*
	 * The number of contexts varies with generation and instance.
	 * Newer SoCs get a total of 8 contexts enabled, older ones just one.
	 */
	if (mmu->features->has_eight_ctx)
		mmu->num_ctx = 8;
	else
		mmu->num_ctx = 1;

	WARN_ON(mmu->num_ctx > IPMMU_CTX_MAX);

	irq = platform_get_irq(pdev, 0);

	/*
	 * Determine if this IPMMU instance is a leaf device by checking
	 * if the renesas,ipmmu-main property exists or not.
	 */
	if (mmu->features->has_cache_leaf_nodes &&
	    of_find_property(pdev->dev.of_node, "renesas,ipmmu-main", NULL))
		mmu->is_leaf = true;

	/* Root devices have mandatory IRQs */
	if (ipmmu_is_root(mmu)) {
		if (irq < 0) {
			dev_err(&pdev->dev, "no IRQ found\n");
			ret = irq;
			goto out;
		}

		ret = devm_request_irq(&pdev->dev, irq, ipmmu_irq, 0,
				       dev_name(&pdev->dev), mmu);
		if (ret < 0) {
			dev_err(&pdev->dev, "failed to request IRQ %d\n", irq);
			goto out;
		}

		ipmmu_device_reset(mmu);
	}

	/*
	 * We can't create the ARM mapping here as it requires the bus to have
	 * an IOMMU, which only happens when bus_set_iommu() is called in
	 * ipmmu_init() after the probe function returns.
	 */

	spin_lock(&ipmmu_devices_lock);
	list_add(&mmu->list, &ipmmu_devices);
	spin_unlock(&ipmmu_devices_lock);

#if 0 /* Xen: Not needed */
	platform_set_drvdata(pdev, mmu);
#endif

	/* Xen: */
	dev_notice(&pdev->dev, "registered %s IPMMU\n",
		ipmmu_is_root(mmu) ? "root" : "cache");

	return 0;

out:
	if (!IS_ERR(mmu->base))
		iounmap(mmu->base);
	kfree(mmu);

	return ret;
}

#if 0 /* Xen: Not needed */
static int ipmmu_remove(struct platform_device *pdev)
{
	struct ipmmu_vmsa_device *mmu = platform_get_drvdata(pdev);

	spin_lock(&ipmmu_devices_lock);
	list_del(&mmu->list);
	spin_unlock(&ipmmu_devices_lock);

#if defined(CONFIG_ARM) && !defined(CONFIG_IOMMU_DMA)
	arm_iommu_release_mapping(mmu->mapping);
#endif

	ipmmu_device_reset(mmu);

	return 0;
}

#define DEV_PM_OPS NULL

static struct platform_driver ipmmu_driver = {
	.driver = {
		.name = "ipmmu-vmsa",
		.pm	= DEV_PM_OPS,
		.of_match_table = of_match_ptr(ipmmu_of_ids),
	},
	.probe = ipmmu_probe,
	.remove	= ipmmu_remove,
};

static int __init ipmmu_init(void)
{
	static bool setup_done;
	int ret;

	if (setup_done)
		return 0;

	ret = platform_driver_register(&ipmmu_driver);
	if (ret < 0)
		return ret;

#if defined(CONFIG_ARM) && !defined(CONFIG_IOMMU_DMA)
	if (!iommu_present(&platform_bus_type))
		bus_set_iommu(&platform_bus_type, &ipmmu_ops);
#endif

	setup_done = true;
	return 0;
}

static void __exit ipmmu_exit(void)
{
	return platform_driver_unregister(&ipmmu_driver);
}

subsys_initcall(ipmmu_init);
module_exit(ipmmu_exit);

#ifdef CONFIG_IOMMU_DMA
static int __init ipmmu_vmsa_iommu_of_setup(struct device_node *np)
{
	static const struct iommu_ops *ops = &ipmmu_ops;

	ipmmu_init();

	of_iommu_set_ops(np, (struct iommu_ops *)ops);
	if (!iommu_present(&platform_bus_type))
		bus_set_iommu(&platform_bus_type, ops);

	return 0;
}

IOMMU_OF_DECLARE(ipmmu_vmsa_iommu_of, "renesas,ipmmu-vmsa",
		 ipmmu_vmsa_iommu_of_setup);
IOMMU_OF_DECLARE(ipmmu_r8a7795_iommu_of, "renesas,ipmmu-r8a7795",
		 ipmmu_vmsa_iommu_of_setup);
IOMMU_OF_DECLARE(ipmmu_r8a7796_iommu_of, "renesas,ipmmu-r8a7796",
		 ipmmu_vmsa_iommu_of_setup);
#endif

MODULE_DESCRIPTION("IOMMU API for Renesas VMSA-compatible IPMMU");
MODULE_AUTHOR("Laurent Pinchart <laurent.pinchart@ideasonboard.com>");
MODULE_LICENSE("GPL v2");
#endif

/***** Start of Xen specific code *****/

static int __must_check ipmmu_vmsa_iotlb_flush(struct domain *d,
		unsigned long gfn, unsigned int page_count)
{
	return 0;
}

static struct iommu_domain *ipmmu_vmsa_get_domain(struct domain *d,
						struct device *dev)
{
	struct iommu_domain *io_domain;
	struct ipmmu_vmsa_xen_domain *xen_domain;
	struct ipmmu_vmsa_device *mmu;

	xen_domain = dom_iommu(d)->arch.priv;

	mmu = dev_iommu_archdata(dev)->mmu;
	if (!mmu)
		return NULL;

	/*
	 * Loop through the &xen_domain->contexts to locate a context
	 * assigned to this IPMMU
	 */
	list_for_each_entry(io_domain, &xen_domain->contexts, list) {
		if (to_vmsa_domain(io_domain)->mmu == mmu)
			return io_domain;
	}

	return NULL;
}

static void ipmmu_vmsa_destroy_domain(struct iommu_domain *io_domain)
{
	struct ipmmu_vmsa_domain *domain = to_vmsa_domain(io_domain);

	list_del(&io_domain->list);

	if (domain->mmu != domain->root) {
		/*
		 * Disable the context for cache IPMMU only. Flush the TLB as required
		 * when modifying the context registers.
		 */
		ipmmu_ctx_write1(domain, IMCTR, IMCTR_FLUSH);
	} else {
		/*
		 * Free main domain resources. We assume that all devices have already
		 * been detached.
		 */
		ipmmu_domain_destroy_context(domain);
		free_io_pgtable_ops(domain->iop);
	}

	kfree(domain);
}

static int ipmmu_vmsa_assign_dev(struct domain *d, u8 devfn,
			       struct device *dev, u32 flag)
{
	struct iommu_domain *io_domain;
	struct ipmmu_vmsa_domain *domain;
	struct ipmmu_vmsa_xen_domain *xen_domain;
	int ret = 0;

	xen_domain = dom_iommu(d)->arch.priv;

	if (!dev->archdata.iommu) {
		dev->archdata.iommu = xzalloc(struct ipmmu_vmsa_xen_device);
		if (!dev->archdata.iommu)
			return -ENOMEM;
	}

	if (!dev_iommu_archdata(dev)) {
		ret = ipmmu_init_platform_device(dev);
		if (ret)
			return ret;
	}

	spin_lock(&xen_domain->lock);

	if (dev_iommu_domain(dev)) {
		dev_err(dev, "already attached to IPMMU domain\n");
		ret = -EEXIST;
		goto out;
	}

	/*
	 * Check to see if a context bank (iommu_domain) already exists for
	 * this Xen domain under the same IPMMU
	 */
	io_domain = ipmmu_vmsa_get_domain(d, dev);
	if (!io_domain) {
		domain = xzalloc(struct ipmmu_vmsa_domain);
		if (!domain) {
			ret = -ENOMEM;
			goto out;
		}
		spin_lock_init(&domain->lock);

		domain->d = d;
		domain->context_id = to_vmsa_domain(xen_domain->base_context)->context_id;
		/* TODO: both ops and cfg might be dropped for non-root domain. */
		domain->iop = to_vmsa_domain(xen_domain->base_context)->iop;
		domain->cfg = to_vmsa_domain(xen_domain->base_context)->cfg;

		io_domain = &domain->io_domain;

		/* Chain the new context to the Xen domain */
		list_add(&io_domain->list, &xen_domain->contexts);
	}

	ret = ipmmu_attach_device(io_domain, dev);
	if (ret) {
		if (io_domain->ref.counter == 0)
			ipmmu_vmsa_destroy_domain(io_domain);
	} else {
		atomic_inc(&io_domain->ref);
		dev_iommu_domain(dev) = io_domain;
	}

out:
	spin_unlock(&xen_domain->lock);

	return ret;
}

static int ipmmu_vmsa_deassign_dev(struct domain *d, struct device *dev)
{
	struct iommu_domain *io_domain = dev_iommu_domain(dev);
	struct ipmmu_vmsa_xen_domain *xen_domain;

	xen_domain = dom_iommu(d)->arch.priv;

	if (!io_domain || to_vmsa_domain(io_domain)->d != d) {
		dev_err(dev, " not attached to domain %d\n", d->domain_id);
		return -ESRCH;
	}

	spin_lock(&xen_domain->lock);

	ipmmu_detach_device(io_domain, dev);
	dev_iommu_domain(dev) = NULL;
	atomic_dec(&io_domain->ref);

	if (io_domain->ref.counter == 0)
		ipmmu_vmsa_destroy_domain(io_domain);

	spin_unlock(&xen_domain->lock);

	return 0;
}

static int ipmmu_vmsa_reassign_dev(struct domain *s, struct domain *t,
				 u8 devfn,  struct device *dev)
{
	int ret = 0;

	/* Don't allow remapping on other domain than hwdom */
	if (t && t != hardware_domain)
		return -EPERM;

	if (t == s)
		return 0;

	ret = ipmmu_vmsa_deassign_dev(s, dev);
	if (ret)
		return ret;

	if (t) {
		/* No flags are defined for ARM. */
		ret = ipmmu_vmsa_assign_dev(t, devfn, dev, 0);
		if (ret)
			return ret;
	}

	return 0;
}

static int ipmmu_vmsa_domain_init(struct domain *d)
{
	struct ipmmu_vmsa_xen_domain *xen_domain;

	xen_domain = xzalloc(struct ipmmu_vmsa_xen_domain);
	if (!xen_domain)
		return -ENOMEM;

	spin_lock_init(&xen_domain->lock);
	INIT_LIST_HEAD(&xen_domain->contexts);

	dom_iommu(d)->arch.priv = xen_domain;

	return 0;
}

static int ipmmu_vmsa_alloc_page_table(struct domain *d)
{
	struct ipmmu_vmsa_xen_domain *xen_domain = dom_iommu(d)->arch.priv;
	struct ipmmu_vmsa_domain *domain;
	struct ipmmu_vmsa_device *root;
	int ret;

	if (!xen_domain)
		return -EINVAL;

	if (!xen_domain->base_context) {
		domain = xzalloc(struct ipmmu_vmsa_domain);
		if (!domain)
			return -ENOMEM;

		spin_lock_init(&domain->lock);
		INIT_LIST_HEAD(&domain->io_domain.list);
		domain->d = d;

		root = ipmmu_find_root(NULL);
		if (!root) {
			printk("d%d: Unable to locate root IPMMU\n", d->domain_id);
			ret = -EAGAIN;
			goto out;
		}

		domain->root = root;
		domain->mmu = root;

		spin_lock(&xen_domain->lock);
		ret = ipmmu_domain_init_context(domain);
		if (ret < 0) {
			dev_err(root->dev, "d%d: Unable to initialize IPMMU context\n", d->domain_id);
			spin_unlock(&xen_domain->lock);
			goto out;
		}
		xen_domain->base_context = &domain->io_domain;
		spin_unlock(&xen_domain->lock);
	}

	return 0;

out:
	xfree(domain);

	return ret;
}

static void __hwdom_init ipmmu_vmsa_hwdom_init(struct domain *d)
{
}

static void ipmmu_vmsa_domain_teardown(struct domain *d)
{
	struct ipmmu_vmsa_xen_domain *xen_domain = dom_iommu(d)->arch.priv;

	if (!xen_domain)
		return;

	if (xen_domain->base_context) {
		spin_lock(&xen_domain->lock);
		ipmmu_vmsa_destroy_domain(xen_domain->base_context);
		xen_domain->base_context = NULL;
		spin_unlock(&xen_domain->lock);
	}

	ASSERT(list_empty(&xen_domain->contexts));
	xfree(xen_domain);
}

static int __must_check ipmmu_vmsa_map_pages(struct domain *d, unsigned long gfn,
			unsigned long mfn, unsigned long page_count, unsigned int flags)
{
	struct ipmmu_vmsa_xen_domain *xen_domain = dom_iommu(d)->arch.priv;
	size_t size = PAGE_SIZE * page_count;
	int ret, prot = 0;

	if (!xen_domain || !xen_domain->base_context)
		return -EINVAL;

	if (flags & IOMMUF_writable)
		prot |= IOMMU_WRITE;
	if (flags & IOMMUF_readable)
		prot |= IOMMU_READ;

	spin_lock(&xen_domain->lock);
	ret = ipmmu_map(xen_domain->base_context, pfn_to_paddr(gfn),
			pfn_to_paddr(mfn), size, prot);

	spin_unlock(&xen_domain->lock);

	return ret;
}

static int __must_check ipmmu_vmsa_map_page(struct domain *d, unsigned long gfn,
		unsigned long mfn, unsigned int flags)
{
	return ipmmu_vmsa_map_pages(d, gfn, mfn, 1, flags);
}

static int __must_check ipmmu_vmsa_unmap_pages(struct domain *d, unsigned long gfn,
		unsigned long page_count)
{
	struct ipmmu_vmsa_xen_domain *xen_domain = dom_iommu(d)->arch.priv;
	size_t ret, size = PAGE_SIZE * page_count;

	if (!xen_domain || !xen_domain->base_context)
		return -EINVAL;

	spin_lock(&xen_domain->lock);
	ret = ipmmu_unmap(xen_domain->base_context, pfn_to_paddr(gfn), size);
	if (ret == size)
		ret = 0;

	spin_unlock(&xen_domain->lock);

	return ret;
}

static int __must_check ipmmu_vmsa_unmap_page(struct domain *d, unsigned long gfn)
{
	return ipmmu_vmsa_unmap_pages(d, gfn, 1);
}

static void ipmmu_vmsa_dump_p2m_table(struct domain *d)
{

}

static const struct iommu_ops ipmmu_vmsa_iommu_ops = {
	.init = ipmmu_vmsa_domain_init,
	.hwdom_init = ipmmu_vmsa_hwdom_init,
	.alloc_page_table = ipmmu_vmsa_alloc_page_table,
	.teardown = ipmmu_vmsa_domain_teardown,
	.iotlb_flush = ipmmu_vmsa_iotlb_flush,
	.assign_device = ipmmu_vmsa_assign_dev,
	.reassign_device = ipmmu_vmsa_reassign_dev,
	.map_page = ipmmu_vmsa_map_page,
	.map_pages = ipmmu_vmsa_map_pages,
	.unmap_page = ipmmu_vmsa_unmap_page,
	.unmap_pages = ipmmu_vmsa_unmap_pages,
	.dump_p2m_table = ipmmu_vmsa_dump_p2m_table,
};

static __init const struct ipmmu_vmsa_device *find_ipmmu(const struct device *dev)
{
	struct ipmmu_vmsa_device *mmu;
	bool found = false;

	spin_lock(&ipmmu_devices_lock);
	list_for_each_entry(mmu, &ipmmu_devices, list) {
		if (mmu->dev == dev) {
			found = true;
			break;
		}
	}
	spin_unlock(&ipmmu_devices_lock);

	return (found) ? mmu : NULL;
}

static __init void populate_ipmmu_slaves(const struct ipmmu_vmsa_device *mmu)
{
	struct dt_device_node *np;

	dt_for_each_device_node(dt_host, np) {
		if (mmu->dev->of_node != dt_parse_phandle(np, "iommus", 0))
			continue;

		/* Let Xen know that the device is protected by an IPMMU */
		dt_device_set_protected(np);

		dev_notice(mmu->dev, "found slave device %s\n", dt_node_full_name(np));
	}
}

/* TODO: What to do if we failed to init leaf ipmmu/root ipmmu? */
static __init int ipmmu_vmsa_init(struct dt_device_node *dev,
				   const void *data)
{
	int rc;
	const struct ipmmu_vmsa_device *mmu;
	static bool set_ops_done;

	/*
	 * Even if the device can't be initialized, we don't want to
	 * give the IPMMU device to dom0.
	 */
	dt_device_set_used_by(dev, DOMID_XEN);

	rc = ipmmu_probe(dev);
	if (rc) {
		dev_err(&dev->dev, "failed to init IPMMU\n");
		return rc;
	}

	/*
	 * Since IPMMU is composed of two parts (a number of cache IPs and
	 * main IP) this function will be called more than once.
	 * Use the flag below to avoid setting IOMMU ops if they already set.
	 */
	if (!set_ops_done) {
		iommu_set_ops(&ipmmu_vmsa_iommu_ops);
		set_ops_done = true;
	}

	/* Find the last IPMMU added. */
	mmu = find_ipmmu(dt_to_dev(dev));
	BUG_ON(mmu == NULL);

	/* Mark all slaves that connected to the last IPMMU as protected. */
	populate_ipmmu_slaves(mmu);

	/*
	 * The IPMMU can't reuse P2M table since it only supports
	 * stage-1 page tables.
	 */
	iommu_hap_pt_share = false;

	return 0;
}

DT_DEVICE_START(ipmmu, "Renesas IPMMU-VMSA", DEVICE_IOMMU)
	.dt_match = ipmmu_of_ids,
	.init = ipmmu_vmsa_init,
DT_DEVICE_END
