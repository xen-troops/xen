/*
 * xen/arch/arm/coproc/plat/coproc_xxx.c
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

#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/err.h>
#include <xen/irq.h>
#include <xen/list.h>
#include <xen/vmap.h>
#include <asm/device.h>
#include <asm/types.h>
#include <asm/platform.h>

#include "../coproc.h"
#include "coproc_xxx.h"

#define DT_MATCH_COPROC_XXX DT_MATCH_COMPATIBLE("vendor_xxx,coproc_xxx")

static int vcoproc_xxx_read(struct vcpu *v, mmio_info_t *info, register_t *r, void *priv)
{
	struct vcoproc_info *vcoproc_xxx = priv;

	(void)vcoproc_xxx;

	return 0;
}

static int vcoproc_xxx_write(struct vcpu *v, mmio_info_t *info, register_t r, void *priv)
{
	struct vcoproc_info *vcoproc_xxx = priv;

	(void)vcoproc_xxx;

	return 0;
}

static const struct mmio_handler_ops vcoproc_xxx_mmio_handler = {
	.read = vcoproc_xxx_read,
	.write = vcoproc_xxx_write,
};


static int vcoproc_xxx_domain_init(struct domain *d, struct vcoproc_info *vcoproc_xxx)
{
	struct coproc_device *coproc_xxx = vcoproc_xxx->coproc;
	int i;

	for (i = 0; i < coproc_xxx->num_mmios; i++) {
		struct mmio *mmio = &coproc_xxx->mmios[i];

		register_mmio_handler(d, &vcoproc_xxx_mmio_handler,
				mmio->addr, mmio->size, vcoproc_xxx);
	}

	return 0;
}

static void vcoproc_xxx_domain_free(struct domain *d, struct vcoproc_info *vcoproc_xxx)
{

}

static const struct vcoproc_domain_ops vcoproc_xxx_domain_ops = {
	.domain_init = vcoproc_xxx_domain_init,
	.domain_free = vcoproc_xxx_domain_free,
};

static int vcoproc_xxx_vcoproc_init(struct domain *d, struct coproc_device *coproc_xxx)
{
	struct vcoproc_info *vcoproc_xxx;
	int ret;

	vcoproc_xxx = xzalloc(struct vcoproc_info);
	if (!vcoproc_xxx) {
		dev_err(coproc_xxx->dev, "failed to allocate vcoproc_info\n");
		return -ENOMEM;
	}

	vcoproc_xxx->coproc = coproc_xxx;
	vcoproc_xxx->domain = d;
	vcoproc_xxx->ops = &vcoproc_xxx_domain_ops;
	spin_lock_init(&vcoproc_xxx->lock);

	spin_lock(&coproc_xxx->vcoprocs_lock);
	list_add(&vcoproc_xxx->list, &coproc_xxx->vcoprocs_list);
	spin_unlock(&coproc_xxx->vcoprocs_lock);

	ret = vcoproc_attach(d, vcoproc_xxx);
	if (ret) {
		dev_err(coproc_xxx->dev, "failed to attach vcoproc to domain %d\n", d->domain_id);
		return ret;
	}

	return 0;
}

static void vcoproc_xxx_vcoproc_free(struct domain *d, struct vcoproc_info *vcoproc_xxx)
{
	struct coproc_device *coproc_xxx = vcoproc_xxx->coproc;

	spin_lock(&coproc_xxx->vcoprocs_lock);
	list_del(&vcoproc_xxx->list);
	spin_unlock(&coproc_xxx->vcoprocs_lock);
	xfree(vcoproc_xxx);
}

static const struct vcoproc_ops vcoproc_xxx_vcoproc_ops = {
	.vcoproc_init = vcoproc_xxx_vcoproc_init,
	.vcoproc_free = vcoproc_xxx_vcoproc_free,
};

static void coproc_xxx_irq_handler(int irq, void *dev, struct cpu_user_regs *regs)
{
	struct coproc_device *coproc_xxx = dev;

	(void)coproc_xxx;
}

static int coproc_xxx_dt_probe(struct platform_device *pdev)
{
	struct coproc_device *coproc_xxx;
	struct device *dev = &pdev->dev;
	struct resource *res;
	int num_irqs, num_mmios, i, ret;

	coproc_xxx = xzalloc(struct coproc_device);
	if (!coproc_xxx) {
		dev_err(dev, "failed to allocate coproc_device\n");
		return -ENOMEM;
	}
	coproc_xxx->dev = dev;

	num_mmios = 0;
	while ((res = platform_get_resource(pdev, IORESOURCE_MEM, num_mmios)))
		num_mmios++;

	if (!num_mmios) {
		dev_err(dev, "failed to find at least one mmio\n");
		ret = -ENODEV;
		goto out_free_mmios;
	}

	coproc_xxx->mmios = xzalloc_array(struct mmio, num_mmios);
	if (!coproc_xxx->mmios) {
		dev_err(dev, "failed to allocate %d mmios\n", num_mmios);
		ret = -ENOMEM;
		goto out_free_mmios;
	}

	for (i = 0; i < num_mmios; ++i) {
		res = platform_get_resource(pdev, IORESOURCE_MEM, i);
		coproc_xxx->mmios[i].base = devm_ioremap_resource(dev, res);
		if (IS_ERR(coproc_xxx->mmios[i].base)) {
			ret = PTR_ERR(coproc_xxx->mmios[i].base);
			goto out_iounmap_mmios;
		}
		coproc_xxx->mmios[i].size = resource_size(res);
		coproc_xxx->mmios[i].addr = resource_addr(res);
	}
	coproc_xxx->num_mmios = num_mmios;

	num_irqs = 0;
	while ((res = platform_get_resource(pdev, IORESOURCE_IRQ, num_irqs)))
		num_irqs++;

	if (!num_irqs) {
		dev_err(dev, "failed to find at least one irq\n");
		ret = -ENODEV;
		goto out_free_irqs;
	}

	coproc_xxx->irqs = xzalloc_array(unsigned int, num_irqs);
	if (!coproc_xxx->irqs) {
		dev_err(dev, "failed to allocate %d irqs\n", num_irqs);
		ret = -ENOMEM;
		goto out_free_irqs;
	}

	for (i = 0; i < num_irqs; ++i) {
		int irq = platform_get_irq(pdev, i);

		if (irq < 0) {
			dev_err(dev, "failed to get irq index %d\n", i);
			ret = -ENODEV;
			goto out_free_irqs;
		}
		coproc_xxx->irqs[i] = irq;
	}
	coproc_xxx->num_irqs = num_irqs;

	for (i = 0; i < num_irqs; ++i) {
		ret = request_irq(coproc_xxx->irqs[i],
				  IRQF_SHARED,
				  coproc_xxx_irq_handler,
				  "coproc_xxx irq",
				  coproc_xxx);
		if (ret) {
			dev_err(dev, "failed to request irq %d (%u)\n", i, coproc_xxx->irqs[i]);
			goto out_release_irqs;
		}
	}

	INIT_LIST_HEAD(&coproc_xxx->vcoprocs_list);
	spin_lock_init(&coproc_xxx->vcoprocs_lock);
	coproc_xxx->ops = &vcoproc_xxx_vcoproc_ops;

	ret = coproc_register(coproc_xxx);
	if (ret) {
		dev_err(dev, "failed to register coproc\n");
		goto out_release_irqs;
	}

	return 0;

out_release_irqs:
	while (i--)
		release_irq(coproc_xxx->irqs[i], coproc_xxx);
out_free_irqs:
	xfree(coproc_xxx->irqs);
out_iounmap_mmios:
	for (i = 0; i < num_mmios; ++i) {
		if (!IS_ERR(coproc_xxx->mmios[i].base))
			iounmap(coproc_xxx->mmios[i].base);
	}
out_free_mmios:
	xfree(coproc_xxx->mmios);
	xfree(coproc_xxx);

	return ret;
}

static const struct dt_device_match coproc_xxx_dt_match[] __initconst =
{
	DT_MATCH_COPROC_XXX,
	{ /* sentinel */ },
};

static __init int coproc_xxx_init(struct dt_device_node *dev,
				   const void *data)
{
	int ret;

	dt_device_set_used_by(dev, DOMID_XEN);

	ret = coproc_xxx_dt_probe(dev);
	if (ret)
		return ret;

	return 0;
}

DT_DEVICE_START(coproc_xxx, "COPROC_XXX", DEVICE_COPROC)
	.dt_match = coproc_xxx_dt_match,
	.init = coproc_xxx_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
