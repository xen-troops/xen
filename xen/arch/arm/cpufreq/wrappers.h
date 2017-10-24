/*
 * xen/arch/arm/cpufreq/wrappers.h
 *
 * This header file contains Linux2Xen wrappers, define-s, different stubs
 * which used by all direct ported CPUfreq components.
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

#ifndef __ARCH_ARM_CPUFREQ_WRAPPERS_H__
#define __ARCH_ARM_CPUFREQ_WRAPPERS_H__

#include <xen/time.h>
#include <xen/delay.h>
#include <xen/softirq.h>
#include <xen/timer.h>
#include <asm/device.h>
#include <asm/atomic.h>

/* Xen doesn't have mutex, so use spinlock instead. */
#define mutex spinlock
#define mutex_lock spin_lock
#define mutex_unlock spin_unlock
#define mutex_init spin_lock_init
#define DEFINE_MUTEX DEFINE_SPINLOCK

/* Aliases to Xen allocation helpers. */
#define devm_kmalloc(dev, size, flags) _xmalloc(size, sizeof(void *))
#define devm_kzalloc(dev, size, flags) _xzalloc(size, sizeof(void *))
#define devm_kcalloc(dev, n, size, flags) _xzalloc_array(size, sizeof(void *), n)
#define kmalloc(size, flags) _xmalloc(size, sizeof(void *))
#define kcalloc(size, n, flags) _xzalloc_array(size, sizeof(void *), n)
#define devm_kfree(dev, p) xfree(p)
#define kfree xfree

/* Aliases to Xen device tree helpers. */
#define device_node dt_device_node
#define platform_device dt_device_node
#define of_device_id dt_device_match
#define of_match_node dt_match_node
#define of_property_count_elems_of_size dt_property_count_elems_of_size
#define of_property_read_u32_index dt_property_read_u32_index
#define of_property_for_each_string dt_property_for_each_string
#define of_parse_phandle_with_args dt_parse_phandle_with_args
#define of_count_phandle_with_args dt_count_phandle_with_args
#define of_property_read_string dt_property_read_string
#define of_parse_phandle dt_parse_phandle
#define of_phandle_args dt_phandle_args
#define of_get_property dt_get_property
#define property dt_property

static inline const struct of_device_id *of_match_device(
		const struct of_device_id *matches, const struct device *dev)
{
	if (!matches || !dev->of_node)
		return NULL;

	return of_match_node(matches, dev->of_node);
}

/* Stuff to deal with device address ranges. */
struct resource
{
	u64 start;
	u64 size;
};

#define resource_size(res) (res)->size;

static inline int of_address_to_resource(struct device_node *node, int index,
		struct resource *res)
{
	return dt_device_get_address(node, index, &res->start, &res->size);
}

typedef u64 resource_size_t;

#define devm_ioremap(dev, addr, size) ioremap_nocache(addr, size)
#define devm_iounmap(dev, addr) iounmap(addr)

/* Device logger functions */
#define dev_print(dev, lvl, fmt, ...)	\
		printk(lvl "scpi: %s: " fmt, dt_node_full_name(dev_to_dt(dev)), ## __VA_ARGS__)

#define dev_info(dev, fmt, ...) dev_print(dev, XENLOG_INFO, fmt, ## __VA_ARGS__)
#define dev_dbg(dev, fmt, ...) dev_print(dev, XENLOG_DEBUG, fmt, ## __VA_ARGS__)
#define dev_warn(dev, fmt, ...) dev_print(dev, XENLOG_WARNING, fmt, ## __VA_ARGS__)
#define dev_err(dev, fmt, ...) dev_print(dev, XENLOG_ERR, fmt, ## __VA_ARGS__)

#define pr_debug printk
#define _dev_info dev_info

/* Helpers to get/set driver specific info. */
static inline void platform_set_drvdata(struct platform_device *pdev, void *data)
{
	pdev->dev.driver_data = data;
}

static inline void *platform_get_drvdata(const struct platform_device *pdev)
{
	return pdev->dev.driver_data;
}

/*
 * Xen doesn't have such a synchronization mechanism as Linux's
 * "wait-for-completion", because of it nature. Create dummy completion
 * infrastructure based on a busy loop to make direct ported code happy.
 */
struct completion {
	atomic_t done;
};

static inline void init_completion(struct completion *x)
{
	atomic_set(&x->done, 0);
}

static inline void reinit_completion(struct completion *x)
{
	atomic_set(&x->done, 0);
}

static inline void complete(struct completion *x)
{
	atomic_set(&x->done, 1);
}

static inline unsigned long
wait_for_completion_timeout(struct completion *x, unsigned long timeout)
{
	s_time_t deadline = NOW() + MILLISECS(timeout);

	do {
		if (atomic_cmpxchg(&x->done, 1, 0))
			return 1;

		cpu_relax();
		udelay(1);
		process_pending_softirqs();
	} while (NOW() <= deadline);

	return 0;
}

static inline bool completion_done(struct completion *x)
{
	if (!atomic_read(&x->done))
		return false;

	return true;
}

/*
 * As we only call this function to obtain a timeout for wait_for_completion_timeout
 * which was modified to expect a timeout in millisecs, just return passed argument.
 */
static inline unsigned long msecs_to_jiffies(unsigned long timeout)
{
	return timeout;
}

/* Misc */
#define MODULE_DEVICE_TABLE(type, name)
#define EXPORT_SYMBOL_GPL(name)

#define module_put(owner)
#define try_module_get(owner) 1

#define of_node_put(np)

#define memcpy_fromio memcpy
#define memcpy_toio memcpy

#define EMSGSIZE 90	/* Message too long */
#define EPROBE_DEFER 517	/* Driver requests probe retry */

#define hrtimer timer

enum hrtimer_restart {
	HRTIMER_NORESTART,	/* Timer is not restarted */
	HRTIMER_RESTART,	/* Timer must be restarted */
};

/* Stubs to make driver compilable */
static inline int dev_pm_opp_add(struct device *dev, unsigned long freq,
		unsigned long u_volt)
{
	return 0;
}

static inline void dev_pm_opp_remove(struct device *dev, unsigned long freq)
{

}

#endif /* __ARCH_ARM_CPUFREQ_WRAPPERS_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
