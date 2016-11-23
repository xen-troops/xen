/*
 * xen/arch/arm/coproc/plat/common.h
 *
 * Common platform header for all Remote processors
 *
 * Oleksandr Tyshchenko <Oleksandr_Tyshchenko@epam.com>
 * Copyright (C) 2016 EPAM Systems Inc.
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

#ifndef __ARCH_ARM_COPROC_PLAT_COMMON_H__
#define __ARCH_ARM_COPROC_PLAT_COMMON_H__

#include <xen/types.h>
#include <xen/device_tree.h>
#include <asm/mmio.h>

/* Copied from smmu.c */

struct resource
{
    u64 addr;
    u64 size;
    unsigned int type;
};

#define resource_size(res) (res)->size;
#define resource_addr(res) (res)->addr;

#define platform_device dt_device_node

#define IORESOURCE_MEM 0
#define IORESOURCE_IRQ 1

struct resource *platform_get_resource(struct platform_device *pdev,
                                       unsigned int type,
                                       unsigned int num);
void __iomem *devm_ioremap_resource(struct device *dev,
                                    struct resource *res);

/* Device logger functions */
#define dev_print(dev, lvl, fmt, ...) \
    printk(lvl "coproc: %s: " fmt, dt_node_full_name(dev_to_dt(dev)), ## __VA_ARGS__)

#define dev_dbg(dev, fmt, ...) dev_print(dev, XENLOG_DEBUG, fmt, ## __VA_ARGS__)
#define dev_notice(dev, fmt, ...) dev_print(dev, XENLOG_INFO, fmt, ## __VA_ARGS__)
#define dev_warn(dev, fmt, ...) dev_print(dev, XENLOG_WARNING, fmt, ## __VA_ARGS__)
#define dev_err(dev, fmt, ...) dev_print(dev, XENLOG_ERR, fmt, ## __VA_ARGS__)

#define dev_err_ratelimited(dev, fmt, ...) \
    dev_print(dev, XENLOG_ERR, fmt, ## __VA_ARGS__)

/* Copied from vgic.h */

#define COPROC_REG_MASK(size) ((~0UL) >> (BITS_PER_LONG - ((1 << (size)) * 8)))

/*
 * The check on the size supported by the register has to be done by
 * the caller of coproc_regN_*.
 *
 * coproc_reg_* should never be called directly. Instead use the coproc_regN_*
 * according to size of the emulated register
 */
static inline register_t coproc_reg_extract(unsigned long reg,
                                            unsigned int offset,
                                            enum dabt_size size)
{
    reg >>= 8 * offset;
    reg &= COPROC_REG_MASK(size);

    return reg;
}

static inline void coproc_reg_update(unsigned long *reg, register_t val,
                                     unsigned int offset,
                                     enum dabt_size size)
{
    unsigned long mask = COPROC_REG_MASK(size);
    int shift = offset * 8;

    *reg &= ~(mask << shift);
    *reg |= ((unsigned long)val & mask) << shift;
}

static inline void coproc_reg_setbits(unsigned long *reg, register_t bits,
                                      unsigned int offset,
                                      enum dabt_size size)
{
    unsigned long mask = COPROC_REG_MASK(size);
    int shift = offset * 8;

    *reg |= ((unsigned long)bits & mask) << shift;
}

static inline void coproc_reg_clearbits(unsigned long *reg, register_t bits,
                                        unsigned int offset,
                                        enum dabt_size size)
{
    unsigned long mask = COPROC_REG_MASK(size);
    int shift = offset * 8;

    *reg &= ~(((unsigned long)bits & mask) << shift);
}

/* N-bit register helpers */
#define COPROC_REG_HELPERS(sz, offmask)                                    \
static inline register_t coproc_reg##sz##_extract(uint##sz##_t reg,        \
                                                  const mmio_info_t *info) \
{                                                                          \
    return coproc_reg_extract(reg, info->gpa & offmask,                    \
                              info->dabt.size);                            \
}                                                                          \
                                                                           \
static inline void coproc_reg##sz##_update(uint##sz##_t *reg,              \
                                           register_t val,                 \
                                           const mmio_info_t *info)        \
{                                                                          \
    unsigned long tmp = *reg;                                              \
                                                                           \
    coproc_reg_update(&tmp, val, info->gpa & offmask,                      \
                      info->dabt.size);                                    \
                                                                           \
    *reg = tmp;                                                            \
}                                                                          \
                                                                           \
static inline void coproc_reg##sz##_setbits(uint##sz##_t *reg,             \
                                            register_t bits,               \
                                            const mmio_info_t *info)       \
{                                                                          \
    unsigned long tmp = *reg;                                              \
                                                                           \
    coproc_reg_setbits(&tmp, bits, info->gpa & offmask,                    \
                       info->dabt.size);                                   \
                                                                           \
    *reg = tmp;                                                            \
}                                                                          \
                                                                           \
static inline void coproc_reg##sz##_clearbits(uint##sz##_t *reg,           \
                                              register_t bits,             \
                                              const mmio_info_t *info)     \
{                                                                          \
    unsigned long tmp = *reg;                                              \
                                                                           \
    coproc_reg_clearbits(&tmp, bits, info->gpa & offmask,                  \
                         info->dabt.size);                                 \
                                                                           \
    *reg = tmp;                                                            \
}

/*
 * 64 bits registers are only supported on platform with 64-bit long.
 * This is also allow us to optimize the 32 bit case by using
 * unsigned long rather than uint64_t
 */
#if BITS_PER_LONG == 64
COPROC_REG_HELPERS(64, 0x7);
#endif
COPROC_REG_HELPERS(32, 0x3);

#undef COPROC_REG_HELPERS

#endif /* __ARCH_ARM_COPROC_PLAT_COMMON_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
