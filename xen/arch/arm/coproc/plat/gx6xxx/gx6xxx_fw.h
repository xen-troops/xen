/*
 * xen/arch/arm/coproc/plat/gx6xxx/gx6xxx_fw.h
 *
 * Gx6XXX firmware utilities
 *
 * Oleksandr Andrushchenko <oleksandr_andrushchenko@epam.com>
 * Copyright (C) 2017 EPAM Systems Inc.
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

#ifndef __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_FW_H__
#define __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_FW_H__

#include <asm/io.h>
#include <xen/mm.h>

/* this must be included before any rgx headers */
#include "config_kernel.h"

#include "rgx_fwif.h"
#include "rgx_fwif_km.h"
#include "rgx_meta.h"
#include "rgxmmudefs_km.h"

struct vcoproc_instance;
struct vgx6xxx_info;

/* FIXME: second set of Slave Port debug registers */
#ifndef RGX_CR_META_SP_MSLVCTRL2
#define RGX_CR_META_SP_MSLVCTRL2    (0x0A20U)
#endif

#ifdef GX6XXX_DEBUG
void gx6xxx_print_reg(const char *prefix, uint32_t reg, uint32_t val);
#else
#define gx6xxx_print_reg(a, b, c) {}
#endif

#define REG_LO32(a) ( (a) )
#define REG_HI32(a) ( (a) + sizeof(uint32_t) )

static inline uint32_t gx6xxx_read32(struct coproc_device *coproc,
                                     uint32_t offset)
{
#ifdef GX6XXX_DEBUG
    uint32_t val = readl((char *)coproc->mmios[0].base + offset);

    gx6xxx_print_reg(__FUNCTION__, offset, val);
    return val;
#else
    return readl((char *)coproc->mmios[0].base + offset);
#endif
}

static inline void gx6xxx_write32(struct coproc_device *coproc,
                                  uint32_t offset, uint32_t val)
{
    gx6xxx_print_reg(__FUNCTION__, offset, val);
    writel(val, (char *)coproc->mmios[0].base + offset);
}

static inline uint64_t gx6xxx_read64(struct coproc_device *coproc,
                                     uint32_t offset)
{
#ifdef GX6XXX_DEBUG
    uint64_t val = readq((char *)coproc->mmios[0].base + offset);

    gx6xxx_print_reg(__FUNCTION__, REG_LO32(offset),
                     val & 0xffffffff);
    gx6xxx_print_reg(__FUNCTION__, REG_HI32(offset),
                     val >> 32);
    return val;
#else
    return readq((char *)coproc->mmios[0].base + offset);
#endif
}

static inline void gx6xxx_write64(struct coproc_device *coproc,
                                  uint32_t offset, uint64_t val)
{
    gx6xxx_print_reg(__FUNCTION__, REG_LO32(offset),
                     val & 0xffffffff);
    gx6xxx_print_reg(__FUNCTION__, REG_HI32(offset),
                     val >> 32);
    writeq(val, (char *)coproc->mmios[0].base + offset);
}

int gx6xxx_fw_init(struct vcoproc_instance *vcoproc,
                   struct vgx6xxx_info *vinfo);
void gx6xxx_fw_deinit(struct vcoproc_instance *vcoproc,
                      struct vgx6xxx_info *vinfo);
#ifdef GX6XXX_DEBUG
void gx6xxx_fw_dump_kccb(struct vcoproc_instance *vcoproc,
                         struct vgx6xxx_info *vinfo);
#endif
int gx6xxx_fw_send_kccb_cmd(struct vcoproc_instance *vcoproc,
                            struct vgx6xxx_info *vinfo,
                            RGXFWIF_KCCB_CMD *cmd, int nr);
int gx6xxx_fw_wait_kccb_cmd(struct vcoproc_instance *vcoproc,
                            struct vgx6xxx_info *vinfo);

#endif /* __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_FW_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
