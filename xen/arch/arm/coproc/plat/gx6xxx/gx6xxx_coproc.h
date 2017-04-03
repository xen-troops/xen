/*
 * xen/arch/arm/coproc/plat/gx6xxx/gx6xxx_coproc.h
 *
 * COPROC GPU GX6XXX platform specific code
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

#ifndef __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_COPROC_H__
#define __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_COPROC_H__

#include <xen/atomic.h>

#include "../../coproc.h"
#include "../common.h"

#include "gx6xxx_fw.h"

enum vgx6xxx_state
{
    /* initialization sequence has started - collecting register values
     * so those can be used for real GPU initialization */
    VGX6XXX_STATE_INITIALIZING,
    /* scheduler is running, at least one context switch was made */
    VGX6XXX_STATE_RUNNING,
    /* asked to switch from but waiting for GPU to finish current jobs */
    VGX6XXX_STATE_IN_TRANSIT,
    /* context is off - queueing requests and interrupts */
    VGX6XXX_STATE_WAITING,
};
#define VGX6XXX_STATE_DEFAULT   VGX6XXX_STATE_INITIALIZING

union reg64_t
{
    struct
    {
        uint32_t lo;
        uint32_t hi;
    } as;
    uint64_t val;
};

struct vgx6xxx_ctx
{
    /* number of the registers in context */
    int count;
    /* saved registers */
    union reg64_t *regs;
};

struct vgx6xxx_info
{
    /* current state of the vcoproc */
    enum vgx6xxx_state state;

    /* set if scheduler has been started for this vcoproc */
    bool scheduler_started;

    /* number of IRQs received - used to check if IRQ expected
     * at "switch from" time
     */
    atomic_t irq_count;

    /* expected KCCB read offset: while injecting commands into KCCB
     * we need to wait for those to be executed. this counter will hold
     * expected ui32ReadOffset to poll for
     */
    uint32_t state_kccb_read_ofs;
    /* set if there was a KCCB command requiring power sync check */
    bool state_psync_pending;

    s_time_t tm_start_sw_to;
    s_time_t tm_start_sw_to_acc;
    int tm_cnt_sw_to;
    s_time_t tm_start_sw_from;
    s_time_t tm_start_sw_from_acc;
    int tm_cnt_sw_from;

    /* FIXME: the below are frequently used, so they are mapped on
     * vcoproc init and unmapped on deinit
     */
    RGXFWIF_INIT *fw_init;
    RGXFWIF_TRACEBUF *fw_trace_buf;
    IMG_UINT8 *fw_kernel_ccb;
    RGXFWIF_CCB_CTL *fw_kernel_ccb_ctl;
    IMG_UINT8 *fw_firmware_ccb;
    RGXFWIF_CCB_CTL *fw_firmware_ccb_ctl;
    volatile IMG_UINT32 *fw_power_sync;

    /*
     ***************************************************************************
     *                           REGISTERS
     ***************************************************************************
     */
    /* this is the register's context */
    struct vgx6xxx_ctx reg_ctx;

    /* This is the current IRQ status register value reported/updated
     * to/from domains. Set on real IRQ from GPU, low 32-bits
     */
    union reg64_t reg_val_irq_status;
    /* Current value of the soft reset register, used to determine
     * when FW starts to run
     */
    union reg64_t reg_val_cr_soft_reset;

    /* number of writes to RGX_CR_MTS_SCHEDULE while not in running state */
    int reg_cr_mts_schedule_lo_wait_cnt;

    /*
     ***************************************************************************
     * FIXME: Value of the registers below must be saved on write
     ***************************************************************************
     */
    /* FIXME: META boot control register - low 32-bits are used */
    /* FIXME: this must be tracked when written, reset on read */
    union reg64_t reg_val_cr_meta_boot;

    union reg64_t reg_val_cr_mts_garten_wrapper_config;

    /*
     ***************************************************************************
     * FIXME: Value of the registers remain constant once written
     * and can be read back
     ***************************************************************************
     */
    /* FIXME: SLC control register - low 32-bits are used */
    union reg64_t reg_val_cr_slc_ctrl_misc;
    union reg64_t reg_val_cr_axi_ace_lite_configuration;
    /* FIXME: address of kernel page catalog, MMU PC
     * FIXME: PD and PC are fixed size and can't be larger than page size
     */
    union reg64_t reg_val_cr_bif_cat_base0;

    /*
     ***************************************************************************
     *                           Gx6XXX MMU
     ***************************************************************************
     */
    /* page catalog */
    mfn_t mfn_pc;
    /* page directory */
    mfn_t mfn_pd;
};

struct gx6xxx_info
{
    struct vcoproc_instance *curr;
    /* FIXME: IRQ registers are 64-bit, but only low 32-bits are used */
    uint32_t *reg_vaddr_irq_status;
    uint32_t *reg_vaddr_irq_clear;

    /* this is the current state of the state machine during context switch */
    struct gx6xxx_ctx_switch_state *state_curr;
};

#endif /* __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_COPROC_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
