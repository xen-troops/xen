/*
 * xen/arch/arm/coproc/plat/gx6xxx/gx6xxx_startstop.h
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

#ifndef __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_STARTSTOP_H__
#define __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_STARTSTOP_H__

#include <xen/time.h>

struct vcoproc_instance;
struct vgx6xxx_info;

#define GX6XXX_POLL_TO_NUM_US   100
#define GX6XXX_WAIT_TIME_US     MICROSECS(100)

struct gx6xxx_ctx_switch_state
{
    /*
     * return value:
     * 0  - on success
     * >0 - retry in us
     * <0 - -EXXX error code:
     *      if -EAGAIN returned then previous step must be retried
     */
    s_time_t (*handler)(struct vcoproc_instance *vcoproc);
    /* if implemented:
     * true - if step needs to be run
     * false - skip this step
     */
    bool (*run_condition)(struct vcoproc_instance *vcoproc);
    /* number of retries for this handler */
    uint32_t num_retries;
    const char *name;
#ifdef GX6XXX_DEBUG
    s_time_t time_min, time_max;
#endif
};

extern struct gx6xxx_ctx_switch_state gx6xxx_ctx_gpu_stop_states[];

int gx6xxx_ctx_init(struct vcoproc_instance *vcoproc,
                        struct vgx6xxx_info *vinfo);
void gx6xxx_ctx_deinit(struct vcoproc_instance *vcoproc,
                           struct vgx6xxx_info *vinfo);

int gx6xxx_ctx_gpu_start(struct vcoproc_instance *vcoproc,
                         struct vgx6xxx_info *vinfo);
/* try stopping the GPU: 0 on success, <0 if still busy */
int gx6xxx_ctx_gpu_stop(struct vcoproc_instance *vcoproc,
                        struct vgx6xxx_info *vinfo);

#endif /* __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_STARTSTOP_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
