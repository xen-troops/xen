/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SCMI device-tree node generator header.
 *
 * Oleksii Moisieiev <oleksii_moisieiev@epam.com>
 * Copyright (c) 2024 EPAM Systems
 */

#ifndef XEN_ARCH_ARM_SCMI_DT_MAKER_H_
#define XEN_ARCH_ARM_SCMI_DT_MAKER_H_

#ifdef CONFIG_SCMI_SMC
#include <asm/kernel.h>

int __init scmi_dt_make_shmem_node(struct kernel_info *kinfo);
int __init scmi_dt_create_node(struct kernel_info *kinfo);
int __init scmi_dt_scan_node(struct kernel_info *kinfo, void *pfdt,
                             int nodeoff);
#else
#define scmi_dt_make_shmem_node(kinfo)          (0)
#define scmi_dt_create_node(kinfo)              (0)
#define scmi_dt_scan_node(kinfo, pfdt, nodeoff) (0)

#endif /* CONFIG_SCMI_SMC */

#endif /* XEN_ARCH_ARM_SCMI_DT_MAKER_H_ */
