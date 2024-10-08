/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Export host FDT to the hypfs
 *
 * Copyright (C) 2024 EPAM Systems
 */

#include <xen/device_tree.h>
#include <xen/hypfs.h>
#include <xen/init.h>
#include <xen/libfdt/libfdt.h>

static HYPFS_VARSIZE_INIT(dt_prop, XEN_HYPFS_TYPE_BLOB,
        "devicetree", CONFIG_HOST_DTB_MAX_SIZE,
        &hypfs_leaf_ro_funcs);

static int __init host_dtb_export_init(void)
{
    ASSERT(dt_host && (dt_host->sibling == NULL));

    dt_prop.u.content = device_tree_flattened;
    dt_prop.e.size = fdt_totalsize(device_tree_flattened);
    hypfs_add_leaf(&hypfs_root, &dt_prop, true);

    return 0;
}

__initcall(host_dtb_export_init);
