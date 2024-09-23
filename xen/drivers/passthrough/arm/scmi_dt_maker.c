/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SCMI device-tree node generator.
 *
 * Oleksii Moisieiev <oleksii_moisieiev@epam.com>
 * Copyright (c) 2024 EPAM Systems
 */

#include <asm/p2m.h>
#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/iocap.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt.h>

#include <xen/scmi_dt_maker.h>

#define SCMI_NODE_PATH_MAX_LEN 128

struct scmi_phandle {
    struct list_head list;
    uint32_t phandle;
    char full_name[SCMI_NODE_PATH_MAX_LEN];
};

LIST_HEAD(scmi_ph_list);

 int __init scmi_dt_make_shmem_node(struct kernel_info *kinfo)
{
    int res;
    void *fdt = kinfo->fdt;
    char buf[64];
    __be32 reg[GUEST_ROOT_ADDRESS_CELLS + GUEST_ROOT_SIZE_CELLS];
    __be32 *cells;
    struct domain *d = kinfo->d;

    snprintf(buf, sizeof(buf), "scmi-shmem@%lx",
            d->arch.sci_channel.paddr);

    res = fdt_begin_node(fdt, buf);
    if ( res )
        return res;

    res = fdt_property_string(fdt, "compatible", "arm,scmi-shmem");
    if ( res )
        return res;

    cells = &reg[0];
    dt_child_set_range(&cells, GUEST_ROOT_ADDRESS_CELLS,
                          GUEST_ROOT_SIZE_CELLS, d->arch.sci_channel.paddr,
                          GUEST_SCI_SHMEM_SIZE);

    res = fdt_property(fdt, "reg", reg, sizeof(reg));
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "phandle", kinfo->phandle_sci_shmem);
    if ( res )
        return res;

    res = fdt_end_node(fdt);
    if ( res )
        return res;

    return 0;
}

/*
 * The following methods are needed to get node name for the node full_path.
 * This was done because some calls, such as dt_node_name return name
 * before "@". So for node "protocol@19" it will return "protocol".
 */
static const char *dt_node_name_from_path(const struct dt_device_node *node)
{
    return strrchr(dt_node_full_name(node), '/') + 1;
}

static const char *name_from_path(const char *path)
{
    return strrchr(path, '/') + 1;
}

static int __init copy_properties(const struct dt_device_node *node, void* fdt)
{
    int rc;
    const struct dt_property *pp;

    printk(XENLOG_DEBUG "scmi_dt_maker: copy properties for node: %s\n",
           dt_node_name_from_path(node));

    dt_for_each_property_node(node, pp)
    {
        /* Skipping phandle nodes in xen device-tree */
        if ( dt_property_name_is_equal(pp, "phandle") ||
             dt_property_name_is_equal(pp, "linux,phandle") )
            continue;

        rc = fdt_property(fdt, pp->name, pp->value, pp->length);
        if ( rc )
            return rc;
    }

   return 0;
}

static struct scmi_phandle * __init get_handle_by_name(const char *name)
{
    struct scmi_phandle *handle;
    list_for_each_entry(handle, &scmi_ph_list, list)
    {
        if ( strcmp( name_from_path(handle->full_name), name) == 0 )
            return handle;
    }

    return NULL;
}

static bool __init guest_has_child(const char *name)
{
    struct scmi_phandle *handle;

    list_for_each_entry(handle, &scmi_ph_list, list)
    {
        if ( strstr(handle->full_name, name) )
            return true;
    }

    return false;
}

static int __init copy_subnodes(const struct dt_device_node *node, void *fdt,
                         bool guest_subnode)
{
    int rc;
    struct dt_device_node *child;
    struct scmi_phandle *handle;

    printk(XENLOG_DEBUG "scmi_dt_maker: copy subnodes for %s\n",
           dt_node_name_from_path(node));

    dt_for_each_child_node(node,child)
    {
        handle = get_handle_by_name(dt_node_name_from_path(child));

        if ( !guest_has_child(dt_node_name_from_path(child)) && !handle &&
             !guest_subnode )
             continue;

         rc = fdt_begin_node(fdt, dt_node_name_from_path(child));
         if ( rc )
             return rc;

         rc = copy_properties(child, fdt);
         if ( rc )
             return rc;

         if ( handle )
         {
             printk(XENLOG_DEBUG "scmi_dt_maker: set phandle %x\n",
                    handle->phandle);

            rc = fdt_property_cell(fdt, "phandle", handle->phandle);
            if ( rc )
                return rc;
         }

         /*
          * Devices in partial device-tree can be linked to the node
          * with child nodes as it happens for scmi-pinctrl nodes.
          * For example:
          *  scmi_pinctrl {
          *      device_mux: mux {
          *          pins_clk {
          *          };
          *          pins_bin {
          *          };
          *     };
          *  };
          *
          *  &device {
          *     pinctrl-0 = <&device_mux>;
          *  };
          *
          *  In this case phandle will be generated only for device_mux
          *  but subnodes should be copied to domain device-tree as well.
          */
         rc = copy_subnodes(child, fdt, (guest_subnode || handle));
         if ( rc )
             return rc;

         rc = fdt_end_node(fdt);
         if ( rc )
             return rc;
     }

     return 0;
 }

static void __init clean_handles(void)
{
    struct scmi_phandle *curr, *_curr;

    if ( list_empty(&scmi_ph_list) )
        return;

    list_for_each_entry_safe (curr, _curr, &scmi_ph_list, list)
    {
        list_del(&curr->list);
        xfree(curr);
    }
}

int __init scmi_dt_create_node(struct kernel_info *kinfo)
{
    int rc = 0;
    struct dt_device_node *scmi = dt_find_node_by_path("/firmware/scmi");

    if ( scmi == NULL )
    {
        rc = -ENODEV;
        printk(XENLOG_ERR "scmi_dt_maker: no SCMI in XEN device-tree\n");
        goto err;
    }

    rc = fdt_begin_node(kinfo->fdt, "scmi");
    if ( rc )
        goto err;

    rc = fdt_property_string(kinfo->fdt, "compatible", "arm,scmi-smc");
    if ( rc )
        goto err;

    rc = fdt_property_cell(kinfo->fdt, "shmem", kinfo->phandle_sci_shmem);
    if ( rc )
        goto err;

    rc = fdt_property_cell(kinfo->fdt, "#addrets-cells", 1);
    if ( rc )
        goto err;

    rc = fdt_property_cell(kinfo->fdt, "#size-cells", 0);
    if ( rc )
        goto err;

    rc = fdt_property_cell(kinfo->fdt, "arm,smc-id", kinfo->d->arch.sci_channel.guest_func_id);
    if ( rc )
        goto err;

    rc = copy_subnodes(scmi, kinfo->fdt, false);
    if ( rc )
        goto err;

    rc = fdt_end_node(kinfo->fdt);
    if ( rc )
        goto err;

err:
    /* Clean handle list after nodes generation */
    clean_handles();

    return rc;
}

int __init scmi_dt_scan_node(struct kernel_info *kinfo, void *pfdt,
                                 int nodeoff)
{
    int rc;
    int node_next;
    struct scmi_phandle *handle;
    uint32_t phandle;

    node_next = fdt_first_subnode(pfdt, nodeoff);
    while ( node_next > 0 )
    {
        printk(XENLOG_DEBUG "scmi_dt_maker: processing node %s\n",
                fdt_get_name(pfdt, node_next, NULL));

        phandle = fdt_get_phandle(pfdt, node_next);

        if ( phandle )
        {
            printk(XENLOG_DEBUG "scmi_dt_maker: phandle %x\n", phandle);

            handle = xmalloc(struct scmi_phandle);
            if ( !handle )
            {
                rc = -ENOMEM;
                goto err;
            }

            handle->phandle = phandle;
            rc = fdt_get_path(pfdt, node_next, handle->full_name, 128);
            if ( rc )
            {
                xfree(handle);
                goto err;
            }

            list_add_tail(&handle->list, &scmi_ph_list);
        }

        rc = scmi_dt_scan_node(kinfo, pfdt, node_next);
        if ( rc )
            goto err;

        node_next = fdt_next_subnode(pfdt, node_next);
    }

    return 0;
err:
    clean_handles();
    return rc;
}

int __init scmi_dt_set_phandle(struct kernel_info *kinfo,
        const char *name)
{
    int offset = fdt_path_offset(kinfo->fdt, name);
    __be32 val = cpu_to_be32(kinfo->phandle_sci_shmem);

    if ( !offset )
        return -ENODEV;

    return fdt_setprop_inplace(kinfo->fdt, offset, "shmem",
            &val,sizeof(val));
}
