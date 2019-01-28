/*
 * Copyright (c) 2016 Citrix Systems Inc.
 * Copyright (c) 2019 Arm ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/nospec.h>

static int dm_op(const struct dmop_args *op_args)
{
    struct domain *d;
    struct xen_dm_op op;
    long rc;
    bool const_op = true;
    const size_t offset = offsetof(struct xen_dm_op, u);

    static const uint8_t op_size[] = {
        [XEN_DMOP_create_ioreq_server]              = sizeof(struct xen_dm_op_create_ioreq_server),
        [XEN_DMOP_get_ioreq_server_info]            = sizeof(struct xen_dm_op_get_ioreq_server_info),
        [XEN_DMOP_map_io_range_to_ioreq_server]     = sizeof(struct xen_dm_op_ioreq_server_range),
        [XEN_DMOP_unmap_io_range_from_ioreq_server] = sizeof(struct xen_dm_op_ioreq_server_range),
        [XEN_DMOP_set_ioreq_server_state]           = sizeof(struct xen_dm_op_set_ioreq_server_state),
        [XEN_DMOP_destroy_ioreq_server]             = sizeof(struct xen_dm_op_destroy_ioreq_server),
        [XEN_DMOP_track_dirty_vram]                 = sizeof(struct xen_dm_op_track_dirty_vram),
        [XEN_DMOP_set_pci_intx_level]               = sizeof(struct xen_dm_op_set_pci_intx_level),
        [XEN_DMOP_set_isa_irq_level]                = sizeof(struct xen_dm_op_set_isa_irq_level),
        [XEN_DMOP_set_pci_link_route]               = sizeof(struct xen_dm_op_set_pci_link_route),
        [XEN_DMOP_modified_memory]                  = sizeof(struct xen_dm_op_modified_memory),
        [XEN_DMOP_set_mem_type]                     = sizeof(struct xen_dm_op_set_mem_type),
        [XEN_DMOP_inject_event]                     = sizeof(struct xen_dm_op_inject_event),
        [XEN_DMOP_inject_msi]                       = sizeof(struct xen_dm_op_inject_msi),
        [XEN_DMOP_map_mem_type_to_ioreq_server]     = sizeof(struct xen_dm_op_map_mem_type_to_ioreq_server),
        [XEN_DMOP_remote_shutdown]                  = sizeof(struct xen_dm_op_remote_shutdown),
        [XEN_DMOP_relocate_memory]                  = sizeof(struct xen_dm_op_relocate_memory),
        [XEN_DMOP_pin_memory_cacheattr]             = sizeof(struct xen_dm_op_pin_memory_cacheattr),
        [XEN_DMOP_set_irq_level]                    = sizeof(struct xen_dm_op_set_irq_level),
    };

    rc = rcu_lock_remote_domain_by_id(op_args->domid, &d);
    if ( rc )
        return rc;

    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_dm_op(XSM_DM_PRIV, d);
    if ( rc )
        goto out;

    rc = -EFAULT;
    if ( op_args->buf[0].size < offset )
        goto out;

    if ( copy_from_guest_offset((void *)&op, op_args->buf[0].h, 0, offset) )
        goto out;

    if ( op.op >= ARRAY_SIZE(op_size) )
    {
        rc = -EOPNOTSUPP;
        goto out;
    }

    op.op = array_index_nospec(op.op, ARRAY_SIZE(op_size));

    if ( op_args->buf[0].size < offset + op_size[op.op] )
        goto out;

    if ( copy_from_guest_offset((void *)&op.u, op_args->buf[0].h, offset,
                                op_size[op.op]) )
        goto out;

    rc = -EINVAL;
    if ( op.pad )
        goto out;

    switch ( op.op )
    {
    case XEN_DMOP_create_ioreq_server:
    {
        struct xen_dm_op_create_ioreq_server *data =
            &op.u.create_ioreq_server;

        const_op = false;

        rc = -EINVAL;
        if ( data->pad[0] || data->pad[1] || data->pad[2] )
            break;

        rc = hvm_create_ioreq_server(d, data->handle_bufioreq,
                                     &data->id);
        break;
    }

    case XEN_DMOP_get_ioreq_server_info:
    {
        struct xen_dm_op_get_ioreq_server_info *data =
            &op.u.get_ioreq_server_info;
        const uint16_t valid_flags = XEN_DMOP_no_gfns;

        const_op = false;

        rc = -EINVAL;
        if ( data->flags & ~valid_flags )
            break;

        rc = hvm_get_ioreq_server_info(d, data->id,
                                       (data->flags & XEN_DMOP_no_gfns) ?
                                       NULL : &data->ioreq_gfn,
                                       (data->flags & XEN_DMOP_no_gfns) ?
                                       NULL : &data->bufioreq_gfn,
                                       &data->bufioreq_port);
        break;
    }

    case XEN_DMOP_map_io_range_to_ioreq_server:
    {
        const struct xen_dm_op_ioreq_server_range *data =
            &op.u.map_io_range_to_ioreq_server;

        rc = -EINVAL;
        if ( data->pad )
            break;

        rc = hvm_map_io_range_to_ioreq_server(d, data->id, data->type,
                                              data->start, data->end);
        break;
    }

    case XEN_DMOP_unmap_io_range_from_ioreq_server:
    {
        const struct xen_dm_op_ioreq_server_range *data =
            &op.u.unmap_io_range_from_ioreq_server;

        rc = -EINVAL;
        if ( data->pad )
            break;

        rc = hvm_unmap_io_range_from_ioreq_server(d, data->id, data->type,
                                                  data->start, data->end);
        break;
    }

    case XEN_DMOP_set_ioreq_server_state:
    {
        const struct xen_dm_op_set_ioreq_server_state *data =
            &op.u.set_ioreq_server_state;

        rc = -EINVAL;
        if ( data->pad )
            break;

        rc = hvm_set_ioreq_server_state(d, data->id, !!data->enabled);
        break;
    }

    case XEN_DMOP_destroy_ioreq_server:
    {
        const struct xen_dm_op_destroy_ioreq_server *data =
            &op.u.destroy_ioreq_server;

        rc = -EINVAL;
        if ( data->pad )
            break;

        rc = hvm_destroy_ioreq_server(d, data->id);
        break;
    }

    default:
        rc = arch_dm_op(&op, d, op_args, &const_op);
    }

    if ( (!rc || rc == -ERESTART) &&
         !const_op && copy_to_guest_offset(op_args->buf[0].h, offset,
                                           (void *)&op.u, op_size[op.op]) )
        rc = -EFAULT;

 out:
    rcu_unlock_domain(d);

    return rc;
}

#ifdef CONFIG_COMPAT
CHECK_dm_op_create_ioreq_server;
CHECK_dm_op_get_ioreq_server_info;
CHECK_dm_op_ioreq_server_range;
CHECK_dm_op_set_ioreq_server_state;
CHECK_dm_op_destroy_ioreq_server;
CHECK_dm_op_track_dirty_vram;
CHECK_dm_op_set_pci_intx_level;
CHECK_dm_op_set_isa_irq_level;
CHECK_dm_op_set_pci_link_route;
CHECK_dm_op_modified_memory;
CHECK_dm_op_set_mem_type;
CHECK_dm_op_inject_event;
CHECK_dm_op_inject_msi;
CHECK_dm_op_remote_shutdown;
CHECK_dm_op_relocate_memory;
CHECK_dm_op_pin_memory_cacheattr;

int compat_dm_op(domid_t domid,
                 unsigned int nr_bufs,
                 XEN_GUEST_HANDLE_PARAM(void) bufs)
{
    struct dmop_args args;
    unsigned int i;
    int rc;

    if ( nr_bufs > ARRAY_SIZE(args.buf) )
        return -E2BIG;

    args.domid = domid;
    args.nr_bufs = array_index_nospec(nr_bufs, ARRAY_SIZE(args.buf) + 1);

    for ( i = 0; i < args.nr_bufs; i++ )
    {
        struct compat_dm_op_buf cmp;

        if ( copy_from_guest_offset(&cmp, bufs, i, 1) )
            return -EFAULT;

#define XLAT_dm_op_buf_HNDL_h(_d_, _s_) \
        guest_from_compat_handle((_d_)->h, (_s_)->h)

        XLAT_dm_op_buf(&args.buf[i], &cmp);

#undef XLAT_dm_op_buf_HNDL_h
    }

    rc = dm_op(&args);

    if ( rc == -ERESTART )
        rc = hypercall_create_continuation(__HYPERVISOR_dm_op, "iih",
                                           domid, nr_bufs, bufs);

    return rc;
}
#endif

long do_dm_op(domid_t domid,
              unsigned int nr_bufs,
              XEN_GUEST_HANDLE_PARAM(xen_dm_op_buf_t) bufs)
{
    struct dmop_args args;
    int rc;

    if ( nr_bufs > ARRAY_SIZE(args.buf) )
        return -E2BIG;

    args.domid = domid;
    args.nr_bufs = array_index_nospec(nr_bufs, ARRAY_SIZE(args.buf) + 1);

    if ( copy_from_guest_offset(&args.buf[0], bufs, 0, args.nr_bufs) )
        return -EFAULT;

    rc = dm_op(&args);

    if ( rc == -ERESTART )
        rc = hypercall_create_continuation(__HYPERVISOR_dm_op, "iih",
                                           domid, nr_bufs, bufs);

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
