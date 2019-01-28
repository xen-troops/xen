/*
 * hvm/io.c: hardware virtual machine I/O emulation
 *
 * Copyright (c) 2016 Citrix Systems Inc.
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
#include <xen/hvm/ioreq.h>

static void set_ioreq_server(struct domain *d, unsigned int id,
                             struct hvm_ioreq_server *s)
{
    ASSERT(id < MAX_NR_IOREQ_SERVERS);
    ASSERT(!s || !d->arch.hvm.ioreq_server.server[id]);

    d->arch.hvm.ioreq_server.server[id] = s;
}

struct hvm_ioreq_server *get_ioreq_server(const struct domain *d,
                                          unsigned int id)
{
    if ( id >= MAX_NR_IOREQ_SERVERS )
        return NULL;

    return GET_IOREQ_SERVER(d, id);
}

static int hvm_ioreq_server_add_vcpu(struct hvm_ioreq_server *s,
                                     struct vcpu *v)
{
    struct hvm_ioreq_vcpu *sv;
    int rc;

    sv = xzalloc(struct hvm_ioreq_vcpu);

    rc = -ENOMEM;
    if ( !sv )
        goto fail1;

    spin_lock(&s->lock);

    rc = alloc_unbound_xen_event_channel(v->domain, v->vcpu_id,
                                         s->emulator->domain_id, NULL);
    if ( rc < 0 )
        goto fail2;

    sv->ioreq_evtchn = rc;

    if ( v->vcpu_id == 0 && HANDLE_BUFIOREQ(s) )
    {
        rc = alloc_unbound_xen_event_channel(v->domain, 0,
                                             s->emulator->domain_id, NULL);
        if ( rc < 0 )
            goto fail3;

        s->bufioreq_evtchn = rc;
    }

    sv->vcpu = v;

    list_add(&sv->list_entry, &s->ioreq_vcpu_list);

    if ( s->enabled )
        hvm_update_ioreq_evtchn(s, sv);

    spin_unlock(&s->lock);
    return 0;

 fail3:
    free_xen_event_channel(v->domain, sv->ioreq_evtchn);

 fail2:
    spin_unlock(&s->lock);
    xfree(sv);

 fail1:
    return rc;
}

static void hvm_ioreq_server_remove_vcpu(struct hvm_ioreq_server *s,
                                         struct vcpu *v)
{
    struct hvm_ioreq_vcpu *sv;

    spin_lock(&s->lock);

    list_for_each_entry ( sv,
                          &s->ioreq_vcpu_list,
                          list_entry )
    {
        if ( sv->vcpu != v )
            continue;

        list_del(&sv->list_entry);

        if ( v->vcpu_id == 0 && HANDLE_BUFIOREQ(s) )
            free_xen_event_channel(v->domain, s->bufioreq_evtchn);

        free_xen_event_channel(v->domain, sv->ioreq_evtchn);

        xfree(sv);
        break;
    }

    spin_unlock(&s->lock);
}

static void hvm_ioreq_server_remove_all_vcpus(struct hvm_ioreq_server *s)
{
    struct hvm_ioreq_vcpu *sv, *next;

    spin_lock(&s->lock);

    list_for_each_entry_safe ( sv,
                               next,
                               &s->ioreq_vcpu_list,
                               list_entry )
    {
        struct vcpu *v = sv->vcpu;

        list_del(&sv->list_entry);

        if ( v->vcpu_id == 0 && HANDLE_BUFIOREQ(s) )
            free_xen_event_channel(v->domain, s->bufioreq_evtchn);

        free_xen_event_channel(v->domain, sv->ioreq_evtchn);

        xfree(sv);
    }

    spin_unlock(&s->lock);
}

static int hvm_ioreq_server_map_pages(struct hvm_ioreq_server *s)
{
    int rc;

    rc = hvm_map_ioreq_gfn(s, false);

    if ( !rc && HANDLE_BUFIOREQ(s) )
        rc = hvm_map_ioreq_gfn(s, true);

    if ( rc )
        hvm_unmap_ioreq_gfn(s, false);

    return rc;
}

static void hvm_ioreq_server_unmap_pages(struct hvm_ioreq_server *s)
{
    hvm_unmap_ioreq_gfn(s, true);
    hvm_unmap_ioreq_gfn(s, false);
}

static int hvm_ioreq_server_alloc_pages(struct hvm_ioreq_server *s)
{
    int rc;

    rc = hvm_alloc_ioreq_mfn(s, false);

    if ( !rc && (s->bufioreq_handling != HVM_IOREQSRV_BUFIOREQ_OFF) )
        rc = hvm_alloc_ioreq_mfn(s, true);

    if ( rc )
        hvm_free_ioreq_mfn(s, false);

    return rc;
}

static void hvm_ioreq_server_free_pages(struct hvm_ioreq_server *s)
{
    hvm_free_ioreq_mfn(s, true);
    hvm_free_ioreq_mfn(s, false);
}

static void hvm_ioreq_server_free_rangesets(struct hvm_ioreq_server *s)
{
    unsigned int i;

    for ( i = 0; i < NR_IO_RANGE_TYPES; i++ )
        rangeset_destroy(s->range[i]);
}


static void hvm_ioreq_server_enable(struct hvm_ioreq_server *s)
{
    struct hvm_ioreq_vcpu *sv;

    spin_lock(&s->lock);

    if ( s->enabled )
        goto done;

    hvm_remove_ioreq_gfn(s, false);
    hvm_remove_ioreq_gfn(s, true);

    s->enabled = true;

    list_for_each_entry ( sv,
                          &s->ioreq_vcpu_list,
                          list_entry )
        hvm_update_ioreq_evtchn(s, sv);

  done:
    spin_unlock(&s->lock);
}

static void hvm_ioreq_server_disable(struct hvm_ioreq_server *s)
{
    spin_lock(&s->lock);

    if ( !s->enabled )
        goto done;

    hvm_add_ioreq_gfn(s, true);
    hvm_add_ioreq_gfn(s, false);

    s->enabled = false;

 done:
    spin_unlock(&s->lock);
}

static int hvm_ioreq_server_init(struct hvm_ioreq_server *s,
                                 struct domain *d, int bufioreq_handling,
                                 ioservid_t id)
{
    struct domain *currd = current->domain;
    struct vcpu *v;
    int rc;

    s->target = d;

    get_knownalive_domain(currd);
    s->emulator = currd;

    spin_lock_init(&s->lock);
    INIT_LIST_HEAD(&s->ioreq_vcpu_list);
    spin_lock_init(&s->bufioreq_lock);

    s->ioreq.gfn = INVALID_GFN;
    s->bufioreq.gfn = INVALID_GFN;

    rc = hvm_ioreq_server_alloc_rangesets(s, id);
    if ( rc )
        return rc;

    s->bufioreq_handling = bufioreq_handling;

    for_each_vcpu ( d, v )
    {
        rc = hvm_ioreq_server_add_vcpu(s, v);
        if ( rc )
            goto fail_add;
    }

    return 0;

 fail_add:
    hvm_ioreq_server_remove_all_vcpus(s);
    hvm_ioreq_server_unmap_pages(s);

    hvm_ioreq_server_free_rangesets(s);

    put_domain(s->emulator);
    return rc;
}

static void hvm_ioreq_server_deinit(struct hvm_ioreq_server *s)
{
    ASSERT(!s->enabled);
    hvm_ioreq_server_remove_all_vcpus(s);

    /*
     * NOTE: It is safe to call both hvm_ioreq_server_unmap_pages() and
     *       hvm_ioreq_server_free_pages() in that order.
     *       This is because the former will do nothing if the pages
     *       are not mapped, leaving the page to be freed by the latter.
     *       However if the pages are mapped then the former will set
     *       the page_info pointer to NULL, meaning the latter will do
     *       nothing.
     */
    hvm_ioreq_server_unmap_pages(s);
    hvm_ioreq_server_free_pages(s);

    hvm_ioreq_server_free_rangesets(s);

    put_domain(s->emulator);
}


int hvm_create_ioreq_server(struct domain *d, int bufioreq_handling,
                            ioservid_t *id)
{
    struct hvm_ioreq_server *s;
    unsigned int i;
    int rc;

    if ( bufioreq_handling > HVM_IOREQSRV_BUFIOREQ_ATOMIC )
        return -EINVAL;

    s = xzalloc(struct hvm_ioreq_server);
    if ( !s )
        return -ENOMEM;

    domain_pause(d);
    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    for ( i = 0; i < MAX_NR_IOREQ_SERVERS; i++ )
    {
        if ( !GET_IOREQ_SERVER(d, i) )
            break;
    }

    rc = -ENOSPC;
    if ( i >= MAX_NR_IOREQ_SERVERS )
        goto fail;

    /*
     * It is safe to call set_ioreq_server() prior to
     * hvm_ioreq_server_init() since the target domain is paused.
     */
    set_ioreq_server(d, i, s);

    rc = hvm_ioreq_server_init(s, d, bufioreq_handling, i);
    if ( rc )
    {
        set_ioreq_server(d, i, NULL);
        goto fail;
    }

    if ( id )
        *id = i;

    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);
    domain_unpause(d);

    return 0;

 fail:
    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);
    domain_unpause(d);

    xfree(s);
    return rc;
}

int hvm_destroy_ioreq_server(struct domain *d, ioservid_t id)
{
    struct hvm_ioreq_server *s;
    int rc;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    domain_pause(d);

    p2m_set_ioreq_server(d, 0, s);

    hvm_ioreq_server_disable(s);

    /*
     * It is safe to call hvm_ioreq_server_deinit() prior to
     * set_ioreq_server() since the target domain is paused.
     */
    hvm_ioreq_server_deinit(s);
    set_ioreq_server(d, id, NULL);

    domain_unpause(d);

    xfree(s);

    rc = 0;

 out:
    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);

    return rc;
}

int hvm_get_ioreq_server_info(struct domain *d, ioservid_t id,
                              unsigned long *ioreq_gfn,
                              unsigned long *bufioreq_gfn,
                              evtchn_port_t *bufioreq_port)
{
    struct hvm_ioreq_server *s;
    int rc;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    if ( ioreq_gfn || bufioreq_gfn )
    {
        rc = hvm_ioreq_server_map_pages(s);
        if ( rc )
            goto out;
    }

    if ( ioreq_gfn )
        *ioreq_gfn = gfn_x(s->ioreq.gfn);

    if ( HANDLE_BUFIOREQ(s) )
    {
        if ( bufioreq_gfn )
            *bufioreq_gfn = gfn_x(s->bufioreq.gfn);

        if ( bufioreq_port )
            *bufioreq_port = s->bufioreq_evtchn;
    }

    rc = 0;

 out:
    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);

    return rc;
}


int hvm_get_ioreq_server_frame(struct domain *d, ioservid_t id,
                               unsigned long idx, mfn_t *mfn)
{
    struct hvm_ioreq_server *s;
    int rc;

    ASSERT(is_hvm_domain(d));

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    rc = hvm_ioreq_server_alloc_pages(s);
    if ( rc )
        goto out;

    switch ( idx )
    {
    case XENMEM_resource_ioreq_server_frame_bufioreq:
        rc = -ENOENT;
        if ( !HANDLE_BUFIOREQ(s) )
            goto out;

        *mfn = page_to_mfn(s->bufioreq.page);
        rc = 0;
        break;

    case XENMEM_resource_ioreq_server_frame_ioreq(0):
        *mfn = page_to_mfn(s->ioreq.page);
        rc = 0;
        break;

    default:
        rc = -EINVAL;
        break;
    }

 out:
    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);

    return rc;
}

int hvm_map_io_range_to_ioreq_server(struct domain *d, ioservid_t id,
                                     uint32_t type, uint64_t start,
                                     uint64_t end)
{
    struct hvm_ioreq_server *s;
    struct rangeset *r;
    int rc;

    if ( start > end )
        return -EINVAL;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    switch ( type )
    {
    case XEN_DMOP_IO_RANGE_PORT:
    case XEN_DMOP_IO_RANGE_MEMORY:
    case XEN_DMOP_IO_RANGE_PCI:
        r = s->range[type];
        break;

    default:
        r = NULL;
        break;
    }

    rc = -EINVAL;
    if ( !r )
        goto out;

    rc = -EEXIST;
    if ( rangeset_overlaps_range(r, start, end) )
        goto out;

    rc = rangeset_add_range(r, start, end);

 out:
    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);

    return rc;
}

int hvm_unmap_io_range_from_ioreq_server(struct domain *d, ioservid_t id,
                                         uint32_t type, uint64_t start,
                                         uint64_t end)
{
    struct hvm_ioreq_server *s;
    struct rangeset *r;
    int rc;

    if ( start > end )
        return -EINVAL;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    switch ( type )
    {
    case XEN_DMOP_IO_RANGE_PORT:
    case XEN_DMOP_IO_RANGE_MEMORY:
    case XEN_DMOP_IO_RANGE_PCI:
        r = s->range[type];
        break;

    default:
        r = NULL;
        break;
    }

    rc = -EINVAL;
    if ( !r )
        goto out;

    rc = -ENOENT;
    if ( !rangeset_contains_range(r, start, end) )
        goto out;

    rc = rangeset_remove_range(r, start, end);

 out:
    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);

    return rc;
}
int hvm_set_ioreq_server_state(struct domain *d, ioservid_t id,
                               bool enabled)
{
    struct hvm_ioreq_server *s;
    int rc;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    domain_pause(d);

    if ( enabled )
        hvm_ioreq_server_enable(s);
    else
        hvm_ioreq_server_disable(s);

    domain_unpause(d);

    rc = 0;

 out:
    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);
    return rc;
}

int hvm_all_ioreq_servers_add_vcpu(struct domain *d, struct vcpu *v)
{
    struct hvm_ioreq_server *s;
    unsigned int id;
    int rc;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    FOR_EACH_IOREQ_SERVER(d, id, s)
    {
        rc = hvm_ioreq_server_add_vcpu(s, v);
        if ( rc )
            goto fail;
    }

    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);

    return 0;

 fail:
    while ( id-- != 0 )
    {
        s = GET_IOREQ_SERVER(d, id);

        if ( !s )
            continue;

        hvm_ioreq_server_remove_vcpu(s, v);
    }

    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);

    return rc;
}


void hvm_all_ioreq_servers_remove_vcpu(struct domain *d, struct vcpu *v)
{
    struct hvm_ioreq_server *s;
    unsigned int id;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    FOR_EACH_IOREQ_SERVER(d, id, s)
        hvm_ioreq_server_remove_vcpu(s, v);

    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);
}

void hvm_destroy_all_ioreq_servers(struct domain *d)
{
    struct hvm_ioreq_server *s;
    unsigned int id;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    /* No need to domain_pause() as the domain is being torn down */

    FOR_EACH_IOREQ_SERVER(d, id, s)
    {
        hvm_ioreq_server_disable(s);

        /*
         * It is safe to call hvm_ioreq_server_deinit() prior to
         * set_ioreq_server() since the target domain is being destroyed.
         */
        hvm_ioreq_server_deinit(s);
        set_ioreq_server(d, id, NULL);

        xfree(s);
    }

    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);
}


void hvm_ioreq_init(struct domain *d)
{
    spin_lock_init(&d->arch.hvm.ioreq_server.lock);

    arch_hvm_ioreq_init(d);
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
