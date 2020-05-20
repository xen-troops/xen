/*
 * Copyright (c) 2007-2008, D G Murray <Derek.Murray@cl.cam.ac.uk>
 * Copyright (c) 2018, Oleksandr Andrushchenko, EPAM Systems Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 * Split out from xc_linux_osdep.c
 */

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include <sys/ioctl.h>
#include <sys/mman.h>

#include <xen/sys/gntdev.h>
#include <xen/sys/gntalloc.h>

#include <xen-tools/libs.h>

#include "private.h"

#define PAGE_SHIFT           12
#define PAGE_SIZE            (1UL << PAGE_SHIFT)
#define PAGE_MASK            (~(PAGE_SIZE-1))

#define DEVXEN "/dev/xen/"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

int osdep_gnttab_open(xengnttab_handle *xgt)
{
    int fd = open(DEVXEN "gntdev", O_RDWR|O_CLOEXEC);
    if ( fd == -1 )
        return -1;
    xgt->fd = fd;
    return 0;
}

int osdep_gnttab_close(xengnttab_handle *xgt)
{
    if ( xgt->fd == -1 )
        return 0;

    return close(xgt->fd);
}

int osdep_gnttab_set_max_grants(xengnttab_handle *xgt, uint32_t count)
{
    int fd = xgt->fd, rc;
    struct ioctl_gntdev_set_max_grants max_grants = { .count = count };

    rc = ioctl(fd, IOCTL_GNTDEV_SET_MAX_GRANTS, &max_grants);
    if (rc) {
        /*
         * Newer (e.g. pv-ops) kernels don't implement this IOCTL,
         * so ignore the resulting specific failure.
         */
        if (errno == ENOTTY)
            rc = 0;
        else
            GTERROR(xgt->logger, "ioctl SET_MAX_GRANTS failed");
    }

    return rc;
}

void *osdep_gnttab_grant_map(xengnttab_handle *xgt,
                             uint32_t count, int flags, int prot,
                             uint32_t *domids, uint32_t *refs,
                             uint32_t notify_offset,
                             evtchn_port_t notify_port)
{
    int fd = xgt->fd;
    struct ioctl_gntdev_map_grant_ref *map;
    unsigned int map_size = ROUNDUP((sizeof(*map) + (count - 1) *
                                    sizeof(struct ioctl_gntdev_map_grant_ref)),
                                    PAGE_SHIFT);
    void *addr = NULL;
    int domids_stride = 1;
    int i;

    if (flags & XENGNTTAB_GRANT_MAP_SINGLE_DOMAIN)
        domids_stride = 0;

    if ( map_size <= PAGE_SIZE )
        map = alloca(sizeof(*map) +
                     (count - 1) * sizeof(struct ioctl_gntdev_map_grant_ref));
    else
    {
        map = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON | MAP_POPULATE, -1, 0);
        if ( map == MAP_FAILED )
        {
            GTERROR(xgt->logger, "mmap of map failed");
            return NULL;
        }
    }

    for ( i = 0; i < count; i++ )
    {
        map->refs[i].domid = domids[i * domids_stride];
        map->refs[i].ref = refs[i];
    }

    map->count = count;

    if ( ioctl(fd, IOCTL_GNTDEV_MAP_GRANT_REF, map) ) {
        GTERROR(xgt->logger, "ioctl MAP_GRANT_REF failed");
        goto out;
    }

 retry:
    addr = mmap(NULL, PAGE_SIZE * count, prot, MAP_SHARED, fd,
                map->index);

    if (addr == MAP_FAILED && errno == EAGAIN)
    {
        /*
         * The grant hypercall can return EAGAIN if the granted page
         * is swapped out. Since the paging daemon may be in the same
         * domain, the hypercall cannot block without causing a
         * deadlock.
         *
         * Because there are no notifications when the page is swapped
         * in, wait a bit before retrying, and hope that the page will
         * arrive eventually.
         */
        usleep(1000);
        goto retry;
    }

    if (addr != MAP_FAILED)
    {
        int rv = 0;
        struct ioctl_gntdev_unmap_notify notify;
        notify.index = map->index;
        notify.action = 0;
        if (notify_offset < PAGE_SIZE * count) {
            notify.index += notify_offset;
            notify.action |= UNMAP_NOTIFY_CLEAR_BYTE;
        }
        if (notify_port != -1) {
            notify.event_channel_port = notify_port;
            notify.action |= UNMAP_NOTIFY_SEND_EVENT;
        }
        if (notify.action)
            rv = ioctl(fd, IOCTL_GNTDEV_SET_UNMAP_NOTIFY, &notify);
        if (rv) {
            GTERROR(xgt->logger, "ioctl SET_UNMAP_NOTIFY failed");
            munmap(addr, count * PAGE_SIZE);
            addr = MAP_FAILED;
        }
    }

    if (addr == MAP_FAILED)
    {
        int saved_errno = errno;
        struct ioctl_gntdev_unmap_grant_ref unmap_grant;

        /* Unmap the driver slots used to store the grant information. */
        GTERROR(xgt->logger, "mmap failed");
        unmap_grant.index = map->index;
        unmap_grant.count = count;
        ioctl(fd, IOCTL_GNTDEV_UNMAP_GRANT_REF, &unmap_grant);
        errno = saved_errno;
        addr = NULL;
    }

 out:
    if ( map_size > PAGE_SIZE )
        munmap(map, map_size);

    return addr;
}

int osdep_gnttab_unmap(xengnttab_handle *xgt,
                       void *start_address,
                       uint32_t count)
{
    int fd = xgt->fd;
    struct ioctl_gntdev_get_offset_for_vaddr get_offset;
    struct ioctl_gntdev_unmap_grant_ref unmap_grant;
    int rc;

    if ( start_address == NULL )
    {
        errno = EINVAL;
        return -1;
    }

    /* First, it is necessary to get the offset which was initially used to
     * mmap() the pages.
     */
    get_offset.vaddr = (unsigned long)start_address;
    if ( (rc = ioctl(fd, IOCTL_GNTDEV_GET_OFFSET_FOR_VADDR,
                     &get_offset)) )
        return rc;

    if ( get_offset.count != count )
    {
        errno = EINVAL;
        return -1;
    }

    /* Next, unmap the memory. */
    if ( (rc = munmap(start_address, count * PAGE_SIZE)) )
        return rc;

    /* Finally, unmap the driver slots used to store the grant information. */
    unmap_grant.index = get_offset.offset;
    unmap_grant.count = count;
    if ( (rc = ioctl(fd, IOCTL_GNTDEV_UNMAP_GRANT_REF, &unmap_grant)) )
        return rc;

    return 0;
}

int osdep_gnttab_grant_copy(xengnttab_handle *xgt,
                            uint32_t count,
                            xengnttab_grant_copy_segment_t *segs)
{
    int rc;
    int fd = xgt->fd;
    struct ioctl_gntdev_grant_copy copy;

    BUILD_BUG_ON(sizeof(struct ioctl_gntdev_grant_copy_segment) !=
                 sizeof(xengnttab_grant_copy_segment_t));

    BUILD_BUG_ON(__alignof__(struct ioctl_gntdev_grant_copy_segment) !=
                 __alignof__(xengnttab_grant_copy_segment_t));

    BUILD_BUG_ON(offsetof(struct ioctl_gntdev_grant_copy_segment,
                          source.virt) !=
                 offsetof(xengnttab_grant_copy_segment_t,
                          source.virt));
    BUILD_BUG_ON(offsetof(struct ioctl_gntdev_grant_copy_segment,
                          source.foreign) !=
                 offsetof(xengnttab_grant_copy_segment_t,
                          source.foreign));
    BUILD_BUG_ON(offsetof(struct ioctl_gntdev_grant_copy_segment,
                          source.foreign.ref) !=
                 offsetof(xengnttab_grant_copy_segment_t,
                          source.foreign));
    BUILD_BUG_ON(offsetof(struct ioctl_gntdev_grant_copy_segment,
                          source.foreign.offset) !=
                 offsetof(xengnttab_grant_copy_segment_t,
                          source.foreign.offset));
    BUILD_BUG_ON(offsetof(struct ioctl_gntdev_grant_copy_segment,
                          source.foreign.domid) !=
                 offsetof(xengnttab_grant_copy_segment_t,
                          source.foreign.domid));

    BUILD_BUG_ON(offsetof(struct ioctl_gntdev_grant_copy_segment,
                          dest.virt) !=
                 offsetof(xengnttab_grant_copy_segment_t,
                          dest.virt));
    BUILD_BUG_ON(offsetof(struct ioctl_gntdev_grant_copy_segment,
                          dest.foreign) !=
                 offsetof(xengnttab_grant_copy_segment_t,
                          dest.foreign));
    BUILD_BUG_ON(offsetof(struct ioctl_gntdev_grant_copy_segment,
                          dest.foreign.ref) !=
                 offsetof(xengnttab_grant_copy_segment_t,
                          dest.foreign));
    BUILD_BUG_ON(offsetof(struct ioctl_gntdev_grant_copy_segment,
                          dest.foreign.offset) !=
                 offsetof(xengnttab_grant_copy_segment_t,
                          dest.foreign.offset));
    BUILD_BUG_ON(offsetof(struct ioctl_gntdev_grant_copy_segment,
                          dest.foreign.domid) !=
                 offsetof(xengnttab_grant_copy_segment_t,
                          dest.foreign.domid));

    BUILD_BUG_ON(offsetof(struct ioctl_gntdev_grant_copy_segment,
                          len) !=
                 offsetof(xengnttab_grant_copy_segment_t, len));
    BUILD_BUG_ON(offsetof(struct ioctl_gntdev_grant_copy_segment,
                          flags) !=
                 offsetof(xengnttab_grant_copy_segment_t, flags));
    BUILD_BUG_ON(offsetof(struct ioctl_gntdev_grant_copy_segment,
                          status) !=
                 offsetof(xengnttab_grant_copy_segment_t, status));

    copy.segments = (struct ioctl_gntdev_grant_copy_segment *)segs;
    copy.count = count;

    rc = ioctl(fd, IOCTL_GNTDEV_GRANT_COPY, &copy);
    if (rc)
        GTERROR(xgt->logger, "ioctl GRANT COPY failed %d ", errno);

    return rc;
}

int osdep_gnttab_dmabuf_exp_from_refs(xengnttab_handle *xgt, uint32_t domid,
                                      uint32_t flags, uint32_t count,
                                      const uint32_t *refs,
                                      uint32_t *dmabuf_fd)
{
    struct ioctl_gntdev_dmabuf_exp_from_refs *from_refs = NULL;
    int rc = -1;

    if ( !count )
    {
        errno = EINVAL;
        goto out;
    }

    from_refs = malloc(sizeof(*from_refs) +
                       (count - 1) * sizeof(from_refs->refs[0]));
    if ( !from_refs )
    {
        errno = ENOMEM;
        goto out;
    }

    from_refs->flags = flags;
    from_refs->count = count;
    from_refs->domid = domid;

    memcpy(from_refs->refs, refs, count * sizeof(from_refs->refs[0]));

    if ( (rc = ioctl(xgt->fd, IOCTL_GNTDEV_DMABUF_EXP_FROM_REFS, from_refs)) )
    {
        GTERROR(xgt->logger, "ioctl DMABUF_EXP_FROM_REFS failed");
        goto out;
    }

    *dmabuf_fd = from_refs->fd;
    rc = 0;

out:
    free(from_refs);
    return rc;
}

int osdep_gnttab_dmabuf_exp_from_refs_v2(xengnttab_handle *xgt, uint32_t domid,
                                         uint32_t flags, uint32_t count,
                                         const uint32_t *refs,
                                         uint32_t *dmabuf_fd,
                                         uint32_t data_ofs)
{
    struct ioctl_gntdev_dmabuf_exp_from_refs_v2 *from_refs_v2 = NULL;
    int rc = -1;

    if ( !count )
    {
        errno = EINVAL;
        goto out;
    }

    from_refs_v2 = malloc(sizeof(*from_refs_v2) +
                          (count - 1) * sizeof(from_refs_v2->refs[0]));
    if ( !from_refs_v2 )
    {
        errno = ENOMEM;
        goto out;
    }

    from_refs_v2->flags = flags;
    from_refs_v2->count = count;
    from_refs_v2->domid = domid;
    from_refs_v2->data_ofs = data_ofs;

    memcpy(from_refs_v2->refs, refs, count * sizeof(from_refs_v2->refs[0]));

    if ( (rc = ioctl(xgt->fd, IOCTL_GNTDEV_DMABUF_EXP_FROM_REFS_V2,
                     from_refs_v2)) )
    {
        GTERROR(xgt->logger, "ioctl DMABUF_EXP_FROM_REFS_V2 failed");
        goto out;
    }

    *dmabuf_fd = from_refs_v2->fd;
    rc = 0;

out:
    free(from_refs_v2);
    return rc;
}

int osdep_gnttab_dmabuf_exp_wait_released(xengnttab_handle *xgt,
                                          uint32_t fd, uint32_t wait_to_ms)
{
    struct ioctl_gntdev_dmabuf_exp_wait_released wait;
    int rc;

    wait.fd = fd;
    wait.wait_to_ms = wait_to_ms;

    if ( (rc = ioctl(xgt->fd, IOCTL_GNTDEV_DMABUF_EXP_WAIT_RELEASED, &wait)) )
    {
        if ( errno == ENOENT )
        {
            /* The buffer may have already been released. */
            errno = 0;
            rc = 0;
        } else
            GTERROR(xgt->logger, "ioctl DMABUF_EXP_WAIT_RELEASED failed");
    }

    return rc;
}

int osdep_gnttab_dmabuf_imp_to_refs(xengnttab_handle *xgt, uint32_t domid,
                                    uint32_t fd, uint32_t count, uint32_t *refs)
{
    struct ioctl_gntdev_dmabuf_imp_to_refs *to_refs = NULL;
    int rc = -1;

    if ( !count )
    {
        errno = EINVAL;
        goto out;
    }

    to_refs = malloc(sizeof(*to_refs) +
                     (count - 1) * sizeof(to_refs->refs[0]));
    if ( !to_refs )
    {
        errno = ENOMEM;
        goto out;
    }

    to_refs->fd = fd;
    to_refs->count = count;
    to_refs->domid = domid;

    if ( (rc = ioctl(xgt->fd, IOCTL_GNTDEV_DMABUF_IMP_TO_REFS, to_refs)) )
    {
        GTERROR(xgt->logger, "ioctl DMABUF_IMP_TO_REFS failed");
        goto out;
    }

    memcpy(refs, to_refs->refs, count * sizeof(*refs));
    rc = 0;

out:
    free(to_refs);
    return rc;
}

int osdep_gnttab_dmabuf_imp_to_refs_v2(xengnttab_handle *xgt, uint32_t domid,
                                       uint32_t fd, uint32_t count,
                                       uint32_t *refs,
                                       uint32_t *data_ofs)
{
    struct ioctl_gntdev_dmabuf_imp_to_refs_v2 *to_refs_v2 = NULL;
    int rc = -1;

    if ( !count )
    {
        errno = EINVAL;
        goto out;
    }

    to_refs_v2 = malloc(sizeof(*to_refs_v2) +
                        (count - 1) * sizeof(to_refs_v2->refs[0]));
    if ( !to_refs_v2 )
    {
        errno = ENOMEM;
        goto out;
    }

    to_refs_v2->fd = fd;
    to_refs_v2->count = count;
    to_refs_v2->domid = domid;

    if ( (rc = ioctl(xgt->fd, IOCTL_GNTDEV_DMABUF_IMP_TO_REFS_V2, to_refs_v2)) )
    {
        GTERROR(xgt->logger, "ioctl DMABUF_IMP_TO_REFS_V2 failed");
        goto out;
    }

    memcpy(refs, to_refs_v2->refs, count * sizeof(*refs));
    *data_ofs = to_refs_v2->data_ofs;
    rc = 0;

out:
    free(to_refs_v2);
    return rc;
}

int osdep_gnttab_dmabuf_imp_release(xengnttab_handle *xgt, uint32_t fd)
{
    struct ioctl_gntdev_dmabuf_imp_release release;
    int rc;

    release.fd = fd;

    if ( (rc = ioctl(xgt->fd, IOCTL_GNTDEV_DMABUF_IMP_RELEASE, &release)) )
        GTERROR(xgt->logger, "ioctl DMABUF_IMP_RELEASE failed");

    return rc;
}

int osdep_gntshr_open(xengntshr_handle *xgs)
{
    int fd = open(DEVXEN "gntalloc", O_RDWR);
    if ( fd == -1 )
        return -1;
    xgs->fd = fd;
    return 0;
}

int osdep_gntshr_close(xengntshr_handle *xgs)
{
    if ( xgs->fd == -1 )
        return 0;

    return close(xgs->fd);
}

void *osdep_gntshr_share_pages(xengntshr_handle *xgs,
                               uint32_t domid, int count,
                               uint32_t *refs, int writable,
                               uint32_t notify_offset,
                               evtchn_port_t notify_port)
{
    struct ioctl_gntalloc_alloc_gref *gref_info = NULL;
    struct ioctl_gntalloc_unmap_notify notify;
    struct ioctl_gntalloc_dealloc_gref gref_drop;
    int fd = xgs->fd;
    int err;
    void *area = NULL;
    gref_info = malloc(sizeof(*gref_info) + count * sizeof(uint32_t));
    if (!gref_info)
        return NULL;
    gref_info->domid = domid;
    gref_info->flags = writable ? GNTALLOC_FLAG_WRITABLE : 0;
    gref_info->count = count;

    err = ioctl(fd, IOCTL_GNTALLOC_ALLOC_GREF, gref_info);
    if (err) {
        GSERROR(xgs->logger, "ioctl failed");
        goto out;
    }

    area = mmap(NULL, count * PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, fd, gref_info->index);

    if (area == MAP_FAILED) {
        area = NULL;
        GSERROR(xgs->logger, "mmap failed");
        goto out_remove_fdmap;
    }

    notify.index = gref_info->index;
    notify.action = 0;
    if (notify_offset < PAGE_SIZE * count) {
        notify.index += notify_offset;
        notify.action |= UNMAP_NOTIFY_CLEAR_BYTE;
    }
    if (notify_port != -1) {
        notify.event_channel_port = notify_port;
        notify.action |= UNMAP_NOTIFY_SEND_EVENT;
    }
    if (notify.action)
        err = ioctl(fd, IOCTL_GNTALLOC_SET_UNMAP_NOTIFY, &notify);
    if (err) {
        GSERROR(xgs->logger, "ioctl SET_UNMAP_NOTIFY failed");
        munmap(area, count * PAGE_SIZE);
        area = NULL;
    }

    memcpy(refs, gref_info->gref_ids, count * sizeof(uint32_t));

 out_remove_fdmap:
    /* Removing the mapping from the file descriptor does not cause the pages to
     * be deallocated until the mapping is removed.
     */
    gref_drop.index = gref_info->index;
    gref_drop.count = count;
    ioctl(fd, IOCTL_GNTALLOC_DEALLOC_GREF, &gref_drop);
 out:
    free(gref_info);
    return area;
}

int osdep_gntshr_unshare(xengntshr_handle *xgs,
                         void *start_address, uint32_t count)
{
    return munmap(start_address, count * PAGE_SIZE);
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
