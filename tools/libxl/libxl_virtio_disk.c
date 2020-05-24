/*
 * Copyright (C) 2020 EPAM Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_internal.h"

static int libxl__device_virtio_disk_setdefault(libxl__gc *gc, uint32_t domid,
                                                libxl_device_virtio_disk *virtio_disk,
                                                bool hotplug)
{
    return libxl__resolve_domid(gc, virtio_disk->backend_domname,
                                &virtio_disk->backend_domid);
}

static int libxl__virtio_disk_from_xenstore(libxl__gc *gc, const char *libxl_path,
                                            libxl_devid devid,
                                            libxl_device_virtio_disk *virtio_disk)
{
    const char *be_path;
    int rc;

    virtio_disk->devid = devid;
    rc = libxl__xs_read_mandatory(gc, XBT_NULL,
                                  GCSPRINTF("%s/backend", libxl_path),
                                  &be_path);
    if (rc) return rc;

    rc = libxl__backendpath_parse_domid(gc, be_path, &virtio_disk->backend_domid);
    if (rc) return rc;

    return 0;
}

static void libxl__update_config_virtio_disk(libxl__gc *gc,
                                             libxl_device_virtio_disk *dst,
                                             libxl_device_virtio_disk *src)
{
    dst->devid = src->devid;
}

static int libxl_device_virtio_disk_compare(libxl_device_virtio_disk *d1,
                                            libxl_device_virtio_disk *d2)
{
    return COMPARE_DEVID(d1, d2);
}

static void libxl__device_virtio_disk_add(libxl__egc *egc, uint32_t domid,
                                          libxl_device_virtio_disk *virtio_disk,
                                          libxl__ao_device *aodev)
{
    libxl__device_add_async(egc, domid, &libxl__virtio_disk_devtype, virtio_disk, aodev);
}

static int libxl__set_xenstore_virtio_disk(libxl__gc *gc, uint32_t domid,
                                           libxl_device_virtio_disk *virtio_disk,
                                           flexarray_t *back, flexarray_t *front,
                                           flexarray_t *ro_front)
{
    int rc;
    unsigned int i;

    for (i = 0; i < virtio_disk->num_disks; i++) {
        rc = flexarray_append_pair(ro_front, GCSPRINTF("%d/filename", i),
                                   GCSPRINTF("%s", virtio_disk->disks[i].filename));
        if (rc) return rc;

        rc = flexarray_append_pair(ro_front, GCSPRINTF("%d/readonly", i),
                                   GCSPRINTF("%d", virtio_disk->disks[i].readonly));
        if (rc) return rc;

        rc = flexarray_append_pair(ro_front, GCSPRINTF("%d/base", i),
                                   GCSPRINTF("%lu", virtio_disk->disks[i].base));
        if (rc) return rc;

        rc = flexarray_append_pair(ro_front, GCSPRINTF("%d/irq", i),
                                   GCSPRINTF("%u", virtio_disk->disks[i].irq));
        if (rc) return rc;
    }

    return 0;
}

static LIBXL_DEFINE_UPDATE_DEVID(virtio_disk)
static LIBXL_DEFINE_DEVICE_FROM_TYPE(virtio_disk)
static LIBXL_DEFINE_DEVICES_ADD(virtio_disk)

DEFINE_DEVICE_TYPE_STRUCT(virtio_disk, VIRTIO_DISK,
    .update_config = (device_update_config_fn_t) libxl__update_config_virtio_disk,
    .from_xenstore = (device_from_xenstore_fn_t) libxl__virtio_disk_from_xenstore,
    .set_xenstore_config = (device_set_xenstore_config_fn_t) libxl__set_xenstore_virtio_disk
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
