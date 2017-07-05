/*
 * Copyright (C) 2016 EPAM Systems Inc.
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

static int libxl__device_vkbd_setdefault(libxl__gc *gc, uint32_t domid,
                                         libxl_device_vkbd *vkbd)
{
    int rc;

    rc = libxl__resolve_domid(gc, vkbd->backend_domname, &vkbd->backend_domid);

    if (vkbd->devid == -1) {
        vkbd->devid = libxl__device_nextid(gc, domid, "vkbd");
    }

    return rc;
}

static int libxl__device_from_vkbd(libxl__gc *gc, uint32_t domid,
                                   libxl_device_vkbd *vkbd,
                                   libxl__device *device)
{
    device->backend_devid = vkbd->devid;
    device->backend_domid = vkbd->backend_domid;
    device->backend_kind = LIBXL__DEVICE_KIND_VKBD;
    device->devid = vkbd->devid;
    device->domid = domid;
    device->kind = LIBXL__DEVICE_KIND_VKBD;

    return 0;
}

static void libxl__device_vkbd_add(libxl__egc *egc, uint32_t domid,
                                   libxl_device_vkbd *vkbd,
                                   libxl__ao_device *aodev)
{
    libxl__device_add_async(egc, domid, &libxl__vkbd_devtype, vkbd, aodev);
}

static int libxl__set_xenstore_vkbd(libxl__gc *gc, uint32_t domid,
                                      libxl_device_vkbd *vkbd)
{
    flexarray_t *front;
    flexarray_t *back;

    front = flexarray_make(gc, 16, 1);
    back = flexarray_make(gc, 16, 1);

    flexarray_append(back, "frontend-id");
    flexarray_append(back, GCSPRINTF("%d", domid));
    flexarray_append(back, "online");
    flexarray_append(back, "1");
    flexarray_append(back, "state");
    flexarray_append(back, GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append(back, "handle");
    flexarray_append(back, GCSPRINTF("%d", vkbd->devid));

    flexarray_append(front, "backend-id");
    flexarray_append(front, GCSPRINTF("%d", vkbd->backend_domid));
    flexarray_append(front, "state");
    flexarray_append(front, GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append(front, "handle");
    flexarray_append(front, GCSPRINTF("%d", vkbd->devid));

    libxl__device *device;
    xs_transaction_t t = XBT_NULL;
    int rc;

    GCNEW(device);

    rc = libxl__device_from_vkbd(gc, domid, vkbd, device);
    if (rc) goto out;

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        rc = libxl__device_generic_add(gc, t, device,
                                       libxl__xs_kvs_of_flexarray(gc, back),
                                       libxl__xs_kvs_of_flexarray(gc, front),
                                       NULL);
        if (rc) goto out;

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc < 0) goto out;
    }

    rc = 0;

out:
    libxl__xs_transaction_abort(gc, &t);
    return rc;
}

static int libxl_device_vkbd_dm_needed(void *e, unsigned domid)
{
    return 1;
}

LIBXL_DEFINE_DEVICE_ADD(vkbd)
LIBXL_DEFINE_DEVICE_REMOVE(vkbd)

#define libxl__add_vkbds NULL
#define libxl_device_vkbd_list NULL
#define libxl_device_vkbd_compare NULL

DEFINE_DEVICE_TYPE_STRUCT(vkbd,
    .set_xenstore_config = (int (*)(libxl__gc *, uint32_t, void *))
                           libxl__set_xenstore_vkbd,
    .dm_needed   = libxl_device_vkbd_dm_needed,
    .skip_attach = 1
);

