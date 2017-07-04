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

int libxl__device_vkbd_setdefault(libxl__gc *gc, libxl_device_vkbd *vkbd)
{
    int rc;
    rc = libxl__resolve_domid(gc, vkbd->backend_domname, &vkbd->backend_domid);
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

int libxl_device_vkbd_add(libxl_ctx *ctx, uint32_t domid,
                          libxl_device_vkbd *vkbd,
                          const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    int rc;

    rc = libxl__device_vkbd_add(gc, domid, vkbd);
    if (rc) {
        LOGD(ERROR, domid, "Unable to add vkbd device");
        goto out;
    }

out:
    libxl__ao_complete(egc, ao, rc);
    return AO_INPROGRESS;
}

int libxl__device_vkbd_add(libxl__gc *gc, uint32_t domid,
                           libxl_device_vkbd *vkbd)
{
    flexarray_t *front;
    flexarray_t *back;
    libxl__device device;
    int rc;

    rc = libxl__device_vkbd_setdefault(gc, vkbd);
    if (rc) goto out;

    front = flexarray_make(gc, 16, 1);
    back = flexarray_make(gc, 16, 1);

    if (vkbd->devid == -1) {
        if ((vkbd->devid = libxl__device_nextid(gc, domid, "vkbd")) < 0) {
            rc = ERROR_FAIL;
            goto out;
        }
    }

    rc = libxl__device_from_vkbd(gc, domid, vkbd, &device);
    if (rc != 0) goto out;

    flexarray_append(back, "frontend-id");
    flexarray_append(back, GCSPRINTF("%d", domid));
    flexarray_append(back, "online");
    flexarray_append(back, "1");
    flexarray_append(back, "state");
    flexarray_append(back, GCSPRINTF("%d", XenbusStateInitialising));

    flexarray_append(front, "backend-id");
    flexarray_append(front, GCSPRINTF("%d", vkbd->backend_domid));
    flexarray_append(front, "state");
    flexarray_append(front, GCSPRINTF("%d", XenbusStateInitialising));

    libxl__device_generic_add(gc, XBT_NULL, &device,
                              libxl__xs_kvs_of_flexarray(gc, back),
                              libxl__xs_kvs_of_flexarray(gc, front),
                              NULL);
    rc = 0;
out:
    return rc;
}

LIBXL_DEFINE_DEVICE_REMOVE(vkbd)
