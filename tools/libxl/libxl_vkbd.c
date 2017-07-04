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

int libxl__device_vkb_setdefault(libxl__gc *gc, libxl_device_vkb *vkb)
{
    int rc;
    rc = libxl__resolve_domid(gc, vkb->backend_domname, &vkb->backend_domid);
    return rc;
}

static int libxl__device_from_vkb(libxl__gc *gc, uint32_t domid,
                                  libxl_device_vkb *vkb,
                                  libxl__device *device)
{
    device->backend_devid = vkb->devid;
    device->backend_domid = vkb->backend_domid;
    device->backend_kind = LIBXL__DEVICE_KIND_VKBD;
    device->devid = vkb->devid;
    device->domid = domid;
    device->kind = LIBXL__DEVICE_KIND_VKBD;

    return 0;
}

int libxl_device_vkb_add(libxl_ctx *ctx, uint32_t domid, libxl_device_vkb *vkb,
                         const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    int rc;

    rc = libxl__device_vkb_add(gc, domid, vkb);
    if (rc) {
        LOGD(ERROR, domid, "Unable to add vkb device");
        goto out;
    }

out:
    libxl__ao_complete(egc, ao, rc);
    return AO_INPROGRESS;
}

int libxl__device_vkb_add(libxl__gc *gc, uint32_t domid,
                          libxl_device_vkb *vkb)
{
    flexarray_t *front;
    flexarray_t *back;
    libxl__device device;
    int rc;

    rc = libxl__device_vkb_setdefault(gc, vkb);
    if (rc) goto out;

    front = flexarray_make(gc, 16, 1);
    back = flexarray_make(gc, 16, 1);

    if (vkb->devid == -1) {
        if ((vkb->devid = libxl__device_nextid(gc, domid, "vkb")) < 0) {
            rc = ERROR_FAIL;
            goto out;
        }
    }

    rc = libxl__device_from_vkb(gc, domid, vkb, &device);
    if (rc != 0) goto out;

    flexarray_append(back, "frontend-id");
    flexarray_append(back, GCSPRINTF("%d", domid));
    flexarray_append(back, "online");
    flexarray_append(back, "1");
    flexarray_append(back, "state");
    flexarray_append(back, GCSPRINTF("%d", XenbusStateInitialising));

    flexarray_append(front, "backend-id");
    flexarray_append(front, GCSPRINTF("%d", vkb->backend_domid));
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

LIBXL_DEFINE_DEVICE_REMOVE(vkb)
