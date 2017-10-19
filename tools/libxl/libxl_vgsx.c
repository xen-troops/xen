/*
 * Copyright (C) 2017 EPAM Systems Inc.
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

static int libxl__device_vgsx_setdefault(libxl__gc *gc, uint32_t domid,
                                         libxl_device_vgsx *vgsx,
                                         bool hotplug)
{
    return libxl__resolve_domid(gc, vgsx->backend_domname,
                                &vgsx->backend_domid);
}

static int libxl__vgsx_from_xenstore(libxl__gc *gc, const char *libxl_path,
                                     libxl_devid devid,
                                     libxl_device_vgsx *vgsx)
{
    const char *tmp;
    int rc;

    vgsx->devid = devid;
    rc = libxl__xs_read_mandatory(gc, XBT_NULL,
                                  GCSPRINTF("%s/backend", libxl_path),
                                  &tmp);
    if (rc) return rc;

    rc = libxl__backendpath_parse_domid(gc, tmp, &vgsx->backend_domid);
    if (rc) return rc;

    return 0;
}

static void libxl__update_config_vgsx(libxl__gc *gc,
                                      libxl_device_vgsx *dst,
                                      libxl_device_vgsx *src)
{
    dst->devid = src->devid;
}

static int libxl_device_vgsx_compare(libxl_device_vgsx *d1,
                                     libxl_device_vgsx *d2)
{
    return COMPARE_DEVID(d1, d2);
}

static void libxl__device_vgsx_add(libxl__egc *egc, uint32_t domid,
                                   libxl_device_vgsx *vgsx,
                                   libxl__ao_device *aodev)
{
    libxl__device_add_async(egc, domid, &libxl__vgsx_devtype, vgsx, aodev);
}

static int libxl__set_xenstore_vgsx(libxl__gc *gc, uint32_t domid,
                                    libxl_device_vgsx *vgsx,
                                    flexarray_t *back, flexarray_t *front,
                                    flexarray_t *ro_front)
{
    int rc;

    rc = flexarray_append_pair(front, "osid", GCSPRINTF("%d", vgsx->osid));
    if (rc) return rc;

    return 0;
}

static LIBXL_DEFINE_UPDATE_DEVID(vgsx)
static LIBXL_DEFINE_DEVICE_FROM_TYPE(vgsx)
static LIBXL_DEFINE_DEVICES_ADD(vgsx)

DEFINE_DEVICE_TYPE_STRUCT(vgsx, VGSX,
    .update_config = (device_update_config_fn_t) libxl__update_config_vgsx,
    .from_xenstore = (device_from_xenstore_fn_t) libxl__vgsx_from_xenstore,
    .set_xenstore_config = (device_set_xenstore_config_fn_t)
                           libxl__set_xenstore_vgsx
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
