/*
 * Copyright (C) 2018 EPAM Systems Inc.
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

#include <xen/io/cameraif.h>

static int libxl__device_vcamera_setdefault(libxl__gc *gc, uint32_t domid,
                                            libxl_device_vcamera *vcamera,
                                            bool hotplug)
{
    return libxl__resolve_domid(gc, vcamera->backend_domname,
                                &vcamera->backend_domid);
}

static int libxl__vcamera_from_xenstore(libxl__gc *gc, const char *libxl_path,
                                        libxl_devid devid,
                                        libxl_device_vcamera *vcamera)
{
    const char *be_path;
    int rc;

    vcamera->devid = devid;
    rc = libxl__xs_read_mandatory(gc, XBT_NULL,
                                  GCSPRINTF("%s/backend", libxl_path),
                                  &be_path);
    if (rc) return rc;

    return libxl__backendpath_parse_domid(gc, be_path, &vcamera->backend_domid);
}

static void libxl__update_config_vcamera(libxl__gc *gc,
                                         libxl_device_vcamera *dst,
                                         libxl_device_vcamera *src)
{
    dst->devid = src->devid;
    dst->be_alloc = src->be_alloc;
}

static int libxl_device_vcamera_compare(libxl_device_vcamera *d1,
                                        libxl_device_vcamera *d2)
{
    return COMPARE_DEVID(d1, d2);
}

static void libxl__device_vcamera_add(libxl__egc *egc, uint32_t domid,
                                      libxl_device_vcamera *vcamera,
                                      libxl__ao_device *aodev)
{
    libxl__device_add_async(egc, domid, &libxl__vcamera_devtype, vcamera, aodev);
}

static int libxl__set_xenstore_vcamera(libxl__gc *gc, uint32_t domid,
                                       libxl_device_vcamera *vcamera,
                                       flexarray_t *back, flexarray_t *front,
                                       flexarray_t *ro_front)
{
    char *controls = "";
    int i;

    flexarray_append_pair(ro_front, XENCAMERA_FIELD_BE_ALLOC,
                          GCSPRINTF("%d", vcamera->be_alloc));
    flexarray_append_pair(ro_front, XENCAMERA_FIELD_UNIQUE_ID,
                          GCSPRINTF("%s", vcamera->unique_id));
    if (vcamera->controls)
        controls = vcamera->controls;
    flexarray_append_pair(ro_front, XENCAMERA_FIELD_CONTROLS,
                          GCSPRINTF("%s", controls));
    flexarray_append_pair(ro_front, XENCAMERA_FIELD_MAX_BUFFERS,
                          GCSPRINTF("%d", vcamera->max_buffers));

    for (i = 0; i < vcamera->num_vcamera_formats; i++)
    {
        char *frame_rates = "";

        if (vcamera->formats[i].frame_rates)
            frame_rates = vcamera->formats[i].frame_rates;

        flexarray_append_pair(ro_front,
                              GCSPRINTF(XENCAMERA_FIELD_FORMATS "/%s/%d"
                                        XENCAMERA_RESOLUTION_SEPARATOR
                                        "%d/" XENCAMERA_FIELD_FRAME_RATES,
                                        vcamera->formats[i].fourcc,
                                        vcamera->formats[i].width,
                                        vcamera->formats[i].height),
                                        frame_rates);
    }
    return 0;
}

static LIBXL_DEFINE_UPDATE_DEVID(vcamera)
static LIBXL_DEFINE_DEVICE_FROM_TYPE(vcamera)
static LIBXL_DEFINE_DEVICES_ADD(vcamera)

DEFINE_DEVICE_TYPE_STRUCT(vcamera, VCAMERA,
                          .update_config = (device_update_config_fn_t) libxl__update_config_vcamera,
                          .from_xenstore = (device_from_xenstore_fn_t) libxl__vcamera_from_xenstore,
                          .set_xenstore_config = (device_set_xenstore_config_fn_t)
                          libxl__set_xenstore_vcamera
                          );

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
