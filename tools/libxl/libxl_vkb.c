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
#include "xen/io/kbdif.h"

static int libxl__device_vkb_setdefault(libxl__gc *gc, uint32_t domid,
                                        libxl_device_vkb *vkb, bool hotplug)
{
    return libxl__resolve_domid(gc, vkb->backend_domname, &vkb->backend_domid);
}

static int libxl__device_vkb_dm_needed(libxl_device_vkb *vkb, uint32_t domid)
{
   if (vkb->backend_type == LIBXL_VKB_BACKEND_QEMU)
        return 1;
    return 0;
}

static int libxl__set_xenstore_vkb(libxl__gc *gc, uint32_t domid,
                                   libxl_device_vkb *vkb,
                                   flexarray_t *back, flexarray_t *front,
                                   flexarray_t *ro_front)
{
    if (vkb->feature_abs_pointer) {
        flexarray_append_pair(back, XENKBD_FIELD_FEAT_ABS_POINTER,
                              GCSPRINTF("%u", vkb->feature_abs_pointer));
    }

    if (vkb->feature_multi_touch) {
        flexarray_append_pair(front, XENKBD_FIELD_FEAT_MTOUCH,
                              GCSPRINTF("%u", vkb->feature_multi_touch));
    }

    if (vkb->id) {
        flexarray_append_pair(front, "id", vkb->id);
    }

    if (vkb->width) {
        flexarray_append_pair(front, XENKBD_FIELD_WIDTH,
                              GCSPRINTF("%u", vkb->width));
    }

    if (vkb->height) {
        flexarray_append_pair(front, XENKBD_FIELD_HEIGHT,
                              GCSPRINTF("%u", vkb->height));
    }

    if (vkb->feature_multi_touch) {
        flexarray_append_pair(front, XENKBD_FIELD_MT_WIDTH,
                              GCSPRINTF("%u", vkb->multi_touch_width));
        flexarray_append_pair(front, XENKBD_FIELD_MT_HEIGHT,
                              GCSPRINTF("%u", vkb->multi_touch_height));
        flexarray_append_pair(front, XENKBD_FIELD_MT_NUM_CONTACTS,
                              GCSPRINTF("%u", vkb->multi_touch_num_contacts));
    }

    return 0;
}

static int libxl__vkb_from_xenstore(libxl__gc *gc, const char *libxl_path,
                                    libxl_devid devid,
                                    libxl_device_vkb *vkb)
{
    const char *be_path;
    const char *fe_path;
    const char *tmp;
    int rc;

    vkb->devid = devid;
    rc = libxl__xs_read_mandatory(gc, XBT_NULL,
                                  GCSPRINTF("%s/backend", libxl_path),
                                  &be_path);
    if (rc) return rc;

    rc = libxl__xs_read_mandatory(gc, XBT_NULL,
                                  GCSPRINTF("%s/frontend", libxl_path),
                                  &fe_path);
    if (rc) return rc;

    rc = libxl__backendpath_parse_domid(gc, be_path, &vkb->backend_domid);
    if (rc) return rc;

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_FEAT_ABS_POINTER,
                                be_path), &tmp);
    if (rc) return rc;

    if (tmp) {
        vkb->feature_abs_pointer = strtoul(tmp, NULL, 0);
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_FEAT_MTOUCH,
                                be_path), &tmp);
    if (rc) return rc;

    if (tmp) {
        vkb->feature_multi_touch = strtoul(tmp, NULL, 0);
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_WIDTH,
                                fe_path), &tmp);
    if (rc) return rc;

    if (tmp) {
        vkb->width = strtoul(tmp, NULL, 0);
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_HEIGHT,
                                fe_path), &tmp);
    if (rc) return rc;

    if (tmp) {
        vkb->height = strtoul(tmp, NULL, 0);
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_MT_WIDTH,
                                fe_path), &tmp);
    if (rc) return rc;

    if (tmp) {
        vkb->multi_touch_width = strtoul(tmp, NULL, 0);
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_MT_HEIGHT,
                                fe_path), &tmp);
    if (rc) return rc;

    if (tmp) {
        vkb->multi_touch_height = strtoul(tmp, NULL, 0);
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_MT_NUM_CONTACTS,
                                fe_path), &tmp);
    if (rc) return rc;

    if (tmp) {
        vkb->multi_touch_num_contacts = strtoul(tmp, NULL, 0);
    }

    return 0;
}

int libxl_device_vkb_add(libxl_ctx *ctx, uint32_t domid, libxl_device_vkb *vkb,
                         const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    int rc;

    rc = libxl__device_add(gc, domid, &libxl__vkb_devtype, vkb);
    if (rc) {
        LOGD(ERROR, domid, "Unable to add vkb device");
        goto out;
    }

out:
    libxl__ao_complete(egc, ao, rc);
    return AO_INPROGRESS;
}

int libxl_device_vkb_getinfo(libxl_ctx *ctx, uint32_t domid,
                             libxl_device_vkb *vkb,
                             libxl_vkbinfo *info)
{
    GC_INIT(ctx);
    char *libxl_path, *dompath, *devpath;
    char *val;
    int rc;

    libxl_vkbinfo_init(info);
    dompath = libxl__xs_get_dompath(gc, domid);
    info->devid = vkb->devid;

    devpath = GCSPRINTF("%s/device/%s/%d", dompath,
                        libxl__device_kind_to_string(LIBXL__DEVICE_KIND_VKBD),
                        info->devid);
    libxl_path = GCSPRINTF("%s/device/%s/%d",
                           libxl__xs_libxl_path(gc, domid),
                           libxl__device_kind_to_string(LIBXL__DEVICE_KIND_VKBD),
                           info->devid);
    info->backend = xs_read(ctx->xsh, XBT_NULL,
                            GCSPRINTF("%s/backend", libxl_path),
                            NULL);
    if (!info->backend) { rc = ERROR_FAIL; goto out; }

    rc = libxl__backendpath_parse_domid(gc, info->backend, &info->backend_id);
    if (rc) goto out;

    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/state", devpath));
    info->state = val ? strtoul(val, NULL, 10) : -1;

    info->frontend = xs_read(ctx->xsh, XBT_NULL,
                             GCSPRINTF("%s/frontend", libxl_path),
                             NULL);
    info->frontend_id = domid;

    info->id = xs_read(ctx->xsh, XBT_NULL, GCSPRINTF("%s/id", devpath), NULL);

    val = libxl__xs_read(gc, XBT_NULL,
          GCSPRINTF("%s/"XENKBD_FIELD_EVT_CHANNEL, devpath));
    info->evtch = val ? strtoul(val, NULL, 10) : -1;

    val = libxl__xs_read(gc, XBT_NULL,
          GCSPRINTF("%s/"XENKBD_FIELD_RING_GREF, devpath));
    info->rref = val ? strtoul(val, NULL, 10) : -1;

    rc = 0;

out:
     GC_FREE;
     return rc;
}

static LIBXL_DEFINE_UPDATE_DEVID(vkb)
static LIBXL_DEFINE_DEVICE_FROM_TYPE(vkb)

#define libxl__add_vkbs NULL
#define libxl_device_vkb_compare NULL

LIBXL_DEFINE_DEVID_TO_DEVICE(vkb)
LIBXL_DEFINE_DEVICE_LIST(vkb)
LIBXL_DEFINE_DEVICE_REMOVE(vkb)

DEFINE_DEVICE_TYPE_STRUCT(vkb, VKBD,
    .skip_attach = 1,
    .dm_needed   = (device_dm_needed_fn_t)libxl__device_vkb_dm_needed,
    .from_xenstore = (device_from_xenstore_fn_t)libxl__vkb_from_xenstore,
    .set_xenstore_config = (device_set_xenstore_config_fn_t)
                           libxl__set_xenstore_vkb,
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
