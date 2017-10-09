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

#include "libxl_osdeps.h"

#include "libxl_internal.h"

static int libxl__device_vdispl_setdefault(libxl__gc *gc, uint32_t domid,
                                           libxl_device_vdispl *vdispl)
{
    int rc;

    rc = libxl__resolve_domid(gc, vdispl->backend_domname,
                              &vdispl->backend_domid);

    if (vdispl->devid == -1) {
        vdispl->devid = libxl__device_nextid(gc, domid, "vdispl");
    }

    return rc;
}

static int libxl__from_xenstore_vdispl(libxl__gc *gc, const char *be_path,
                                       uint32_t devid,
                                       libxl_device_vdispl *vdispl)
{
    vdispl->devid = devid;

    return libxl__backendpath_parse_domid(gc, be_path, &vdispl->backend_domid);
}

static int libxl__device_from_vdispl(libxl__gc *gc, uint32_t domid,
                                     libxl_device_vdispl *vdispl,
                                     libxl__device *device)
{
   device->backend_devid   = vdispl->devid;
   device->backend_domid   = vdispl->backend_domid;
   device->backend_kind    = LIBXL__DEVICE_KIND_VDISPL;
   device->devid           = vdispl->devid;
   device->domid           = domid;
   device->kind            = LIBXL__DEVICE_KIND_VDISPL;

   return 0;
}

static int libxl__set_xenstore_connectors(libxl__gc *gc, xs_transaction_t t,
                                          libxl__device *device,
                                          libxl_device_vdispl *vdispl)
{
    struct xs_permissions perms[2];
    char *frontend_path = NULL;
    flexarray_t *connector;
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int i;
    int rc;

    frontend_path = libxl__device_frontend_path(gc, device);

    perms[0].id = device->domid;
    perms[0].perms = XS_PERM_NONE;
    perms[1].id = device->backend_domid;
    perms[1].perms = XS_PERM_READ;

    connector = flexarray_make(gc, 2, 1);
    flexarray_append(connector, "resolution");
    flexarray_append(connector, "");
    flexarray_append(connector, "id");
    flexarray_append(connector, "");

    for (i = 0; i < vdispl->num_connectors; i++) {
        char *connector_path = GCSPRINTF("%s/%d", frontend_path, i);

        if (!xs_mkdir(ctx->xsh, t, connector_path)) {
            rc = ERROR_FAIL; goto out;
        }

        if (!xs_set_permissions(ctx->xsh, t, connector_path, perms,
                                ARRAY_SIZE(perms))) {
            rc = ERROR_FAIL; goto out;
        }

        flexarray_set(connector, 1,
                      GCSPRINTF("%dx%d", vdispl->connectors[i].width,
                                 vdispl->connectors[i].height));
        flexarray_set(connector, 3, vdispl->connectors[i].id);

        rc = libxl__xs_writev(gc, t, connector_path,
                              libxl__xs_kvs_of_flexarray(gc, connector));
        if (rc) goto out;
    }

    rc = 0;

out:
    return rc;
}

static int libxl__set_xenstore_vdispl(libxl__gc *gc, uint32_t domid,
                                      libxl_device_vdispl *vdispl)
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
    flexarray_append(back, GCSPRINTF("%d", vdispl->devid));

    flexarray_append(front, "backend-id");
    flexarray_append(front, GCSPRINTF("%d", vdispl->backend_domid));
    flexarray_append(front, "state");
    flexarray_append(front, GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append(front, "handle");
    flexarray_append(front, GCSPRINTF("%d", vdispl->devid));
    flexarray_append(front, "be_alloc");
    flexarray_append(front, GCSPRINTF("%d", vdispl->be_alloc));

    libxl__device *device;
    xs_transaction_t t = XBT_NULL;
    int rc;

    GCNEW(device);

    rc = libxl__device_from_vdispl(gc, domid, vdispl, device);
    if (rc) goto out;

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        rc = libxl__device_generic_add(gc, t, device,
                                       libxl__xs_kvs_of_flexarray(gc, back),
                                       libxl__xs_kvs_of_flexarray(gc, front),
                                       NULL);
        if (rc) goto out;

        rc = libxl__set_xenstore_connectors(gc, t, device, vdispl);
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

static void libxl__update_config_vdispl(libxl__gc *gc,
                                        libxl_device_vdispl *dst,
                                        libxl_device_vdispl *src)
{
    dst->devid = src->devid;
    dst->be_alloc = src->be_alloc;
}

static int libxl_device_vdispl_compare(libxl_device_vdispl *d1,
                                       libxl_device_vdispl *d2)
{
    return COMPARE_DEVID(d1, d2);
}

static void libxl__device_vdispl_add(libxl__egc *egc, uint32_t domid,
                                     libxl_device_vdispl *vdispl,
                                     libxl__ao_device *aodev)
{
    libxl__device_add_async(egc, domid, &libxl__vdispl_devtype, vdispl, aodev);
}

static int libxl__device_vdispl_getconnectors(libxl_ctx *ctx,
                                              const char *path,
                                              libxl_vdisplinfo *info)
{
    GC_INIT(ctx);
    char *connector = NULL;
    char *connector_path = NULL;
    int i, rc;

    GCNEW_ARRAY(connector_path, 128);

    info->num_connectors = 0;

    rc = snprintf(connector_path, 128, "%s/%d", path, info->num_connectors);
    if (rc < 0) goto out;

    while((connector = xs_read(ctx->xsh, XBT_NULL, connector_path, NULL))
          != NULL) {
        free(connector);

        rc = snprintf(connector_path, 128, "%s/%d",
                      path, ++info->num_connectors);
        if (rc < 0) goto out;
    }

    info->connectors = libxl__calloc(NOGC, info->num_connectors,
                                     sizeof(*info->connectors));

    for (i = 0; i < info->num_connectors; i++) {
        char *value;

        snprintf(connector_path, 128, "%s/%d/id", path, i);
        info->connectors[i].id = xs_read(ctx->xsh, XBT_NULL,
                                         connector_path, NULL);
        if (info->connectors[i].id == NULL) { rc = ERROR_FAIL; goto out; }

        snprintf(connector_path, 128, "%s/%d/resolution", path, i);
        value = xs_read(ctx->xsh, XBT_NULL, connector_path, NULL);
        if (value == NULL) { rc = ERROR_FAIL; goto out; }

        rc = sscanf(value, "%ux%u", &info->connectors[i].width,
                   &info->connectors[i].height);
        free(value);
        if (rc != 2) {
            rc = ERROR_FAIL; goto out;
        }

        snprintf(connector_path, 128, "%s/%d/req-ring-ref", path, i);
        value = xs_read(ctx->xsh, XBT_NULL, connector_path, NULL);
        info->connectors[i].req_rref = value ? strtoul(value, NULL, 10) : -1;
        free(value);

        snprintf(connector_path, 128, "%s/%d/req-event-channel", path, i);
        value = xs_read(ctx->xsh, XBT_NULL, connector_path, NULL);
        info->connectors[i].req_evtch = value ? strtoul(value, NULL, 10) : -1;
        free(value);

        snprintf(connector_path, 128, "%s/%d/evt-ring-ref", path, i);
        value = xs_read(ctx->xsh, XBT_NULL, connector_path, NULL);
        info->connectors[i].evt_rref = value ? strtoul(value, NULL, 10) : -1;
        free(value);

        snprintf(connector_path, 128, "%s/%d/evt-event-channel", path, i);
        value = xs_read(ctx->xsh, XBT_NULL, connector_path, NULL);
        info->connectors[i].evt_evtch = value ? strtoul(value, NULL, 10) : -1;
        free(value);
    }

    rc = 0;

out:
    return rc;
}

libxl_device_vdispl *libxl_device_vdispl_list(libxl_ctx *ctx, uint32_t domid,
                                              int *num)
{
    return libxl__device_list(&libxl__vdispl_devtype, ctx, domid, num);
}

void libxl_device_vdispl_list_free(libxl_device_vdispl* list, int num)
{
    libxl__device_list_free(&libxl__vdispl_devtype, list, num);
}

int libxl_device_vdispl_getinfo(libxl_ctx *ctx, uint32_t domid,
                                libxl_device_vdispl *vdispl,
                                libxl_vdisplinfo *info)
{
    GC_INIT(ctx);
    char *libxl_path, *dompath, *devpath;
    char *val;
    int rc;

    libxl_vdisplinfo_init(info);
    dompath = libxl__xs_get_dompath(gc, domid);
    info->devid = vdispl->devid;

    devpath = GCSPRINTF("%s/device/vdispl/%d", dompath, info->devid);
    libxl_path = GCSPRINTF("%s/device/vdispl/%d",
                           libxl__xs_libxl_path(gc, domid),
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

    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/be_alloc", devpath));
    info->be_alloc = val ? strtoul(val, NULL, 10) : 0;

    rc = libxl__device_vdispl_getconnectors(ctx, devpath, info);
    if (rc) goto out;

    rc = 0;

out:
     GC_FREE;
     return rc;
}

int libxl_devid_to_device_vdispl(libxl_ctx *ctx, uint32_t domid,
                                 int devid, libxl_device_vdispl *vdispl)
{
    libxl_device_vdispl *vdispls = NULL;
    int n, i;
    int rc;

    libxl_device_vdispl_init(vdispl);

    vdispls = libxl_device_vdispl_list(ctx, domid, &n);

    if (!vdispls) { rc = ERROR_NOTFOUND; goto out; }

    for (i = 0; i < n; ++i) {
        if (devid == vdispls[i].devid) {
            libxl_device_vdispl_copy(ctx, vdispl, &vdispls[i]);
            rc = 0;
            goto out;
        }
    }

    rc = ERROR_NOTFOUND;

out:

    if (vdispls) {
        libxl_device_vdispl_list_free(vdispls, n);
    }
    return rc;
}

LIBXL_DEFINE_DEVICE_ADD(vdispl)
static LIBXL_DEFINE_DEVICES_ADD(vdispl)
LIBXL_DEFINE_DEVICE_REMOVE(vdispl)

DEFINE_DEVICE_TYPE_STRUCT(vdispl,
    .update_config = (void (*)(libxl__gc *, void *, void *))
                     libxl__update_config_vdispl,
    .from_xenstore = (int (*)(libxl__gc *, const char *, uint32_t, void *))
                     libxl__from_xenstore_vdispl,
    .set_xenstore_config = (int (*)(libxl__gc *, uint32_t, void *))
                           libxl__set_xenstore_vdispl
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
